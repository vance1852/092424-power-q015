"""访问控制的 SQLite 模式与数据访问。

表名统一使用 ``access_`` 前缀，可以与业务库共存于同一个 SQLite 文件。
授权状态（岗位、授权变更、会话、复核票据、访问审计）全部持久化，
进程重启后仍然可查；会话令牌本身不落库，只保存其 SHA-256 摘要。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from typing import Any, Iterator, Mapping


ACCESS_SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS access_roles (
    role_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_role_parents (
    role_id TEXT NOT NULL REFERENCES access_roles(role_id),
    parent_role_id TEXT NOT NULL REFERENCES access_roles(role_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY(role_id, parent_role_id),
    CHECK(role_id <> parent_role_id)
);

CREATE TABLE IF NOT EXISTS access_grants (
    grant_id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_type TEXT NOT NULL CHECK(subject_type IN ('role','user')),
    subject_id TEXT NOT NULL,
    permission TEXT NOT NULL,
    effect TEXT NOT NULL CHECK(effect IN ('allow','deny')),
    effective_from TEXT NOT NULL,
    reason TEXT NOT NULL,
    granted_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    revoked_by TEXT,
    revoke_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_access_grants_subject
ON access_grants(subject_type, subject_id, effective_from);

CREATE TABLE IF NOT EXISTS access_sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    label TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT,
    revoked_by TEXT,
    revoke_reason TEXT,
    replaced_session_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_access_sessions_user
ON access_sessions(user_id, created_at);

CREATE TABLE IF NOT EXISTS access_review_tickets (
    ticket_id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    expected_version TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    requester_session_id TEXT NOT NULL,
    requester_id TEXT NOT NULL,
    decision TEXT CHECK(decision IS NULL OR decision IN ('approved','rejected')),
    reviewer_id TEXT,
    review_note TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    reviewed_at TEXT,
    consumed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_access_review_lookup
ON access_review_tickets(scope, entity_type, entity_id);

CREATE TABLE IF NOT EXISTS access_audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_access_audit_actor
ON access_audit_events(actor_id, event_id);
"""


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def initialize_access_control(connection: sqlite3.Connection) -> None:
    """在既有连接上创建访问控制表，可重复执行。"""

    connection.executescript(ACCESS_SCHEMA)


@contextmanager
def transaction(connection: sqlite3.Connection, *, immediate: bool = False) -> Iterator[None]:
    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


class AccessStore:
    """只负责读写访问控制表，不包含策略判断。"""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        initialize_access_control(connection)

    # -- 访问审计（独立哈希链） -------------------------------------------------

    def append_audit(
        self,
        event_type: str,
        actor_id: str,
        subject_type: str,
        subject_id: str,
        payload: Mapping[str, Any],
        now: str,
    ) -> int:
        previous = self.connection.execute(
            "SELECT event_hash FROM access_audit_events ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        previous_hash = "0" * 64 if previous is None else previous["event_hash"]
        body = {
            "event_type": event_type,
            "actor_id": actor_id,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "payload": dict(payload),
            "created_at": now,
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
        cursor = self.connection.execute(
            "INSERT INTO access_audit_events(event_type,actor_id,subject_type,subject_id,payload_json,"
            "previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                event_type,
                actor_id,
                subject_type,
                subject_id,
                canonical_json(payload),
                previous_hash,
                event_hash,
                now,
            ),
        )
        return int(cursor.lastrowid)

    def audit_events(self, actor_id: str | None = None) -> list[sqlite3.Row]:
        if actor_id is None:
            return self.connection.execute(
                "SELECT * FROM access_audit_events ORDER BY event_id"
            ).fetchall()
        return self.connection.execute(
            "SELECT * FROM access_audit_events WHERE actor_id=? ORDER BY event_id", (actor_id,)
        ).fetchall()

    def verify_chain(self) -> dict[str, Any]:
        rows = self.connection.execute("SELECT * FROM access_audit_events ORDER BY event_id").fetchall()
        previous_hash = "0" * 64
        valid = True
        for row in rows:
            body = {
                "event_type": row["event_type"],
                "actor_id": row["actor_id"],
                "subject_type": row["subject_type"],
                "subject_id": row["subject_id"],
                "payload": json.loads(row["payload_json"]),
                "created_at": row["created_at"],
                "previous_hash": row["previous_hash"],
            }
            calculated = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
            if row["previous_hash"] != previous_hash or row["event_hash"] != calculated:
                valid = False
                break
            previous_hash = row["event_hash"]
        return {"valid": valid, "events": len(rows), "head_hash": previous_hash}

    # -- 岗位与继承 -------------------------------------------------------------

    def upsert_role(self, role_id: str, display_name: str, now: str, active: bool = True) -> None:
        self.connection.execute(
            "INSERT INTO access_roles(role_id,display_name,active,created_at) VALUES(?,?,?,?) "
            "ON CONFLICT(role_id) DO UPDATE SET display_name=excluded.display_name,active=excluded.active",
            (role_id, display_name, 1 if active else 0, now),
        )

    def get_role(self, role_id: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM access_roles WHERE role_id=?", (role_id,)
        ).fetchone()

    def list_roles(self) -> list[sqlite3.Row]:
        return self.connection.execute("SELECT * FROM access_roles ORDER BY role_id").fetchall()

    def set_role_parents(self, role_id: str, parent_ids: list[str], now: str) -> None:
        self.connection.execute("DELETE FROM access_role_parents WHERE role_id=?", (role_id,))
        self.connection.executemany(
            "INSERT INTO access_role_parents(role_id,parent_role_id,created_at) VALUES(?,?,?)",
            [(role_id, parent, now) for parent in parent_ids],
        )

    def parent_ids(self, role_id: str) -> list[str]:
        return [
            row["parent_role_id"]
            for row in self.connection.execute(
                "SELECT parent_role_id FROM access_role_parents WHERE role_id=? ORDER BY parent_role_id",
                (role_id,),
            ).fetchall()
        ]

    # -- 授权变更 ---------------------------------------------------------------

    def insert_grant(
        self,
        subject_type: str,
        subject_id: str,
        permission: str,
        effect: str,
        effective_from: str,
        reason: str,
        granted_by: str,
        now: str,
    ) -> int:
        cursor = self.connection.execute(
            "INSERT INTO access_grants(subject_type,subject_id,permission,effect,effective_from,"
            "reason,granted_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (subject_type, subject_id, permission, effect, effective_from, reason, granted_by, now),
        )
        return int(cursor.lastrowid)

    def revoke_grant(self, grant_id: int, revoked_by: str, reason: str, now: str) -> bool:
        cursor = self.connection.execute(
            "UPDATE access_grants SET revoked_at=?,revoked_by=?,revoke_reason=? "
            "WHERE grant_id=? AND revoked_at IS NULL",
            (now, revoked_by, reason, grant_id),
        )
        return cursor.rowcount == 1

    def get_grant(self, grant_id: int) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM access_grants WHERE grant_id=?", (grant_id,)
        ).fetchone()

    def list_grants(self, include_revoked: bool = False) -> list[sqlite3.Row]:
        sql = "SELECT * FROM access_grants"
        if not include_revoked:
            sql += " WHERE revoked_at IS NULL"
        sql += " ORDER BY grant_id"
        return self.connection.execute(sql).fetchall()

    def active_grants(self, now: str) -> list[sqlite3.Row]:
        return self.connection.execute(
            "SELECT * FROM access_grants WHERE revoked_at IS NULL AND effective_from<=? ORDER BY grant_id",
            (now,),
        ).fetchall()

    # -- 会话 -------------------------------------------------------------------

    def insert_session(
        self,
        session_id: str,
        user_id: str,
        label: str,
        created_at: str,
        expires_at: str | None,
        replaced_session_id: str | None,
    ) -> None:
        self.connection.execute(
            "INSERT INTO access_sessions(session_id,user_id,label,created_at,expires_at,"
            "replaced_session_id) VALUES(?,?,?,?,?,?)",
            (session_id, user_id, label, created_at, expires_at, replaced_session_id),
        )

    def get_session(self, session_id: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM access_sessions WHERE session_id=?", (session_id,)
        ).fetchone()

    def revoke_session(self, session_id: str, revoked_by: str, reason: str, now: str) -> bool:
        cursor = self.connection.execute(
            "UPDATE access_sessions SET revoked_at=?,revoked_by=?,revoke_reason=? "
            "WHERE session_id=? AND revoked_at IS NULL",
            (now, revoked_by, reason, session_id),
        )
        return cursor.rowcount == 1

    def revoke_all_user_sessions(self, user_id: str, revoked_by: str, reason: str, now: str) -> int:
        cursor = self.connection.execute(
            "UPDATE access_sessions SET revoked_at=?,revoked_by=?,revoke_reason=? "
            "WHERE user_id=? AND revoked_at IS NULL",
            (now, revoked_by, reason, user_id),
        )
        return cursor.rowcount

    def list_sessions(self, user_id: str | None = None, include_revoked: bool = True) -> list[sqlite3.Row]:
        sql = "SELECT * FROM access_sessions"
        clauses: list[str] = []
        params: list[Any] = []
        if user_id is not None:
            clauses.append("user_id=?")
            params.append(user_id)
        if not include_revoked:
            clauses.append("revoked_at IS NULL")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at DESC,session_id"
        return self.connection.execute(sql, params).fetchall()

    # -- 二次复核票据 -----------------------------------------------------------

    def insert_ticket(
        self,
        ticket_id: str,
        scope: str,
        entity_type: str,
        entity_id: str,
        expected_version: str,
        request_sha256: str,
        requester_session_id: str,
        requester_id: str,
        created_at: str,
        expires_at: str,
    ) -> None:
        self.connection.execute(
            "INSERT INTO access_review_tickets(ticket_id,scope,entity_type,entity_id,expected_version,"
            "request_sha256,requester_session_id,requester_id,expires_at,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                ticket_id,
                scope,
                entity_type,
                entity_id,
                str(expected_version),
                request_sha256,
                requester_session_id,
                requester_id,
                expires_at,
                created_at,
            ),
        )

    def get_ticket(self, ticket_id: str) -> sqlite3.Row | None:
        return self.connection.execute(
            "SELECT * FROM access_review_tickets WHERE ticket_id=?", (ticket_id,)
        ).fetchone()

    def decide_ticket(
        self, ticket_id: str, decision: str, reviewer_id: str, note: str, now: str
    ) -> bool:
        cursor = self.connection.execute(
            "UPDATE access_review_tickets SET decision=?,reviewer_id=?,review_note=?,reviewed_at=? "
            "WHERE ticket_id=? AND decision IS NULL",
            (decision, reviewer_id, note, now, ticket_id),
        )
        return cursor.rowcount == 1

    def consume_ticket(self, ticket_id: str, now: str) -> bool:
        cursor = self.connection.execute(
            "UPDATE access_review_tickets SET consumed_at=? "
            "WHERE ticket_id=? AND decision='approved' AND consumed_at IS NULL",
            (now, ticket_id),
        )
        return cursor.rowcount == 1
