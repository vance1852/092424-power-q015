"""统计分析准入服务的领域用例。"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import timedelta
from decimal import Decimal
from typing import Any, Iterable, Mapping

from .analysis import ALGORITHM_VERSION, analyze
from .clock import SystemClock, isoformat
from .contracts import Observation, Protocol, ValidationError
from .errors import Conflict, Forbidden, InvalidState, NotFound, Unauthorized, ValidationFailed
from .identity import effective_permissions, sortable_ts
from .jsonio import canonical_json, content_digest
from .storage import initialize, transaction


SESSION_TTL_SECONDS_DEFAULT = 12 * 3600

# 当前请求绑定的会话编号，审计事件自动记录。
_current_session: ContextVar[str | None] = ContextVar("current_session", default=None)


class TrialService:
    """在单个 SQLite 连接上提供全部业务操作。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    @staticmethod
    @contextmanager
    def bind_session(session_id: str):
        token = _current_session.set(session_id)
        try:
            yield
        finally:
            _current_session.reset(token)

    def _now(self) -> str:
        return isoformat(self.clock.now())

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT user_id, display_name, position_id, active FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        user = self._user(user_id)
        if permission not in effective_permissions(self.connection, user["position_id"], self._now()):
            raise Forbidden(f"岗位 {user['position_id']} 无权执行 {permission}")
        return user

    def _permissions(self, user: sqlite3.Row) -> set[str]:
        return effective_permissions(self.connection, user["position_id"], self._now())

    def _audit(
        self, entity_type: str, entity_id: str, event_type: str, actor_id: str, payload: Mapping[str, Any]
    ) -> None:
        body = dict(payload)
        session_id = _current_session.get()
        if session_id is not None:
            body.setdefault("session_id", session_id)
        self.connection.execute(
            "INSERT INTO audit_events(entity_type,entity_id,event_type,actor_id,payload_json,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (entity_type, entity_id, event_type, actor_id, canonical_json(body), self._now()),
        )

    # ------------------------------------------------------------------ 岗位、权限与用户

    def list_positions(self, actor_id: str) -> dict[str, Any]:
        self._require(actor_id, "position.manage")
        rows = self.connection.execute(
            "SELECT * FROM positions WHERE active=1 ORDER BY position_id"
        ).fetchall()
        at = self._now()
        return {
            "positions": [
                {
                    "position_id": row["position_id"],
                    "display_name": row["display_name"],
                    "parent_id": row["parent_id"],
                    "built_in": bool(row["built_in"]),
                    "permissions": sorted(effective_permissions(self.connection, row["position_id"], at)),
                }
                for row in rows
            ]
        }

    def create_position(
        self, actor_id: str, position_id: str, display_name: str, parent_id: str | None
    ) -> dict[str, Any]:
        self._require(actor_id, "position.manage")
        if not position_id.strip() or not display_name.strip():
            raise ValidationFailed("岗位编号和名称不能为空")
        if parent_id is not None and self.connection.execute(
            "SELECT 1 FROM positions WHERE position_id=? AND active=1", (parent_id,)
        ).fetchone() is None:
            raise ValidationFailed("父岗位不存在")
        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO positions(position_id,display_name,parent_id,built_in,created_at) "
                    "VALUES(?,?,?,0,?)",
                    (position_id.strip(), display_name.strip(), parent_id, now),
                )
                self._audit("position", position_id, "position.created", actor_id,
                            {"display_name": display_name, "parent_id": parent_id})
        except sqlite3.IntegrityError as exc:
            raise Conflict("岗位编号已经存在") from exc
        return {"position_id": position_id, "parent_id": parent_id}

    def change_permission(
        self,
        actor_id: str,
        position_id: str,
        permission: str,
        effect: str,
        effective_from: str | None,
        reason: str,
    ) -> dict[str, Any]:
        self._require(actor_id, "position.manage")
        if effect not in {"grant", "deny", "revoke"}:
            raise ValidationFailed("effect 必须是 grant、deny 或 revoke")
        if not reason.strip():
            raise ValidationFailed("权限变更必须填写审计原因")
        if self.connection.execute(
            "SELECT 1 FROM positions WHERE position_id=? AND active=1", (position_id,)
        ).fetchone() is None:
            raise NotFound("岗位不存在")
        if not permission.strip():
            raise ValidationFailed("权限名不能为空")
        effective_at = (
            sortable_ts(self._now()) if effective_from is None else sortable_ts(self._parse_time(effective_from))
        )
        now = self._now()
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "INSERT INTO permission_changes"
                "(position_id,permission,effect,effective_from,reason,changed_by,created_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (position_id, permission.strip(), effect, effective_at, reason.strip(), actor_id, now),
            )
            change_id = cursor.lastrowid
            self._audit("position", position_id, "permission.changed", actor_id, {
                "change_id": change_id, "permission": permission.strip(), "effect": effect,
                "effective_from": effective_at, "reason": reason.strip(),
            })
        return {"change_id": change_id, "position_id": position_id,
                "permission": permission.strip(), "effect": effect, "effective_from": effective_at}

    def list_permission_changes(self, actor_id: str, position_id: str | None = None) -> dict[str, Any]:
        self._require(actor_id, "position.manage")
        if position_id is None:
            rows = self.connection.execute(
                "SELECT * FROM permission_changes ORDER BY change_id"
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM permission_changes WHERE position_id=? ORDER BY change_id",
                (position_id,),
            ).fetchall()
        return {"changes": [dict(row) for row in rows]}

    def _insert_user(self, user_id: str, display_name: str, position_id: str) -> dict[str, Any]:
        if not user_id.strip() or not display_name.strip():
            raise ValidationFailed("用户编号和名称不能为空")
        if self.connection.execute(
            "SELECT 1 FROM positions WHERE position_id=? AND active=1", (position_id,)
        ).fetchone() is None:
            raise ValidationFailed(f"未知岗位: {position_id}")
        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO users(user_id,display_name,position_id,created_at) VALUES(?,?,?,?)",
                    (user_id.strip(), display_name.strip(), position_id, now),
                )
                self.connection.execute(
                    "INSERT INTO user_position_history"
                    "(user_id,position_id,effective_from,reason,changed_by,created_at) "
                    "VALUES(?,?,?, '开户建档', 'system', ?)",
                    (user_id.strip(), position_id, now, now),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"用户已存在: {user_id}") from exc
        return {"user_id": user_id.strip(), "position_id": position_id}

    def create_user(self, user_id: str, display_name: str, position_id: str) -> dict[str, Any]:
        return self._insert_user(user_id, display_name, position_id)

    def bootstrap_user(self, user_id: str, display_name: str, position_id: str) -> dict[str, Any]:
        count = self.connection.execute("SELECT count(*) FROM users").fetchone()[0]
        if count:
            raise Forbidden("系统已经存在用户，引导入口已关闭")
        return self._insert_user(user_id, display_name, position_id)

    def admin_create_user(self, actor_id: str, user_id: str, display_name: str, position_id: str) -> dict[str, Any]:
        self._require(actor_id, "user.manage")
        return self._insert_user(user_id, display_name, position_id)

    def deactivate_user(self, actor_id: str, user_id: str, reason: str) -> dict[str, Any]:
        self._require(actor_id, "user.manage")
        if not reason.strip():
            raise ValidationFailed("停用用户必须填写原因")
        now = self._now()
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE users SET active=0 WHERE user_id=? AND active=1", (user_id,)
            )
            if cursor.rowcount != 1:
                raise NotFound("用户不存在或已停用")
            self.connection.execute(
                "UPDATE sessions SET revoked_at=?,revoke_reason=?,revoked_by=? "
                "WHERE user_id=? AND revoked_at IS NULL",
                (now, f"用户停用: {reason.strip()}", actor_id, user_id),
            )
            self._audit("user", user_id, "user.deactivated", actor_id, {"reason": reason.strip()})
        return {"user_id": user_id, "active": False}

    def assign_position(
        self, actor_id: str, user_id: str, position_id: str, effective_from: str | None, reason: str
    ) -> dict[str, Any]:
        """换岗立即生效并撤销旧会话；岗位历史链完整保留。"""

        self._require(actor_id, "user.manage")
        if not reason.strip():
            raise ValidationFailed("换岗必须填写审计原因")
        if self.connection.execute(
            "SELECT 1 FROM positions WHERE position_id=? AND active=1", (position_id,)
        ).fetchone() is None:
            raise ValidationFailed(f"未知岗位: {position_id}")
        if self.connection.execute("SELECT 1 FROM users WHERE user_id=?", (user_id,)).fetchone() is None:
            raise NotFound("用户不存在")
        effective_at = self._now() if effective_from is None else self._parse_time(effective_from)
        now = self._now()
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "INSERT INTO user_position_history"
                "(user_id,position_id,effective_from,reason,changed_by,created_at) VALUES(?,?,?,?,?,?)",
                (user_id, position_id, effective_at, reason.strip(), actor_id, now),
            )
            self.connection.execute(
                "UPDATE users SET position_id=? WHERE user_id=?", (position_id, user_id)
            )
            self.connection.execute(
                "UPDATE sessions SET revoked_at=?,revoke_reason=?,revoked_by=? "
                "WHERE user_id=? AND revoked_at IS NULL",
                (now, f"换岗至 {position_id}: {reason.strip()}", actor_id, user_id),
            )
            self._audit("user", user_id, "position.assigned", actor_id,
                        {"position_id": position_id, "effective_from": effective_at,
                         "reason": reason.strip()})
        return {"user_id": user_id, "position_id": position_id, "effective_from": effective_at}

    def _parse_time(self, value: str) -> str:
        from datetime import datetime
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise ValidationFailed("时间必须是 ISO 8601 格式") from exc
        if parsed.tzinfo is None:
            raise ValidationFailed("时间必须包含时区")
        return isoformat(parsed)

    # ------------------------------------------------------------------ 会话签发与撤销

    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def issue_session(self, actor_id: str, ttl_seconds: int = SESSION_TTL_SECONDS_DEFAULT) -> dict[str, Any]:
        user = self._user(actor_id)
        if ttl_seconds <= 0:
            raise ValidationFailed("会话有效期必须大于零")
        now_text = self._now()
        expires_at = isoformat(self.clock.now() + timedelta(seconds=ttl_seconds))
        token = secrets.token_urlsafe(32)
        session_id = "sess-" + secrets.token_hex(12)
        permissions = sorted(effective_permissions(self.connection, user["position_id"], now_text))
        with transaction(self.connection, immediate=True):
            previous = self.connection.execute(
                "SELECT session_id FROM sessions WHERE user_id=? AND revoked_at IS NULL AND expires_at>? "
                "ORDER BY issued_at",
                (actor_id, now_text),
            ).fetchall()
            self.connection.execute(
                "INSERT INTO sessions(session_id,user_id,token_sha256,position_snapshot,"
                "issued_at,expires_at) VALUES(?,?,?,?,?,?)",
                (session_id, actor_id, self._hash_token(token), canonical_json(
                    {"position_id": user["position_id"], "permissions": permissions}
                ), now_text, expires_at),
            )
            for row in previous:
                self.connection.execute(
                    "UPDATE sessions SET revoked_at=?,revoke_reason='重复登录被新会话替换',"
                    "revoked_by=?,replaced_by=? WHERE session_id=?",
                    (now_text, actor_id, session_id, row["session_id"]),
                )
            self._audit("session", session_id, "session.issued", actor_id, {
                "user_id": actor_id, "position_id": user["position_id"],
                "replaces": [r["session_id"] for r in previous],
            })
        return {
            "session_id": session_id, "token": token, "user_id": actor_id,
            "position_id": user["position_id"], "permissions": permissions,
            "issued_at": now_text, "expires_at": expires_at,
        }

    def authenticate(self, token: str) -> sqlite3.Row:
        presented = (token or "").strip()
        if not presented:
            raise Unauthorized("缺少会话令牌")
        row = self.connection.execute(
            "SELECT s.*,u.active AS user_active FROM sessions s "
            "JOIN users u ON u.user_id=s.user_id WHERE s.token_sha256=?",
            (self._hash_token(presented),),
        ).fetchone()
        now = self._now()
        if row is None:
            raise Unauthorized("会话令牌无效")
        if row["revoked_at"] is not None:
            raise Unauthorized("会话已撤销")
        if row["expires_at"] <= now:
            raise Unauthorized("会话已过期")
        if not row["user_active"]:
            raise Unauthorized("用户已停用")
        return row

    def revoke_session(self, actor_id: str, session_id: str, reason: str) -> dict[str, Any]:
        self._require(actor_id, "session.revoke")
        if not reason.strip():
            raise ValidationFailed("撤销会话必须填写原因")
        now = self._now()
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT user_id,revoked_at FROM sessions WHERE session_id=?", (session_id,)
            ).fetchone()
            if row is None:
                raise NotFound("会话不存在")
            if row["revoked_at"] is not None:
                raise Conflict("会话已经撤销")
            self.connection.execute(
                "UPDATE sessions SET revoked_at=?,revoke_reason=?,revoked_by=? WHERE session_id=?",
                (now, reason.strip(), actor_id, session_id),
            )
            self._audit("session", session_id, "session.revoked", actor_id,
                        {"user_id": row["user_id"], "reason": reason.strip()})
        return {"session_id": session_id, "status": "revoked"}

    def revoke_user_sessions(self, actor_id: str, user_id: str, reason: str) -> dict[str, Any]:
        self._require(actor_id, "session.revoke")
        if not reason.strip():
            raise ValidationFailed("撤销会话必须填写原因")
        now = self._now()
        with transaction(self.connection, immediate=True):
            rows = self.connection.execute(
                "SELECT session_id FROM sessions WHERE user_id=? AND revoked_at IS NULL", (user_id,)
            ).fetchall()
            for row in rows:
                self.connection.execute(
                    "UPDATE sessions SET revoked_at=?,revoke_reason=?,revoked_by=? WHERE session_id=?",
                    (now, reason.strip(), actor_id, row["session_id"]),
                )
                self._audit("session", row["session_id"], "session.revoked", actor_id,
                            {"user_id": user_id, "reason": reason.strip()})
        return {"revoked": len(rows)}

    def list_sessions(self, actor_id: str, user_id: str | None = None) -> dict[str, Any]:
        self._require(actor_id, "session.read")
        sql = ("SELECT session_id,user_id,issued_at,expires_at,revoked_at,revoke_reason,revoked_by,"
               "replaced_by FROM sessions")
        if user_id is None:
            rows = self.connection.execute(sql + " ORDER BY issued_at").fetchall()
        else:
            rows = self.connection.execute(sql + " WHERE user_id=? ORDER BY issued_at", (user_id,)).fetchall()
        return {"sessions": [dict(row) for row in rows]}

    def register_robot(
        self, actor_id: str, robot_id: str, model_name: str, vendor: str
    ) -> dict[str, Any]:
        self._require(actor_id, "catalog.write")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO robots(robot_id,model_name,vendor,created_at) VALUES(?,?,?,?)",
                    (robot_id, model_name, vendor, self._now()),
                )
                self._audit("robot", robot_id, "robot.registered", actor_id, {"model_name": model_name})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"传感器已存在: {robot_id}") from exc
        return {"robot_id": robot_id, "model_name": model_name, "vendor": vendor}

    def register_build(
        self, actor_id: str, build_id: str, robot_id: str, version: str, content_sha256: str
    ) -> dict[str, Any]:
        self._require(actor_id, "catalog.write")
        if len(content_sha256) != 64:
            raise ValidationFailed("构建摘要必须是 64 位 SHA-256")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO builds(build_id,robot_id,version,content_sha256,created_at) VALUES(?,?,?,?,?)",
                    (build_id, robot_id, version, content_sha256.lower(), self._now()),
                )
                self._audit("build", build_id, "build.registered", actor_id, {"robot_id": robot_id, "version": version})
        except sqlite3.IntegrityError as exc:
            raise Conflict("构建编号、版本或摘要冲突") from exc
        return {"build_id": build_id, "robot_id": robot_id, "version": version}

    def publish_protocol(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "protocol.publish")
        try:
            protocol = Protocol.from_dict(raw)
        except ValidationError as exc:
            raise ValidationFailed(str(exc)) from exc
        text = canonical_json(raw)
        digest = content_digest([raw])
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO protocol_catalog(protocol_id,version,title,task_family,canonical_json,content_sha256,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        protocol.protocol_id,
                        protocol.version,
                        protocol.title,
                        protocol.task_family,
                        text,
                        digest,
                        self._now(),
                    ),
                )
                identity = f"{protocol.protocol_id}@{protocol.version}"
                self._audit("protocol", identity, "protocol.published", actor_id, {"sha256": digest})
        except sqlite3.IntegrityError as exc:
            raise Conflict("协议版本或内容摘要已经存在") from exc
        return {"protocol_id": protocol.protocol_id, "version": protocol.version, "sha256": digest}

    def _protocol(self, protocol_id: str, version: int) -> tuple[Protocol, str]:
        row = self.connection.execute(
            "SELECT canonical_json,content_sha256 FROM protocol_catalog WHERE protocol_id=? AND version=?",
            (protocol_id, version),
        ).fetchone()
        if row is None:
            raise NotFound("协议版本不存在")
        return Protocol.from_dict(json.loads(row["canonical_json"])), row["content_sha256"]

    def create_batch(
        self,
        actor_id: str,
        batch_id: str,
        protocol_id: str,
        protocol_version: int,
        build_id: str,
    ) -> dict[str, Any]:
        self._require(actor_id, "batch.create")
        self._protocol(protocol_id, protocol_version)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO batches(batch_id,protocol_id,protocol_version,build_id,state,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (batch_id, protocol_id, protocol_version, build_id, "draft", actor_id, self._now()),
                )
                self._audit("batch", batch_id, "batch.created", actor_id, {"build_id": build_id})
        except sqlite3.IntegrityError as exc:
            raise Conflict("批次编号冲突或构建不存在") from exc
        return self.get_batch(batch_id)

    def get_batch(self, batch_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM batches WHERE batch_id=?", (batch_id,)).fetchone()
        if row is None:
            raise NotFound("批次不存在")
        return dict(row)

    def start_batch(self, actor_id: str, batch_id: str, expected_revision: int) -> dict[str, Any]:
        self._require(actor_id, "batch.start")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE batches SET state='running',revision=revision+1,started_at=? "
                "WHERE batch_id=? AND state='draft' AND revision=?",
                (self._now(), batch_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise InvalidState("批次不是当前草稿版本")
            self._audit("batch", batch_id, "batch.started", actor_id, {"from_revision": expected_revision})
        return self.get_batch(batch_id)

    def _idempotent_response(self, scope: str, key: str, request_digest: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT request_sha256,response_json FROM idempotency_keys WHERE scope=? AND key=?",
            (scope, key),
        ).fetchone()
        if row is None:
            return None
        if row["request_sha256"] != request_digest:
            raise Conflict("同一幂等键对应了不同请求内容")
        return json.loads(row["response_json"])

    def import_observations(
        self,
        actor_id: str,
        batch_id: str,
        idempotency_key: str,
        raw_rows: Iterable[Mapping[str, Any]],
    ) -> dict[str, Any]:
        self._require(actor_id, "observation.import")
        rows = tuple(raw_rows)
        if not rows:
            raise ValidationFailed("测点数组不能为空")
        request_digest = content_digest(rows)
        scope = f"observations:{batch_id}"
        existing = self._idempotent_response(scope, idempotency_key, request_digest)
        if existing is not None:
            return existing
        batch = self.get_batch(batch_id)
        if batch["state"] != "running":
            raise InvalidState("只有运行中的批次可以导入测点")
        protocol, _ = self._protocol(batch["protocol_id"], batch["protocol_version"])
        parsed: list[Observation] = []
        for raw in rows:
            try:
                item = Observation.from_dict(raw, protocol)
            except ValidationError as exc:
                raise ValidationFailed(str(exc)) from exc
            if item.robot_id != self.connection.execute(
                "SELECT robot_id FROM builds WHERE build_id=?", (batch["build_id"],)
            ).fetchone()["robot_id"]:
                raise ValidationFailed("测点传感器与批次构建不一致")
            parsed.append(item)
        response = {"batch_id": batch_id, "inserted": len(parsed), "request_sha256": request_digest}
        try:
            with transaction(self.connection, immediate=True):
                for item, raw in zip(parsed, rows):
                    self.connection.execute(
                        "INSERT INTO observations(batch_id,source_batch,source_row,robot_id,stratum_key,observed_at," 
                        "metrics_json,content_sha256,imported_by,imported_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (
                            batch_id,
                            item.source_batch,
                            item.source_row,
                            item.robot_id,
                            item.stratum_key,
                            item.observed_at,
                            canonical_json({key: format(value, "f") for key, value in item.metrics.items()}),
                            content_digest([raw]),
                            actor_id,
                            self._now(),
                        ),
                    )
                self.connection.execute(
                    "INSERT INTO idempotency_keys(scope,key,request_sha256,response_json,created_at) VALUES(?,?,?,?,?)",
                    (scope, idempotency_key, request_digest, canonical_json(response), self._now()),
                )
                self._audit("batch", batch_id, "observations.imported", actor_id, response)
        except sqlite3.IntegrityError as exc:
            raise Conflict("来源行重复或幂等键并发冲突") from exc
        return response

    def request_exclusion(self, actor_id: str, observation_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "exclusion.request")
        observation = self.connection.execute(
            "SELECT observation_id,batch_id FROM observations WHERE observation_id=?", (observation_id,)
        ).fetchone()
        if observation is None:
            raise NotFound("测点不存在")
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO exclusion_requests(observation_id,status,reason,requested_by,requested_at) "
                    "VALUES(?,?,?,?,?)",
                    (observation_id, "pending", reason, actor_id, self._now()),
                )
                exclusion_id = cursor.lastrowid
                self._audit("observation", str(observation_id), "exclusion.requested", actor_id, {"reason": reason})
        except sqlite3.IntegrityError as exc:
            raise Conflict("该测点已有待处理或生效排除") from exc
        return {"exclusion_id": exclusion_id, "status": "pending"}

    def review_exclusion(
        self, actor_id: str, exclusion_id: int, approve: bool, note: str
    ) -> dict[str, Any]:
        self._require(actor_id, "exclusion.review")
        row = self.connection.execute(
            "SELECT * FROM exclusion_requests WHERE exclusion_id=?", (exclusion_id,)
        ).fetchone()
        if row is None:
            raise NotFound("排除申请不存在")
        if row["status"] != "pending":
            raise InvalidState("排除申请已经处理")
        if row["requested_by"] == actor_id:
            raise Forbidden("申请人不能复核自己的排除申请")
        status = "approved" if approve else "rejected"
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE exclusion_requests SET status=?,reviewed_by=?,reviewed_at=?,review_note=? "
                "WHERE exclusion_id=? AND status='pending'",
                (status, actor_id, self._now(), note, exclusion_id),
            )
            self._audit("exclusion", str(exclusion_id), f"exclusion.{status}", actor_id, {"note": note})
        return {"exclusion_id": exclusion_id, "status": status}

    def revoke_exclusion(self, actor_id: str, exclusion_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "exclusion.revoke")
        row = self.connection.execute(
            "SELECT e.*,o.batch_id FROM exclusion_requests e "
            "JOIN observations o ON o.observation_id=e.observation_id WHERE e.exclusion_id=?",
            (exclusion_id,),
        ).fetchone()
        if row is None:
            raise NotFound("排除记录不存在")
        if row["status"] != "approved":
            raise InvalidState("只有已批准的排除可以撤销")
        if row["requested_by"] != actor_id:
            raise Forbidden("只有原申请人可以撤销排除")
        batch = self.get_batch(row["batch_id"])
        if batch["state"] != "running":
            raise InvalidState("批次封存后不能改变排除状态")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE exclusion_requests SET status='revoked',review_note=?,reviewed_at=? "
                "WHERE exclusion_id=? AND status='approved'",
                (reason, self._now(), exclusion_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("排除状态已变化")
            self._audit(
                "observation",
                str(row["observation_id"]),
                "exclusion.revoked",
                actor_id,
                {"exclusion_id": exclusion_id, "reason": reason},
            )
        return {"exclusion_id": exclusion_id, "status": "revoked"}

    def seal_batch(self, actor_id: str, batch_id: str, expected_revision: int) -> dict[str, Any]:
        self._require(actor_id, "batch.seal")
        with transaction(self.connection, immediate=True):
            pending = self.connection.execute(
                "SELECT count(*) FROM exclusion_requests e JOIN observations o ON o.observation_id=e.observation_id "
                "WHERE o.batch_id=? AND e.status='pending'", (batch_id,)
            ).fetchone()[0]
            if pending:
                raise InvalidState("仍有待复核的排除申请")
            cursor = self.connection.execute(
                "UPDATE batches SET state='sealed',revision=revision+1,sealed_at=? "
                "WHERE batch_id=? AND state='running' AND revision=?",
                (self._now(), batch_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise InvalidState("批次状态或版本已变化")
            new_revision = expected_revision + 1
            now = self._now()
            self.connection.execute(
                "INSERT INTO analysis_jobs(batch_id,batch_revision,state,available_at,created_at,updated_at) "
                "VALUES(?,?, 'queued', ?,?,?)",
                (batch_id, new_revision, now, now, now),
            )
            self._audit("batch", batch_id, "batch.sealed", actor_id, {"revision": new_revision})
        return self.get_batch(batch_id)

    def claim_job(self, worker_id: str, lease_seconds: int = 60) -> dict[str, Any] | None:
        if lease_seconds <= 0:
            raise ValidationFailed("租约时长必须大于零")
        now = self._now()
        expires = isoformat(self.clock.now() + timedelta(seconds=lease_seconds))
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT job_id FROM analysis_jobs WHERE "
                "(state='queued' AND available_at<=?) OR (state='leased' AND lease_expires_at<=?) "
                "ORDER BY available_at,job_id LIMIT 1",
                (now, now),
            ).fetchone()
            if row is None:
                return None
            self.connection.execute(
                "UPDATE analysis_jobs SET state='leased',attempts=attempts+1,lease_owner=?,lease_expires_at=?,updated_at=? "
                "WHERE job_id=?",
                (worker_id, expires, now, row["job_id"]),
            )
            claimed = self.connection.execute("SELECT * FROM analysis_jobs WHERE job_id=?", (row["job_id"],)).fetchone()
        return dict(claimed)

    def _analysis_observations(self, batch_id: str, protocol: Protocol) -> tuple[Observation, ...]:
        rows = self.connection.execute(
            "SELECT o.*,e.reason AS excluded_reason FROM observations o "
            "LEFT JOIN exclusion_requests e ON e.observation_id=o.observation_id AND e.status='approved' "
            "WHERE o.batch_id=? ORDER BY o.observation_id",
            (batch_id,),
        ).fetchall()
        items: list[Observation] = []
        for row in rows:
            metrics = json.loads(row["metrics_json"])
            items.append(Observation(
                source_batch=row["source_batch"],
                source_row=row["source_row"],
                robot_id=row["robot_id"],
                protocol_id=protocol.protocol_id,
                protocol_version=protocol.version,
                stratum_key=row["stratum_key"],
                observed_at=row["observed_at"],
                metrics={key: Decimal(str(value)) for key, value in metrics.items()},
                excluded_reason=row["excluded_reason"],
            ))
        return tuple(items)

    def complete_job(self, worker_id: str, job_id: int, statistician_id: str) -> dict[str, Any]:
        self._require(statistician_id, "analysis.run")
        job = self.connection.execute("SELECT * FROM analysis_jobs WHERE job_id=?", (job_id,)).fetchone()
        if job is None:
            raise NotFound("分析任务不存在")
        if job["state"] != "leased" or job["lease_owner"] != worker_id:
            raise InvalidState("任务未由当前工作进程持有")
        if job["lease_expires_at"] <= self._now():
            raise InvalidState("任务租约已经过期")
        batch = self.get_batch(job["batch_id"])
        protocol, protocol_digest = self._protocol(batch["protocol_id"], batch["protocol_version"])
        observations = self._analysis_observations(batch["batch_id"], protocol)
        snapshot_rows = [
            {
                "source_batch": item.source_batch,
                "source_row": item.source_row,
                "stratum": item.stratum_key,
                "metrics": {key: format(value, "f") for key, value in item.metrics.items()},
                "excluded_reason": item.excluded_reason,
            }
            for item in observations
        ]
        input_digest = content_digest(snapshot_rows)
        result = analyze(protocol, observations)
        with transaction(self.connection, immediate=True):
            existing = self.connection.execute(
                "SELECT analysis_id,result_json FROM analyses WHERE batch_id=? AND batch_revision=? AND input_sha256=?",
                (batch["batch_id"], job["batch_revision"], input_digest),
            ).fetchone()
            if existing is None:
                cursor = self.connection.execute(
                    "INSERT INTO analyses(batch_id,batch_revision,protocol_sha256,input_sha256,algorithm_version,seed," 
                    "result_json,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        batch["batch_id"], job["batch_revision"], protocol_digest, input_digest,
                        ALGORITHM_VERSION, protocol.seed, canonical_json(result), statistician_id, self._now(),
                    ),
                )
                analysis_id = cursor.lastrowid
            else:
                analysis_id = existing["analysis_id"]
                result = json.loads(existing["result_json"])
            self.connection.execute(
                "UPDATE analysis_jobs SET state='succeeded',lease_owner=NULL,lease_expires_at=NULL,updated_at=? "
                "WHERE job_id=? AND state='leased' AND lease_owner=?",
                (self._now(), job_id, worker_id),
            )
            self.connection.execute(
                "UPDATE batches SET state='analyzed' WHERE batch_id=? AND state IN ('sealed','analyzing')",
                (batch["batch_id"],),
            )
            self._audit(
                "batch",
                batch["batch_id"],
                "analysis.completed",
                statistician_id,
                {"analysis_id": analysis_id, "input_sha256": input_digest},
            )
        return {"analysis_id": analysis_id, "input_sha256": input_digest, "result": result}

    def fail_job(self, worker_id: str, job_id: int, error: str, retry_seconds: int = 0) -> dict[str, Any]:
        available = isoformat(self.clock.now() + timedelta(seconds=retry_seconds))
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE analysis_jobs SET state='queued',available_at=?,lease_owner=NULL,lease_expires_at=NULL," 
                "last_error=?,updated_at=? WHERE job_id=? AND state='leased' AND lease_owner=?",
                (available, error[:1000], self._now(), job_id, worker_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("任务未由当前工作进程持有")
        return {"job_id": job_id, "state": "queued", "available_at": available}

    def request_decision(
        self, actor_id: str, batch_id: str, analysis_id: int, decision: str, reason: str
    ) -> dict[str, Any]:
        """敏感操作第一步：统计岗对当前批次分析版本发起准入决定复核。"""

        self._require(actor_id, "decision.request")
        if decision not in {"needs_more_data", "approved", "rejected"}:
            raise ValidationFailed("未知分析准入决定")
        analysis_row = self._decisionable_analysis(batch_id, analysis_id)
        request = {
            "batch_id": batch_id,
            "analysis_id": analysis_id,
            "decision": decision,
            "reason": reason,
        }
        request_text = canonical_json(request)
        request_sha = hashlib.sha256(request_text.encode("utf-8")).hexdigest()
        with transaction(self.connection, immediate=True):
            existing = self.connection.execute(
                "SELECT approval_id FROM approvals WHERE operation='decision' AND entity_id=? "
                "AND status='pending'",
                (batch_id,),
            ).fetchone()
            if existing is not None:
                raise Conflict("该批次已有待复核的准入决定")
            cursor = self.connection.execute(
                "INSERT INTO approvals(operation,entity_type,entity_id,request_sha256,"
                "expected_revision,request_json,requested_by,requested_at) "
                "VALUES('decision','batch',?,?,?,?,?,?)",
                (batch_id, request_sha, analysis_row["batch_revision"], request_text, actor_id, self._now()),
            )
            approval_id = cursor.lastrowid
            self._audit("batch", batch_id, "decision.requested", actor_id, {
                "approval_id": approval_id, "analysis_id": analysis_id,
                "decision": decision, "request_sha256": request_sha,
            })
        return {"approval_id": approval_id, "operation": "decision", "status": "pending"}

    def _decisionable_analysis(self, batch_id: str, analysis_id: int) -> sqlite3.Row:
        analysis_row = self.connection.execute(
            "SELECT * FROM analyses WHERE analysis_id=? AND batch_id=?", (analysis_id, batch_id)
        ).fetchone()
        if analysis_row is None:
            raise NotFound("分析版本不存在")
        batch = self.get_batch(batch_id)
        if batch["state"] != "analyzed" or batch["revision"] != analysis_row["batch_revision"]:
            raise InvalidState("分析不是批次当前可审批版本")
        return analysis_row

    def review_decision(
        self, reviewer_id: str, approval_id: int, approve: bool, note: str
    ) -> dict[str, Any]:
        """敏感操作第二步：另一审批岗确认或驳回，确认时重新校验业务版本。"""

        self._require(reviewer_id, "decision.confirm")
        approval = self.connection.execute(
            "SELECT * FROM approvals WHERE approval_id=? AND operation='decision'", (approval_id,)
        ).fetchone()
        if approval is None:
            raise NotFound("准入复核单不存在")
        if approval["status"] != "pending":
            raise InvalidState("复核单已经处理")
        if approval["requested_by"] == reviewer_id:
            raise Forbidden("发起者不能复核自己的准入决定")
        request = json.loads(approval["request_json"])
        batch_id = request["batch_id"]
        analysis_id = request["analysis_id"]
        now = self._now()
        with transaction(self.connection, immediate=True):
            if not approve:
                if not note.strip():
                    raise ValidationFailed("驳回必须填写说明")
                self.connection.execute(
                    "UPDATE approvals SET status='rejected',reviewed_by=?,reviewed_at=?,review_note=? "
                    "WHERE approval_id=? AND status='pending'",
                    (reviewer_id, now, note.strip(), approval_id),
                )
                self._audit("batch", batch_id, "decision.rejected", reviewer_id,
                            {"approval_id": approval_id, "note": note.strip()})
                return {"approval_id": approval_id, "status": "rejected"}
            # 确认时以当前状态重新校验，防止发起后业务版本漂移。
            analysis_row = self._decisionable_analysis(batch_id, analysis_id)
            if analysis_row["created_by"] == reviewer_id:
                raise Forbidden("分析完成者不能批准自己的分析")
            cursor = self.connection.execute(
                "INSERT INTO decisions(batch_id,analysis_id,decision,reason,decided_by,decided_at) "
                "VALUES(?,?,?,?,?,?)",
                (batch_id, analysis_id, request["decision"], request["reason"], reviewer_id, now),
            )
            self.connection.execute("UPDATE batches SET state='decided' WHERE batch_id=?", (batch_id,))
            response = {"batch_id": batch_id, "analysis_id": analysis_id,
                        "decision": request["decision"], "decision_id": cursor.lastrowid}
            self.connection.execute(
                "UPDATE approvals SET status='confirmed',reviewed_by=?,reviewed_at=?,"
                "review_note=?,response_json=? WHERE approval_id=? AND status='pending'",
                (reviewer_id, now, note, canonical_json(response), approval_id),
            )
            self._audit("batch", batch_id, "decision.recorded", reviewer_id, {
                "decision_id": cursor.lastrowid, "analysis_id": analysis_id,
                "decision": request["decision"], "approval_id": approval_id,
                "requested_by": approval["requested_by"], "reviewed_by": reviewer_id,
            })
        return {"approval_id": approval_id, "status": "confirmed", **response}

    def report(self, actor_id: str, batch_id: str) -> dict[str, Any]:
        self._require(actor_id, "report.read")
        batch = self.get_batch(batch_id)
        protocol, protocol_digest = self._protocol(batch["protocol_id"], batch["protocol_version"])
        analysis_row = self.connection.execute(
            "SELECT * FROM analyses WHERE batch_id=? ORDER BY analysis_id DESC LIMIT 1", (batch_id,)
        ).fetchone()
        decision_row = None
        if analysis_row is not None:
            decision_row = self.connection.execute(
                "SELECT * FROM decisions WHERE analysis_id=?", (analysis_row["analysis_id"],)
            ).fetchone()
        exclusions = self.connection.execute(
            "SELECT e.exclusion_id,e.observation_id,e.status,e.reason,e.requested_by,e.reviewed_by "
            "FROM exclusion_requests e JOIN observations o ON o.observation_id=e.observation_id "
            "WHERE o.batch_id=? ORDER BY e.exclusion_id", (batch_id,)
        ).fetchall()
        events = self.connection.execute(
            "SELECT event_type,actor_id,payload_json,created_at FROM audit_events "
            "WHERE entity_type='batch' AND entity_id=? "
            "ORDER BY event_id", (batch_id,)
        ).fetchall()
        return {
            "batch": batch,
            "protocol": {
                "protocol_id": protocol.protocol_id,
                "version": protocol.version,
                "sha256": protocol_digest,
                "seed": protocol.seed,
                "bootstrap_samples": protocol.bootstrap_samples,
            },
            "analysis": None if analysis_row is None else {
                "analysis_id": analysis_row["analysis_id"],
                "input_sha256": analysis_row["input_sha256"],
                "algorithm_version": analysis_row["algorithm_version"],
                "created_by": analysis_row["created_by"],
                "result": json.loads(analysis_row["result_json"]),
            },
            "decision": None if decision_row is None else dict(decision_row),
            "exclusions": [dict(row) for row in exclusions],
            "events": [dict(row) | {"payload": json.loads(row["payload_json"])} for row in events],
        }

    def audit_events(
        self,
        actor_id: str,
        *,
        actor_filter: str | None = None,
        entity_type: str | None = None,
        limit: int = 200,
    ) -> dict[str, Any]:
        """按原操作者或实体检索历史审计；操作者停用或换岗后历史仍可追溯。"""

        self._require(actor_id, "audit.read")
        if limit <= 0 or limit > 1000:
            raise ValidationFailed("limit 必须在 1 到 1000 之间")
        clauses: list[str] = []
        params: list[Any] = []
        if actor_filter:
            clauses.append("actor_id=?")
            params.append(actor_filter)
        if entity_type:
            clauses.append("entity_type=?")
            params.append(entity_type)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self.connection.execute(
            f"SELECT event_id,entity_type,entity_id,event_type,actor_id,payload_json,created_at "
            f"FROM audit_events{where} ORDER BY event_id DESC LIMIT ?",
            (*params, limit),
        ).fetchall()
        return {
            "events": [
                {
                    "event_id": row["event_id"],
                    "entity_type": row["entity_type"],
                    "entity_id": row["entity_id"],
                    "event_type": row["event_type"],
                    "actor_id": row["actor_id"],
                    "payload": json.loads(row["payload_json"]),
                    "created_at": row["created_at"],
                }
                for row in rows
            ]
        }
