"""机组试验域的岗位继承与可配置权限解析。

规则与调度域一致：权限以不可变变更记录保存，带生效时间和审计原因；
grant/deny/revoke 三种效果，子岗位覆盖父岗位，继承链不允许成环。
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import NamedTuple

from .errors import ValidationFailed


class PositionPermission(NamedTuple):
    permission: str
    effect: str
    change_id: int


def sortable_ts(value: str) -> str:
    """把 ISO 8601 时间规范为定宽微秒 UTC 文本，保证词法序等于时间序。"""

    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValidationFailed("时间必须包含时区")
    parsed = parsed.astimezone(timezone.utc)
    return f"{parsed:%Y-%m-%dT%H:%M:%S}.{parsed.microsecond:06d}Z"


SEED_EPOCH = "1970-01-01T00:00:00.000000Z"

BUILTIN_POSITIONS: dict[str, dict[str, object]] = {
    "admin": {
        "display_name": "身份与权限管理员",
        "permissions": (
            "user.manage", "position.manage", "session.revoke", "session.read",
            "report.read", "audit.read",
        ),
    },
    "operator": {
        "display_name": "现场机组试验岗",
        "permissions": (
            "catalog.write", "batch.create", "batch.start", "observation.import",
            "exclusion.request", "exclusion.revoke",
        ),
    },
    "statistician": {
        "display_name": "统计分析岗",
        "permissions": (
            "protocol.publish", "batch.seal", "exclusion.review", "analysis.run",
            "decision.request", "report.read",
        ),
    },
    "approver": {
        "display_name": "分析准入审批岗",
        "permissions": ("decision.confirm", "report.read"),
    },
    "auditor": {
        "display_name": "审计岗",
        "permissions": ("report.read", "audit.read"),
    },
}


def seed_positions(connection: sqlite3.Connection) -> None:
    for position_id, spec in BUILTIN_POSITIONS.items():
        connection.execute(
            "INSERT INTO positions(position_id,display_name,parent_id,built_in,created_at) "
            "VALUES(?,?,?,1,?) ON CONFLICT(position_id) DO NOTHING",
            (position_id, str(spec["display_name"]), spec.get("parent_id"), SEED_EPOCH),
        )
        for permission in spec["permissions"]:
            connection.execute(
                "INSERT INTO permission_changes"
                "(position_id,permission,effect,effective_from,reason,changed_by,created_at) "
                "SELECT ?,?, 'grant', ?, '出厂岗位授权', 'system', ? "
                "WHERE NOT EXISTS (SELECT 1 FROM permission_changes "
                "WHERE position_id=? AND permission=?)",
                (position_id, permission, SEED_EPOCH, SEED_EPOCH, position_id, permission),
            )


def position_chain(connection: sqlite3.Connection, position_id: str) -> list[str]:
    chain: list[str] = []
    current: str | None = position_id
    seen: set[str] = set()
    while current is not None:
        if current in seen:
            raise ValidationFailed(f"岗位继承链成环: {current}")
        row = connection.execute(
            "SELECT position_id,parent_id FROM positions WHERE position_id=?", (current,)
        ).fetchone()
        if row is None:
            raise ValidationFailed(f"岗位不存在: {current}")
        seen.add(current)
        chain.append(current)
        current = row["parent_id"]
    chain.reverse()
    return chain


def effective_permissions(connection: sqlite3.Connection, position_id: str, at: str) -> set[str]:
    chain = position_chain(connection, position_id)
    at = sortable_ts(at)
    placeholders = ",".join("?" for _ in chain)
    rows = connection.execute(
        f"SELECT position_id,permission,effect,change_id FROM permission_changes "
        f"WHERE effective_from<=? AND position_id IN ({placeholders})",
        (at, *chain),
    ).fetchall()
    latest: dict[tuple[str, str], PositionPermission] = {}
    for row in rows:
        key = (row["position_id"], row["permission"])
        candidate = PositionPermission(row["permission"], row["effect"], int(row["change_id"]))
        if key not in latest or candidate.change_id > latest[key].change_id:
            latest[key] = candidate
    decision: dict[str, bool] = {}
    for current in chain:
        for (owner, permission), item in latest.items():
            if owner != current:
                continue
            if item.effect == "grant":
                decision[permission] = True
            elif item.effect == "deny":
                decision[permission] = False
    return {permission for permission, allowed in decision.items() if allowed}
