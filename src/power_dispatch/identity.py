"""岗位继承与可配置权限的解析。

权限以不可变的变更记录（``supply_permission_changes``）保存，每条记录带生效
时间和审计原因：

- ``grant``：该岗位显式授予权限；
- ``deny``：该岗位显式拒绝权限（子岗位上的拒绝优先于继承来的授予）；
- ``revoke``：撤销该岗位此前的配置，恢复沿继承链向上继承。

解析顺序自根岗位向子岗位进行，子岗位的显式配置覆盖父岗位，岗位链不允许成环。
只有 ``effective_from`` 不晚于给定时间的变更才参与计算，因此未来生效的换岗授权
不会提前放行。
"""

from __future__ import annotations

import sqlite3
from datetime import timezone
from datetime import datetime
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

# 内置岗位及其出厂权限。
BUILTIN_POSITIONS: dict[str, dict[str, object]] = {
    "admin": {
        "display_name": "身份与权限管理员",
        "parent_id": None,
        "permissions": (
            "user.manage", "position.manage", "session.revoke", "session.read",
            "report.read", "audit.read",
        ),
    },
    "planner": {
        "display_name": "交易计划岗",
        "permissions": (
            "quote.write", "catalog.write", "scenario.write", "scenario.run",
            "scenario.approval.request",
        ),
    },
    "dispatcher": {
        "display_name": "调度岗",
        "permissions": ("nomination.write", "allocation.run", "transfer.write", "inventory.write"),
    },
    "risk": {
        "display_name": "风险复核岗",
        "permissions": ("outage.write", "scenario.approve", "transfer.confirm", "report.read"),
    },
    "auditor": {
        "display_name": "审计岗",
        "permissions": ("report.read", "audit.read"),
    },
}


def seed_positions(connection: sqlite3.Connection) -> None:
    """幂等写入内置岗位与出厂授权，重复初始化不覆盖运行期配置。"""

    for position_id, spec in BUILTIN_POSITIONS.items():
        connection.execute(
            "INSERT INTO supply_positions(position_id,display_name,parent_id,built_in,created_at) "
            "VALUES(?,?,?,1,?) ON CONFLICT(position_id) DO NOTHING",
            (position_id, str(spec["display_name"]), spec.get("parent_id"), SEED_EPOCH),
        )
        for permission in spec["permissions"]:
            connection.execute(
                "INSERT INTO supply_permission_changes"
                "(position_id,permission,effect,effective_from,reason,changed_by,created_at) "
                "SELECT ?,?, 'grant', ?, '出厂岗位授权', 'system', ? "
                "WHERE NOT EXISTS (SELECT 1 FROM supply_permission_changes "
                "WHERE position_id=? AND permission=?)",
                (position_id, permission, SEED_EPOCH, SEED_EPOCH, position_id, permission),
            )


def position_chain(connection: sqlite3.Connection, position_id: str) -> list[str]:
    """返回自根岗位到目标岗位的继承链，岗位不存在或成环时报错。"""

    chain: list[str] = []
    current: str | None = position_id
    seen: set[str] = set()
    while current is not None:
        if current in seen:
            raise ValidationFailed(f"岗位继承链成环: {current}")
        row = connection.execute(
            "SELECT position_id,parent_id FROM supply_positions WHERE position_id=?",
            (current,),
        ).fetchone()
        if row is None:
            raise ValidationFailed(f"岗位不存在: {current}")
        seen.add(current)
        chain.append(current)
        current = row["parent_id"]
    chain.reverse()
    return chain


def effective_permissions(connection: sqlite3.Connection, position_id: str, at: str) -> set[str]:
    """计算某岗位在给定 UTC 时间点实际生效的权限集合。"""

    chain = position_chain(connection, position_id)
    at = sortable_ts(at)
    placeholders = ",".join("?" for _ in chain)
    rows = connection.execute(
        f"SELECT position_id,permission,effect,change_id FROM supply_permission_changes "
        f"WHERE effective_from<=? AND position_id IN ({placeholders})",
        (at, *chain),
    ).fetchall()
    # 每个 (岗位, 权限) 只取编号最大的一条，即最近一次变更。
    latest: dict[tuple[str, str], PositionPermission] = {}
    for row in rows:
        key = (row["position_id"], row["permission"])
        candidate = PositionPermission(row["permission"], row["effect"], int(row["change_id"]))
        if key not in latest or candidate.change_id > latest[key].change_id:
            latest[key] = candidate
    # 自根向子叠加：本岗位 grant/deny 覆盖继承结果；revoke 表示本岗位无意见，
    # 父岗位的授予继续有效。
    decision: dict[str, bool] = {}
    for current in chain:
        for (owner, permission), item in latest.items():
            if owner != current:
                continue
            if item.effect == "grant":
                decision[permission] = True
            elif item.effect == "deny":
                decision[permission] = False
            # revoke：不在本岗位写入意见，保留继承结果。
    return {permission for permission, allowed in decision.items() if allowed}
