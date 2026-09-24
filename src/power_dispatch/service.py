"""电价、燃料库存、送出线路和提名的事务用例。"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import timedelta
from decimal import Decimal
from typing import Any, Mapping

from .clock import SystemClock, parse_utc, utc_text
from .errors import Conflict, Forbidden, InvalidState, NotFound, Unauthorized, ValidationFailed
from .identity import effective_permissions, sortable_ts
from .models import IndexQuote, Facility, InventoryLot, NominationRequest, Route, SupplyScenario
from .planning import (
    AllocationRequest,
    PricePoint,
    allocate_capacity,
    canonical_json,
    decimal_text,
    delivered_after_loss,
    digest,
    effective_capacity,
    latest_streak,
    moving_average,
    quantize_volume,
    scenario_projection,
    weighted_inventory_cost,
)
from .storage import initialize, transaction


SESSION_TTL_SECONDS_DEFAULT = 12 * 3600

# 需要另一人二次复核的敏感操作与其复核权限。
REVIEW_PERMISSIONS = {
    "transfer": "transfer.confirm",
    "scenario.approve": "scenario.approve",
}

# 当前请求绑定的会话编号，审计事件会自动记录，便于按令牌追踪操作。
_current_session: ContextVar[str | None] = ContextVar("current_session", default=None)


class SupplyService:
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
        return utc_text(self.clock.now())

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM supply_users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound("用户不存在")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _permissions(self, user: sqlite3.Row) -> set[str]:
        return effective_permissions(self.connection, user["position_id"], self._now())

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        user = self._user(user_id)
        if permission not in self._permissions(user):
            raise Forbidden(f"岗位 {user['position_id']} 无权执行 {permission}")
        return user

    def _audit(
        self,
        entity_type: str,
        entity_id: str,
        event_type: str,
        actor_id: str,
        payload: Mapping[str, Any],
    ) -> None:
        body_payload = dict(payload)
        session_id = _current_session.get()
        if session_id is not None:
            body_payload.setdefault("session_id", session_id)
        previous = self.connection.execute(
            "SELECT event_hash FROM supply_audit_events ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        previous_hash = "0" * 64 if previous is None else previous["event_hash"]
        body = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "event_type": event_type,
            "actor_id": actor_id,
            "payload": body_payload,
            "created_at": self._now(),
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
        self.connection.execute(
            "INSERT INTO supply_audit_events(entity_type,entity_id,event_type,actor_id,payload_json,"
            "previous_hash,event_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (
                entity_type,
                entity_id,
                event_type,
                actor_id,
                canonical_json(body_payload),
                previous_hash,
                event_hash,
                body["created_at"],
            ),
        )

    # ------------------------------------------------------------------ 岗位与权限

    def list_positions(self, actor_id: str) -> dict[str, Any]:
        self._require(actor_id, "position.manage")
        rows = self.connection.execute(
            "SELECT * FROM supply_positions WHERE active=1 ORDER BY position_id"
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
        if parent_id is not None:
            if self.connection.execute(
                "SELECT 1 FROM supply_positions WHERE position_id=? AND active=1", (parent_id,)
            ).fetchone() is None:
                raise ValidationFailed("父岗位不存在")
        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO supply_positions(position_id,display_name,parent_id,built_in,created_at) "
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
            "SELECT 1 FROM supply_positions WHERE position_id=? AND active=1", (position_id,)
        ).fetchone() is None:
            raise NotFound("岗位不存在")
        if not permission.strip():
            raise ValidationFailed("权限名不能为空")
        if effective_from is None:
            effective_at = sortable_ts(self._now())
        else:
            try:
                effective_at = sortable_ts(utc_text(parse_utc(effective_from, "effective_from")))
            except ValueError as exc:
                raise ValidationFailed(str(exc)) from exc
        now = self._now()
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "INSERT INTO supply_permission_changes"
                "(position_id,permission,effect,effective_from,reason,changed_by,created_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (position_id, permission.strip(), effect, effective_at, reason.strip(), actor_id, now),
            )
            change_id = int(cursor.lastrowid)
            self._audit("position", position_id, "permission.changed", actor_id, {
                "change_id": change_id,
                "permission": permission.strip(),
                "effect": effect,
                "effective_from": effective_at,
                "reason": reason.strip(),
            })
        return {
            "change_id": change_id,
            "position_id": position_id,
            "permission": permission.strip(),
            "effect": effect,
            "effective_from": effective_at,
        }

    def list_permission_changes(self, actor_id: str, position_id: str | None = None) -> dict[str, Any]:
        self._require(actor_id, "position.manage")
        if position_id is None:
            rows = self.connection.execute(
                "SELECT * FROM supply_permission_changes ORDER BY change_id"
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM supply_permission_changes WHERE position_id=? ORDER BY change_id",
                (position_id,),
            ).fetchall()
        return {"changes": [dict(row) for row in rows]}

    def create_user(self, user_id: str, display_name: str, position_id: str) -> dict[str, Any]:
        if not user_id.strip() or not display_name.strip():
            raise ValidationFailed("用户编号和名称不能为空")
        if self.connection.execute(
            "SELECT 1 FROM supply_positions WHERE position_id=? AND active=1", (position_id,)
        ).fetchone() is None:
            raise ValidationFailed(f"未知岗位: {position_id}")
        now = self._now()
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO supply_users(user_id,display_name,position_id,created_at) VALUES(?,?,?,?)",
                    (user_id.strip(), display_name.strip(), position_id, now),
                )
                self.connection.execute(
                    "INSERT INTO supply_user_position_history"
                    "(user_id,position_id,effective_from,reason,changed_by,created_at) "
                    "VALUES(?,?,?, '开户建档', 'system', ?)",
                    (user_id.strip(), position_id, now, now),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("用户已经存在") from exc
        return {"user_id": user_id.strip(), "position_id": position_id}

    def bootstrap_user(self, user_id: str, display_name: str, position_id: str) -> dict[str, Any]:
        """首个用户只能在系统尚无任何用户时免会话建立，之后该入口永久关闭。"""

        count = self.connection.execute("SELECT count(*) FROM supply_users").fetchone()[0]
        if count:
            raise Forbidden("系统已经存在用户，引导入口已关闭")
        return self.create_user(user_id, display_name, position_id)

    def admin_create_user(self, actor_id: str, user_id: str, display_name: str, position_id: str) -> dict[str, Any]:
        self._require(actor_id, "user.manage")
        return self.create_user(user_id, display_name, position_id)

    def deactivate_user(self, actor_id: str, user_id: str, reason: str) -> dict[str, Any]:
        self._require(actor_id, "user.manage")
        if not reason.strip():
            raise ValidationFailed("停用用户必须填写原因")
        now = self._now()
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE supply_users SET active=0 WHERE user_id=? AND active=1", (user_id,)
            )
            if cursor.rowcount != 1:
                raise NotFound("用户不存在或已停用")
            self.connection.execute(
                "UPDATE supply_sessions SET revoked_at=?,revoke_reason=?,revoked_by=? "
                "WHERE user_id=? AND revoked_at IS NULL",
                (now, f"用户停用: {reason.strip()}", actor_id, user_id),
            )
            self._audit("user", user_id, "user.deactivated", actor_id, {"reason": reason.strip()})
        return {"user_id": user_id, "active": False}

    def assign_position(
        self, actor_id: str, user_id: str, position_id: str, effective_from: str | None, reason: str
    ) -> dict[str, Any]:
        """换岗立即生效；历史岗位链完整保留以便审计。生效时间点由调用方记录。"""

        self._require(actor_id, "user.manage")
        if not reason.strip():
            raise ValidationFailed("换岗必须填写审计原因")
        if self.connection.execute(
            "SELECT 1 FROM supply_positions WHERE position_id=? AND active=1", (position_id,)
        ).fetchone() is None:
            raise ValidationFailed(f"未知岗位: {position_id}")
        user = self.connection.execute(
            "SELECT position_id FROM supply_users WHERE user_id=?", (user_id,)
        ).fetchone()
        if user is None:
            raise NotFound("用户不存在")
        if effective_from is not None:
            effective_at = utc_text(parse_utc(effective_from, "effective_from"))
        else:
            effective_at = self._now()
        now = self._now()
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "INSERT INTO supply_user_position_history"
                "(user_id,position_id,effective_from,reason,changed_by,created_at) VALUES(?,?,?,?,?,?)",
                (user_id, position_id, effective_at, reason.strip(), actor_id, now),
            )
            self.connection.execute(
                "UPDATE supply_users SET position_id=? WHERE user_id=?", (position_id, user_id)
            )
            # 换岗后旧会话的岗位快照不再可信，立即撤销，要求重新登录。
            self.connection.execute(
                "UPDATE supply_sessions SET revoked_at=?,revoke_reason=?,revoked_by=? "
                "WHERE user_id=? AND revoked_at IS NULL",
                (now, f"换岗至 {position_id}: {reason.strip()}", actor_id, user_id),
            )
            self._audit("user", user_id, "position.assigned", actor_id,
                        {"position_id": position_id, "effective_from": effective_at,
                         "reason": reason.strip()})
        return {"user_id": user_id, "position_id": position_id, "effective_from": effective_at}

    # ------------------------------------------------------------------ 会话签发与撤销

    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def issue_session(
        self,
        actor_id: str,
        ttl_seconds: int = SESSION_TTL_SECONDS_DEFAULT,
    ) -> dict[str, Any]:
        """签发会话。重复登录会作废旧会话并记录替换链，重启后状态仍可追踪。"""

        user = self._user(actor_id)
        if ttl_seconds <= 0:
            raise ValidationFailed("会话有效期必须大于零")
        now_text = self._now()
        issued_at = self.clock.now()
        expires_at = utc_text(issued_at + timedelta(seconds=ttl_seconds))
        token = secrets.token_urlsafe(32)
        session_id = "sess-" + secrets.token_hex(12)
        permissions = sorted(effective_permissions(self.connection, user["position_id"], now_text))
        with transaction(self.connection, immediate=True):
            previous_rows = self.connection.execute(
                "SELECT session_id FROM supply_sessions "
                "WHERE user_id=? AND revoked_at IS NULL AND expires_at>? ORDER BY issued_at",
                (actor_id, now_text),
            ).fetchall()
            # 先插入新会话，再把旧会话的 replaced_by 指向它，满足外键约束。
            self.connection.execute(
                "INSERT INTO supply_sessions(session_id,user_id,token_sha256,position_snapshot,"
                "issued_at,expires_at) VALUES(?,?,?,?,?,?)",
                (session_id, actor_id, self._hash_token(token), canonical_json(
                    {"position_id": user["position_id"], "permissions": permissions}
                ), now_text, expires_at),
            )
            for row in previous_rows:
                self.connection.execute(
                    "UPDATE supply_sessions SET revoked_at=?,revoke_reason='重复登录被新会话替换',"
                    "revoked_by=?,replaced_by=? WHERE session_id=?",
                    (now_text, actor_id, session_id, row["session_id"]),
                )
            self._audit("session", session_id, "session.issued", actor_id,
                        {"user_id": actor_id, "position_id": user["position_id"],
                         "replaces": [r["session_id"] for r in previous_rows]})
        return {
            "session_id": session_id,
            "token": token,
            "user_id": actor_id,
            "position_id": user["position_id"],
            "permissions": permissions,
            "issued_at": now_text,
            "expires_at": expires_at,
        }

    def authenticate(self, token: str) -> sqlite3.Row:
        """按令牌解析会话；缺失/无效/过期/撤销统一返回稳定的 unauthorized 错误。"""

        presented = (token or "").strip()
        if not presented:
            raise Unauthorized("缺少会话令牌", )
        row = self.connection.execute(
            "SELECT s.*,u.active AS user_active,u.position_id AS current_position FROM supply_sessions s "
            "JOIN supply_users u ON u.user_id=s.user_id WHERE s.token_sha256=?",
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
                "SELECT user_id,revoked_at FROM supply_sessions WHERE session_id=?", (session_id,)
            ).fetchone()
            if row is None:
                raise NotFound("会话不存在")
            if row["revoked_at"] is not None:
                raise Conflict("会话已经撤销")
            self.connection.execute(
                "UPDATE supply_sessions SET revoked_at=?,revoke_reason=?,revoked_by=? WHERE session_id=?",
                (now, reason.strip(), actor_id, session_id),
            )
            self._audit("session", session_id, "session.revoked", actor_id,
                        {"user_id": row["user_id"], "reason": reason.strip()})
        return {"session_id": session_id, "status": "revoked"}

    def revoke_user_sessions(self, actor_id: str, user_id: str, reason: str) -> dict[str, Any]:
        """交接班：立即撤销某用户全部有效会话。"""

        self._require(actor_id, "session.revoke")
        if not reason.strip():
            raise ValidationFailed("撤销会话必须填写原因")
        now = self._now()
        with transaction(self.connection, immediate=True):
            rows = self.connection.execute(
                "SELECT session_id FROM supply_sessions WHERE user_id=? AND revoked_at IS NULL", (user_id,)
            ).fetchall()
            for row in rows:
                self.connection.execute(
                    "UPDATE supply_sessions SET revoked_at=?,revoke_reason=?,revoked_by=? WHERE session_id=?",
                    (now, reason.strip(), actor_id, row["session_id"]),
                )
                self._audit("session", row["session_id"], "session.revoked", actor_id,
                            {"user_id": user_id, "reason": reason.strip()})
        return {"revoked": len(rows)}

    def list_sessions(self, actor_id: str, user_id: str | None = None) -> dict[str, Any]:
        self._require(actor_id, "session.read")
        if user_id is None:
            rows = self.connection.execute(
                "SELECT session_id,user_id,issued_at,expires_at,revoked_at,revoke_reason,revoked_by,"
                "replaced_by FROM supply_sessions ORDER BY issued_at"
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT session_id,user_id,issued_at,expires_at,revoked_at,revoke_reason,revoked_by,"
                "replaced_by FROM supply_sessions WHERE user_id=? ORDER BY issued_at",
                (user_id,),
            ).fetchall()
        return {"sessions": [dict(row) for row in rows]}

    # ------------------------------------------------------------------ 二次复核

    def _create_approval(
        self,
        actor_id: str,
        operation: str,
        entity_type: str,
        entity_id: str,
        expected_revision: int,
        request: Mapping[str, Any],
    ) -> int:
        request_text = canonical_json(request)
        request_sha = hashlib.sha256(request_text.encode("utf-8")).hexdigest()
        now = self._now()
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "INSERT INTO supply_approvals(operation,entity_type,entity_id,request_sha256,"
                "expected_revision,request_json,requested_by,requested_at) VALUES(?,?,?,?,?,?,?,?)",
                (operation, entity_type, entity_id, request_sha, expected_revision,
                 request_text, actor_id, now),
            )
            approval_id = int(cursor.lastrowid)
            self._audit(entity_type, entity_id, "approval.requested", actor_id,
                        {"approval_id": approval_id, "operation": operation,
                         "expected_revision": expected_revision, "request_sha256": request_sha})
        return approval_id

    def _pending_approval(self, reviewer_id: str, approval_id: int, review_permission: str) -> sqlite3.Row:
        self._require(reviewer_id, review_permission)
        row = self.connection.execute(
            "SELECT * FROM supply_approvals WHERE approval_id=?", (approval_id,)
        ).fetchone()
        if row is None:
            raise NotFound("复核单不存在")
        if row["status"] != "pending":
            raise InvalidState("复核单已经处理")
        if row["requested_by"] == reviewer_id:
            raise Forbidden("发起者不能复核自己的敏感操作")
        return row

    def review_approval(self, reviewer_id: str, approval_id: int, approve: bool, note: str) -> dict[str, Any]:
        """按复核单的操作类型分发到送电或情景审批的确认/驳回。"""

        row = self.connection.execute(
            "SELECT operation FROM supply_approvals WHERE approval_id=?", (approval_id,)
        ).fetchone()
        if row is None:
            raise NotFound("复核单不存在")
        if row["operation"] == "transfer":
            return (
                self.confirm_transfer(reviewer_id, approval_id, note)
                if approve
                else self.reject_transfer(reviewer_id, approval_id, note)
            )
        if row["operation"] == "scenario.approve":
            return (
                self.confirm_scenario_approval(reviewer_id, approval_id, note)
                if approve
                else self.reject_scenario_approval(reviewer_id, approval_id, note)
            )
        raise InvalidState(f"未知复核操作类型: {row['operation']}")

    def record_quote(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "quote.write")
        quote = IndexQuote.from_dict(raw)
        previous = self.connection.execute(
            "SELECT quote_id,source_revision FROM market_index_quotes WHERE market_index=? AND trade_date=? "
            "ORDER BY quote_id DESC LIMIT 1",
            (quote.market_index, quote.trade_date),
        ).fetchone()
        if previous is not None and previous["source_revision"] == quote.source_revision:
            raise Conflict("同一来源修订已登记")
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO market_index_quotes(market_index,trade_date,close_cny,source_revision,observed_at,"
                    "supersedes_quote_id,recorded_by,recorded_at) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        quote.market_index,
                        quote.trade_date,
                        decimal_text(quote.close_cny),
                        quote.source_revision,
                        quote.observed_at,
                        None if previous is None else previous["quote_id"],
                        actor_id,
                        self._now(),
                    ),
                )
                quote_id = int(cursor.lastrowid)
                self._audit(
                    "quote",
                    str(quote_id),
                    "quote.recorded",
                    actor_id,
                    {"market_index": quote.market_index, "trade_date": quote.trade_date},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("电价版本冲突") from exc
        return {"quote_id": quote_id, "market_index": quote.market_index, "trade_date": quote.trade_date}

    def price_summary(self, market_index: str, sessions: int = 20) -> dict[str, Any]:
        rows = self.connection.execute(
            "SELECT q.trade_date,q.close_cny FROM market_index_quotes q "
            "JOIN (SELECT trade_date,max(quote_id) quote_id FROM market_index_quotes "
            "WHERE market_index=? GROUP BY trade_date) latest ON latest.quote_id=q.quote_id "
            "ORDER BY q.trade_date DESC LIMIT ?",
            (market_index.upper(), sessions),
        ).fetchall()
        points = [PricePoint(row["trade_date"], Decimal(row["close_cny"])) for row in rows]
        if not points:
            raise NotFound("没有基准电价")
        streak = latest_streak(points)
        average = moving_average(points, min(5, len(points)))
        latest = max(points, key=lambda item: item.trade_date)
        return {
            "market_index": market_index.upper(),
            "latest": {"trade_date": latest.trade_date, "close_cny": decimal_text(latest.close)},
            "latest_streak": None if streak is None else streak.as_dict(),
            "moving_average": None if average is None else decimal_text(average),
            "observations": len(points),
        }

    def create_facility(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "catalog.write")
        facility = Facility.from_dict(raw)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO facilities(facility_id,name,kind,timezone,capacity_mwh,created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (
                        facility.facility_id,
                        facility.name,
                        facility.kind,
                        facility.timezone,
                        decimal_text(facility.capacity_mwh),
                        self._now(),
                    ),
                )
                self._audit("facility", facility.facility_id, "facility.created", actor_id, raw)
        except sqlite3.IntegrityError as exc:
            raise Conflict("设施编号已经存在") from exc
        return dict(raw)

    def create_route(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "catalog.write")
        route = Route.from_dict(raw)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO routes(route_id,origin_id,destination_id,product,daily_capacity,"
                    "loss_basis_points,transit_hours,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        route.route_id,
                        route.origin_id,
                        route.destination_id,
                        route.product,
                        decimal_text(route.daily_capacity),
                        route.loss_basis_points,
                        route.transit_hours,
                        self._now(),
                    ),
                )
                self._audit("route", route.route_id, "route.created", actor_id, raw)
        except sqlite3.IntegrityError as exc:
            raise Conflict("送出线路编号冲突或设施不存在") from exc
        return self.route(route.route_id)

    def route(self, route_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM routes WHERE route_id=?", (route_id,)).fetchone()
        if row is None:
            raise NotFound("送出线路不存在")
        return dict(row)

    def announce_outage(
        self,
        actor_id: str,
        route_id: str,
        starts_at: str,
        ends_at: str | None,
        capacity_percent: object,
        reason: str,
    ) -> dict[str, Any]:
        self._require(actor_id, "outage.write")
        self.route(route_id)
        try:
            start = parse_utc(starts_at, "starts_at")
            end = None if ends_at is None else parse_utc(ends_at, "ends_at")
        except ValueError as exc:
            raise ValidationFailed(str(exc)) from exc
        if end is not None and end <= start:
            raise ValidationFailed("ends_at 必须晚于 starts_at")
        percentage = Decimal(str(capacity_percent))
        if percentage < 0 or percentage > 100:
            raise ValidationFailed("capacity_percent 必须在 0 到 100 之间")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "INSERT INTO route_outages(route_id,starts_at,ends_at,capacity_percent,reason,created_by,created_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (route_id, utc_text(start), None if end is None else utc_text(end), decimal_text(percentage), reason, actor_id, self._now()),
            )
            outage_id = int(cursor.lastrowid)
            self._audit("route", route_id, "outage.announced", actor_id, {"outage_id": outage_id})
        return {"outage_id": outage_id, "route_id": route_id, "state": "announced"}

    def add_inventory_lot(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "inventory.write")
        lot = InventoryLot.from_dict(raw)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO inventory_lots(lot_id,facility_id,product,grade,quantity_mwh,available_mwh,"
                    "unit_cost_cny,received_at,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        lot.lot_id,
                        lot.facility_id,
                        lot.product,
                        lot.grade,
                        decimal_text(lot.quantity_mwh),
                        decimal_text(lot.quantity_mwh),
                        decimal_text(lot.unit_cost_cny),
                        lot.received_at,
                        actor_id,
                        self._now(),
                    ),
                )
                self._audit("inventory_lot", lot.lot_id, "inventory.received", actor_id, raw)
        except sqlite3.IntegrityError as exc:
            raise Conflict("燃料批次冲突或设施不存在") from exc
        return self.inventory_lot(lot.lot_id)

    def inventory_lot(self, lot_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM inventory_lots WHERE lot_id=?", (lot_id,)).fetchone()
        if row is None:
            raise NotFound("燃料批次不存在")
        return dict(row)

    def inventory_summary(self, facility_id: str, product: str) -> dict[str, Any]:
        rows = self.connection.execute(
            "SELECT * FROM inventory_lots WHERE facility_id=? AND product=? ORDER BY received_at,lot_id",
            (facility_id, product),
        ).fetchall()
        return {"facility_id": facility_id, "product": product, **weighted_inventory_cost(rows)}

    def submit_nomination(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "nomination.write")
        nomination = NominationRequest.from_dict(raw)
        request_digest = digest(raw)
        stored = self.connection.execute(
            "SELECT request_sha256,response_json FROM supply_idempotency WHERE scope='nomination' AND idempotency_key=?",
            (nomination.idempotency_key,),
        ).fetchone()
        if stored is not None:
            if stored["request_sha256"] != request_digest:
                raise Conflict("幂等键对应不同提名内容")
            return json.loads(stored["response_json"])
        route = self.route(nomination.route_id)
        if route["state"] != "active":
            raise InvalidState("送出线路当前不可提名")
        response = {
            "nomination_id": nomination.nomination_id,
            "route_id": nomination.route_id,
            "state": "submitted",
            "revision": 1,
        }
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO nominations(nomination_id,route_id,shipper_id,service_date,requested_mwh,"
                    "priority,idempotency_key,submitted_by,submitted_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        nomination.nomination_id,
                        nomination.route_id,
                        nomination.shipper_id,
                        nomination.service_date,
                        decimal_text(nomination.requested_mwh),
                        nomination.priority,
                        nomination.idempotency_key,
                        actor_id,
                        self._now(),
                    ),
                )
                self.connection.execute(
                    "INSERT INTO supply_idempotency(scope,idempotency_key,request_sha256,response_json,created_at) "
                    "VALUES('nomination',?,?,?,?)",
                    (nomination.idempotency_key, request_digest, canonical_json(response), self._now()),
                )
                self._audit("nomination", nomination.nomination_id, "nomination.submitted", actor_id, raw)
        except sqlite3.IntegrityError as exc:
            raise Conflict("提名编号或幂等键冲突") from exc
        return response

    def _capacity_for_date(self, route: sqlite3.Row, service_date: str) -> Decimal:
        start = service_date + "T00:00:00Z"
        end = service_date + "T23:59:59Z"
        rows = self.connection.execute(
            "SELECT capacity_percent FROM route_outages WHERE route_id=? AND state IN ('announced','active') "
            "AND starts_at<=? AND (ends_at IS NULL OR ends_at>=?) ORDER BY outage_id",
            (route["route_id"], end, start),
        ).fetchall()
        percentages = [Decimal(row["capacity_percent"]) for row in rows]
        return effective_capacity(Decimal(route["daily_capacity"]), percentages)

    def allocate(self, actor_id: str, route_id: str, service_date: str) -> dict[str, Any]:
        self._require(actor_id, "allocation.run")
        route = self.connection.execute("SELECT * FROM routes WHERE route_id=?", (route_id,)).fetchone()
        if route is None:
            raise NotFound("送出线路不存在")
        nominations = self.connection.execute(
            "SELECT * FROM nominations WHERE route_id=? AND service_date=? AND state='submitted' "
            "ORDER BY priority,submitted_at,nomination_id",
            (route_id, service_date),
        ).fetchall()
        if not nominations:
            raise InvalidState("没有待分配提名")
        requests = [
            AllocationRequest(
                row["nomination_id"],
                Decimal(row["requested_mwh"]),
                int(row["priority"]),
                row["submitted_at"],
            )
            for row in nominations
        ]
        available = self._capacity_for_date(route, service_date)
        input_value = [dict(row) for row in nominations]
        input_sha256 = digest({"route": dict(route), "nominations": input_value, "capacity": str(available)})
        result_rows = allocate_capacity(available, requests)
        result = {
            "route_id": route_id,
            "service_date": service_date,
            "available_capacity": decimal_text(available),
            "allocations": result_rows,
        }
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "INSERT INTO allocation_runs(route_id,service_date,input_sha256,available_capacity,result_json,"
                "created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                (route_id, service_date, input_sha256, decimal_text(available), canonical_json(result), actor_id, self._now()),
            )
            for item in result_rows:
                state = "allocated" if Decimal(item["allocated_mwh"]) > 0 else "cancelled"
                self.connection.execute(
                    "UPDATE nominations SET allocated_mwh=?,state=?,revision=revision+1 "
                    "WHERE nomination_id=? AND state='submitted'",
                    (item["allocated_mwh"], state, item["nomination_id"]),
                )
            allocation_id = int(cursor.lastrowid)
            self._audit("route", route_id, "allocation.completed", actor_id, {"allocation_id": allocation_id})
        return {"allocation_id": allocation_id, **result}

    def request_transfer(
        self,
        actor_id: str,
        transfer_id: str,
        nomination_id: str,
        lot_id: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        """敏感操作第一步：调度岗发起送电复核请求，不实际扣减库存。"""

        self._require(actor_id, "transfer.write")
        request = {
            "transfer_id": transfer_id,
            "nomination_id": nomination_id,
            "lot_id": lot_id,
            "expected_revision": int(expected_revision),
        }
        # 发起时校验一次业务版本，复核确认时还会再次校验。
        self._load_transfer_request(nomination_id, lot_id, expected_revision)
        approval_id = self._create_approval(
            actor_id, "transfer", "transfer", transfer_id, int(expected_revision), request
        )
        return {"approval_id": approval_id, "operation": "transfer", "status": "pending"}

    def _load_transfer_request(self, nomination_id: str, lot_id: str, expected_revision: int):
        nomination = self.connection.execute(
            "SELECT n.*,r.loss_basis_points,r.transit_hours,r.origin_id,r.product,r.route_id "
            "FROM nominations n JOIN routes r ON r.route_id=n.route_id WHERE n.nomination_id=?",
            (nomination_id,),
        ).fetchone()
        if nomination is None:
            raise NotFound("提名不存在")
        if nomination["state"] != "allocated" or nomination["revision"] != expected_revision:
            raise InvalidState("提名不是当前可送电版本")
        lot = self.connection.execute("SELECT * FROM inventory_lots WHERE lot_id=?", (lot_id,)).fetchone()
        if lot is None:
            raise NotFound("燃料批次不存在")
        allocated = Decimal(nomination["allocated_mwh"])
        available = Decimal(lot["available_mwh"])
        if lot["facility_id"] != nomination["origin_id"] or lot["product"] != nomination["product"]:
            raise Conflict("燃料批次与送出线路起点或电源类型不匹配")
        if available < allocated:
            raise Conflict("燃料库存不足以完成分配")
        return nomination, lot, allocated, available

    def confirm_transfer(self, reviewer_id: str, approval_id: int, note: str = "") -> dict[str, Any]:
        """敏感操作第二步：另一岗位确认后才真正送电，确认时重新校验业务版本。"""

        approval = self._pending_approval(reviewer_id, approval_id, REVIEW_PERMISSIONS["transfer"])
        if approval["operation"] != "transfer":
            raise InvalidState("复核单不是送电操作")
        request = json.loads(approval["request_json"])
        # 复核时以当前数据库状态重新校验，防止发起后业务版本漂移。
        nomination, lot, allocated, available = self._load_transfer_request(
            request["nomination_id"], request["lot_id"], int(request["expected_revision"])
        )
        expected_delivery = delivered_after_loss(allocated, int(nomination["loss_basis_points"]))
        departed_at = self._now()
        response: dict[str, Any]
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE inventory_lots SET available_mwh=?,revision=revision+1 WHERE lot_id=? AND revision=?",
                (decimal_text(quantize_volume(available - allocated)), lot["lot_id"], lot["revision"]),
            )
            self.connection.execute(
                "UPDATE nominations SET state='in_transit',revision=revision+1 WHERE nomination_id=? AND revision=?",
                (nomination["nomination_id"], request["expected_revision"]),
            )
            self.connection.execute(
                "INSERT INTO transfers(transfer_id,nomination_id,inventory_lot_id,loaded_mwh,"
                "expected_delivered_mwh,departed_at,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    request["transfer_id"],
                    nomination["nomination_id"],
                    lot["lot_id"],
                    decimal_text(allocated),
                    decimal_text(expected_delivery),
                    departed_at,
                    approval["requested_by"],
                    departed_at,
                ),
            )
            response = {
                "transfer_id": request["transfer_id"],
                "state": "in_transit",
                "loaded_mwh": decimal_text(allocated),
                "expected_delivered_mwh": decimal_text(expected_delivery),
                "expected_arrival": utc_text(
                    parse_utc(departed_at) + timedelta(hours=int(nomination["transit_hours"]))
                ),
            }
            self.connection.execute(
                "UPDATE supply_approvals SET status='confirmed',reviewed_by=?,reviewed_at=?,"
                "review_note=?,response_json=? WHERE approval_id=? AND status='pending'",
                (reviewer_id, departed_at, note, canonical_json(response), approval_id),
            )
            self._audit("transfer", request["transfer_id"], "transfer.dispatched", approval["requested_by"], {
                "nomination_id": nomination["nomination_id"],
                "approval_id": approval_id,
                "requested_by": approval["requested_by"],
                "reviewed_by": reviewer_id,
                "expected_revision": request["expected_revision"],
            })
        return {"approval_id": approval_id, "status": "confirmed", **response}

    def reject_transfer(self, reviewer_id: str, approval_id: int, note: str) -> dict[str, Any]:
        approval = self._pending_approval(reviewer_id, approval_id, REVIEW_PERMISSIONS["transfer"])
        if approval["operation"] != "transfer":
            raise InvalidState("复核单不是送电操作")
        if not note.strip():
            raise ValidationFailed("驳回必须填写说明")
        now = self._now()
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE supply_approvals SET status='rejected',reviewed_by=?,reviewed_at=?,review_note=? "
                "WHERE approval_id=? AND status='pending'",
                (reviewer_id, now, note.strip(), approval_id),
            )
            self._audit("transfer", approval["entity_id"], "approval.rejected", reviewer_id,
                        {"approval_id": approval_id, "operation": "transfer", "note": note.strip()})
        return {"approval_id": approval_id, "status": "rejected"}

    def create_scenario(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "scenario.write")
        scenario = SupplyScenario.from_dict(raw)
        definition = canonical_json(raw)
        content_sha256 = hashlib.sha256(definition.encode("utf-8")).hexdigest()
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO supply_scenarios(scenario_id,name,definition_json,content_sha256,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (scenario.scenario_id, scenario.name, definition, content_sha256, actor_id, self._now()),
                )
                self._audit("scenario", scenario.scenario_id, "scenario.created", actor_id, {"sha256": content_sha256})
        except sqlite3.IntegrityError as exc:
            raise Conflict("情景编号或内容已经存在") from exc
        return {"scenario_id": scenario.scenario_id, "state": "draft", "sha256": content_sha256}

    def request_scenario_approval(
        self, actor_id: str, scenario_id: str, expected_revision: int
    ) -> dict[str, Any]:
        """情景审批第一步：计划岗发起批准请求。"""

        self._require(actor_id, "scenario.approval.request")
        self._load_approvable_scenario(scenario_id, expected_revision)
        approval_id = self._create_approval(
            actor_id, "scenario.approve", "scenario", scenario_id, int(expected_revision),
            {"scenario_id": scenario_id, "expected_revision": int(expected_revision)},
        )
        return {"approval_id": approval_id, "operation": "scenario.approve", "status": "pending"}

    def _load_approvable_scenario(self, scenario_id: str, expected_revision: int) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM supply_scenarios WHERE scenario_id=?", (scenario_id,)
        ).fetchone()
        if row is None:
            raise NotFound("情景不存在")
        if row["state"] != "draft" or row["revision"] != expected_revision:
            raise InvalidState("情景不是当前草稿版本")
        return row

    def confirm_scenario_approval(self, reviewer_id: str, approval_id: int, note: str = "") -> dict[str, Any]:
        """情景审批第二步：风险岗确认后情景才进入 approved，绑定业务版本。"""

        approval = self._pending_approval(reviewer_id, approval_id, REVIEW_PERMISSIONS["scenario.approve"])
        if approval["operation"] != "scenario.approve":
            raise InvalidState("复核单不是情景审批操作")
        request = json.loads(approval["request_json"])
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE supply_scenarios SET state='approved',revision=revision+1 "
                "WHERE scenario_id=? AND state='draft' AND revision=?",
                (request["scenario_id"], request["expected_revision"]),
            )
            if cursor.rowcount != 1:
                raise InvalidState("情景不是当前草稿版本")
            response = {
                "scenario_id": request["scenario_id"],
                "state": "approved",
                "revision": request["expected_revision"] + 1,
            }
            self.connection.execute(
                "UPDATE supply_approvals SET status='confirmed',reviewed_by=?,reviewed_at=?,"
                "review_note=?,response_json=? WHERE approval_id=? AND status='pending'",
                (reviewer_id, self._now(), note, canonical_json(response), approval_id),
            )
            self._audit("scenario", request["scenario_id"], "scenario.approved", reviewer_id, {
                "approval_id": approval_id,
                "requested_by": approval["requested_by"],
                "reviewed_by": reviewer_id,
                "expected_revision": request["expected_revision"],
            })
        return {"approval_id": approval_id, "status": "confirmed", **response}

    def reject_scenario_approval(self, reviewer_id: str, approval_id: int, note: str) -> dict[str, Any]:
        approval = self._pending_approval(reviewer_id, approval_id, REVIEW_PERMISSIONS["scenario.approve"])
        if approval["operation"] != "scenario.approve":
            raise InvalidState("复核单不是情景审批操作")
        if not note.strip():
            raise ValidationFailed("驳回必须填写说明")
        now = self._now()
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE supply_approvals SET status='rejected',reviewed_by=?,reviewed_at=?,review_note=? "
                "WHERE approval_id=? AND status='pending'",
                (reviewer_id, now, note.strip(), approval_id),
            )
            self._audit("scenario", approval["entity_id"], "approval.rejected", reviewer_id,
                        {"approval_id": approval_id, "operation": "scenario.approve", "note": note.strip()})
        return {"approval_id": approval_id, "status": "rejected"}

    def run_scenario(self, actor_id: str, scenario_id: str, as_of_date: str) -> dict[str, Any]:
        self._require(actor_id, "scenario.run")
        row = self.connection.execute(
            "SELECT * FROM supply_scenarios WHERE scenario_id=?", (scenario_id,)
        ).fetchone()
        if row is None:
            raise NotFound("情景不存在")
        if row["state"] != "approved":
            raise InvalidState("只有已批准情景可以运行")
        scenario = SupplyScenario.from_dict(json.loads(row["definition_json"]))
        price_row = self.connection.execute(
            "SELECT close_cny FROM market_index_quotes WHERE trade_date<=? ORDER BY trade_date DESC,quote_id DESC LIMIT 1",
            (as_of_date,),
        ).fetchone()
        if price_row is None:
            raise InvalidState("截止日期没有可用电价")
        routes = self.connection.execute("SELECT * FROM routes WHERE state='active' ORDER BY route_id").fetchall()
        inventory = self.connection.execute(
            "SELECT facility_id,product,sum(CAST(available_mwh AS REAL)) available_mwh "
            "FROM inventory_lots GROUP BY facility_id,product ORDER BY facility_id,product"
        ).fetchall()
        input_value = {
            "scenario_sha256": row["content_sha256"],
            "as_of_date": as_of_date,
            "price": price_row["close_cny"],
            "routes": [dict(item) for item in routes],
            "inventory": [dict(item) for item in inventory],
        }
        input_sha256 = digest(input_value)
        existing = self.connection.execute(
            "SELECT run_id,result_json FROM scenario_runs WHERE scenario_id=? AND as_of_date=? AND input_sha256=?",
            (scenario_id, as_of_date, input_sha256),
        ).fetchone()
        if existing is not None:
            return {"run_id": existing["run_id"], **json.loads(existing["result_json"]), "replayed": True}
        result = scenario_projection(
            current_price=Decimal(price_row["close_cny"]),
            market_index_drop_percent=scenario.market_index_drop_percent,
            routes=routes,
            inventory=inventory,
            route_capacity_changes=scenario.route_capacity_changes,
            demand_changes=scenario.demand_changes,
        )
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "INSERT INTO scenario_runs(scenario_id,as_of_date,input_sha256,result_json,created_by,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (scenario_id, as_of_date, input_sha256, canonical_json(result), actor_id, self._now()),
            )
            run_id = int(cursor.lastrowid)
            self._audit("scenario", scenario_id, "scenario.executed", actor_id, {"run_id": run_id})
        return {"run_id": run_id, **result, "replayed": False}

    def audit_chain(self, actor_id: str) -> dict[str, Any]:
        self._require(actor_id, "audit.read")
        rows = self.connection.execute("SELECT * FROM supply_audit_events ORDER BY event_id").fetchall()
        previous_hash = "0" * 64
        valid = True
        for row in rows:
            body = {
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "event_type": row["event_type"],
                "actor_id": row["actor_id"],
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
            f"FROM supply_audit_events{where} ORDER BY event_id DESC LIMIT ?",
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
