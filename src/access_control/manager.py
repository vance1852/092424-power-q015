"""岗位继承、生效授权、会话签发/撤销与二次复核的用例层。

设计要点：

- 每次请求都实时从 SQLite 计算有效权限，授权变更到点生效、撤销立即生效；
- 会话令牌只以 SHA-256 摘要落库，重复登录产生独立可追踪的会话；
- 二次复核票据一次性消费，并与操作者、业务主体、业务版本和请求摘要绑定；
- 所有管理动作写入独立的哈希串联审计表。
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from collections import deque
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Callable, Iterable, Mapping

from .errors import (
    AuthorizationFailed,
    Conflict,
    NotFound,
    ReviewRejected,
    ReviewRequired,
    SessionRevoked,
    ValidationFailed,
)
from .clock import SystemClock, parse_utc, utc_text
from .store import AccessStore, canonical_json, transaction


# 复核岗位的统一权限名；敏感操作的申请权限由各域按 scope 映射提供。
REVIEW_PERMISSION = "review.approve"

DEFAULT_SESSION_TTL_SECONDS = 12 * 60 * 60
DEFAULT_TICKET_TTL_SECONDS = 5 * 60

ResolveUser = Callable[[str], sqlite3.Row | None]


@dataclass(frozen=True, slots=True)
class AccessContext:
    """一次已认证请求的操作者上下文，权限为认证时刻的实时快照。"""

    session_id: str
    user_id: str
    role: str
    permissions: frozenset[str]

    def has(self, permission: str) -> bool:
        return permission in self.permissions


@dataclass(frozen=True, slots=True)
class ReviewGate:
    scope: str
    entity_type: str
    entity_id: str
    expected_version: str
    payload: Mapping[str, Any]


class AccessManager:
    def __init__(
        self,
        connection: sqlite3.Connection,
        resolve_user: ResolveUser,
        clock=None,
        sensitive_permissions: Mapping[str, str] | None = None,
    ) -> None:
        self.connection = connection
        self.store = AccessStore(connection)
        self.clock = clock or SystemClock()
        self.resolve_user = resolve_user
        # scope -> 申请该敏感操作所需权限
        self.sensitive_permissions = dict(sensitive_permissions or {})

    def _now_text(self) -> str:
        return utc_text(self.clock.now())

    # -- 审计 -------------------------------------------------------------------

    def _log(self, event_type: str, actor_id: str, subject_type: str, subject_id: str, payload: Mapping[str, Any]) -> None:
        self.store.append_audit(event_type, actor_id, subject_type, subject_id, payload, self._now_text())

    def audit_chain(self, ctx: AccessContext) -> dict[str, Any]:
        self.require(ctx, "access.audit.read")
        return self.store.verify_chain()

    def audit_events(self, ctx: AccessContext, actor_id: str | None = None) -> list[dict[str, Any]]:
        self.require(ctx, "access.audit.read")
        rows = self.store.audit_events(actor_id)
        return [
            {
                "event_id": row["event_id"],
                "event_type": row["event_type"],
                "actor_id": row["actor_id"],
                "subject_type": row["subject_type"],
                "subject_id": row["subject_id"],
                "payload": json.loads(row["payload_json"]),
                "created_at": row["created_at"],
                "event_hash": row["event_hash"],
            }
            for row in rows
        ]

    # -- 权限判定 ---------------------------------------------------------------

    def require(self, ctx: AccessContext, permission: str) -> None:
        if not ctx.has(permission):
            raise AuthorizationFailed(f"岗位 {ctx.role} 无权执行 {permission}")

    def _role_chain(self, role: str) -> list[str]:
        """返回岗位自身及全部继承祖先，循环继承会被拒绝并截断。"""

        ordered: list[str] = []
        seen: set[str] = set()
        queue: deque[str] = deque([role])
        while queue:
            current = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            ordered.append(current)
            queue.extend(self.store.parent_ids(current))
        return ordered

    def effective_permissions(self, role: str, user_id: str, now: str | None = None) -> frozenset[str]:
        """用户的有效权限：岗位继承链 allow/deny 叠加用户级 allow/deny，deny 优先。"""

        now = now or self._now_text()
        allow: set[str] = set()
        deny: set[str] = set()
        self._collect_grants(set(self._role_chain(role)), user_id, now, allow, deny)
        return frozenset(allow - deny)

    def _collect_grants(
        self,
        role_chain: set[str],
        user_id: str,
        now: str,
        allow: set[str],
        deny: set[str],
    ) -> None:
        for row in self.store.active_grants(now):
            applies = (
                (row["subject_type"] == "role" and row["subject_id"] in role_chain)
                or (row["subject_type"] == "user" and row["subject_id"] == user_id)
            )
            if applies:
                (deny if row["effect"] == "deny" else allow).add(row["permission"])

    # -- 默认岗位种子 ------------------------------------------------------------

    def seed_defaults(self, role_permissions: Mapping[str, Iterable[str]]) -> bool:
        """首次初始化时写入出厂岗位与授权；已存在配置则保持不变。"""

        if self.store.list_roles():
            return False
        now = self._now_text()
        with transaction(self.connection, immediate=True):
            for role_id, permissions in role_permissions.items():
                self.store.upsert_role(role_id, role_id, now)
                for permission in permissions:
                    self.store.insert_grant(
                        "role", role_id, permission, "allow", now, "出厂默认岗位授权", "system", now
                    )
                self._log("role.seeded", "system", "role", role_id, {"permissions": sorted(permissions)})
        return True

    # -- 岗位管理 ---------------------------------------------------------------

    def define_role(
        self,
        ctx: AccessContext,
        role_id: str,
        display_name: str | None,
        parent_ids: list[str] | None,
        reason: str,
    ) -> dict[str, Any]:
        self.require(ctx, "access.role.write")
        role_id = role_id.strip()
        if not role_id:
            raise ValidationFailed("岗位编号不能为空")
        if not reason.strip():
            raise ValidationFailed("调整岗位必须填写审计原因")
        parent_ids = parent_ids or []
        for parent in parent_ids:
            if self.store.get_role(parent) is None:
                raise ValidationFailed(f"父岗位不存在: {parent}")
            if parent == role_id:
                raise ValidationFailed("岗位不能继承自己")
        with transaction(self.connection, immediate=True):
            self.store.upsert_role(role_id, (display_name or role_id).strip(), self._now_text())
            self._assert_no_cycle(role_id, parent_ids)
            self.store.set_role_parents(role_id, parent_ids, self._now_text())
            self._log(
                "role.defined",
                ctx.user_id,
                "role",
                role_id,
                {"parents": parent_ids, "reason": reason},
            )
        return self.describe_role(role_id)

    def _assert_no_cycle(self, role_id: str, new_parents: list[str]) -> None:
        def reaches(start: str, target: str) -> bool:
            seen: set[str] = set()
            queue: deque[str] = deque([start])
            while queue:
                current = queue.popleft()
                if current == target:
                    return True
                if current in seen:
                    continue
                seen.add(current)
                parents = new_parents if current == role_id else self.store.parent_ids(current)
                queue.extend(parents)
            return False

        for parent in new_parents:
            if reaches(parent, role_id):
                raise ValidationFailed(f"岗位继承出现循环: {role_id} -> {parent}")

    def describe_role(self, role_id: str) -> dict[str, Any]:
        role_row = self.store.get_role(role_id)
        if role_row is None:
            raise NotFound("岗位不存在")
        now = self._now_text()
        chain = self._role_chain(role_id)
        allow: set[str] = set()
        deny: set[str] = set()
        # 岗位描述只反映岗位继承链本身的权限，不含任何具体用户的个人授权
        for grant in self.store.active_grants(now):
            if grant["subject_type"] == "role" and grant["subject_id"] in set(chain):
                (deny if grant["effect"] == "deny" else allow).add(grant["permission"])
        permissions = allow - deny
        return {
            "role_id": role_id,
            "display_name": role_row["display_name"],
            "active": bool(role_row["active"]),
            "parents": self.store.parent_ids(role_id),
            "inherits": chain[1:],
            "permissions": sorted(permissions),
        }

    def list_roles(self, ctx: AccessContext) -> list[dict[str, Any]]:
        return [self.describe_role(row["role_id"]) for row in self.store.list_roles()]

    # -- 授权变更（生效时间 + 审计原因） ------------------------------------------

    def grant_permission(
        self,
        ctx: AccessContext,
        subject_type: str,
        subject_id: str,
        permission: str,
        effect: str,
        reason: str,
        effective_from: str | None = None,
    ) -> dict[str, Any]:
        self.require(ctx, "access.grant.write")
        if subject_type not in {"role", "user"}:
            raise ValidationFailed("subject_type 必须是 role 或 user")
        permission = permission.strip()
        if "." not in permission or not all(part for part in permission.split(".")):
            raise ValidationFailed("权限名必须是 domain.action 形式")
        if effect not in {"allow", "deny"}:
            raise ValidationFailed("effect 必须是 allow 或 deny")
        if not reason.strip():
            raise ValidationFailed("权限变更必须填写审计原因")
        if subject_type == "role" and self.store.get_role(subject_id) is None:
            raise ValidationFailed(f"岗位不存在: {subject_id}")
        if subject_type == "user" and self.resolve_user(subject_id) is None:
            raise NotFound(f"用户不存在: {subject_id}")
        if effective_from:
            effective_at = utc_text(parse_utc(effective_from, "effective_from"))
        else:
            effective_at = self._now_text()
        with transaction(self.connection, immediate=True):
            grant_id = self.store.insert_grant(
                subject_type, subject_id, permission, effect, effective_at,
                reason.strip(), ctx.user_id, self._now_text(),
            )
            self._log(
                "grant.created",
                ctx.user_id,
                subject_type,
                subject_id,
                {
                    "grant_id": grant_id,
                    "permission": permission,
                    "effect": effect,
                    "effective_from": effective_at,
                    "reason": reason.strip(),
                },
            )
        return dict(self.store.get_grant(grant_id))  # type: ignore[arg-type]

    def revoke_grant(self, ctx: AccessContext, grant_id: int, reason: str) -> dict[str, Any]:
        self.require(ctx, "access.grant.write")
        if not reason.strip():
            raise ValidationFailed("撤销授权必须填写审计原因")
        existing = self.store.get_grant(grant_id)
        if existing is None:
            raise NotFound("授权记录不存在")
        with transaction(self.connection, immediate=True):
            if not self.store.revoke_grant(grant_id, ctx.user_id, reason.strip(), self._now_text()):
                raise Conflict("授权已经被撤销")
            self._log(
                "grant.revoked",
                ctx.user_id,
                existing["subject_type"],
                existing["subject_id"],
                {"grant_id": grant_id, "permission": existing["permission"], "reason": reason.strip()},
            )
        return dict(self.store.get_grant(grant_id))  # type: ignore[arg-type]

    def list_grants(self, ctx: AccessContext, include_revoked: bool = False) -> list[dict[str, Any]]:
        self.require(ctx, "access.audit.read")
        return [dict(row) for row in self.store.list_grants(include_revoked)]

    # -- 会话签发与撤销 ----------------------------------------------------------

    @staticmethod
    def _session_id(token: str) -> str:
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return "ses_" + digest[:32]

    def issue_session(
        self,
        user_id: str,
        label: str = "login",
        ttl_seconds: int | None = None,
    ) -> dict[str, Any]:
        """签发会话。重复登录不会覆盖旧会话，而是产生独立可追踪的新会话。"""

        user = self.resolve_user(user_id)
        if user is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not user["active"]:
            raise AuthorizationFailed("用户已停用，不能签发会话")
        ttl = DEFAULT_SESSION_TTL_SECONDS if ttl_seconds is None else ttl_seconds
        if ttl <= 0:
            raise ValidationFailed("会话有效期必须大于零")
        now = self._now_text()
        expires_at = utc_text(self.clock.now() + timedelta(seconds=ttl))
        token = secrets.token_urlsafe(32)
        session_id = self._session_id(token)
        with transaction(self.connection, immediate=True):
            self.store.insert_session(session_id, user_id, label, now, expires_at, None)
            self._log("session.issued", user_id, "session", session_id, {"label": label, "expires_at": expires_at})
        return {
            "token": token,
            "session_id": session_id,
            "user_id": user_id,
            "role": user["role"],
            "expires_at": expires_at,
        }

    def authenticate(self, token: str) -> AccessContext:
        """按令牌解析操作者；不存在、已撤销或已过期一律返回稳定错误码。"""

        token = (token or "").strip()
        if not token:
            raise SessionRevoked("会话不存在或已撤销")
        row = self.store.get_session(self._session_id(token))
        if row is None or row["revoked_at"] is not None:
            raise SessionRevoked("会话不存在或已撤销")
        now = self._now_text()
        if row["expires_at"] is not None and row["expires_at"] <= now:
            raise SessionRevoked("会话已过期")
        user = self.resolve_user(row["user_id"])
        if user is None or not user["active"]:
            raise SessionRevoked("会话对应的操作者已失效")
        permissions = self.effective_permissions(user["role"], user["user_id"], now)
        return AccessContext(
            session_id=row["session_id"],
            user_id=user["user_id"],
            role=user["role"],
            permissions=permissions,
        )

    def revoke_session(self, ctx: AccessContext, session_id: str, reason: str) -> dict[str, Any]:
        self.require(ctx, "access.session.revoke")
        if not reason.strip():
            raise ValidationFailed("撤销会话必须填写原因")
        row = self.store.get_session(session_id)
        if row is None:
            raise NotFound("会话不存在")
        with transaction(self.connection, immediate=True):
            if not self.store.revoke_session(session_id, ctx.user_id, reason.strip(), self._now_text()):
                raise Conflict("会话已经被撤销")
            self._log(
                "session.revoked",
                ctx.user_id,
                "session",
                session_id,
                {"user_id": row["user_id"], "reason": reason.strip()},
            )
        return {"session_id": session_id, "state": "revoked"}

    def revoke_user_sessions(self, ctx: AccessContext, user_id: str, reason: str) -> dict[str, Any]:
        """交接班：撤销某操作者全部有效会话，撤销后其旧令牌立即失效。"""

        self.require(ctx, "access.session.revoke")
        if self.resolve_user(user_id) is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not reason.strip():
            raise ValidationFailed("批量撤销会话必须填写原因")
        active = [
            row for row in self.store.list_sessions(user_id, include_revoked=False)
        ]
        with transaction(self.connection, immediate=True):
            count = self.store.revoke_all_user_sessions(user_id, ctx.user_id, reason.strip(), self._now_text())
            if count:
                self._log(
                    "session.all_revoked",
                    ctx.user_id,
                    "user",
                    user_id,
                    {"session_ids": [row["session_id"] for row in active], "reason": reason.strip()},
                )
        return {"user_id": user_id, "revoked": count}

    def list_sessions(self, ctx: AccessContext, user_id: str | None = None) -> list[dict[str, Any]]:
        self.require(ctx, "access.session.read")
        if user_id is not None and self.resolve_user(user_id) is None:
            raise NotFound(f"用户不存在: {user_id}")
        return [dict(row) for row in self.store.list_sessions(user_id)]

    # -- 二次复核 ---------------------------------------------------------------

    @staticmethod
    def request_digest(gate: ReviewGate) -> str:
        body = {
            "scope": gate.scope,
            "entity_type": gate.entity_type,
            "entity_id": gate.entity_id,
            "expected_version": str(gate.expected_version),
            "payload": dict(gate.payload),
        }
        return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()

    def request_review(self, ctx: AccessContext, gate: ReviewGate, ttl_seconds: int | None = None) -> dict[str, Any]:
        permission = self.sensitive_permissions.get(gate.scope)
        if permission is None:
            raise ValidationFailed(f"未知敏感操作范围: {gate.scope}")
        self.require(ctx, permission)
        if not gate.entity_id.strip() or not str(gate.expected_version).strip():
            raise ValidationFailed("复核票据必须绑定业务主体与业务版本")
        ttl = DEFAULT_TICKET_TTL_SECONDS if ttl_seconds is None else ttl_seconds
        if ttl <= 0:
            raise ValidationFailed("复核有效期必须大于零")
        now_text = self._now_text()
        expires_at = utc_text(self.clock.now() + timedelta(seconds=ttl))
        ticket_id = "rvw_" + secrets.token_urlsafe(18)
        request_sha = self.request_digest(gate)
        with transaction(self.connection, immediate=True):
            self.store.insert_ticket(
                ticket_id,
                gate.scope,
                gate.entity_type,
                gate.entity_id,
                str(gate.expected_version),
                request_sha,
                ctx.session_id,
                ctx.user_id,
                now_text,
                expires_at,
            )
            self._log(
                "review.requested",
                ctx.user_id,
                gate.entity_type,
                gate.entity_id,
                {"ticket_id": ticket_id, "scope": gate.scope, "expected_version": str(gate.expected_version)},
            )
        return {
            "ticket_id": ticket_id,
            "scope": gate.scope,
            "entity_type": gate.entity_type,
            "entity_id": gate.entity_id,
            "expected_version": str(gate.expected_version),
            "status": "pending",
            "expires_at": expires_at,
        }

    def decide_review(
        self, ctx: AccessContext, ticket_id: str, approve: bool, note: str
    ) -> dict[str, Any]:
        self.require(ctx, REVIEW_PERMISSION)
        row = self.store.get_ticket(ticket_id)
        if row is None:
            raise NotFound("复核票据不存在")
        if row["decision"] is not None:
            raise Conflict("复核票据已经处理")
        if row["requester_id"] == ctx.user_id:
            raise AuthorizationFailed("复核人不能与申请人为同一操作者")
        if row["expires_at"] <= self._now_text():
            raise ReviewRejected("复核票据已过期，不能再批准")
        decision = "approved" if approve else "rejected"
        with transaction(self.connection, immediate=True):
            if not self.store.decide_ticket(ticket_id, decision, ctx.user_id, note, self._now_text()):
                raise Conflict("复核票据已经处理")
            self._log(
                f"review.{decision}",
                ctx.user_id,
                row["entity_type"],
                row["entity_id"],
                {
                    "ticket_id": ticket_id,
                    "scope": row["scope"],
                    "requester_id": row["requester_id"],
                    "note": note,
                },
            )
        return {"ticket_id": ticket_id, "status": decision, "reviewer_id": ctx.user_id}

    def get_review(self, ctx: AccessContext, ticket_id: str) -> dict[str, Any]:
        row = self.store.get_ticket(ticket_id)
        if row is None:
            raise NotFound("复核票据不存在")
        if ctx.user_id not in {row["requester_id"], row["reviewer_id"]} and not ctx.has("access.audit.read"):
            raise AuthorizationFailed("只能查看与自己相关的复核票据")
        return dict(row)

    def consume_review(self, ctx: AccessContext, ticket_id: str, gate: ReviewGate) -> dict[str, Any]:
        """在业务事务内调用：校验并一次性消费复核票据。

        任何不匹配（版本、主体、请求摘要、操作者、过期、重复使用）都抛出
        稳定的 ``review_rejected`` 错误，业务写入随之回滚。
        """

        row = self.store.get_ticket(ticket_id)
        if row is None:
            # 敏感操作缺少有效票据：需要先发起二次复核
            raise ReviewRequired("该操作需要二次复核票据")
        if row["decision"] is None:
            raise ReviewRequired("二次复核尚未完成")
        if row["decision"] == "rejected":
            raise ReviewRejected("二次复核已被拒绝")
        problems: list[str] = []
        if row["consumed_at"] is not None:
            problems.append("复核票据已使用")
        if row["expires_at"] <= self._now_text():
            problems.append("复核票据已过期")
        if row["requester_id"] != ctx.user_id:
            problems.append("复核票据不属于当前操作者")
        if row["scope"] != gate.scope:
            problems.append("复核范围不匹配")
        if row["entity_type"] != gate.entity_type or row["entity_id"] != gate.entity_id:
            problems.append("复核业务主体不匹配")
        if row["expected_version"] != str(gate.expected_version):
            problems.append("业务版本与复核时不一致")
        if row["request_sha256"] != self.request_digest(gate):
            problems.append("请求内容与复核时不一致")
        if problems:
            raise ReviewRejected("；".join(problems))
        if not self.store.consume_ticket(ticket_id, self._now_text()):
            raise ReviewRejected("复核票据已使用")
        return dict(row)

    # -- 换岗 -------------------------------------------------------------------

    def reassign_user_role(
        self,
        ctx: AccessContext,
        user_id: str,
        new_role: str,
        reason: str,
        apply_role: Callable[[str, str, str], None],
    ) -> dict[str, Any]:
        """变更用户岗位并撤销其全部会话。

        ``apply_role(user_id, new_role, now)`` 在同一事务内执行各域用户表的 UPDATE。
        """

        self.require(ctx, "access.user.write")
        if self.store.get_role(new_role) is None:
            raise ValidationFailed(f"岗位不存在: {new_role}")
        if self.resolve_user(user_id) is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not reason.strip():
            raise ValidationFailed("岗位变更必须填写审计原因")
        now = self._now_text()
        with transaction(self.connection, immediate=True):
            apply_role(user_id, new_role, now)
            revoked = self.store.revoke_all_user_sessions(user_id, ctx.user_id, reason.strip(), now)
            self._log(
                "user.reassigned",
                ctx.user_id,
                "user",
                user_id,
                {"new_role": new_role, "revoked_sessions": revoked, "reason": reason.strip(), "effective_from": now},
            )
        return {"user_id": user_id, "role": new_role, "revoked_sessions": revoked}
