"""两个业务域 HTTP 接口共用的会话、岗位、授权与复核路由。"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from .manager import AccessManager, ReviewGate


def bearer_token(headers: Mapping[str, str]) -> str:
    authorization = headers.get("authorization", "").strip()
    if not authorization.lower().startswith("bearer "):
        return ""
    return authorization.split(" ", 1)[1].strip()


def route_access(
    manager: AccessManager,
    method: str,
    path: str,
    parts: list[str],
    query: Mapping[str, list[str]],
    payload: Mapping[str, Any],
    token: str,
    reassign_role: Callable[[str, str, str], None] | None = None,
) -> tuple[int, dict[str, Any]] | None:
    """处理访问控制类路由；不匹配时返回 None，由业务 API 继续分发。

    ``reassign_role(user_id, new_role, now)`` 在换岗事务内更新业务用户表。
    """

    def q(name: str, default: str = "") -> str:
        return query.get(name, [default])[0]

    if method == "POST" and path == "/sessions":
        ttl = payload.get("ttl_seconds")
        result = manager.issue_session(
            payload["user_id"], str(payload.get("label", "login")), None if ttl is None else int(ttl)
        )
        return 201, result

    ctx = manager.authenticate(token)

    if method == "GET" and path == "/roles":
        return 200, {"roles": manager.list_roles(ctx)}
    if method == "POST" and path == "/roles":
        result = manager.define_role(
            ctx,
            payload["role_id"],
            payload.get("display_name"),
            list(payload.get("parents", [])),
            payload["reason"],
        )
        return 201, result
    if method == "POST" and path == "/users/reassign":
        user_id = payload["user_id"]
        new_role = payload["role"]
        result = manager.reassign_user_role(
            ctx,
            user_id,
            new_role,
            payload["reason"],
            lambda role, now: (
                reassign_role(user_id, role, now) if reassign_role is not None else None
            ),
        )
        return 200, result
    if method == "GET" and path == "/grants":
        include_revoked = q("include_revoked", "false").lower() in {"1", "true", "yes"}
        return 200, {"grants": manager.list_grants(ctx, include_revoked)}
    if method == "POST" and path == "/grants":
        result = manager.grant_permission(
            ctx,
            payload["subject_type"],
            payload["subject_id"],
            payload["permission"],
            payload.get("effect", "allow"),
            payload["reason"],
            payload.get("effective_from"),
        )
        return 201, result
    if method == "POST" and len(parts) == 3 and parts[:2] == ["grants", "revoke"]:
        return 200, manager.revoke_grant(ctx, int(parts[2]), payload["reason"])
    if method == "GET" and path == "/sessions":
        user_id = q("user_id") or None
        return 200, {"sessions": manager.list_sessions(ctx, user_id)}
    if method == "POST" and path == "/sessions/revoke":
        return 200, manager.revoke_session(ctx, payload["session_id"], payload["reason"])
    if method == "POST" and path == "/sessions/revoke-user":
        return 200, manager.revoke_user_sessions(ctx, payload["user_id"], payload["reason"])
    if method == "POST" and path == "/reviews":
        gate = ReviewGate(
            scope=payload["scope"],
            entity_type=payload["entity_type"],
            entity_id=str(payload["entity_id"]),
            expected_version=str(payload["expected_version"]),
            payload=dict(payload.get("payload", {})),
        )
        ttl = payload.get("ttl_seconds")
        return 201, manager.request_review(ctx, gate, None if ttl is None else int(ttl))
    if method == "POST" and len(parts) == 3 and parts[0] == "reviews" and parts[2] == "decision":
        result = manager.decide_review(
            ctx, parts[1], bool(payload["approve"]), str(payload.get("note", ""))
        )
        return 200, result
    if method == "GET" and len(parts) == 2 and parts[0] == "reviews":
        return 200, manager.get_review(ctx, parts[1])
    if method == "GET" and path == "/access/audit":
        actor_id = q("actor_id") or None
        return 200, {"events": manager.audit_events(ctx, actor_id)}
    if method == "GET" and path == "/access/chain":
        return 200, manager.audit_chain(ctx)
    return None
