"""访问控制向 API 暴露的稳定错误码。"""

from __future__ import annotations


class AccessControlError(RuntimeError):
    """所有访问控制错误的基类，携带稳定错误码与 HTTP 状态。"""

    code = "access_control_error"
    status = 400


class ValidationFailed(AccessControlError):
    code = "validation_failed"
    status = 422


class NotFound(AccessControlError):
    code = "not_found"
    status = 404


class Conflict(AccessControlError):
    code = "conflict"
    status = 409


class AuthenticationFailed(AccessControlError):
    """请求未携带合法会话令牌。"""

    code = "authentication_failed"
    status = 401


class SessionRevoked(AccessControlError):
    """令牌对应会话已被撤销；错误码刻意保持稳定，不区分不存在与已撤销。"""

    code = "session_revoked"
    status = 401


class AuthorizationFailed(AccessControlError):
    """已认证但不具备所需权限。"""

    code = "forbidden"
    status = 403


class ReviewRequired(AccessControlError):
    """敏感操作缺少有效的二次复核票据。"""

    code = "review_required"
    status = 409


class ReviewRejected(AccessControlError):
    """二次复核人拒绝放行，或票据与本次请求/业务版本不一致。"""

    code = "review_rejected"
    status = 409
