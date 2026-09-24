"""可配置岗位权限、会话签发与二次复核。

该包被供应调度域和机组分析准入域共用：

- ``store``：岗位（岗位继承）、授权变更（生效时间+审计原因）、会话签发/撤销、
  二次复核票据的 SQLite 持久化；
- ``manager``：鉴权、生效授权解析、会话与复核票据的用例。

所有授权状态都落库，进程重启和重复登录都不会产生不可追踪的状态。
"""

from .errors import (
    AccessControlError,
    AuthenticationFailed,
    AuthorizationFailed,
    ReviewRejected,
    ReviewRequired,
    SessionRevoked,
)
from .manager import AccessManager, AccessContext, ReviewGate
from .store import AccessStore, initialize_access_control

__all__ = [
    "AccessContext",
    "AccessControlError",
    "AccessManager",
    "AccessStore",
    "AuthenticationFailed",
    "AuthorizationFailed",
    "ReviewGate",
    "ReviewRejected",
    "ReviewRequired",
    "initialize_access_control",
]
