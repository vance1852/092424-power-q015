"""无第三方依赖的 HTTP JSON 接口。

除健康检查外，所有接口通过 ``Authorization: Bearer <token>`` 携带会话令牌；
令牌由 ``POST /sessions`` 签发。令牌无效、过期或撤销统一返回 ``401
unauthorized``。分析任务的工作进程以 ``worker_id`` 标识租约持有者，仍需持有
有效会话。
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse

from .errors import ServiceError, Unauthorized, ValidationFailed
from .service import TrialService
from .storage import connect


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: Mapping[str, Any]


class JsonApplication:
    """将 HTTP 路由映射到领域服务，便于无网络单元测试。"""

    def __init__(self, service: TrialService) -> None:
        self.service = service

    @staticmethod
    def _token(headers: Mapping[str, str]) -> str:
        authorization = headers.get("authorization", "").strip()
        if not authorization.startswith("Bearer "):
            raise Unauthorized("缺少 Bearer 会话令牌")
        token = authorization[len("Bearer "):].strip()
        if not token:
            raise Unauthorized("缺少 Bearer 会话令牌")
        return token

    @staticmethod
    def _json(body: bytes) -> dict[str, Any]:
        if not body:
            return {}
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationFailed("请求体必须是 UTF-8 JSON 对象") from exc
        if not isinstance(value, dict):
            raise ValidationFailed("请求体必须是 JSON 对象")
        return value

    def handle(
        self, method: str, target: str, headers: Mapping[str, str] | None = None, body: bytes = b""
    ) -> Response:
        normalized_headers = {key.lower(): value for key, value in (headers or {}).items()}
        parsed = urlparse(target)
        path = parsed.path.rstrip("/") or "/"
        parts = [part for part in path.split("/") if part]
        query = parse_qs(parsed.query)
        try:
            if method == "GET" and path == "/health":
                return Response(200, {"status": "ok"})
            payload = self._json(body) if method in {"POST", "PUT", "PATCH"} else {}
            if method == "POST" and path == "/sessions":
                return Response(201, self.service.issue_session(
                    payload["user_id"], int(payload.get("ttl_seconds", 12 * 3600))
                ))
            if method == "POST" and path == "/bootstrap/users":
                return Response(201, self.service.bootstrap_user(
                    payload["user_id"], payload["display_name"], payload["position_id"]
                ))
            session = self.service.authenticate(self._token(normalized_headers))
            actor = session["user_id"]
            idempotency_key = normalized_headers.get("idempotency-key", "").strip()
            with self.service.bind_session(session["session_id"]):
                return self._route(method, path, parts, query, payload, actor, idempotency_key)
        except ServiceError as exc:
            return Response(exc.status, {"error": {"code": exc.code, "message": str(exc)}})
        except (KeyError, TypeError, ValueError) as exc:
            return Response(422, {"error": {"code": "invalid_request", "message": str(exc)}})

    def _route(self, method, path, parts, query, payload, actor, idempotency_key="") -> Response:
        service = self.service
        # ---- 身份、岗位、权限管理 ----
        if method == "POST" and path == "/users":
            return Response(201, service.admin_create_user(
                actor, payload["user_id"], payload["display_name"], payload["position_id"]
            ))
        if method == "GET" and path == "/positions":
            return Response(200, service.list_positions(actor))
        if method == "POST" and path == "/positions":
            return Response(201, service.create_position(
                actor, payload["position_id"], payload["display_name"], payload.get("parent_id")
            ))
        if method == "POST" and len(parts) == 3 and parts[0] == "positions" and parts[2] == "permissions":
            return Response(201, service.change_permission(
                actor, parts[1], payload["permission"], payload["effect"],
                payload.get("effective_from"), payload["reason"],
            ))
        if method == "GET" and path == "/permissions/changes":
            return Response(200, service.list_permission_changes(actor, query.get("position_id", [None])[0]))
        if method == "POST" and len(parts) == 3 and parts[0] == "users" and parts[2] == "position":
            return Response(200, service.assign_position(
                actor, parts[1], payload["position_id"], payload.get("effective_from"), payload["reason"]
            ))
        if method == "POST" and len(parts) == 3 and parts[0] == "users" and parts[2] == "deactivate":
            return Response(200, service.deactivate_user(actor, parts[1], payload["reason"]))
        if method == "GET" and path == "/sessions":
            return Response(200, service.list_sessions(actor, query.get("user_id", [None])[0]))
        if method == "POST" and path == "/sessions/revoke":
            return Response(200, service.revoke_session(actor, payload["session_id"], payload["reason"]))
        if method == "POST" and len(parts) == 3 and parts[0] == "users" and parts[2] == "sessions/revoke":
            return Response(200, service.revoke_user_sessions(actor, parts[1], payload["reason"]))
        # ---- 设备与协议 ----
        if method == "POST" and path == "/robots":
            return Response(201, service.register_robot(
                actor, payload["robot_id"], payload["model_name"], payload["vendor"]
            ))
        if method == "POST" and path == "/builds":
            return Response(201, service.register_build(
                actor, payload["build_id"], payload["robot_id"],
                payload["version"], payload["content_sha256"],
            ))
        if method == "POST" and path == "/protocols":
            return Response(201, service.publish_protocol(actor, payload))
        # ---- 批次与测点 ----
        if method == "POST" and path == "/batches":
            return Response(201, service.create_batch(
                actor, payload["batch_id"], payload["protocol_id"],
                int(payload["protocol_version"]), payload["build_id"],
            ))
        if method == "POST" and len(parts) == 3 and parts[0] == "batches" and parts[2] == "start":
            return Response(200, service.start_batch(actor, parts[1], int(payload["expected_revision"])))
        if method == "POST" and len(parts) == 3 and parts[0] == "batches" and parts[2] == "observations":
            key = payload.get("idempotency_key") or idempotency_key
            if not key:
                raise ValidationFailed("缺少 idempotency_key")
            return Response(200, service.import_observations(
                actor, parts[1], key, payload.get("observations", [])
            ))
        if method == "POST" and len(parts) == 3 and parts[0] == "batches" and parts[2] == "seal":
            return Response(200, service.seal_batch(actor, parts[1], int(payload["expected_revision"])))
        if method == "GET" and len(parts) == 3 and parts[0] == "batches" and parts[2] == "report":
            return Response(200, service.report(actor, parts[1]))
        # ---- 测点排除 ----
        if method == "POST" and path == "/exclusions":
            return Response(201, service.request_exclusion(
                actor, int(payload["observation_id"]), payload["reason"]
            ))
        if method == "POST" and len(parts) == 3 and parts[0] == "exclusions" and parts[2] == "review":
            return Response(200, service.review_exclusion(
                actor, int(parts[1]), bool(payload["approve"]), payload.get("note", "")
            ))
        if method == "POST" and len(parts) == 3 and parts[0] == "exclusions" and parts[2] == "revoke":
            return Response(200, service.revoke_exclusion(
                actor, int(parts[1]), payload["reason"]
            ))
        # ---- 分析任务 ----
        if method == "POST" and path == "/jobs/claim":
            return Response(200, {"job": service.claim_job(
                payload["worker_id"], int(payload.get("lease_seconds", 60))
            )})
        if method == "POST" and len(parts) == 3 and parts[0] == "jobs" and parts[2] == "complete":
            return Response(200, service.complete_job(
                payload["worker_id"], int(parts[1]), actor
            ))
        if method == "POST" and len(parts) == 3 and parts[0] == "jobs" and parts[2] == "fail":
            return Response(200, service.fail_job(
                payload["worker_id"], int(parts[1]), payload["error"],
                int(payload.get("retry_seconds", 0)),
            ))
        # ---- 准入决定两阶段复核 ----
        if method == "POST" and path == "/decisions/request":
            return Response(201, service.request_decision(
                actor, payload["batch_id"], int(payload["analysis_id"]),
                payload["decision"], payload["reason"],
            ))
        if method == "POST" and len(parts) == 3 and parts[0] == "decisions" and parts[2] == "review":
            return Response(200, service.review_decision(
                actor, int(parts[1]), bool(payload["approve"]), payload.get("note", "")
            ))
        # ---- 审计检索 ----
        if method == "GET" and path == "/audit/events":
            return Response(200, service.audit_events(
                actor,
                actor_filter=query.get("actor_id", [None])[0],
                entity_type=query.get("entity_type", [None])[0],
                limit=int(query.get("limit", ["200"])[0]),
            ))
        return Response(404, {"error": {"code": "route_not_found", "message": "接口不存在"}})


def make_handler(application: JsonApplication):
    class Handler(BaseHTTPRequestHandler):
        server_version = "RobotTrials/2"

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch()

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch()

        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            response = application.handle(self.command, self.path, dict(self.headers.items()), body)
            encoded = json.dumps(response.body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="启动机组试验统计分析准入 HTTP 服务")
    parser.add_argument("--database", type=Path, default=Path("plant_science.sqlite3"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)
    connection = connect(args.database)
    application = JsonApplication(TrialService(connection))
    server = ThreadingHTTPServer((args.host, args.port), make_handler(application))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
