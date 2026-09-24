"""无第三方依赖的供应调度 HTTP JSON 接口。

除健康检查外，所有接口都通过 ``Authorization: Bearer <token>`` 携带会话令牌；
令牌由 ``POST /sessions`` 用用户编号签发。令牌无效、过期或撤销时统一返回
``401 unauthorized``，不区分具体原因，避免泄露令牌状态。
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlparse

from .errors import SupplyError, Unauthorized, ValidationFailed
from .service import SupplyService
from .storage import connect


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: Mapping[str, Any]


class JsonApplication:
    def __init__(self, service: SupplyService) -> None:
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

    def handle(self, method: str, target: str, headers: Mapping[str, str] | None = None, body: bytes = b"") -> Response:
        normalized = {key.lower(): value for key, value in (headers or {}).items()}
        parsed = urlparse(target)
        path = parsed.path.rstrip("/") or "/"
        parts = [part for part in path.split("/") if part]
        query = parse_qs(parsed.query)
        try:
            if method == "GET" and path == "/health":
                return Response(200, {"status": "ok"})
            payload = self._json(body) if method in {"POST", "PUT", "PATCH"} else {}
            # 会话签发与首个管理员开户不需要已有会话。
            if method == "POST" and path == "/sessions":
                return Response(201, self.service.issue_session(
                    payload["user_id"], int(payload.get("ttl_seconds", 12 * 3600))
                ))
            if method == "POST" and path == "/bootstrap/users":
                return Response(201, self.service.bootstrap_user(
                    payload["user_id"], payload["display_name"], payload["position_id"]
                ))
            session = self.service.authenticate(self._token(normalized))
            actor = session["user_id"]
            with self.service.bind_session(session["session_id"]):
                return self._route(method, path, parts, query, payload, actor)
        except SupplyError as exc:
            return Response(exc.status, {"error": {"code": exc.code, "message": str(exc)}})
        except (KeyError, TypeError, ValueError) as exc:
            return Response(422, {"error": {"code": "invalid_request", "message": str(exc)}})

    def _route(self, method, path, parts, query, payload, actor) -> Response:
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
            return Response(200, service.revoke_session(
                actor, payload["session_id"], payload["reason"]
            ))
        if method == "POST" and len(parts) == 3 and parts[0] == "users" and parts[2] == "sessions/revoke":
            return Response(200, service.revoke_user_sessions(actor, parts[1], payload["reason"]))
        # ---- 二次复核 ----
        if method == "POST" and len(parts) == 3 and parts[0] == "approvals" and parts[2] == "confirm":
            return Response(200, service.review_approval(
                actor, int(parts[1]), True, payload.get("note", "")
            ))
        if method == "POST" and len(parts) == 3 and parts[0] == "approvals" and parts[2] == "reject":
            return Response(200, service.review_approval(
                actor, int(parts[1]), False, payload.get("note", "")
            ))
        # ---- 调度业务 ----
        if method == "POST" and path == "/quotes":
            return Response(201, service.record_quote(actor, payload))
        if method == "GET" and len(parts) == 3 and parts[:2] == ["quotes", "summary"]:
            return Response(200, service.price_summary(parts[2], int(query.get("sessions", ["20"])[0])))
        if method == "POST" and path == "/facilities":
            return Response(201, service.create_facility(actor, payload))
        if method == "POST" and path == "/routes":
            return Response(201, service.create_route(actor, payload))
        if method == "POST" and len(parts) == 3 and parts[0] == "routes" and parts[2] == "outages":
            return Response(201, service.announce_outage(
                actor, parts[1], payload["starts_at"], payload.get("ends_at"),
                payload["capacity_percent"], payload["reason"],
            ))
        if method == "POST" and path == "/inventory/lots":
            return Response(201, service.add_inventory_lot(actor, payload))
        if method == "GET" and path == "/inventory/summary":
            return Response(200, service.inventory_summary(
                query.get("facility_id", [""])[0], query.get("product", [""])[0]
            ))
        if method == "POST" and path == "/nominations":
            return Response(201, service.submit_nomination(actor, payload))
        if method == "POST" and len(parts) == 3 and parts[0] == "routes" and parts[2] == "allocate":
            return Response(200, service.allocate(actor, parts[1], payload["service_date"]))
        if method == "POST" and path == "/transfers/request":
            return Response(201, service.request_transfer(
                actor, payload["transfer_id"], payload["nomination_id"],
                payload["lot_id"], int(payload["expected_revision"]),
            ))
        if method == "POST" and path == "/scenarios":
            return Response(201, service.create_scenario(actor, payload))
        if method == "POST" and len(parts) == 3 and parts[0] == "scenarios" and parts[2] == "approval-request":
            return Response(201, service.request_scenario_approval(
                actor, parts[1], int(payload["expected_revision"])
            ))
        if method == "POST" and len(parts) == 3 and parts[0] == "scenarios" and parts[2] == "run":
            return Response(200, service.run_scenario(actor, parts[1], payload["as_of_date"]))
        if method == "GET" and path == "/audit/chain":
            return Response(200, service.audit_chain(actor))
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
        server_version = "PowerDispatch/2"

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
    parser = argparse.ArgumentParser(description="启动电厂调度与能源分析服务")
    parser.add_argument("--database", type=Path, default=Path("power_dispatch.sqlite3"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)
    connection = connect(args.database)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(JsonApplication(SupplyService(connection))))
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
