"""可配置权限、岗位继承、会话签发撤销与二次复核的端到端测试。"""

from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timezone

from power_dispatch.api import JsonApplication
from power_dispatch.clock import FrozenClock
from power_dispatch.errors import (
    Conflict,
    Forbidden,
    InvalidState,
    Unauthorized,
    ValidationFailed,
)
from power_dispatch.service import SupplyService


class IdentityTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = SupplyService(self.connection, self.clock)
        for user_id, position in (
            ("admin", "admin"),
            ("plan", "planner"),
            ("dispatch", "dispatcher"),
            ("risk", "risk"),
            ("audit", "auditor"),
        ):
            self.service.create_user(user_id, user_id, position)

    def tearDown(self) -> None:
        self.connection.close()

    def token(self, user_id: str) -> str:
        return self.service.issue_session(user_id)["token"]

    def headers(self, user_id: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token(user_id)}"}


class PermissionModelTests(IdentityTestBase):
    def test_builtin_positions_seed_expected_permissions(self) -> None:
        positions = {p["position_id"]: p for p in self.service.list_positions("admin")["positions"]}
        self.assertIn("quote.write", positions["planner"]["permissions"])
        self.assertNotIn("quote.write", positions["dispatcher"]["permissions"])
        self.assertIn("audit.read", positions["auditor"]["permissions"])

    def test_child_position_inherits_and_overrides_parent(self) -> None:
        self.service.create_position("admin", "senior-planner", "高级计划岗", "planner")
        positions = {p["position_id"]: p for p in self.service.list_positions("admin")["positions"]}
        # 子岗位继承父岗位权限。
        self.assertIn("quote.write", positions["senior-planner"]["permissions"])
        # 在子岗位上 deny 覆盖继承来的授予。
        self.service.change_permission(
            "admin", "senior-planner", "quote.write", "deny", None, "交接班隔离报价权"
        )
        positions = {p["position_id"]: p for p in self.service.list_positions("admin")["positions"]}
        self.assertNotIn("quote.write", positions["senior-planner"]["permissions"])
        # 父岗位不受影响。
        self.assertIn("quote.write", positions["planner"]["permissions"])
        # revoke 恢复继承。
        self.service.change_permission(
            "admin", "senior-planner", "quote.write", "revoke", None, "恢复继承报价权"
        )
        positions = {p["position_id"]: p for p in self.service.list_positions("admin")["positions"]}
        self.assertIn("quote.write", positions["senior-planner"]["permissions"])

    def test_future_grant_does_not_take_effect_early(self) -> None:
        self.service.create_position("admin", "future-trader", "未来交易岗", "planner")
        self.service.create_user("ft", "未来交易员", "future-trader")
        self.service.change_permission(
            "admin", "future-trader", "transfer.write", "grant",
            "2026-09-25T00:00:00Z", "次日生效的送电权",
        )
        # 生效时间之前没有该权限。
        with self.assertRaises(Forbidden):
            self.service._require("ft", "transfer.write")
        self.clock.advance(hours=17)
        # 生效时间之后自动获得权限，无需重启或重新登录。
        user = self.service._user("ft")
        self.assertIn("transfer.write", self.service._permissions(user))

    def test_change_takes_effect_within_same_second(self) -> None:
        # 生效时间只精确到秒时，同一秒的稍后时刻（带小数秒）也必须生效，
        # 防止 ISO 文本词法比较把 "...:00Z" 排在 "...:00.500000Z" 之后。
        from power_dispatch.identity import effective_permissions
        self.service.change_permission(
            "admin", "planner", "quote.write", "deny",
            "2026-09-25T00:00:00Z", "整点静默",
        )
        self.assertIn(
            "quote.write",
            effective_permissions(self.connection, "planner", "2026-09-24T23:59:59.999999Z"),
        )
        self.assertNotIn(
            "quote.write",
            effective_permissions(self.connection, "planner", "2026-09-25T00:00:00.000000Z"),
        )
        self.assertNotIn(
            "quote.write",
            effective_permissions(self.connection, "planner", "2026-09-25T00:00:00.500000Z"),
        )

    def test_permission_change_requires_reason(self) -> None:
        with self.assertRaises(ValidationFailed):
            self.service.change_permission("admin", "planner", "quote.write", "deny", None, "  ")

    def test_permission_change_history_is_immutable(self) -> None:
        self.service.change_permission("admin", "planner", "quote.write", "deny", None, "临时收回")
        changes = self.service.list_permission_changes("admin", "planner")["changes"]
        effects = [(c["permission"], c["effect"], c["reason"]) for c in changes if c["permission"] == "quote.write"]
        self.assertEqual(
            effects,
            [("quote.write", "grant", "出厂岗位授权"), ("quote.write", "deny", "临时收回")],
        )

    def test_position_inheritance_cycle_is_rejected(self) -> None:
        # 正常建岗无法成环（父岗位必须先存在）；解析器对脏数据中的环也要安全报错。
        self.service.create_position("admin", "alpha", "甲岗", None)
        self.service.create_position("admin", "beta", "乙岗", "alpha")
        from power_dispatch.identity import position_chain
        self.assertEqual(position_chain(self.connection, "beta"), ["alpha", "beta"])
        self.connection.execute(
            "UPDATE supply_positions SET parent_id='beta' WHERE position_id='alpha'"
        )
        with self.assertRaises(ValidationFailed):
            position_chain(self.connection, "alpha")


class SessionTests(IdentityTestBase):
    def test_token_required_and_has_stable_error_code(self) -> None:
        app = JsonApplication(self.service)
        for headers in ({}, {"Authorization": "Bearer "}, {"Authorization": "Basic abc"}):
            response = app.handle("POST", "/facilities", headers, b'{"facility_id":"f"}')
            self.assertEqual(response.status, 401)
            self.assertEqual(response.body["error"]["code"], "unauthorized")

    def test_revoked_session_immediately_rejected(self) -> None:
        issued = self.service.issue_session("dispatch")
        self.service.authenticate(issued["token"])
        self.service.revoke_session("admin", issued["session_id"], "交接班")
        with self.assertRaises(Unauthorized):
            self.service.authenticate(issued["token"])

    def test_duplicate_login_replaces_previous_session(self) -> None:
        first = self.service.issue_session("dispatch")
        second = self.service.issue_session("dispatch")
        self.assertNotEqual(first["token"], second["token"])
        # 旧会话立即失效，新会话可用。
        with self.assertRaises(Unauthorized):
            self.service.authenticate(first["token"])
        self.assertEqual(self.service.authenticate(second["token"])["user_id"], "dispatch")
        row = self.connection.execute(
            "SELECT replaced_by,revoke_reason FROM supply_sessions WHERE session_id=?",
            (first["session_id"],),
        ).fetchone()
        self.assertEqual(row["replaced_by"], second["session_id"])
        self.assertIn("重复登录", row["revoke_reason"])

    def test_expired_and_unknown_token_rejected(self) -> None:
        issued = self.service.issue_session("dispatch", ttl_seconds=60)
        self.clock.advance(seconds=61)
        with self.assertRaises(Unauthorized):
            self.service.authenticate(issued["token"])
        with self.assertRaises(Unauthorized):
            self.service.authenticate("not-a-real-token")

    def test_sessions_survive_service_restart(self) -> None:
        issued = self.service.issue_session("dispatch")
        # 用同一数据库连接构造新的服务实例，模拟进程重启后的状态重建。
        restarted = SupplyService(self.connection, self.clock)
        self.assertEqual(restarted.authenticate(issued["token"])["user_id"], "dispatch")

    def test_revocation_and_sessions_persist_across_database_reopen(self) -> None:
        import tempfile
        from pathlib import Path
        from power_dispatch.storage import connect as connect_db
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "restart.sqlite3"
            connection = connect_db(path)
            service = SupplyService(connection)
            service.create_user("admin", "管理员", "admin")
            service.create_user("dispatch", "调度", "dispatcher")
            issued = service.issue_session("dispatch", ttl_seconds=24 * 3600)
            service.revoke_session("admin", issued["session_id"], "交接班收令牌")
            active = service.issue_session("dispatch", ttl_seconds=24 * 3600)
            connection.close()
            # 重新打开数据库文件，模拟真实进程重启。
            reopened = connect_db(path)
            restarted = SupplyService(reopened)
            with self.assertRaises(Unauthorized):
                restarted.authenticate(issued["token"])
            self.assertEqual(restarted.authenticate(active["token"])["user_id"], "dispatch")
            reopened.close()

    def test_position_change_revokes_existing_sessions(self) -> None:
        issued = self.service.issue_session("plan")
        self.service.create_position("admin", "desk-a", "甲班调度", "dispatcher")
        self.service.assign_position("admin", "plan", "desk-a", None, "换岗到调度班组")
        with self.assertRaises(Unauthorized):
            self.service.authenticate(issued["token"])

    def test_revoked_token_cannot_call_api_after_restart(self) -> None:
        issued = self.service.issue_session("dispatch")
        self.service.revoke_user_sessions("admin", "dispatch", "下班收令牌")
        app = JsonApplication(SupplyService(self.connection, self.clock))
        response = app.handle("GET", "/audit/chain", {"Authorization": f"Bearer {issued['token']}"})
        self.assertEqual(response.status, 401)
        self.assertEqual(response.body["error"]["code"], "unauthorized")


class TwoPartyReviewTests(IdentityTestBase):
    def _ready_transfer(self) -> dict:
        self.service.create_facility("plan", {"facility_id": "field-a", "name": "电厂", "kind": "storage", "timezone": "Asia/Shanghai", "capacity_mwh": "500000"})
        self.service.create_facility("plan", {"facility_id": "terminal-b", "name": "终端", "kind": "terminal", "timezone": "Asia/Shanghai", "capacity_mwh": "800000"})
        self.service.create_route("plan", {"route_id": "pipe", "origin_id": "field-a", "destination_id": "terminal-b", "product": "crude", "daily_capacity": "100000", "loss_basis_points": 25, "transit_hours": 36})
        self.service.add_inventory_lot("dispatch", {"lot_id": "lot-1", "facility_id": "field-a", "product": "crude", "grade": "X", "quantity_mwh": "60000", "unit_cost_cny": "91", "received_at": "2026-09-24T06:00:00Z"})
        self.service.submit_nomination("dispatch", {"nomination_id": "nom-1", "route_id": "pipe", "shipper_id": "s1", "service_date": "2026-09-25", "requested_mwh": "40000", "priority": 10, "idempotency_key": "k1"})
        self.service.allocate("dispatch", "pipe", "2026-09-25")
        return self.service.request_transfer("dispatch", "tr-1", "nom-1", "lot-1", 2)

    def test_transfer_needs_separate_reviewer_and_binds_version(self) -> None:
        requested = self._ready_transfer()
        # 发起人不能自己确认。
        with self.assertRaises(Forbidden):
            self.service.confirm_transfer("dispatch", requested["approval_id"])
        confirmed = self.service.confirm_transfer("risk", requested["approval_id"], "同意送电")
        self.assertEqual(confirmed["status"], "confirmed")
        self.assertEqual(confirmed["loaded_mwh"], "40000.000")
        # 复核单与审计同时绑定发起者、复核者和业务版本。
        approval = self.connection.execute(
            "SELECT * FROM supply_approvals WHERE approval_id=?", (requested["approval_id"],)
        ).fetchone()
        self.assertEqual(approval["requested_by"], "dispatch")
        self.assertEqual(approval["reviewed_by"], "risk")
        self.assertEqual(approval["expected_revision"], 2)
        event = self.connection.execute(
            "SELECT payload_json FROM supply_audit_events WHERE event_type='transfer.dispatched'"
        ).fetchone()
        payload = json.loads(event["payload_json"])
        self.assertEqual(payload["requested_by"], "dispatch")
        self.assertEqual(payload["reviewed_by"], "risk")
        self.assertEqual(payload["expected_revision"], 2)

    def test_confirmation_fails_when_business_version_drifts(self) -> None:
        requested = self._ready_transfer()
        # 模拟提名版本在发起与确认之间被改动。
        self.connection.execute(
            "UPDATE nominations SET revision=revision+1 WHERE nomination_id='nom-1'"
        )
        with self.assertRaises(InvalidState):
            self.service.confirm_transfer("risk", requested["approval_id"])
        # 复核单仍是 pending，可在版本恢复后处理。
        self.connection.execute(
            "UPDATE nominations SET revision=2 WHERE nomination_id='nom-1'"
        )
        self.assertEqual(
            self.service.confirm_transfer("risk", requested["approval_id"])["status"], "confirmed"
        )

    def test_rejected_review_leaves_no_business_change(self) -> None:
        requested = self._ready_transfer()
        result = self.service.review_approval("risk", requested["approval_id"], False, "资料不全")
        self.assertEqual(result["status"], "rejected")
        available = self.service.inventory_lot("lot-1")["available_mwh"]
        self.assertEqual(available, "60000")
        with self.assertRaises(InvalidState):
            self.service.confirm_transfer("risk", requested["approval_id"])

    def test_review_via_http_uses_session_identity(self) -> None:
        requested = self._ready_transfer()
        app = JsonApplication(self.service)
        body = json.dumps({"approve": True, "note": "ok"}).encode()
        # 调度岗令牌无权确认。
        denied = app.handle(
            "POST", f"/approvals/{requested['approval_id']}/confirm", self.headers("dispatch"), body
        )
        self.assertEqual(denied.status, 403)
        ok = app.handle(
            "POST", f"/approvals/{requested['approval_id']}/confirm", self.headers("risk"), body
        )
        self.assertEqual(ok.status, 200)
        self.assertEqual(ok.body["status"], "confirmed")


class AuditHistoryTests(IdentityTestBase):
    def test_history_searchable_by_original_actor_after_deactivation(self) -> None:
        self.service.record_quote("plan", {
            "market_index": "PEAK_VALLEY", "trade_date": "2026-09-23", "close_cny": "98",
            "source_revision": "r1", "observed_at": "2026-09-23T21:00:00Z",
        })
        # 停用操作者（其会话也被撤销）。
        self.service.deactivate_user("admin", "plan", "操作员离职")
        events = self.service.audit_events("audit", actor_filter="plan")["events"]
        self.assertTrue(any(e["event_type"] == "quote.recorded" for e in events))
        # 历史仍带操作者标识，可按操作者检索，且该用户无法再登录。
        self.assertTrue(all(e["actor_id"] == "plan" for e in events))
        with self.assertRaises(Forbidden):
            self.service._user("plan")

    def test_audit_events_filtered_by_entity_type(self) -> None:
        self.service.issue_session("plan")
        self.service.record_quote("plan", {
            "market_index": "PEAK_VALLEY", "trade_date": "2026-09-23", "close_cny": "98",
            "source_revision": "r1", "observed_at": "2026-09-23T21:00:00Z",
        })
        events = self.service.audit_events("audit", entity_type="session")["events"]
        self.assertTrue(events)
        self.assertTrue(all(e["entity_type"] == "session" for e in events))

    def test_chain_remains_valid_with_identity_events(self) -> None:
        self.service.issue_session("plan")
        self.service.change_permission("admin", "planner", "quote.write", "deny", None, "临时收回")
        chain = self.service.audit_chain("audit")
        self.assertTrue(chain["valid"])
        self.assertGreater(chain["events"], 0)


class BootstrapTests(IdentityTestBase):
    def test_first_user_bootstrap_then_closed(self) -> None:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        service = SupplyService(connection, self.clock)
        first = service.bootstrap_user("root", "首个管理员", "admin")
        self.assertEqual(first["position_id"], "admin")
        with self.assertRaises(Forbidden):
            service.bootstrap_user("root2", "第二个", "admin")
        connection.close()


if __name__ == "__main__":
    unittest.main()
