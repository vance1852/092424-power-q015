from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime, timezone
from decimal import Decimal

from access_control import ReviewGate
from access_control.errors import ReviewRequired, SessionRevoked
from power_dispatch.api import JsonApplication
from power_dispatch.clock import FrozenClock
from power_dispatch.errors import Conflict, Forbidden
from power_dispatch.planning import AllocationRequest, PricePoint, allocate_capacity, latest_streak
from power_dispatch.service import SupplyService
from power_dispatch.risk import DemandBucket, inventory_coverage, mark_to_market, supply_gap


class PlanningTests(unittest.TestCase):
    def test_latest_down_streak_uses_first_close_as_base(self) -> None:
        streak = latest_streak([
            PricePoint("2026-09-18", Decimal("108")),
            PricePoint("2026-09-19", Decimal("105")),
            PricePoint("2026-09-20", Decimal("102")),
            PricePoint("2026-09-21", Decimal("98")),
        ])
        self.assertEqual(streak.direction, "down")
        self.assertEqual(streak.sessions, 4)
        self.assertEqual(streak.start_date, "2026-09-18")
        self.assertEqual(streak.end_close, Decimal("98"))

    def test_allocation_is_stable_and_does_not_exceed_capacity(self) -> None:
        rows = allocate_capacity(Decimal("100"), [
            AllocationRequest("later", Decimal("80"), 20, "2026-09-24T09:00:00Z"),
            AllocationRequest("first", Decimal("70"), 10, "2026-09-24T10:00:00Z"),
        ])
        self.assertEqual(rows[0]["nomination_id"], "first")
        self.assertEqual(rows[0]["allocated_mwh"], "70.000")
        self.assertEqual(rows[1]["allocated_mwh"], "30.000")

    def test_inventory_coverage_and_supply_gap(self) -> None:
        coverage = inventory_coverage(
            [{"facility_id": "terminal", "product": "gasoline-92", "available_mwh": "250"}],
            [DemandBucket("terminal", "gasoline-92", Decimal("100"), Decimal("20"))],
        )
        self.assertEqual(coverage[0]["coverage_days"], "2.30")
        self.assertTrue(coverage[0]["below_three_days"])
        gap = supply_gap(
            opening_inventory=Decimal("100"),
            confirmed_inbound=Decimal("30"),
            forecast_demand=Decimal("120"),
            protected_reserve=Decimal("40"),
        )
        self.assertEqual(gap["supply_gap"], "30.000")

    def test_mark_to_market_groups_deterministically(self) -> None:
        result = mark_to_market(
            [{"position_id": "p1", "market_index": "PEAK_VALLEY", "quantity_mwh": "100", "entry_price_cny": "105"}],
            {"PEAK_VALLEY": Decimal("98")},
        )
        self.assertEqual(result["unrealized_pnl_cny"], "-700.00")


class SupplyServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = SupplyService(self.connection, self.clock)
        self.users = {}
        for user_id, role in (("plan", "planner"), ("dispatch", "dispatcher"), ("risk", "risk"), ("audit", "auditor")):
            self.service.create_user(user_id, user_id, role)
            self.users[user_id] = self.login(user_id)
        self.plan = self.users["plan"]
        self.dispatch = self.users["dispatch"]
        self.risk = self.users["risk"]
        self.audit = self.users["audit"]
        self.service.create_facility(self.plan, {"facility_id": "field-a", "name": "北部电厂", "kind": "storage", "timezone": "Asia/Shanghai", "capacity_mwh": "500000"})
        self.service.create_facility(self.plan, {"facility_id": "terminal-b", "name": "沿海终端", "kind": "terminal", "timezone": "Asia/Shanghai", "capacity_mwh": "800000"})
        self.service.create_route(self.plan, {"route_id": "pipe-a-b", "origin_id": "field-a", "destination_id": "terminal-b", "product": "crude", "daily_capacity": "100000", "loss_basis_points": 25, "transit_hours": 36})

    def login(self, user_id: str):
        token = self.service.access.issue_session(user_id, label="test")["token"]
        return self.service.access.authenticate(token)

    def tearDown(self) -> None:
        self.connection.close()

    def quote(self, day: int, close: str) -> dict[str, object]:
        return self.service.record_quote(self.plan, {"market_index": "PEAK_VALLEY", "trade_date": f"2026-09-{day}", "close_cny": close, "source_revision": f"r-{day}", "observed_at": f"2026-09-{day}T21:00:00Z"})

    def approve_transfer(self, expected_revision: int = 2, transfer_id: str = "transfer-1", lot_id: str = "lot-1", nomination_id: str = "nom-1") -> str:
        """调度员申请、风险岗第二人复核，返回可消费的票据号。"""

        gate = ReviewGate(
            scope="transfer.dispatch", entity_type="nomination", entity_id=nomination_id,
            expected_version=expected_revision, payload={"transfer_id": transfer_id, "lot_id": lot_id},
        )
        ticket = self.service.access.request_review(self.dispatch, gate)["ticket_id"]
        self.service.access.decide_review(self.risk, ticket, True, "复核通过")
        return ticket

    def test_quote_revisions_preserve_history(self) -> None:
        first = self.quote(23, "98")
        second = self.service.record_quote(self.plan, {"market_index": "PEAK_VALLEY", "trade_date": "2026-09-23", "close_cny": "97.8", "source_revision": "r-23-corrected", "observed_at": "2026-09-23T22:00:00Z"})
        self.assertNotEqual(first["quote_id"], second["quote_id"])
        rows = self.connection.execute("SELECT * FROM market_index_quotes ORDER BY quote_id").fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1]["supersedes_quote_id"], rows[0]["quote_id"])

    def test_nomination_replay_and_payload_conflict(self) -> None:
        payload = {"nomination_id": "nom-1", "route_id": "pipe-a-b", "shipper_id": "refinery", "service_date": "2026-09-25", "requested_mwh": "80000", "priority": 10, "idempotency_key": "key-1"}
        first = self.service.submit_nomination(self.dispatch, payload)
        self.assertEqual(first, self.service.submit_nomination(self.dispatch, payload))
        changed = dict(payload, requested_mwh="81000")
        with self.assertRaises(Conflict):
            self.service.submit_nomination(self.dispatch, changed)

    def test_outage_reduces_allocation_and_transfer_consumes_inventory(self) -> None:
        self.service.announce_outage(self.risk, "pipe-a-b", "2026-09-25T00:00:00Z", "2026-09-25T23:59:59Z", "50", "检修")
        for number, requested, priority in ((1, "40000", 10), (2, "30000", 20)):
            self.service.submit_nomination(self.dispatch, {"nomination_id": f"nom-{number}", "route_id": "pipe-a-b", "shipper_id": f"shipper-{number}", "service_date": "2026-09-25", "requested_mwh": requested, "priority": priority, "idempotency_key": f"key-{number}"})
        allocation = self.service.allocate(self.dispatch, "pipe-a-b", "2026-09-25")
        self.assertEqual(allocation["available_capacity"], "50000.000")
        self.assertEqual(allocation["allocations"][1]["allocated_mwh"], "10000.000")
        self.service.add_inventory_lot(self.dispatch, {"lot_id": "lot-1", "facility_id": "field-a", "product": "crude", "grade": "PEAK_VALLEY", "quantity_mwh": "60000", "unit_cost_cny": "91", "received_at": "2026-09-24T06:00:00Z"})

        # 没有二次复核票据时，敏感送电操作被稳定错误拒绝，且库存不变。
        with self.assertRaises(ReviewRequired):
            self.service.dispatch_transfer(self.dispatch, "transfer-1", "nom-1", "lot-1", 2, "rvw_missing")
        ticket = self.approve_transfer()
        transfer = self.service.dispatch_transfer(self.dispatch, "transfer-1", "nom-1", "lot-1", 2, ticket)
        self.assertEqual(transfer["loaded_mwh"], "40000.000")
        self.assertEqual(self.service.inventory_lot("lot-1")["available_mwh"], "20000.000")

        # 票据一次性：重复使用立即被拒。
        self.service.add_inventory_lot(self.dispatch, {"lot_id": "lot-2", "facility_id": "field-a", "product": "crude", "grade": "PEAK_VALLEY", "quantity_mwh": "60000", "unit_cost_cny": "91", "received_at": "2026-09-24T07:00:00Z"})
        from access_control.errors import ReviewRejected
        with self.assertRaises(ReviewRejected):
            self.service.dispatch_transfer(self.dispatch, "transfer-2", "nom-2", "lot-2", 2, ticket)

    def test_reviewer_must_be_different_operator(self) -> None:
        for number, requested in (("a", "1000"), ("b", "1000")):
            self.service.submit_nomination(self.dispatch, {"nomination_id": f"nom-{number}", "route_id": "pipe-a-b", "shipper_id": "shipper-x", "service_date": "2026-09-26", "requested_mwh": requested, "priority": 10, "idempotency_key": f"key-{number}"})
        self.service.allocate(self.dispatch, "pipe-a-b", "2026-09-26")
        gate = ReviewGate(scope="transfer.dispatch", entity_type="nomination", entity_id="nom-a", expected_version=2, payload={"transfer_id": "t-a", "lot_id": "lot-x"})
        ticket = self.service.access.request_review(self.dispatch, gate)["ticket_id"]
        from access_control.errors import AuthorizationFailed
        with self.assertRaises(AuthorizationFailed):
            self.service.access.decide_review(self.dispatch, ticket, True, "自己复核自己")

    def test_scenario_is_approved_and_replayed_by_input(self) -> None:
        self.quote(23, "98")
        self.service.add_inventory_lot(self.dispatch, {"lot_id": "lot-1", "facility_id": "field-a", "product": "crude", "grade": "PEAK_VALLEY", "quantity_mwh": "60000", "unit_cost_cny": "91", "received_at": "2026-09-24T06:00:00Z"})
        self.service.create_scenario(self.plan, {"scenario_id": "restart", "name": "机组检修恢复", "market_index_drop_percent": "9", "route_capacity_changes": {"pipe-a-b": "20"}, "demand_changes": {"field-a:crude": "-5"}})
        with self.assertRaises(Forbidden):
            self.service.approve_scenario(self.plan, "restart", 1)
        self.service.approve_scenario(self.risk, "restart", 1)
        first = self.service.run_scenario(self.plan, "restart", "2026-09-23")
        second = self.service.run_scenario(self.plan, "restart", "2026-09-23")
        self.assertFalse(first["replayed"])
        self.assertTrue(second["replayed"])
        self.assertEqual(first["run_id"], second["run_id"])

    def test_audit_chain_detects_tampering(self) -> None:
        self.assertTrue(self.service.audit_chain(self.audit)["valid"])
        self.connection.execute("UPDATE supply_audit_events SET payload_json='{}' WHERE event_id=1")
        self.assertFalse(self.service.audit_chain(self.audit)["valid"])

    def test_audit_history_still_searchable_by_original_actor(self) -> None:
        self.quote(23, "98")
        events = self.service.audit_events(self.audit, actor_id="plan")["events"]
        self.assertTrue(events)
        self.assertTrue(all(event["actor_id"] == "plan" for event in events))
        self.assertTrue(all(event["session_id"] for event in events))

    def test_revoked_session_gets_stable_error_immediately(self) -> None:
        app = JsonApplication(self.service)
        issued = self.service.access.issue_session("plan", label="extra")
        token = issued["token"]
        headers = {"Authorization": f"Bearer {token}"}
        self.assertEqual(app.handle("POST", "/facilities", headers, b'{"facility_id":"f-x","name":"x","kind":"storage","timezone":"Asia/Shanghai","capacity_mwh":"1"}').status, 201)
        # 交接班撤销会话
        self.service.access.revoke_session(self._security_ctx(), issued["session_id"], "交接班撤销")
        response = app.handle("POST", "/facilities", headers, b'{"facility_id":"f-y","name":"y","kind":"storage","timezone":"Asia/Shanghai","capacity_mwh":"1"}')
        self.assertEqual(response.status, 401)
        self.assertEqual(response.body["error"]["code"], "session_revoked")
        # 伪造或空令牌得到同样稳定的错误
        self.assertEqual(app.handle("POST", "/facilities", {"Authorization": "Bearer not-a-real-token"}, b"{}").body["error"]["code"], "session_revoked")

    def _security_ctx(self):
        self.service.create_user("sec", "安全员", "security_officer")
        token = self.service.access.issue_session("sec", label="test")["token"]
        return self.service.access.authenticate(token)

    def test_repeated_login_creates_distinct_trackable_sessions(self) -> None:
        first = self.service.access.issue_session("plan", label="shift-1")
        second = self.service.access.issue_session("plan", label="shift-2")
        self.assertNotEqual(first["token"], second["token"])
        self.assertNotEqual(first["session_id"], second["session_id"])
        sec = self._security_ctx()
        sessions = self.service.access.list_sessions(sec, "plan")
        self.assertEqual(len(sessions), 3)  # setUp 登录一次 + 重复登录两次，各自独立留痕

    def test_permission_change_takes_effect_at_effective_time(self) -> None:
        sec = self._security_ctx()
        # 给计划员追加 nomination.write，两小时后生效
        self.service.access.grant_permission(
            sec, "role", "planner", "nomination.write", "allow", "试运行扩权",
            effective_from="2026-09-24T10:00:00Z",
        )
        payload = {"nomination_id": "nom-future", "route_id": "pipe-a-b", "shipper_id": "shipper-future", "service_date": "2026-09-27", "requested_mwh": "100", "priority": 10, "idempotency_key": "key-future"}
        with self.assertRaises(Forbidden):
            self.service.submit_nomination(self.plan, payload)
        self.clock.advance(hours=3)
        fresh = self.login("plan")
        self.assertEqual(self.service.submit_nomination(fresh, payload)["state"], "submitted")

    def test_role_inheritance_and_deny_override(self) -> None:
        sec = self._security_ctx()
        # 班长岗位继承调度员，但显式 deny 送电申请权限
        self.service.access.define_role(sec, "lead_dispatcher", "调度班长", ["dispatcher"], "新增班长岗")
        self.service.create_user("lead", "班长", "lead_dispatcher")
        self.service.access.grant_permission(sec, "role", "lead_dispatcher", "transfer.write", "deny", "送电必须由专责调度员")
        lead = self.login("lead")
        self.assertTrue(lead.has("nomination.write"))
        self.assertFalse(lead.has("transfer.write"))

    def test_reassign_revokes_sessions_and_audit_reasons_recorded(self) -> None:
        sec = self._security_ctx()
        issued = self.service.access.issue_session("plan", label="old-role")
        result = self.service.access.reassign_user_role(
            sec, "plan", "auditor", "调岗到审计班组", self.service.apply_role
        )
        self.assertGreaterEqual(result["revoked_sessions"], 1)
        from access_control.errors import SessionRevoked
        with self.assertRaises(SessionRevoked):
            self.service.access.authenticate(issued["token"])
        # 旧会话的历史审计仍能按原操作者检索
        events = self.service.audit_events(self.audit, actor_id="plan")["events"]
        self.assertTrue(events)

    def test_state_survives_restart_with_inmemory_reopen(self) -> None:
        # 会话与授权全部落库：重新构造服务（模拟重启）后撤销状态仍然有效
        app = JsonApplication(self.service)
        issued = self.service.access.issue_session("plan", label="persist")
        sec = self._security_ctx()
        self.service.access.revoke_session(sec, issued["session_id"], "重启前撤销")
        reopened = SupplyService(self.connection, self.clock)
        with self.assertRaises(SessionRevoked):
            reopened.access.authenticate(issued["token"])

    def test_api_requires_bearer_token(self) -> None:
        app = JsonApplication(self.service)
        self.assertEqual(app.handle("GET", "/health").status, 200)
        response = app.handle("GET", "/quotes/summary/PEAK_VALLEY", {"X-Actor-Id": "plan"})
        self.assertEqual(response.status, 401)
        self.assertEqual(response.body["error"]["code"], "session_revoked")


if __name__ == "__main__":
    unittest.main()
