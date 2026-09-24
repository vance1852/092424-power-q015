from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime, timezone

from access_control import AccessManager, ReviewGate
from access_control.errors import (
    AuthorizationFailed,
    Conflict,
    NotFound,
    ReviewRejected,
    ReviewRequired,
    SessionRevoked,
    ValidationFailed,
)
from power_dispatch.clock import FrozenClock
from power_dispatch.service import SupplyService


class AccessControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = SupplyService(self.connection, self.clock)
        for user_id, role in (
            ("sec", "security_officer"),
            ("plan", "planner"),
            ("dispatch", "dispatcher"),
            ("risk", "risk"),
        ):
            self.service.create_user(user_id, user_id, role)
        self.sec = self.login("sec")
        self.plan = self.login("plan")
        self.dispatch = self.login("dispatch")
        self.risk = self.login("risk")

    def login(self, user_id: str):
        token = self.service.access.issue_session(user_id, label="t")["token"]
        return self.service.access.authenticate(token)

    def tearDown(self) -> None:
        self.connection.close()

    def test_grant_requires_reason_and_supports_future_effective_time(self) -> None:
        with self.assertRaises(ValidationFailed):
            self.service.access.grant_permission(
                self.sec, "role", "planner", "inventory.write", "allow", "   "
            )
        self.service.access.grant_permission(
            self.sec, "role", "planner", "inventory.write", "allow", "临时授权",
            effective_from="2026-09-24T12:00:00Z",
        )
        self.assertFalse(self.plan.has("inventory.write"))  # 认证快照在 08:00，尚未生效
        self.clock.advance(hours=5)
        self.assertTrue(self.login("plan").has("inventory.write"))

    def test_revoked_grant_is_removed_immediately_and_keeps_history(self) -> None:
        grant_id = self.service.access.grant_permission(
            self.sec, "role", "planner", "inventory.write", "allow", "临时授权",
        )["grant_id"]
        self.assertTrue(self.login("plan").has("inventory.write"))
        self.service.access.revoke_grant(self.sec, grant_id, "试运行结束收回")
        self.assertFalse(self.login("plan").has("inventory.write"))
        # 撤销是软删除，历史仍可查且带原因
        revoked = [g for g in self.service.access.list_grants(self.sec, include_revoked=True) if g["grant_id"] == grant_id][0]
        self.assertIsNotNone(revoked["revoked_at"])
        self.assertEqual(revoked["revoke_reason"], "试运行结束收回")
        with self.assertRaises(Conflict):
            self.service.access.revoke_grant(self.sec, grant_id, "再次撤销")

    def test_role_inheritance_transitive_and_deny_wins_with_cycle_guard(self) -> None:
        self.service.access.define_role(self.sec, "lead", "班长", ["planner"], "新增班长")
        self.service.access.define_role(self.sec, "chief", "总值长", ["lead"], "新增总值长")
        self.service.create_user("chief1", "总值长", "chief")
        chief = self.login("chief1")
        self.assertTrue(chief.has("quote.write"))       # 继承自 planner
        self.assertTrue(chief.has("scenario.run"))      # 多级继承
        self.service.access.grant_permission(self.sec, "role", "chief", "scenario.run", "deny", "禁用运行")
        self.assertFalse(self.login("chief1").has("scenario.run"))  # deny 优先
        with self.assertRaises(ValidationFailed):
            self.service.access.define_role(self.sec, "planner", "计划员", ["chief"], "制造循环")

    def test_user_level_grant_overrides_role(self) -> None:
        self.service.access.grant_permission(
            self.sec, "user", "plan", "scenario.run", "deny", "该员工暂停运行权限"
        )
        self.assertFalse(self.login("plan").has("scenario.run"))
        other = self.login("dispatch")
        self.assertFalse(other.has("scenario.run"))

    def test_session_revocation_is_immediate_stable_and_restart_proof(self) -> None:
        issued = self.service.access.issue_session("plan", label="extra")
        self.service.access.revoke_session(self.sec, issued["session_id"], "交接班")
        with self.assertRaises(SessionRevoked):
            self.service.access.authenticate(issued["token"])
        # 重启：新建 manager 指向同一数据库，撤销仍然生效
        restarted = AccessManager(self.connection, self.service._load_user, self.clock)
        with self.assertRaises(SessionRevoked):
            restarted.authenticate(issued["token"])
        # 批量撤销
        a = self.service.access.issue_session("dispatch", label="s1")
        b = self.service.access.issue_session("dispatch", label="s2")
        result = self.service.access.revoke_user_sessions(self.sec, "dispatch", "整班交接")
        self.assertEqual(result["revoked"], 3)  # setUp 的 1 个 + 2 个新会话
        for token in (a["token"], b["token"]):
            with self.assertRaises(SessionRevoked):
                self.service.access.authenticate(token)

    def test_reassign_changes_role_and_revokes_sessions(self) -> None:
        old = self.service.access.issue_session("plan", label="before")
        result = self.service.access.reassign_user_role(
            self.sec, "plan", "auditor", "轮岗", self.service.apply_role
        )
        self.assertEqual(result["role"], "auditor")
        with self.assertRaises(SessionRevoked):
            self.service.access.authenticate(old["token"])
        self.assertEqual(self.connection.execute("SELECT role FROM supply_users WHERE user_id='plan'").fetchone()[0], "auditor")

    def test_review_flow_binds_operator_version_and_payload_one_shot(self) -> None:
        gate = ReviewGate(
            scope="transfer.dispatch", entity_type="nomination", entity_id="nom-9",
            expected_version=2, payload={"transfer_id": "t9", "lot_id": "lot-9"},
        )
        ticket_id = self.service.access.request_review(self.dispatch, gate)["ticket_id"]
        # 未完成复核不能消费
        with self.assertRaises(ReviewRequired):
            self.service.access.consume_review(self.dispatch, ticket_id, gate)
        # 申请人不能自复核
        with self.assertRaises(AuthorizationFailed):
            self.service.access.decide_review(self.dispatch, ticket_id, True, "自批")
        self.service.access.decide_review(self.risk, ticket_id, True, "同意")
        # 版本不一致 -> 拒绝
        changed = ReviewGate(
            scope="transfer.dispatch", entity_type="nomination", entity_id="nom-9",
            expected_version=3, payload={"transfer_id": "t9", "lot_id": "lot-9"},
        )
        with self.assertRaises(ReviewRejected):
            self.service.access.consume_review(self.dispatch, ticket_id, changed)
        # 票据不属于别的操作者
        with self.assertRaises(ReviewRejected):
            self.service.access.consume_review(self.plan, ticket_id, gate)
        # 一致 -> 成功消费，且只能一次
        self.service.access.consume_review(self.dispatch, ticket_id, gate)
        with self.assertRaises(ReviewRejected):
            self.service.access.consume_review(self.dispatch, ticket_id, gate)

    def test_rejected_and_expired_ticket_cannot_be_consumed(self) -> None:
        gate = ReviewGate("transfer.dispatch", "nomination", "nom-1", 2, {"transfer_id": "t", "lot_id": "l"})
        ticket_id = self.service.access.request_review(self.dispatch, gate, ttl_seconds=60)["ticket_id"]
        self.service.access.decide_review(self.risk, ticket_id, False, "资料不全")
        with self.assertRaises(ReviewRejected):
            self.service.access.consume_review(self.dispatch, ticket_id, gate)
        # 过期票据不能批准
        gate2 = ReviewGate("transfer.dispatch", "nomination", "nom-2", 2, {"transfer_id": "t2", "lot_id": "l2"})
        expired = self.service.access.request_review(self.dispatch, gate2, ttl_seconds=10)["ticket_id"]
        self.clock.advance(seconds=11)
        with self.assertRaises(ReviewRejected):
            self.service.access.decide_review(self.risk, expired, True, "迟来的批准")

    def test_access_audit_chain_and_search_by_original_actor(self) -> None:
        self.service.access.grant_permission(self.sec, "role", "planner", "inventory.write", "allow", "审计原因示例")
        events = self.service.access.audit_events(self.sec, actor_id="sec")
        self.assertTrue(events)
        self.assertTrue(all(event["actor_id"] == "sec" for event in events))
        chain = self.service.access.audit_chain(self.sec)
        self.assertTrue(chain["valid"])
        # 篡改可被哈希链检出
        self.connection.execute("UPDATE access_audit_events SET payload_json='{}' WHERE event_id=1")
        self.assertFalse(self.service.access.audit_chain(self.sec)["valid"])

    def test_unknown_session_and_user_listing_boundaries(self) -> None:
        with self.assertRaises(NotFound):
            self.service.access.revoke_session(self.sec, "ses_does_not_exist", "x")
        # 普通岗位无权管理会话
        with self.assertRaises(AuthorizationFailed):
            self.service.access.list_sessions(self.plan)


if __name__ == "__main__":
    unittest.main()
