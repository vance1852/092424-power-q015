"""机组试验域的会话、岗位权限、准入决定两阶段复核与审计检索测试。"""

from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timezone
from pathlib import Path

from plant_science.api import JsonApplication
from plant_science.clock import FrozenClock
from plant_science.errors import Forbidden, InvalidState, Unauthorized
from plant_science.jsonio import load_json
from plant_science.service import TrialService


ROOT = Path(__file__).resolve().parents[1]


class TrialIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = TrialService(self.connection, self.clock)
        for user_id, position in (
            ("admin", "admin"),
            ("operator", "operator"),
            ("stat", "statistician"),
            ("approver", "approver"),
            ("auditor", "auditor"),
        ):
            self.service.create_user(user_id, user_id, position)
        self.protocol = load_json(ROOT / "fixtures" / "demo_protocol.json")
        self.rows = [
            json.loads(line)
            for line in (ROOT / "fixtures" / "demo_observations.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.service.register_robot("operator", "robot-a", "A 型", "厂商")
        self.service.register_build("operator", "build-a", "robot-a", "1.0", "b" * 64)
        self.service.publish_protocol("stat", self.protocol)
        self.service.create_batch("operator", "batch-a", "demo-delivery-v1", 1, "build-a")
        self.service.start_batch("operator", "batch-a", 1)
        self.service.import_observations("operator", "batch-a", "key-1", self.rows)
        self.service.seal_batch("stat", "batch-a", 2)

    def tearDown(self) -> None:
        self.connection.close()

    def _analyzed(self) -> dict:
        job = self.service.claim_job("worker", 30)
        return self.service.complete_job("worker", job["job_id"], "stat")

    def test_session_required_revoked_and_stable_error(self) -> None:
        app = JsonApplication(self.service)
        missing = app.handle("POST", "/robots", {}, b'{"robot_id":"x"}')
        self.assertEqual(missing.status, 401)
        self.assertEqual(missing.body["error"]["code"], "unauthorized")
        issued = self.service.issue_session("auditor")
        good = app.handle(
            "GET", "/batches/batch-a/report",
            {"Authorization": f"Bearer {issued['token']}"},
        )
        self.assertEqual(good.status, 200)
        self.service.revoke_session("admin", issued["session_id"], "交接班")
        revoked = app.handle(
            "GET", "/batches/batch-a/report",
            {"Authorization": f"Bearer {issued['token']}"},
        )
        self.assertEqual(revoked.status, 401)
        self.assertEqual(revoked.body["error"]["code"], "unauthorized")

    def test_duplicate_login_replaces_old_token(self) -> None:
        first = self.service.issue_session("operator")
        second = self.service.issue_session("operator")
        with self.assertRaises(Unauthorized):
            self.service.authenticate(first["token"])
        self.assertEqual(self.service.authenticate(second["token"])["user_id"], "operator")

    def test_position_change_revokes_sessions(self) -> None:
        issued = self.service.issue_session("operator")
        self.service.create_position("admin", "ops2", "试验二组", "operator")
        self.service.assign_position("admin", "operator", "ops2", None, "班组轮换")
        with self.assertRaises(Unauthorized):
            self.service.authenticate(issued["token"])

    def test_configurable_permission_grant_takes_effect_at_future_time(self) -> None:
        self.service.create_position("admin", "lead-ops", "试验组长", "operator")
        self.service.create_user("lead", "组长", "lead-ops")
        self.service.change_permission(
            "admin", "lead-ops", "batch.seal", "grant",
            "2026-09-25T00:00:00Z", "次日起可封批次",
        )
        with self.assertRaises(Forbidden):
            self.service._require("lead", "batch.seal")
        self.clock.advance(hours=17)
        self.assertTrue("batch.seal" in self.service._permissions(self.service._user("lead")))

    def test_decision_requires_two_parties_and_binds_revision(self) -> None:
        analysis = self._analyzed()
        requested = self.service.request_decision(
            "stat", "batch-a", analysis["analysis_id"], "approved", "满足规则"
        )
        # 发起者不能自审。
        with self.assertRaises(Forbidden):
            self.service.review_decision("stat", requested["approval_id"], True, "")
        confirmed = self.service.review_decision(
            "approver", requested["approval_id"], True, "准入确认"
        )
        self.assertEqual(confirmed["status"], "confirmed")
        approval = self.connection.execute(
            "SELECT * FROM approvals WHERE approval_id=?", (requested["approval_id"],)
        ).fetchone()
        self.assertEqual(approval["requested_by"], "stat")
        self.assertEqual(approval["reviewed_by"], "approver")
        self.assertEqual(approval["expected_revision"], 3)
        # 复核单一次性。
        with self.assertRaises(InvalidState):
            self.service.review_decision("approver", requested["approval_id"], True, "")

    def test_decision_confirmation_rechecks_business_version(self) -> None:
        analysis = self._analyzed()
        requested = self.service.request_decision(
            "stat", "batch-a", analysis["analysis_id"], "approved", "ok"
        )
        self.connection.execute(
            "UPDATE batches SET revision=revision+1 WHERE batch_id='batch-a'"
        )
        with self.assertRaises(InvalidState):
            self.service.review_decision("approver", requested["approval_id"], True, "")

    def test_history_searchable_by_actor_after_deactivation(self) -> None:
        self._analyzed()
        self.service.deactivate_user("admin", "stat", "统计岗轮换")
        events = self.service.audit_events("auditor", actor_filter="stat")["events"]
        self.assertTrue(any(e["event_type"] == "analysis.completed" for e in events))
        self.assertTrue(all(e["actor_id"] == "stat" for e in events))
        with self.assertRaises(Forbidden):
            self.service._user("stat")

    def test_sessions_survive_restart(self) -> None:
        issued = self.service.issue_session("auditor")
        restarted = TrialService(self.connection, self.clock)
        self.assertEqual(restarted.authenticate(issued["token"])["user_id"], "auditor")


if __name__ == "__main__":
    unittest.main()
