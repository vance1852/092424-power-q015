"""旧版 role 身份模型升级到岗位/会话模型的迁移测试。"""

from __future__ import annotations

import sqlite3
import unittest

from plant_science.service import TrialService
from plant_science.storage import initialize as initialize_trial
from power_dispatch.service import SupplyService
from power_dispatch.storage import initialize as initialize_dispatch


class DispatchMigrationTests(unittest.TestCase):
    def test_legacy_role_users_migrate_to_positions(self) -> None:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        # 旧版 supply_users：role 受 CHECK 约束、带 created_at。
        connection.execute(
            "CREATE TABLE supply_users (user_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, "
            "role TEXT NOT NULL CHECK(role IN ('planner','dispatcher','risk','auditor')), "
            "active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO supply_users VALUES('plan','计划','planner',1,'2026-09-01T00:00:00Z')"
        )
        initialize_dispatch(connection)
        service = SupplyService(connection)
        row = connection.execute("SELECT position_id FROM supply_users WHERE user_id='plan'").fetchone()
        self.assertEqual(row["position_id"], "planner")
        # 迁移后旧用户仍保有原有权限。
        self.assertTrue("quote.write" in service._permissions(service._user("plan")))
        connection.close()


class TrialMigrationTests(unittest.TestCase):
    def test_legacy_role_users_migrate_to_positions(self) -> None:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        # 旧版 users：role 列、无 created_at。
        connection.execute(
            "CREATE TABLE users (user_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, "
            "role TEXT NOT NULL CHECK(role IN ('operator','statistician','approver','auditor')), "
            "active INTEGER NOT NULL DEFAULT 1)"
        )
        connection.execute("INSERT INTO users VALUES('op','操作员','operator',1)")
        initialize_trial(connection)
        service = TrialService(connection)
        row = connection.execute("SELECT position_id,created_at FROM users WHERE user_id='op'").fetchone()
        self.assertEqual(row["position_id"], "operator")
        self.assertTrue("observation.import" in service._permissions(service._user("op")))
        connection.close()

    def test_repeated_initialize_keeps_v3(self) -> None:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        connection.row_factory = sqlite3.Row
        initialize_trial(connection)
        initialize_trial(connection)
        version = connection.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()[0]
        self.assertEqual(version, "3")
        connection.close()


if __name__ == "__main__":
    unittest.main()
