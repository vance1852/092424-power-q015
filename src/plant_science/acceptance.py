"""完整产品流程的离线验收入口。"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from access_control import ReviewGate

from .jsonio import load_json
from .service import TrialService
from .storage import connect, inspect_schema


def _ctx(service: TrialService, user_id: str):
    """用持久化会话换取认证上下文，等价于一次真实登录。"""

    token = service.access.issue_session(user_id, label="acceptance")["token"]
    return service.access.authenticate(token)


def run(workspace: Path) -> dict[str, object]:
    fixtures = workspace / "fixtures"
    protocol = load_json(fixtures / "demo_protocol.json")
    observation_rows = [
        json.loads(line)
        for line in (fixtures / "demo_observations.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    with tempfile.TemporaryDirectory(prefix="robot-trials-") as temporary:
        database = Path(temporary) / "foundation.sqlite3"
        connection = connect(database)
        try:
            service = TrialService(connection)
            service.create_user("operator-1", "测试操作员", "operator")
            service.create_user("stat-1", "统计负责人", "statistician")
            service.create_user("approver-1", "分析准入审批人", "approver")
            service.create_user("auditor-1", "审计人员", "auditor")
            operator = _ctx(service, "operator-1")
            stat = _ctx(service, "stat-1")
            approver = _ctx(service, "approver-1")
            auditor = _ctx(service, "auditor-1")
            service.register_robot(operator, "robot-a", "A 型人形传感器", "示例厂商")
            service.register_build(operator, "build-a1", "robot-a", "1.0.0", "a" * 64)
            service.publish_protocol(stat, protocol)
            service.create_batch(operator, "batch-demo", protocol["protocol_id"], protocol["version"], "build-a1")
            service.start_batch(operator, "batch-demo", 1)
            imported = service.import_observations(
                operator, "batch-demo", "demo-import-1", observation_rows
            )
            service.seal_batch(stat, "batch-demo", 2)
            job = service.claim_job("worker-1", lease_seconds=60)
            if job is None:
                raise RuntimeError("未能领取分析任务")
            analysis = service.complete_job("worker-1", job["job_id"], stat)
            decision_value = "approved" if analysis["result"]["conclusion"] == "pass" else "rejected"

            # 准入决定是敏感操作：审批人申请 -> 统计负责人第二人复核 -> 持一次性票据执行。
            review = service.access.request_review(approver, ReviewGate(
                scope="analysis.decision",
                entity_type="analysis",
                entity_id=str(analysis["analysis_id"]),
                expected_version=job["batch_revision"],
                payload={
                    "batch_id": "batch-demo",
                    "decision": decision_value,
                    "reason": "离线验收决定",
                },
            ))
            service.access.decide_review(stat, review["ticket_id"], True, "复核分析输入与结论一致")
            service.decide(
                approver, "batch-demo", analysis["analysis_id"], decision_value,
                "离线验收决定", review["ticket_id"],
            )
            report = service.report(auditor, "batch-demo")
            schema = inspect_schema(connection)
            access_audit = service.access.audit_chain(auditor)
        finally:
            connection.close()
    if schema["missing_tables"] or schema["schema_version"] != "3":
        raise RuntimeError("SQLite 基础结构检查失败")
    return {
        "status": "ok",
        "protocol": f"{protocol['protocol_id']}@{protocol['version']}",
        "observation_count": imported["inserted"],
        "analysis_id": analysis["analysis_id"],
        "input_sha256": analysis["input_sha256"],
        "conclusion": analysis["result"]["conclusion"],
        "decision": report["decision"]["decision"],
        "event_count": len(report["events"]),
        "access_audit": access_audit,
        "schema": schema,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="执行校准数据基础工具的离线自检")
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    result = run(args.workspace.resolve())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
