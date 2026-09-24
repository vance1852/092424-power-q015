# 电厂调度与能源分析与机组分析准入服务

本项目是一套可直接运行的 Python 服务端系统，用于记录电力市场基准电价、电厂与变电站设施、送出线路、燃料批次、发电计划和负荷情景，并保留机组巡检传感器统计分析准入流程。系统面向电价连续波动、关键送电送出线路恢复、电量调度和现场设备验证同时发生的运营环境，让调度、风险和审计人员在同一个 SQLite 数据库中获得可追溯结论。

供应调度子域提供以下能力：

- 电力市场基准电价按结算日和来源修订登记，历史版本不会被覆盖；
- 电厂、储罐、终端与储能站设施建档，送出线路保存日能力、在途时间和损耗规则；
- 送出线路停运或降容事件按 UTC 时间区间生效，日分配会计算实际可用能力；
- 燃料批次保留电源类型、牌号、数量、单位成本和接收时间，可计算加权燃料库存成本；
- 交易方提名支持载荷级幂等、优先级分配、燃料库存扣减和在途交接；
- 负荷情景保存电价变化、送出线路能力变化和需求变化，审批后产生可重放的确定性结果；
- 关键写操作进入哈希串联审计日志，可离线验证事件顺序和内容完整性。

机组分析准入子域位于 `plant_science` 包，负责机组巡检传感器的设备构建登记、不可变校准协议、测点分片导入、异常测点复核、统计任务租约、分析准入决定和审计报告。该子域不连接传感器硬件，只处理已经结构化的校准记录。

## 目录

- `src/power_dispatch/`：电价、设施、送出线路、燃料库存、提名、负荷情景、HTTP API 与离线验收；
- `src/plant_science/`：机组巡检传感器校准与统计分析准入；
- `fixtures/`：机组分析准入演示协议和结构化测点；
- `tests/`：核心规则、错误边界、API 和端到端验收测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 无第三方运行依赖

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

测试使用内存数据库和临时目录，不访问公网，也不会启动常驻服务。

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m power_dispatch.acceptance --workspace .
```

该命令会在内存数据库中登记六个结算日的峰谷电价，创建电厂、终端和送出线路，完成燃料库存入账、提名分配、送电及负荷情景分析，最后输出一行 JSON。成功时退出码为 `0` 且 `status` 为 `ok`。

机组分析准入子域也保留独立验收入口：

```bash
PYTHONPATH=src python3 -m plant_science.acceptance --workspace .
```

## HTTP 服务

```bash
PYTHONPATH=src python3 -m power_dispatch.api --database power_dispatch.sqlite3 --host 127.0.0.1 --port 8080
```

健康检查为 `GET /health`。除健康检查、`POST /sessions` 和首次引导开户外，请求都通过
`Authorization: Bearer <token>` 携带会话令牌。令牌由 `POST /sessions`（请求体 `user_id`）
签发，数据库只保存令牌的 SHA-256 哈希。令牌缺失、无效、过期或被撤销统一返回
`401 unauthorized` 稳定错误码。可用接口覆盖电价、设施、送出线路、停运事件、燃料批次、
提名、能力分配、送电、负荷情景和审计链。服务重启后，SQLite 中的业务状态、岗位权限、
会话与撤销状态和历史版本都会继续保留。

## 身份、岗位权限与交接班

身份模型在两个子域上对称实现，不再使用写死的角色集合：

- **岗位继承与可配置权限**：岗位（`positions`）可指定父岗位，子岗位沿继承链获得父岗位
  权限，并可用 `grant`/`deny`/`revoke` 在本岗位覆盖；拒绝优先于继承的授予。每条权限
  变更都是不可变记录，带 `effective_from`（支持未来定时生效）和必填的审计 `reason`，
  解析时只统计不晚于当前时间的变更。
- **会话签发与撤销**：`POST /sessions` 签发带有效期的令牌；重复登录会自动作废旧会话并
  记录 `replaced_by` 替换链。管理员可撤销单个会话（`POST /sessions/revoke`）或某用户
  全部会话（`POST /users/{id}/sessions/revoke`，用于交接班）；换岗和停用用户也会立即
  撤销其现有会话。撤销、过期、无效一律返回同一个 `401 unauthorized`。
- **敏感操作二次复核**：送电（`/transfers/request` → `/approvals/{id}/confirm`）、
  负荷情景审批（`/scenarios/{id}/approval-request` → 复核确认）和机组分析准入决定
  （`/decisions/request` → `/decisions/{id}/review`）都必须由发起者之外、持有对应复核
  权限的另一人确认；复核单记录发起者、复核者、业务版本（`expected_revision`）和请求
  内容摘要，确认时重新校验业务版本，版本已漂移则拒绝执行。
- **审计可追溯**：权限变更、会话签发/撤销、复核发起/确认全部进入审计。可通过
  `GET /audit/events?actor_id=...` 按原操作者检索历史，用户停用或换岗后历史仍可追溯；
  调度子域的这些事件同样进入哈希串联审计链。
- **首个管理员**：全新数据库可用一次 `POST /bootstrap/users` 免令牌建立首位 `admin`
  用户，系统一旦存在用户该入口即关闭；此后开户走 `POST /users`（需 `user.manage`）。

