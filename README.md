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
- `src/access_control/`：可配置岗位与继承、生效授权、会话签发/撤销、二次复核票据与访问审计；
- `fixtures/`：机组分析准入演示协议和结构化测点；
- `tests/`：核心规则、错误边界、API、访问控制和端到端验收测试。

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

健康检查为 `GET /health`。除健康检查和引导用的 `POST /users` 外，所有接口都必须携带
`Authorization: Bearer <token>` 会话令牌；旧的自报 `X-Actor-Id` 不再被信任。

### 身份、岗位与会话

- `POST /sessions`：按用户编号签发会话令牌。令牌本身不落库（只存 SHA-256 摘要），
  重复登录产生相互独立、各自留痕的会话；服务重启后授权状态仍然有效。
- `POST /sessions/revoke`、`POST /sessions/revoke-user`：交接班时撤销单个或某操作者
  全部会话。撤销即时生效，旧令牌再请求一律得到稳定错误码 `session_revoked`（HTTP 401），
  令牌不存在、伪造、过期使用同一错误码，不泄露令牌是否存在过。
- `POST /users/reassign`：换岗，更新岗位并撤销其全部会话，必须填写审计原因。

### 可配置权限与岗位继承

岗位、授权不再写死在代码里，出厂岗位仅在首次初始化时种子化：

- `GET/POST /roles`：定义岗位与父岗位（多继承，继承链可多级展开，禁止循环继承）；
- `POST /grants`：对岗位或具体用户授予/收回（allow/deny）权限，必须带 `reason`，
  可用 `effective_from` 指定未来生效时间，到点自动生效；deny 优先于继承来的 allow；
- `POST /grants/revoke/{id}`：软撤销授权（保留原因与历史）；`GET /grants` 可含已撤销记录。

出厂岗位新增 `security_officer`（安全员）持有 `access.*` 管理权限。

### 敏感操作二次复核

送电（`POST /transfers`）和机组分析准入决定（`POST /decisions`）是敏感操作：

1. 操作者 `POST /reviews` 发起复核，票据绑定操作者会话、业务主体、业务版本
   （提名/分析版本号）和请求内容摘要；
2. 另一名持 `review.approve` 权限的操作者（不得是申请人本人）在有效期内
   `POST /reviews/{id}/decision` 批准或拒绝；
3. 操作者在正式请求中携带一次性 `review_ticket_id`。票据与业务版本或请求内容
   不一致、已过期、已使用、不属于本人时返回稳定错误码 `review_rejected`；
   完全没有票据时返回 `review_required`。票据消费与业务写入在同一事务内，
   校验失败整体回滚，票据不会被误消耗。

### 审计

- `GET /audit/events?actor_id=...`：业务审计可按**原操作者**检索，历史操作者字段
  不随换岗改写；每条事件记录会话号与复核票据号。
- `GET /audit/chain`：业务事件哈希链校验；`GET /access/chain`、`GET /access/audit`
  为访问控制（登录、授权、换岗、复核）的独立哈希链与检索。

两个子域（`power_dispatch`、`plant_science`）共用无第三方依赖的 `access_control` 包，
可与业务表共存在同一个 SQLite 文件中；旧库重启会幂等补全新增审计列。
