# PDCERF 动作层 — 接口与工具参考

> 本文是 `actions/` 包的**设计依据与接口契约**。
> 一句话：把「模型会写动作 JSON」变成「系统真的能做这些动作」，并且**什么时候能做**由 PDCERF 阶段决定。

---

## 1. 为什么要这一层

在本层出现之前，这个项目的链路是：

```
告警 → RAG/情报 → 模型 → schema 校验 → 建议动作 JSON → （没有下文）
```

`cyber_range/red_blue_loop.py` 里的执行点写着：

```python
# 真实执行点：此处对接 SOAR / EDR / 防火墙 API（部署时按环境实现）
```

于是有三个说不清的问题：

| 问题 | 后果 |
| --- | --- |
| 动作**怎么落地**没说 | 无法证明系统具备动作能力，只能证明它会写 JSON |
| 动作**什么时候该做**没说 | 模型可能「先隔离再取证」，销毁易失证据；或「没检测就重建」 |
| 动作**做完拿到什么**没说 | 没有观测回灌，模型无法据实调整下一步（ReAct 闭环缺失） |

本层补的正是这三件事：**适配器**（怎么落地）、**阶段机**（什么时候做）、**观测回执**（做完看到什么）。

---

## 2. 分层与职责

```
security/action_schema.py     R3 白名单 + R5 两阶段确认      ← 唯一安全闸门（谁都不能绕过）
actions/pdcerf.py             PDCERF 阶段机 + 案例状态        ← 什么时候该做什么
actions/registry.py           动作 → 工具描述 / JSON Schema   ← 对外的接口定义
actions/adapters/             soar（真实）/ filesystem（沙箱）/ sim（仿真）
actions/executor.py           放行检查 → 路由 → 审计          ← 唯一放行点
actions/toolkit.py            目录 / 协议解析 / 观测回执      ← 面向模型
actions/loop.py               PDCERF 驱动的工具调用闭环       ← 端到端行为
actions/cli.py                命令行（run / loop / doctor / selftest）
```

**设计取舍**：阶段元数据放在 `actions/`，而**不**塞进 `security/action_schema.py`。
前者是"业务编排知识"（会随流程改），后者是"安全基线"（改动需评审）。混在一起会让安全基线
变成频繁改动的文件，评审就形同虚设。

---

## 3. PDCERF 阶段机

| 阶段 | 中文 | 目标 | 完成判据 | 前置 |
| --- | --- | --- | --- | --- |
| `P` | 准备 | 确认资产归属、回滚点、备份可用性 | 掌握责任人/角色，且存在可用快照或备份 | — |
| `D` | 检测 | 把告警收敛为可复现的事实 | 有明确受影响资产、时间线、可追溯证据 | — |
| `C` | 遏制 | 限制影响面 | 攻击者失去通路，业务影响已知 | **D** |
| `E` | 根除 | 移除持久化与恶意产物，修补入口 | 持久化/恶意文件/凭据已清除 | **C** |
| `R` | 恢复 | 受控恢复业务并验证无残留 | 业务恢复、隔离解除、完整性校验通过 | **C** |
| `F` | 复盘 | 归档证据、沉淀规则与 IOC | 证据链归档、规则更新、IOC 登记 | **D** |

### 两条关键规则

1. **前置约束只针对处置类动作**（`irreversible=True` 或风险 `high/critical`）。
   只读动作（`query_logs` / `asset_lookup` / `verify_integrity` …）**不受阶段限制** ——
   补充检测、复盘回看任何阶段都允许，否则会逼着模型"为了合规而不查"。

2. **阶段会自动推进，但不会自动跳跃**：成功执行 `isolate_host` 会把案例从 `D` 推到 `C`；
   若前置未满足，`advance()` 抛 `PhaseError` 且案例保持原阶段（动作本身仍如实记录）。

### 动作 → 阶段映射（34 个）

| 阶段 | 动 作 |
| --- | --- |
| P (5) | `asset_lookup` `snapshot_host` `verify_backup` `raise_log_level` `query_logs`* |
| D (10) | `query_logs` `query_flow` `enrich_ioc` `collect_timeline` `capture_pcap` `collect_forensics` `notify_analyst` `asset_lookup`* `raise_log_level`* `archive_evidence`* |
| C (7) | `isolate_host` `block_ip` `block_domain` `revoke_session` `restrict_account` `disable_account` `collect_forensics`* |
| E (9) | `kill_process` `quarantine_file` `remove_persistence` `delete_file` `reset_credential` `patch_vulnerability` `rebuild_host` `snapshot_host`* `disable_account`* |
| R (7) | `restore_host` `restore_from_backup` `restart_service` `lift_isolation` `verify_integrity` `verify_backup`* `rebuild_host`* |
| F (9) | `close_case` `archive_evidence` `write_postmortem` `update_detection_rule` `publish_ioc` `collect_timeline`* `notify_analyst`* `verify_integrity`* `query_logs`* |

`*` = 次要阶段（首项为主阶段，决定前置判定与自动推进）。
用 `python -m actions.cli phases` 可随时打印这张表。

---

## 4. 执行器的 7 道检查（全部 fail-closed）

```
① R3 schema 白名单       未知动作 / 未知字段 / 非法参数 → denied
② 案例动作预算           超过 max_actions_per_case → denied（防失控循环）
③ 保护对象               不可逆动作打到受保护资产 → denied（不可被 auto_confirm 绕过）
④ PDCERF 前置            处置类动作阶段前置不满足 → denied
⑤ R5 两阶段确认          不可逆动作：无签名 → pending_confirmation（不执行）
   ...并让确认校验**先于**去重 —— 确认令牌重放是安全事件，不能被 duplicate 掩盖
⑥ 幂等去重               同案例同参数重复调用 → duplicate（返回首次结果）
⑦ 适配器路由             真实执行模式下不允许静默降级到仿真靶场 → unavailable
```

### 保护对象为什么必须是硬拦截

`protected_hosts: [dc-01, jump-01, backup-01]` + `protected_ips` + `protected_accounts`。

理由来自本项目已实测的失败模式：隐蔽信道评测里 **`block_fabricated=0` 但"封成受害主机自己的 IP" = 0.417**，
良性用例误伤业务 **0.425** —— 误伤最重的几个家族全是**合法业务**（会议软件定长帧、运维跳板机、HTTPS）。
在真实环境里，这类动作的代价是**封掉自己的跳板机/域控/备份服务器**，往往比攻击本身更难恢复。
所以保护对象在**策略层硬拦**，而不是靠提示词祈求模型别这么干。

---

## 5. 适配器契约

| 适配器 | `real_effects` | 支持动作数 | 说明 |
| --- | --- | --- | --- |
| `soar` | ✅ 是 | 全部（可配 `capabilities`） | POST 到真实 SOAR/EDR/防火墙；密钥只从环境变量读（R4） |
| `filesystem` | ✅ 是（限沙箱内） | 5 | 证据归档 / 复盘报告 / 沙箱内样本隔离 |
| `sim` | ❌ 否 | 34（全部） | 内存靶场，确定性、无副作用 |

**诚实性约定**（比"能跑通"更重要）：

- `sim` 的结果一律带 `simulated: true`，且 `observations` 前缀 `[仿真靶场]`。
- 真实执行模式下若只有 `sim` 可用、且 `allow_sim_fallback=false` → 返回 **`unavailable`**，
  绝不"假装执行成功"。
- 靶场对**未知主机/账号**返回失败（`failed`）而不是编造观测 —— 与 `grounding_check` 抗幻觉同源。
- `verify_backup` 在没有快照时**明确说"没有可用快照"**，而不是回一句"备份正常"。

### SOAR 请求契约

```http
POST {base_url}/{prefix}/{action_name}
Authorization: Bearer <SOAR_API_KEY 环境变量>
{"action":"isolate_host","args":{...},"case_id":"INC-1","phase":"C","dry_run":false}
```

响应：`{"ok":true,"observations":"...","output":{...}}` 或 `{"ok":false,"error":"..."}`。
重试策略遵循 R2：**只有幂等动作**（`idempotent_actions` 列出的检索类）才重试，
写操作一律不自动重试 —— 否则"封禁失败"会被重试成"重复封禁"。

---

## 6. 面向模型的工具接口

两条协议并存，因为部署形态不同：

**① 文本协议（默认，微调模型走这条）** —— 模型学的是：

````
```action
{"action": "query_logs", "args": {"host_id": "fin-ws-07", "query": "rundll32"}}
```
````

`tool_catalog_text()` 按 PDCERF 阶段分组下发工具目录，可用 `only_trained=True`
**只下发微调模型实际见过的 10 个动作**——否则会出现"写得出动作名、但从未学过该格式"的假能力。

**② OpenAI function-calling** —— `openai_tools()` 直接生成 `tools` 数组，
适配 llama-server（`--jinja` + Qwen 模板）。

`parse_tool_calls()` 把两种协议（外加 `<tool_call>`）归一成 `(name, args)`，
非法动作**不会被解析成调用**（从源头杜绝"绕过执行器"）。

---

## 7. 工具调用闭环

```
        ┌──────────── 注入当前阶段指引 + 工具目录 ────────────┐
        │                                                      │
   模型输出 ──┬─ 有工具调用 → ActionExecutor 放行 → 执行 → 观测回灌 ─┘
              └─ 无工具调用 → 收敛为最终研判
```

三种终止条件，都必须**显式暴露原因**：

| `stopped_reason` | 含义 |
| --- | --- |
| `final_answer` | 模型认为不需要再观测 |
| `awaiting_confirmation` | 出现待确认的不可逆动作 → 立即停轮（防止反复提交刷屏） |
| `no_progress` | 本步所有结果都是重复/拒绝/不可用 → 继续只是烧步数 |
| `max_steps_wrapped` | 达到步数上限后强制收敛 |

`no_progress` 是本项目实测教训的产物：stub 后端会一直提同一个 `query_logs`，
执行器正确地判为 `duplicate`，但循环仍会空转到 `max_steps` ——
**"模型没进展"和"模型在做事"必须能被区分开**，否则延迟与审计双双失真。

---

## 8. 命令行

```bash
python -m actions.cli phases                    # PDCERF 阶段机总览
python -m actions.cli list --phase C            # 按阶段列工具
python -m actions.cli schema --format openai    # 生成 tools JSON
python -m actions.cli doctor                    # 策略 + 适配器健康状态
python -m actions.cli selftest                  # 安全语义自检（38 项）

# 执行动作（默认 dry-run；--execute 才产生副作用）
python -m actions.cli run --action query_logs \
    --args-file actions/examples/args_query_logs.json --execute --case-file logs/case.json

# 不可逆动作：先挂起、再带 HMAC 签名确认
python -m actions.cli run --action block_ip \
    --args-file actions/examples/args_block_ip.json --execute
python -m actions.cli run --action block_ip --args-file ... --execute \
    --confirm-proposal <id> --confirm-signature <hmac>

# 工具调用闭环
python -m actions.cli loop --alert-file actions/examples/alert_fin_ws.txt --backend stub
```

> ⚠ **PowerShell 会剥掉 `--args` 里的双引号**（`{"host_id":"x"}` → `{host_id:x}`）。
> 请一律用 `--args-file`。CLI 遇到坏 JSON 会给出这条提示，而不是抛 traceback。
> 中文输出建议加 `--out <文件>` 写 UTF-8 文件后再查看。

---

## 9. 自检覆盖（38 项，`python -m actions.cli selftest`）

不是"代码能跑"，而是**安全语义是否成立**：

- 元数据：34 个动作的阶段/风险标注齐全；JSON Schema 与白名单一致
- 仿真靶场：覆盖全部动作，且**每个动作都有 `_do_*` 实现**（防能力虚标）
- R3：未知动作 / 未知字段 / 枚举越界 / 路径穿越 / CVE 格式 / ID 正则 → 全部被拒
- 策略：保护主机、保护 IP 拦截；只读动作不受前置限制
- PDCERF：`E` 之前必须先 `C`；`C` 之前必须先 `D`；阶段自动推进
- R5：必须两阶段确认；签名通过后执行；**重放被拒**；**确认前后篡改被拒**；重复提交不重复登记提案
- 幂等与审计：去重生效；审计落盘；**被拒的不可逆动作在审计里仍标记 `irreversible=true`**
- 沙箱：路径逃逸被拒；隔离前哈希不匹配被拒；隔离保留原件
- 闭环：stub 后端跑通；待确认即停轮；无进展提前终止

---

## 10. 安全边界（勿回退）

- 本层是**防御方工具**：只做检测、取证、遏制、根除、恢复、复盘。
- `remove_persistence` 的 `mechanism` 枚举只用于**枚举并清除**持久化，不涉及任何创建；
  不提供"布置持久化/免杀/横向移动"的能力，也不提供"剥离任意模型安全性"的接口。
- 不接入真实环境时，`sim` 恒为默认；接真实环境必须显式改 `adapters.soar.enabled: true`
  并自行提供凭据（环境变量，不硬编码）。
- 保护对象清单（域控/跳板机/备份机/服务账号）**必须**按真实资产清单填写后再启用真实执行。
