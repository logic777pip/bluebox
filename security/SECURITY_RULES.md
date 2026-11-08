# 安全编码规则（蓝队项目专用）

本目录是仓库的**安全基线**。所有模块、脚本、以及模型输出到执行的链路都必须遵守。

## 规则清单

| # | 规则 | 实现位置 |
| --- | --- | --- |
| R1 | 日志输出必须脱敏，禁止输出完整 IP、Token、密码、邮箱、内网凭据 | `security/sanitize.py` → `mask_text()` / `get_logger()` |
| R2 | 网络请求必须设置超时与重试上限 | `_http_post()`（`red_blue_loop.py`）、`HF_HUB_DOWNLOAD_TIMEOUT`（`data_prep.py`） |
| R3 | 模型输出必须经 schema 校验后才能执行任何动作 | `security/action_schema.py` → `validate_action()`；唯一放行点是 `actions/executor.py` |
| R4 | 禁止在代码中硬编码密钥或凭据 | 用环境变量 + `os.environ.get`，缺失即失败（fail-closed） |
| R5 | 不可逆操作（删除 / 写入 / 网络配置变更）必须两阶段确认 | `security/action_schema.py` → `TwoPhaseGuard` |

## R1 脱敏细则

- IPv4 / IPv6 → `<IP_n>`
- 邮箱 → `<EMAIL_n>`
- 密钥类 Token（`sk-*`、`AKIA*`、`ghp_*`、JWT、Bearer、长十六进制）→ `<SECRET_n>`
- `password=`、`passwd:`、`pwd=` 等键值对 → `<PASSWORD>`
- URL 内嵌凭据 `scheme://user:pass@host` → `scheme://<CRED>@host`
- 脱敏是**幂等**的：同一实体在一条文本里始终映射到同一个占位符。

> 训练数据（`data_prep.py`）默认对凭据/邮箱强制脱敏，IP 可通过 `--no-mask-ip` 开关
> 按需保留（用于学习"如何分析内网 IP 分布"这类任务，此时 IP 应已在源数据中被替换为 RFC5737 文档地址段）。

## R2 超时与重试

- 默认 `timeout=30s`，`retries=3`，指数退避（1s/2s/4s）。
- 只对**幂等**请求重试（GET、推理请求）。写操作不自动重试，交由两阶段确认。

## R3 动作 schema

动作白名单（默认拒绝，未知动作直接抛错）。共 **34** 个，按 PDCERF 阶段分组，
阶段归属/风险等级/目标参数在 `actions/pdcerf.py`：

```
P 准备：asset_lookup, snapshot_host, verify_backup, raise_log_level
D 检测：query_logs, collect_forensics, notify_analyst,
        enrich_ioc, query_flow, collect_timeline, capture_pcap
C 遏制：block_ip, isolate_host, disable_account,
        block_domain, revoke_session, restrict_account
E 根除：kill_process, quarantine_file, delete_file, remove_persistence,
        reset_credential, patch_vulnerability, rebuild_host
R 恢复：restore_host, restore_from_backup, restart_service,
        lift_isolation, verify_integrity
F 复盘：close_case, archive_evidence, write_postmortem,
        update_detection_rule, publish_ioc
```

每个动作都有必填字段、类型、取值范围、**风险等级**与**不可逆标记**。

> ⚠ 前 10 个动作（`query_logs` … `restore_host`）是微调模型实际学过的，**不得改名或删除**；
> 新增动作是纯追加（`actions/pdcerf.py:TRAINED_ACTIONS` 记录了已训练集合）。

### 执行链路（唯一放行点：`actions/executor.py`）

```
① R3 schema 白名单  ② 案例动作预算  ③ 保护对象（不可逆动作不得打到域控/跳板机/备份机）
④ PDCERF 前置（C←D, E←C, R←C, F←D；仅约束处置类动作，只读动作不受限）
⑤ R5 两阶段确认（先于去重：确认令牌重放属安全事件，不能被 duplicate 掩盖）
⑥ 幂等去重  ⑦ 适配器路由（真实执行模式下不允许静默降级到仿真靶场）
```

结果状态：`ok` / `dry_run` / `pending_confirmation` / `denied` / `unavailable` / `duplicate` / `failed`。
审计落 `logs/action_audit.jsonl`（R1 脱敏，含保真字段：即使动作被拒，也按动作本身属性记 `irreversible`）。

全量安全语义自检：`python -m actions.cli selftest`（当前 38/38 通过）。

## R4 凭据

```python
# 正确
token = os.environ.get("OLLAMA_API_TOKEN")          # 可为 None（本地 Ollama 无需鉴权）
if required and not token:
    raise RuntimeError("缺少环境变量 OLLAMA_API_TOKEN")

# 禁止
token = "sk-xxxxxxxx"                                # ← 代码评审直接拒绝
```

## R5 两阶段确认

```
阶段一：agent 产出 proposal（写入 logs/pending/<id>.json，状态 pending）
阶段二：人工/策略引擎返回确认 token（HMAC-SHA256，TTL 默认 300s，单次有效）
        → 校验通过后才真正执行；否则丢弃并记录审计事件
```

实现见 `TwoPhaseGuard.propose()` / `TwoPhaseGuard.confirm()`。
即使确认通过，`red_blue_loop.py` 默认仍以 `--dry-run` 方式执行，真实执行需显式 `--execute`。
`actions/executor.py` 同样默认 `dry_run: true`；`allow_auto_confirm` **仅限隔离靶场/自测**，
生产环境必须为 `false`，否则两阶段确认形同虚设。
