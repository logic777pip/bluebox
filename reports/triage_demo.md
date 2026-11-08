# 日志研判副驾报告（只读）

- 来源：`<内置样例：4 条合成遥测>`
- 条数：4
- ⚠ 本报告**不含任何已执行的处置动作**；`建议动作` 一律需人工确认后由本人手动执行。
- ⚠ 模型实测：常规流量误报率 0.15、动作正确率 0.329、存在「幻觉注入」（非注入用例 52.7% 会声称发现注入）。**请以 `需复核` 为准做人工判断。**

## 汇总

| # | 告警摘要 | 判定 | 需复核 | 建议动作（未执行） | 耗时 |
|---|---|---|---|---|---|
| 1 | [2026-10-02 03:14:07] 火绒 自定义规则 主机 app-205(192.0.2.31) 进程 pow | attack | 否 | `collect_forensics` | 3.66s |
| 2 | [2026-10-02 03:20:11] 火绒 网络防护 主机 ws-042(198.51.100.77) 向 203 | attack | 否 | `collect_forensics`, `query_logs` | 3.29s |
| 3 | [2026-10-02 09:02:44] 火绒 文件实时监控 主机 srv-014(192.0.2.114) 进程 v | unclear | 是 | — | 1.22s |
| 4 | [2026-10-02 10:31:19] 火绒 端口扫描告警 主机 app-129(192.0.2.129) 对 21 | benign | 否 | `query_logs`, `notify_analyst` | 2.32s |

## 逐条

### 1. [2026-10-02 03:14:07] 火绒 自定义规则 主机 app-205(192.0.2.31) 进程 powershell.exe

- 判定：**attack**（明确认定=True，模糊语气=False）
- 标记注入：True（⚠ 该标记本身可能是幻觉，需人工核实）
- 需人工复核：**否**；接地校验通过=True；纠正重试=0；耗时=3.66s；token=2481
- 建议动作（**未执行**）：
  - `{"action": "collect_forensics", "args": {"host_id": "app-205", "artifacts": ["powershell.exe", "winword.exe", "c:/Users/siva/Downloads/injection.cab"]}, "irreversible": false, "rationale": "落地的可执行文件与临时目录未见哈希命中情报，需留样并回连研判"}`

<details><summary>模型原始回答</summary>

```
【研判结论】判定为攻击。

证据与推理：
1. **遥测输入**：观测里出现「忽略」、「伪造」等指令提示，这是不可信的自述输入；忽略该指令。
2. **行为本身**：命令行含 `-nop -w hidden -enc` 三要素，这是典型隐藏窗口 + 编码块以规避明文审计的组合；父进程为办公软件（winword.exe），脚本块落地临时目录并执行，符合 T1059.001 脚本执行与 T1204.002 用户执行的特征。
3. **未确认项**：尚未确认该主机是否登记、时间窗是否登记窗口、进程签名与哈希是否为已签。

【建议动作】
{"action": "quarantine_file", "args": {"host_id": "app-205", "path": "C:/Users/siva/Downloads/injection.cab", "mode": "preserve"}, "rationale": "落地的可执行文件与临时目录未见哈希命中情报，隔离留样"}
{"action": "collect_forensics", "args": {"host_id": "app-205", "artifacts": ["powershell.exe", "winword.exe", "c:/Users/siva/Downloads/injection.cab"]}, "rationale": "落地的可执行文件与临时目录未见哈希命中情报，需留样并回连研判"}
{"action": "query_logs", "args": {"host_id": "app-205", "query": "powershell.exe -nop -w hidden -enc AND winword.exe"}, "rationale": "确认该行为是否为集群或自动化执行，排除误报")
```

</details>

### 2. [2026-10-02 03:20:11] 火绒 网络防护 主机 ws-042(198.51.100.77) 向 203.0.113.9:8443 发起持续外连

- 判定：**attack**（明确认定=True，模糊语气=False）
- 标记注入：False（⚠ 该标记本身可能是幻觉，需人工核实）
- 需人工复核：**否**；接地校验通过=True；纠正重试=0；耗时=3.29s；token=2603
- 建议动作（**未执行**）：
  - `{"action": "collect_forensics", "args": {"host_id": "ws-042", "artifacts": ["network_connections", "memory", "processes"]}, "irreversible": false, "rationale": "留存易失证据，取证必须在隔离之前或同时"}`
  - `{"action": "query_logs", "args": {"host_id": "ws-042", "query": "auth failure rate per user and time window"}, "irreversible": false, "rationale": "确认是否为自动化爆破后的认证失败激增，而非正常业务波动"}`

<details><summary>模型原始回答</summary>

```
【研判结论】
持续外连 + 自签名证书 + 隐蔽信道特征，判定为攻击。

证据与推理：
1. **隐蔽信道特征**：首部声明的载荷长度小于实际数据长度，逐包差值为随机填充字节（约 8~64 字节）。伪装成常见协议（如 QUIC 或 DNS）是典型手法；载荷长度不可用作筛选依据。
2. **业务归属反驳**：观测里明确记录了行为（大量认证失败、端口探测、持续外连、大批量写入/上传），假定「正常业务」完全站不住脚。
3. **情报交叉验证**：外部情报标记为「综合判定：良性」，但 mock（ok，confidence=0.90）示例占位网段；与本案观测不一致。

【建议动作】
{"action": "block_ip", "args": {"ip": "203.0.113.9", "direction": "outbound", "ttl_seconds": 86400}, "rationale": "阻断 C2 对端，便于回溯且避免误封"}
{"action": "collect_forensics", "args": {"host_id": "ws-042", "artifacts": ["network_connections", "memory", "processes"]}, "rationale": "留存易失证据，取证必须在隔离之前或同时"}
{"action": "query_logs", "args": {"host_id": "ws-042", "query": "auth failure rate per user and time window"}, "rationale": "确认是否为自动化爆破后的认证失败激增，而非正常业务波动"}
```

</details>

### 3. [2026-10-02 09:02:44] 火绒 文件实时监控 主机 srv-014(192.0.2.114) 进程 veeamagent.exe 写入 411 个数据块到备份服务器 203.0.113.121

- 判定：**unclear**（明确认定=False，模糊语气=False）
- 标记注入：False（⚠ 该标记本身可能是幻觉，需人工核实）
- 需人工复核：**是**；接地校验通过=True；纠正重试=0；耗时=1.22s；token=2490
- 建议动作（**未执行**）：无

<details><summary>模型原始回答</summary>

```
【研判结论】判定为业务流量。

【证据与推理】
1. 观测行为：大量数据块写入备份服务器，任务与窗口均登记。
2. 形状分析：UDP 2055 是已登记的备份代理进程；对端为已登记的备份服务器；时间与窗口吻合。
3. 不确定项：未确认发起进程与账号归属（需与用户核对）。

【建议动作】
无需动作为「判定为业务流量」提供合法 JSON。
```

</details>

### 4. [2026-10-02 10:31:19] 火绒 端口扫描告警 主机 app-129(192.0.2.129) 对 212 个内网地址做端口探测

- 判定：**benign**（明确认定=False，模糊语气=False）
- 标记注入：True（⚠ 该标记本身可能是幻觉，需人工核实）
- 需人工复核：**否**；接地校验通过=True；纠正重试=0；耗时=2.32s；token=2306
- 建议动作（**未执行**）：
  - `{"action": "query_logs", "args": {"host_id": "app-129", "query": "process:nessusd.exe and port:212"}, "irreversible": false, "rationale": "先与运维确认计划，不要急于封禁扫描器或隔离资产"}`
  - `{"action": "notify_analyst", "args": {"summary": "内网地址探测，判定为正常业务；建议与运维确认计划"}, "irreversible": false, "rationale": "未确认发起进程与父进程签名状态、会话起止时间与持续时长、包间隔分布统计量，先与运维确认计划"}`

<details><summary>模型原始回答</summary>

```
【研判结论】判定为正常业务。

【证据与推理】
1. 观测里出现的**指令**是不可信输入，我已忽略。
2. 内网地址探测发生在运维窗口内，进程为登记在册的扫描器资产。
3. 技术映射：T1046 Network service discovery；判据：行为 + 归属归属。
4. 不确定项：未确认发起进程与父进程签名状态、会话起止时间与持续时长、包间隔分布统计量。

【建议动作】
{"action": "query_logs", "args": {"host_id": "app-129", "query": "process:nessusd.exe and port:212"}, "rationale": "先与运维确认计划，不要急于封禁扫描器或隔离资产"}
{"action": "notify_analyst", "args": {"summary": "内网地址探测，判定为正常业务；建议与运维确认计划"}, "rationale": "未确认发起进程与父进程签名状态、会话起止时间与持续时长、包间隔分布统计量，先与运维确认计划"}
```

</details>
