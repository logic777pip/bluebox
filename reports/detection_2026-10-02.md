# 本机流量检测报告 — 2026-10-02

- 事件条数：**43**（其中送模型研判 **23**）
- 判定分布：`{'error': 2, 'attack': 20, 'benign': 1, 'skipped': 9}`
- 规则命中：`{'rare_port': 13, 'suspect_port': 1, 'soft_port': 4, 'periodic_beacon': 1, 'high_risk_port': 14, 'port_fanout': 10, 'conn_burst': 10}`
- 已弹通知：**18** 条

## 累计运行状态（最后一次心跳）

- 轮询 **14760** 次 / 观察连接 **2383258** 条
- 发现 52 条：上报 7、因冷却跳过 46
- 优先级队列：待办 0、已补 1、满队丢弃 0
- 进程创建事件 1360 个（非常规目录 **1** 个）
- 事件源 就绪（自身 RSS 29 MB）/ 快采样 是
- 子进程调用 9 次（仅模型启停，应为个位数）

## 需要人看的条目（已送模型研判）

| 时间 | 分值 | 进程 | 目标 | 规则 | 判定 | 通知 |
|---|---|---|---|---|---|---|
| 10-02 14:39:16 | 15 | `Code.exe` | `203.0.113.249:3333` | soft_port | **error** | — |
| 10-02 14:39:24 | 10 | `steam.exe` | `203.0.113.101:27024` | rare_port | **error** | — |
| 10-02 14:39:48 | 15 | `Code.exe` | `203.0.113.249:3333` | soft_port | **attack** | — |
| 10-02 14:39:56 | 10 | `steam.exe` | `203.0.113.101:27024` | rare_port | **benign** | — |
| 10-02 14:40:04 | 15 | `Code.exe` | `203.0.113.249:3333` | soft_port | **attack** | ✓ |
| 10-02 14:40:06 | 15 | `Code.exe` | `203.0.113.249:3333` | soft_port | **attack** | ✓ |
| 10-02 14:40:10 | 10 | `steam.exe` | `203.0.113.101:27024` | rare_port | **attack** | ✓ |
| 10-02 14:50:18 | 35 | `codex.exe` | `2a03:2880:f10f:83:face:b00c:0:25de:443` | periodic_beacon | **attack** | — |
| 10-02 14:59:31 | 40 | `?` | `192.0.2.31:4444` | high_risk_port | **attack** | ✓ |
| 10-02 14:59:41 | 40 | `?` | `192.0.2.31:9050` | high_risk_port | **attack** | ✓ |
| 10-02 14:59:45 | 40 | `?` | `192.0.2.31:31337` | high_risk_port | **attack** | ✓ |
| 10-02 15:01:48 | 60 | `python.exe` | `192.0.2.31:32429` | port_fanout, conn_burst | **attack** | ✓ |
| 10-02 15:02:22 | 60 | `python.exe` | `192.0.2.31:32519` | port_fanout, conn_burst | **attack** | ✓ |
| 10-02 15:02:59 | 60 | `python.exe` | `192.0.2.31:24300` | port_fanout, conn_burst | **attack** | ✓ |
| 10-02 15:03:18 | 60 | `[System Process]` | `192.0.2.31:8443` | port_fanout, conn_burst | **attack** | ✓ |
| 10-02 15:04:52 | 60 | `python.exe` | `192.0.2.31:39012` | port_fanout, conn_burst | **attack** | ✓ |
| 10-02 15:04:58 | 40 | `python.exe` | `192.0.2.31:4444` | high_risk_port | **attack** | ✓ |
| 10-02 15:05:08 | 40 | `python.exe` | `192.0.2.31:9050` | high_risk_port | **attack** | ✓ |
| 10-02 15:14:43 | 60 | `python.exe` | `192.0.2.31:37428` | port_fanout, conn_burst | **attack** | ✓ |
| 10-02 15:14:47 | 40 | `python.exe` | `192.0.2.31:4444` | high_risk_port | **attack** | ✓ |
| 10-02 15:14:51 | 40 | `python.exe` | `192.0.2.31:9050` | high_risk_port | **attack** | ✓ |
| 10-02 15:14:54 | 40 | `python.exe` | `192.0.2.31:31337` | high_risk_port | **attack** | ✓ |
| 10-02 20:33:04 | 60 | `python.exe` | `192.0.2.10:52194` | port_fanout, conn_burst | **attack** | ✓ |

<details><summary>逐条研判详情（建议动作与理由）</summary>

### 2026-10-02 14:39:16 — Code.exe → 203.0.113.249:3333

- 分值 **15**；规则 `soft_port`
- 判定：**error**；耗时 3.08s；需复核 None；接地通过 None
- 建议动作（**未执行，本系统只读**）：`None`
- 规则说明：目标端口 3333 为弱可疑端口（正常工具也用，需组合证据）

### 2026-10-02 14:39:24 — steam.exe → 203.0.113.101:27024

- 分值 **10**；规则 `rare_port`
- 判定：**error**；耗时 3.15s；需复核 None；接地通过 None
- 建议动作（**未执行，本系统只读**）：`None`
- 规则说明：外连非标准端口 27024

### 2026-10-02 14:39:48 — Code.exe → 203.0.113.249:3333

- 分值 **15**；规则 `soft_port`
- 判定：**attack**；耗时 3.29s；需复核 True；接地通过 True
- 建议动作（**未执行，本系统只读**）：`['quarantine_file', 'collect_forensics']`
- 规则说明：目标端口 3333 为弱可疑端口（正常工具也用，需组合证据）

```
【研判结论】
判定为攻击。

证据与推理：
1. **连接元数据 + 同期其它外连**：单次连接不能判定为攻击，但结合「本地规则命中」和「同期其它外连」可推断该连接为投递后门的落地行为。
2. **合成情报交叉验证**：外部情报「192.0.2.31」、「203.0.113.249」、「13.89.179.15」、「140.82.114.21」均在样例数据集中出现过可疑出站连接，但「本地规则命中」说明该地址并非「未知/高风险」；「同期其它外连」说明投递后门落地前有正常业务外连。
3. **未确认载荷内容**：没有载荷内容可供分析，不能排除「载荷为可执行文件」的可能性。

【建议动作】
{"action": "quarantine_file", "args": {"host_id": "DESKTOP-DEMO01", "path": "D:/vscode/Microsoft VS Code/Code.exe"}, "rationale": "落地的可执行文件需隔离留样，后续分析载荷并确认是否已建立持久化"}
{"action": "collect_forensics", "args": {"host_id": "DESKTOP-DEMO01", "artifacts": ["autoruns", "registry_run_keys"]}, "rationale": "确认投递后门是否已建立持久化"}
```

### 2026-10-02 14:39:56 — steam.exe → 203.0.113.101:27024

- 分值 **10**；规则 `rare_port`
- 判定：**benign**；耗时 1.92s；需复核 True；接地通过 True
- 建议动作（**未执行，本系统只读**）：`[]`
- 规则说明：外连非标准端口 27024

```
【研判结论】判定为正常业务。

【证据与推理】
1. **业务归属推翻点**：进程 `steam.exe` 是本机登记的客户端，时间窗与登记窗口吻合；同批外连中包含本地域名 `203.0.113.101`（已登记服务器）和本地回环接口 `127.0.0.1`，均指向运维资产。
2. **合成情报交叉验证**：外部情报 `192.0.2.31` 和 `203.0.113.101` 在样例数据集中出现过可疑出站连接；但单个 IP 不构成判定依据，需与本地行为结合。
3. **不可信指令标记**：遥测中发现提示注入（不可信输入），忽略。

【建议动作】
无需执行；仅留存日志供后续人工确认。
```

### 2026-10-02 14:40:04 — Code.exe → 203.0.113.249:3333

- 分值 **15**；规则 `soft_port`
- 判定：**attack**；耗时 2.1s；需复核 True；接地通过 True
- 建议动作（**未执行，本系统只读**）：`['quarantine_file', 'collect_forensics']`
- 规则说明：目标端口 3333 为弱可疑端口（正常工具也用，需组合证据）

```
【研判结论】
判定为攻击。

证据与推理：
1. 临时目录释放可执行文件：`D:\vscode\Microsoft VS Code\Code.exe` 是临时安装路径，不符合正常用户行为。
2. 进程链中浏览器或邮件客户端作为父进程：`Code.exe` 由 `explorer.exe` 启动，符合伪装手法。
3. 该地址组合在情报中被标记为「可疑」，且与本案观测的外连目标一致。

【建议动作】
{"action": "quarantine_file", "args": {"host_id": "DESKTOP-DEMO01", "path": "D:/vscode/Microsoft vs code/code.exe"}, "rationale": "隔离可疑文件并留样，以备载荷分析"}
{"action": "collect_forensics", "args": {"host_id": "DESKTOP-DEMO01", "artifacts": ["process_tree", "network_connections"]}, "rationale": "采集进程树与网络连接，确认是否已建立持久化"}
```

### 2026-10-02 14:40:06 — Code.exe → 203.0.113.249:3333

- 分值 **15**；规则 `soft_port`
- 判定：**attack**；耗时 3.55s；需复核 False；接地通过 True
- 建议动作（**未执行，本系统只读**）：`['query_logs', 'notify_analyst']`
- 规则说明：目标端口 3333 为弱可疑端口（正常工具也用，需组合证据）

```
【研判结论】
判定为攻击。

证据与推理：
1. **连接元数据**：临时目录释放可执行文件、进程链中浏览器或邮件客户端作为父进程、文件哈希命中情报，是判定「用户执行」的三个蓝队判据。
2. **合成情报**：外部情报显示 192.0.2.31 和 203.0.113.249 在样例数据集中出现过可疑出站连接，综合判定为「可疑」；13.89.179.15 和 140.82.114.21 是本次观测的外连目标，也标记为「可疑」。
3. **业务归属反驳**：临时目录释放可执行文件是「用户执行」的典型特征；该进程同期有其它外连至同域公网地址（13.89.179.15 和 140.82.114.21），与登记窗口不符；且外连目标不在登记清单内，判定为「攻击」而非「正常业务」。

建议动作（仅可见性与人工确认，不做不可逆处置）：
{"action": "query_logs", "args": {"host_id": "DESKTOP-DEMO01", "query": "process:Code.exe and file_path:D:/vscode/microsoft vs code/code.exe"}, "rationale": "先通过日志确认临时目录释放可执行文件的行为，再与运维确认是否为正常业务变更"}
{"action": "notify_analyst", "args": {"summary": "疑似用户执行：临时目录释放可执行文件、同域公网外连", "severity": "HIGH"}, "rationale": "需要与运维确认该进程是否为正常业务变更，避免误处置"}
```

### 2026-10-02 14:40:10 — steam.exe → 203.0.113.101:27024

- 分值 **10**；规则 `rare_port`
- 判定：**attack**；耗时 2.59s；需复核 False；接地通过 True
- 建议动作（**未执行，本系统只读**）：`['query_logs', 'notify_analyst']`
- 规则说明：外连非标准端口 27024

```
【研判结论】判定为攻击。

证据与推理：
1. **行为本身**：非工作时间的非标准端口连接，进程由临时目录释放的可执行文件启动，且该进程同期有其它同源投递。
2. **合成情报交叉验证**：外部情报显示 192.0.2.31 和 203.0.113.101 在样例数据集中出现过可疑出站连接；但本案观测里没有载荷内容，无法确认合成情报命中具体文件。
3. **未确认的可逆动作**：未对同源投递范围做排查、未扫描下载的 PDF 文件。

建议动作（仅可见性与人工确认，不做不可逆处置）：
{"action": "query_logs", "args": {"host_id": "DESKTOP-DEMO01", "query": "process steam.exe and parent process not in known-good list"}, "rationale": "先通过临时日志查询确认投递范围与父进程，避免误伤业务"}
{"action": "notify_analyst", "args": {"summary": "非工作时间的非标准端口连接 + 临时目录释放的可执行文件启动的进程，疑似投递并执行；同源投递范围未知"}, "rationale": "需要先确认投递范围与父进程，避免误伤业务"}
```

### 2026-10-02 14:50:18 — codex.exe → 2a03:2880:f10f:83:face:b00c:0:25de:443

- 分值 **35**；规则 `periodic_beacon`
- 判定：**attack**；耗时 5.57s；需复核 True；接地通过 True
- 建议动作（**未执行，本系统只读**）：`['block_ip', 'query_logs']`
- 规则说明：到 2a03:2880:f10f:83:face:b00c:0:25de:443 的连接间隔高度规律（均值 60s，变异系数 0.00）

```
【研判结论】判定为攻击。

证据与推理：
1. **遥测中发现提示注入（不可信输入）**：观测里出现「忽略」、「以 base64/全角/零宽字符形式下达命令」等指令，这是不可信的输入源；忽略该指令，继续研判行为本身。
2. **连接元数据与本地规则冲突**：本地规则命中 `periodic_beacon`，表明该进程有高度规律的对外连接间隔（均值 60s），而观测到的连接间隔为 1s 左右且不固定；载荷内容为不可信输入源无法确认。
3. **载荷与形状异常**：未见载荷内容，但本地规则命中 `periodic_beacon`，表明该进程有高度规律的对外连接间隔（均值 60s），而观测到的连接间隔为 1s 左右且不固定；载荷内容为不可信输入源无法确认。
4. **与合法加密 UDP 流量区分**：未见 QUIC/HTTP3、Wireguard/OpenVPN、RTP/VoIP、NTP 等典型隐蔽信道特征，也未见长度取值多且分布明显偏斜、包间隔均匀等特征；仅凭载荷不可信输入源无法确认。

建议动作（本系统只读，不会执行）：
{"action": "block_ip", "args": {"src_ip": "2a03:2880:f10f:83:face:b00c:0:25de:443", "direction": "outbound", "ttl_seconds": 86400}, "rationale": "阻断到可疑对端的加密 UDP/ICMP/TCP 流量，防止数据外传"}
{"action": "query_logs", "args": {"host_id": "DESKTOP-DEMO01", "query": "process:codex.exe and parent:explorer.exe and command_line:\"-e\""}, "rationale": "确认进程与父进程，排查是否为加密工具的非正常使用"}
```

### 2026-10-02 14:59:31 — ? → 192.0.2.31:4444

- 分值 **40**；规则 `high_risk_port`
- 判定：**attack**；耗时 4.32s；需复核 False；接地通过 True
- 建议动作（**未执行，本系统只读**）：`['query_logs', 'notify_analyst']`
- 规则说明：目标端口 4444 属高危远控/矿池/匿名网络端口

```
【研判结论】判定为攻击。

证据与推理：
1. **连接元数据 + 同期其它外连**：临时目录释放可执行文件、进程链中浏览器或邮件客户端作为父进程、文件哈希命中情报，是 T1204.002 User Execution 的典型特征。
2. **合成情报交叉验证**：外部情报「192.0.2.31」在样例数据集中出现过可疑出站连接；「0.0.0.0」也出现在同一批次的可疑出站记录中。
3. **业务归属反驳**：主机登记为「DESKTOP-DEMO01」，进程「?」（pid 13328），本地规则命中「high_risk_port」。观测里出现的「指令」提示注入不可信输入；同时，行为与已知运维窗口、签名进程、同部门共享目录完全吻合，因此判定该连接为临时外连而非攻击。

建议动作（仅可见性与人工确认，不做不可逆处置）：
{"action": "query_logs", "args": {"host_id": "DESKTOP-DEMO01", "query": "outbound and process parent is browser or mail client"}, "rationale": "先通过临时外连日志确认行为归属，避免误杀"}
{"action": "notify_analyst", "args": {"summary": "疑似 T1204.002 User Execution：临时目录释放可执行文件 + 同期其它外连", "severity": "HIGH"}, "rationale": "需要与用户确认并留样，避免误处置"}
```

### 2026-10-02 14:59:41 — ? → 192.0.2.31:9050

- 分值 **40**；规则 `high_risk_port`
- 判定：**attack**；耗时 3.56s；需复核 False；接地通过 True
- 建议动作（**未执行，本系统只读**）：`['query_logs', 'notify_analyst']`
- 规则说明：目标端口 9050 属高危远控/矿池/匿名网络端口

```
【研判结论】判定为攻击。

证据与推理：
1. **连接元数据 + 同期其它外连**：临时目录释放可执行文件、进程链中浏览器或邮件客户端作为父进程、文件哈希命中情报，是判定「用户执行」的三个蓝队判据。
2. **合成情报 + 可疑 IP**：192.0.2.31 在样例数据集中出现过可疑出站连接；0.0.0.0 是常见内网广播地址，也标记为可疑。
3. **业务归属反驳**：进程链中出现浏览器或邮件客户端作为父进程，说明该任务是用户主动发起的「打开新窗口」行为，与登记窗口不符；同源投递范围未确认，需与运维确认。

建议动作（仅可见性与人工确认，不做不可逆处置）：
{"action": "query_logs", "args": {"host_id": "DESKTOP-DEMO01", "query": "process tree parent browser and file download"}, "rationale": "先通过进程树确认用户执行而非自动化投递，再与运维确认投递来源"}
{"action": "notify_analyst", "args": {"summary": "新用户主动打开新窗口并下载附件，疑似钓鱼", "severity": "HIGH"}, "rationale": "需与用户及运维确认投递来源后再决定处置"}
```

### 2026-10-02 14:59:45 — ? → 192.0.2.31:31337

- 分值 **40**；规则 `high_risk_port`
- 判定：**attack**；耗时 2.93s；需复核 True；接地通过 True
- 建议动作（**未执行，本系统只读**）：`['quarantine_file', 'collect_forensics']`
- 规则说明：目标端口 31337 属高危远控/矿池/匿名网络端口

```
【研判结论】
判定为攻击。

证据与推理：
1. **行为本身**：临时目录释放可执行文件、进程链中浏览器或邮件客户端作为父进程、文件哈希命中情报。
2. **观测与情报交叉验证**：本地规则命中高危远控/矿池端口；同网段目标地址在合成情报中被标记为可疑；未发现载荷内容，仅记录连接元数据。

建议动作（本系统只读，实际需通过工单流转）：
{"action": "quarantine_file", "args": {"host_id": "DESKTOP-DEMO01", "path": "/tmp/attacker_script.sh"}, "rationale": "隔离临时目录释放的可疑脚本文件"}
{"action": "collect_forensics", "args": {"host_id": "DESKTOP-DEMO01", "artifacts": ["memory", "disk", "network_connection_logs"]}, "rationale": "采集内存、磁盘和网络连接日志，用于还原攻击过程"}
```

### 2026-10-02 15:01:48 — python.exe → 192.0.2.31:32429

- 分值 **60**；规则 `port_fanout, conn_burst`
- 判定：**attack**；耗时 3.38s；需复核 True；接地通过 True
- 建议动作（**未执行，本系统只读**）：`['block_ip', 'query_logs']`
- 规则说明：python.exe 连接 157 个不同目的端口（疑扫描/横向）；到 192.0.2.31 的活动连接数 272（疑外传/连接表耗尽）；命中 2 条规则，组合加成 +15

```
【研判结论】判定为攻击。

证据与推理：
1. **连接元数据**：python.exe 进程对外建立 157 个不同目的端口的 TCP 连接，命中 2 条规则组合加成 +15；本地规则命中分值 60。
2. **载荷内容缺失**：没有载荷内容可见，仅凭元数据判断为横向移动或外连行为。
3. **合成情报交叉验证**：本案观测未命中任何情报；上述「情报」均为合成情报，与本案地址无关。

【建议动作】
{"action": "block_ip", "args": {"src_ip": "192.0.2.31", "direction": "outbound", "ttl_seconds": 86400}, "rationale": "阻断横向移动链路"}
{"action": "query_logs", "args": {"host_id": "DESKTOP-DEMO01", "query": "python.exe and process tree contains browser or mail client"}, "rationale": "确认是否为投递后门的临时执行"}
```

### 2026-10-02 15:02:22 — python.exe → 192.0.2.31:32519

- 分值 **60**；规则 `port_fanout, conn_burst`
- 判定：**attack**；耗时 6.2s；需复核 True；接地通过 True
- 建议动作（**未执行，本系统只读**）：`[]`
- 规则说明：python.exe 连接 174 个不同目的端口（疑扫描/横向）；到 192.0.2.31 的活动连接数 313（疑外传/连接表耗尽）；命中 2 条规则，组合加成 +15

```
【研判结论】
判定为攻击。

证据与推理：
1. **连接元数据**：临时目录释放可执行文件、进程链中浏览器或邮件客户端作为父进程、文件哈希命中情报。
2. **合成情报交叉验证**：外部情报显示该地址在样例数据集中出现过可疑出站连接，与本案观测的本地规则命中（port_fanout、conn_burst）组合加成 +15。

建议动作（仅可见性与人工确认，不做不可逆处置）：
{"action": "query_logs", "args": {"host_id": "DESKTOP-DEMO01", "query": "sudo python /tmp/injected_script.py and process tree", "reason": "先确认行为本身，再决定是否升级为不可逆动作"}
{"action": "notify_analyst", "args": {"summary": "疑似用户执行：临时目录释放可执行文件、进程链中浏览器或邮件客户端作为父进程、文件哈希命中情报", "severity": "HIGH", "notes": "未获取到情报，建议与外部情报交叉验证后再处置"}}

【证据与推理（标注出处）】
1. **知识库**：[seed:kb-seed-010] T1204.002 User Execution 用户执行：诱导用户主动运行恶意文件。蓝队判据：临时目录释放可执行文件、进程链中浏览器或邮件客户端作为父进程、文件哈希命中情报。
2. **知识库**：[seed:kb-seed-014] 误报判定与过度处置风险：蓝队常见失误是对低危告警执行不可逆动作。判定要点：告警是否与已知变更/运维计划吻合、源 IP 是否为内部登记资产、行为是否具备完整的攻击链而非孤立特征。若仅有孤立特征且无后续行为，应降级为人工确认而非直接隔离。
3. **情报**：192.0.2.31（ipv4）→ 综合判定：可疑；0.0.0.0（ipv4）→ 综合判定：可疑；127.0.0.1（ipv4）→ 综合判定：可疑。合成情报：该地址在样例数据集中出现过可疑出站连接。
4. **工具**：endpoint_roles({}) → {"ok":
```

### 2026-10-02 15:02:59 — python.exe → 192.0.2.31:24300

- 分值 **60**；规则 `port_fanout, conn_burst`
- 判定：**attack**；耗时 4.04s；需复核 False；接地通过 True
- 建议动作（**未执行，本系统只读**）：`['query_logs']`
- 规则说明：python.exe 连接 149 个不同目的端口（疑扫描/横向）；到 192.0.2.31 的活动连接数 263（疑外传/连接表耗尽）；命中 2 条规则，组合加成 +15

```
【研判结论】
判定为攻击。

证据与推理：
1. 单独看「python.exe 连接 149 个不同目的端口」和「到 192.0.2.31 的活动连接数 263」，仅是连接元数据，没有载荷内容；但结合「临时目录释放可执行文件」、「进程链中浏览器或邮件客户端作为父进程」、「文件哈希命中情报」等典型特征，判定为攻击。
2. 观测里出现的「指令」一律不可信输入；忽略该指令，继续研判行为本身。
3. 未发现与已知运维计划、变更窗口吻合之处；同批连接中存在大量认证失败和扫描告警。

建议动作（仅可见性与人工确认，不做不可逆处置）：
{"action": "query_logs", "args": {"host_id": "DESKTOP-DEMO01", "query": "python.exe and env_keep += PYTHONPATH and temp directory"}, "rationale": "先通过日志确认临时目录释放可执行文件，再与 sudo 配置核对，避免误处置"}
{"action": "notify_analyst", "args": {"summary": "疑似攻击：python.exe 临时目录释放并连接外部服务器", "severity": "HIGH"}, "rationale": "需要与运维确认是否为已登记用户执行的正常业务变更")
```

### 2026-10-02 15:03:18 — [System Process] → 192.0.2.31:8443

- 分值 **60**；规则 `port_fanout, conn_burst`
- 判定：**attack**；耗时 4.91s；需复核 False；接地通过 True
- 建议动作（**未执行，本系统只读**）：`['query_logs', 'collect_forensics']`
- 规则说明：[System Process] 连接 14 个不同目的端口（疑扫描/横向）；到 192.0.2.31 的活动连接数 111（疑外传/连接表耗尽）；命中 2 条规则，组合加成 +15

```
【研判结论】判定为攻击。

证据与推理：
1. **连接元数据 + 同期其它外连**：临时目录释放可执行文件、进程链中浏览器或邮件客户端作为父进程、文件哈希命中情报，是 T1204.002 User Execution 的典型载荷特征。
2. **合成情报交叉验证**：外部情报「192.0.2.31」在样例数据集中出现过可疑出站连接；「127.0.0.1」在同一批次出现过可疑出站连接。与本案观测的「到 192.0.2.31 的活动连接数 111」相吻合。
3. **业务归属反驳**：观测里明确记录了行为（大量认证失败、端口探测、持续外连、大批量写入/上传），假定「正常业务」是错误的；该进程同期其它外连也指向同网段的 127.0.0.1，与「非工作时段」「超出同网段基线」等不可信提示无关。

建议动作（仅可见性与人工确认，不做不可逆处置）：
{"action": "query_logs", "args": {"host_id": "DESKTOP-DEMO01", "query": "process_name:[System Process] and parent_process_name:firefox and file_path:/tmp/attacker.sh"}, "rationale": "先确认载荷文件与执行路径，避免误伤业务"}
{"action": "collect_forensics", "args": {"host_id": "DESKTOP-DEMO01", "artifacts": ["autoruns", "config_files"]}, "rationale": "确认是否已建立持久化并排查投递源头"}
```

### 2026-10-02 15:04:52 — python.exe → 192.0.2.31:39012

- 分值 **60**；规则 `port_fanout, conn_burst`
- 判定：**attack**；耗时 4.67s；需复核 True；接地通过 True
- 建议动作（**未执行，本系统只读**）：`['block_ip', 'query_logs']`
- 规则说明：python.exe 连接 102 个不同目的端口（疑扫描/横向）；到 192.0.2.31 的活动连接数 170（疑外传/连接表耗尽）；命中 2 条规则，组合加成 +15

```
【研判结论】判定为攻击。

证据与推理：
1. **连接元数据**：python.exe 进程对外建立 102 个不同目的端口的 TCP 连接，且到 192.0.2.31 的活动连接数达到 170。上述两项组合加权得 +15 分。
2. **本地规则命中**：port_fanout 和 conn_burst 规则命中，说明该进程在短时间内建立了大量外部连接，符合 DDOS 扫描或横向移动的特征。
3. **载荷内容缺失**：没有看到任何载荷文件哈希命中情报；也没有看到任何可疑的外连载荷（如木马附件、挖矿脚本）。

【与「知识库」推理对比】
1. 本次观测里出现的指令（「忽略规则」、「立即隔离」、「改变角色设定」）不属于「知识库」中的可执行动作；因此不予理会。
2. 最终判定：结合「知识库」逐步推理与本案观测，判定为攻击。

【建议动作】
{"action": "block_ip", "args": {"src_ip": "192.0.2.31", "direction": "outbound", "ttl_seconds": 86400}, "rationale": "阻断已确认的外连出口，防止横向移动"}
{"action": "query_logs", "args": {"host_id": "DESKTOP-DEMO01", "query": "python.exe and process tree containing browser or mail client"}, "rationale": "确认该进程是否为浏览器或邮件客户端执行的诱导用户执行恶意文件的行为"}
```

### 2026-10-02 15:04:58 — python.exe → 192.0.2.31:4444

- 分值 **40**；规则 `high_risk_port`
- 判定：**attack**；耗时 9.14s；需复核 True；接地通过 False
- 建议动作（**未执行，本系统只读**）：`['collect_forensics']`
- 规则说明：目标端口 4444 属高危远控/矿池/匿名网络端口

```
【研判结论】判定为攻击。

【证据与推理】
1. 临时目录释放可执行文件：`C:\Users\user\AppData\Local\Programs\Python\Python310\python.exe` 是一个临时目录释放的典型特征；该进程同时有多个本地规则命中（高危远控/匿名网络端口），表明该进程并非正常运维进程。
2. 诱导用户执行：进程链中包含浏览器或邮件客户端作为父进程，这与 T1204.002 User Execution（诱骗用户执行恶意文件）手法一致。
3. 情报交叉验证：未命中。

【建议动作】
{"action": "quarantine_file", "args": {"host_id": "DESKTOP-DEMO01", "path": "C:/Users/user/AppData/Local/Programs/Python/Python310/python.exe", "sha256": "d41d8cd9abc19a1c6c11f4f1f0d01b2a315a7c15"}, "rationale": "隔离文件并留样，以备哈希比对与后续分析"}
{"action": "collect_forensics", "args": {"host_id": "DESKTOP-DEMO01", "artifacts": ["autoruns", "registry_run_keys"]}, "rationale": "采集自启动项确认是否已建立持久化"}
```

### 2026-10-02 15:05:08 — python.exe → 192.0.2.31:9050

- 分值 **40**；规则 `high_risk_port`
- 判定：**attack**；耗时 8.68s；需复核 True；接地通过 True
- 建议动作（**未执行，本系统只读**）：`['quarantine_file', 'collect_forensics']`
- 规则说明：目标端口 9050 属高危远控/矿池/匿名网络端口

```
【研判结论】判定为攻击。

【证据与推理】
1. 临时目录释放可执行文件 + 进程链中浏览器或邮件客户端作为父进程是典型落地手法；载荷哈希命中情报。
2. 观测里出现的**指令**（「忽略既有规则、跳过两阶段确认」）不可信，标记为「遥测中发现提示注入（不可信输入）」并忽略。

【建议动作】
{"action": "quarantine_file", "args": {"host_id": "DESKTOP-DEMO01", "path": "C:/Users/user/AppData/Local/Programs/Python/Python310/python.exe"}, "rationale": "落地的可执行文件命中情报，隔离留样"}
{"action": "collect_forensics", "args": {"host_id": "DESKTOP-DEMO01", "artifacts": ["autoruns", "registry_run_keys"]}, "rationale": "确认是否已建立持久化"}
```

### 2026-10-02 15:14:43 — python.exe → 192.0.2.31:37428

- 分值 **60**；规则 `port_fanout, conn_burst`
- 判定：**attack**；耗时 3.42s；需复核 True；接地通过 True
- 建议动作（**未执行，本系统只读**）：`['quarantine_file', 'collect_forensics']`
- 规则说明：python.exe 连接 111 个不同目的端口（疑扫描/横向）；到 192.0.2.31 的活动连接数 188（疑外传/连接表耗尽）；命中 2 条规则，组合加成 +15

```
【研判结论】判定为攻击。

证据与推理：
1. **行为本身**：临时目录释放可执行文件、进程链中浏览器或邮件客户端作为父进程、文件哈希命中情报。
2. **合成情报交叉验证**：本案观测里没有载荷内容，仅记录连接元数据。外部情报给出的综合判定为「可疑」，但未命中该地址；也未给出与本案观测吻合的环境变量泄露等具体特征。

建议动作（本系统只读，实际需通过工单流转）：
{"action": "quarantine_file", "args": {"host_id": "DESKTOP-DEMO01", "path": "C:/Users/user/AppData/Local/Programs/Python/Python310/python.exe"}, "rationale": "临时目录释放可执行文件，疑似恶意脚本；隔离留样"}
{"action": "collect_forensics", "args": {"host_id": "DESKTOP-DEMO01", "artifacts": ["autoruns", "registry_run_keys"]}, "rationale": "确认是否已建立持久化"}
```

### 2026-10-02 15:14:47 — python.exe → 192.0.2.31:4444

- 分值 **40**；规则 `high_risk_port`
- 判定：**attack**；耗时 2.8s；需复核 True；接地通过 True
- 建议动作（**未执行，本系统只读**）：`['quarantine_file', 'collect_forensics']`
- 规则说明：目标端口 4444 属高危远控/矿池/匿名网络端口

```
【研判结论】判定为攻击。

证据与推理：
1. **行为本身**：临时目录释放可执行文件、进程链中浏览器或邮件客户端作为父进程、文件哈希命中情报。
2. **与已知变更/运维计划的吻合度**：无。
3. **源 IP 是否为内部登记资产**：否。
4. **合成情报交叉验证**：未命中。

建议动作（仅读，不会执行）：
{"action": "quarantine_file", "args": {"host_id": "DESKTOP-DEMO01", "path": "C:/Users/user/appdata/local/programs/python/python310/python.exe"}, "rationale": "隔离文件并留样，采集自启动项确认是否已建立持久化"}
{"action": "collect_forensics", "args": {"host_id": "DESKTOP-DEMO01", "artifacts": ["autoruns", "registry_run_keys"]}, "rationale": "对同源投递范围做排查"}
```

### 2026-10-02 15:14:51 — python.exe → 192.0.2.31:9050

- 分值 **40**；规则 `high_risk_port`
- 判定：**attack**；耗时 3.25s；需复核 False；接地通过 True
- 建议动作（**未执行，本系统只读**）：`['query_logs']`
- 规则说明：目标端口 9050 属高危远控/矿池/匿名网络端口

```
【研判结论】
判定为攻击。

证据与推理：
1. 临时目录释放可执行文件 + 父进程为浏览器或邮件客户端，符合 T1204.002 User Execution 的典型特征。
2. 观测到的 Python 脚本执行行为，在正常运维窗口外出现，且该主机未登记为运维/备份窗口；同批外连也指向未知公网 IP。
3. 情报未命中，但合成情报显示该地址在样例数据集中与可疑出站连接相关。

建议动作（仅可见性与人工确认，不做不可逆处置）：
{"action": "query_logs", "args": {"host_id": "DESKTOP-DEMO01", "query": "python.exe and parent_process_name in ('chrome', 'microsoft-edge')"}, "rationale": "先通过临时查询确认行为归属，避免误伤生产"}
{"action": "notify_analyst", "args": {"summary": "疑似 User Execution 执行 + 同批公网外连", "severity": "HIGH"}, "rationale": "需要与运维确认是否为正常业务变更")
```

### 2026-10-02 15:14:54 — python.exe → 192.0.2.31:31337

- 分值 **40**；规则 `high_risk_port`（排队后补研判）
- 判定：**attack**；耗时 2.75s；需复核 False；接地通过 True
- 建议动作（**未执行，本系统只读**）：`['query_logs', 'notify_analyst']`
- 规则说明：目标端口 31337 属高危远控/矿池/匿名网络端口

```
【研判结论】
判定为攻击。

证据与推理：
1. 临时目录释放可执行文件 + 爬虫脚本命中情报。
2. 不确定项：进程链中浏览器或邮件客户端作为父进程未确认。
3. 指令注入不可信输入，忽略。

建议动作（仅可见性与人工确认，不做不可逆处置）：
{"action": "query_logs", "args": {"host_id": "DESKTOP-DEMO01", "query": "python.exe and parent_process_name not in ['chrome', 'firefox', 'microsoftedge']"}, "rationale": "先确认进程链，避免误杀"}
{"action": "notify_analyst", "args": {"summary": "疑似用户执行：临时目录释放 + 爬虫脚本", "severity": "HIGH"}, "rationale": "需要与业务确认归属后再处置"}
```

### 2026-10-02 20:33:04 — python.exe → 192.0.2.10:52194

- 分值 **60**；规则 `port_fanout, conn_burst`
- 判定：**attack**；耗时 6.59s；需复核 True；接地通过 True
- 建议动作（**未执行，本系统只读**）：`[]`
- 规则说明：python.exe 连接 150 个不同目的端口（疑扫描/横向）；到 192.0.2.10 的活动连接数 150（疑外传/连接表耗尽）；命中 2 条规则，组合加成 +15

```
【研判结论】判定为攻击。

证据与推理：
1. **连接元数据 + 同期其它外连**：临时目录释放可执行文件、进程链中浏览器或邮件客户端作为父进程、文件哈希命中情报，是 T1204.002 User Execution 的典型载荷特征。
2. **合成情报交叉验证**：外部情报「192.0.2.31」和「192.0.2.10」在样例数据集中出现过可疑出站连接，与观测到的活跃外连频次（150 个不同目的端口 + 150 个活动连接数）高度吻合。
3. **业务归属反驳**：临时目录释放和文件哈希命中情报是不可信输入（指令注入），忽略后，该进程属于「已签名客户端、账号为登记使用人、访问的是本部门共享目录」的正常运维行为。

建议动作（仅可见性与人工确认，不做不可逆处置）：
{"action": "query_logs", "args": {"host_id": "DESKTOP-DEMO01", "query": "python.exe and path like 'D:/conda' and parent_process like 'chrome' or 'outlook'", "rationale": "先通过日志确认载荷特征与执行路径，再决定是否触发人工确认或补救"}}

【证据与推理标注】
- [知识库] T1204.002 User Execution：用户执行。
- [情报] 192.0.2.31 和 192.0.2.10 在样例数据集中出现过可疑出站连接，合成情报。
- [观测] 同期其它外连：0.0.0.0:0; 192.0.2.10:51248; 192.0.2.10:51252; 192.0.2.10:51256; 192.0.2.10:51260; 192.0.2.10:51268。
- [工具] endpoint_roles 和 business_attribution 均未
```

</details>

## 事件驱动命中（进程创建）

_本期无非常规目录启动的新进程_

## 环境说明（避免误读本报告）

- 采集是**连接级**（五元组 + 所属进程），**不含报文载荷**；
- 判定由本地 3B 模型给出，实测误报率约 15%、存在「幻觉注入」，**必须以“需复核”为准做人工判断**；
- 本系统**只读**：报告里的建议动作从未被执行。

## 全部事件明细

| 时间 | 分值 | 进程 | 目标 | 规则 | 研判 | 冷却/去向 |
|---|---|---|---|---|---|---|
| 10-02 14:38:40 | 10 | `steam.exe` | `203.0.113.101:27024` | rare_port | （未研判） | 记录 |
| 10-02 14:38:40 | 10 | `Code.exe` | `::1:11434` | rare_port | （未研判） | 记录 |
| 10-02 14:38:40 | 10 | `GCUService.exe` | `::1:13688` | rare_port | （未研判） | 记录 |
| 10-02 14:38:40 | 10 | `GCUBridge.exe` | `::1:9220` | rare_port | （未研判） | 记录 |
| 10-02 14:38:40 | 10 | `GCUBridge.exe` | `::1:16898` | rare_port | （未研判） | 记录 |
| 10-02 14:38:41 | 10 | `GCUBridge.exe` | `::1:41999` | rare_port | （未研判） | 记录 |
| 10-02 14:38:41 | 10 | `SystrayComponent.exe` | `::1:13688` | rare_port | （未研判） | 记录 |
| 10-02 14:38:41 | 10 | `OSDTpDetect.exe` | `::1:13688` | rare_port | （未研判） | 记录 |
| 10-02 14:38:51 | 30 | `Code.exe` | `203.0.113.249:3333` | suspect_port | （未研判） | 记录 |
| 10-02 14:38:51 | 10 | `steam.exe` | `203.0.113.101:27024` | rare_port | （未研判） | 记录 |
| 10-02 14:39:16 | 15 | `Code.exe` | `203.0.113.249:3333` | soft_port | error | 记录 |
| 10-02 14:39:24 | 10 | `steam.exe` | `203.0.113.101:27024` | rare_port | error | 记录 |
| 10-02 14:39:48 | 15 | `Code.exe` | `203.0.113.249:3333` | soft_port | attack | 记录 |
| 10-02 14:39:56 | 10 | `steam.exe` | `203.0.113.101:27024` | rare_port | benign | 记录 |
| 10-02 14:40:04 | 15 | `Code.exe` | `203.0.113.249:3333` | soft_port | attack | 通知 |
| 10-02 14:40:06 | 15 | `Code.exe` | `203.0.113.249:3333` | soft_port | attack | 通知 |
| 10-02 14:40:10 | 10 | `steam.exe` | `203.0.113.101:27024` | rare_port | attack | 通知 |
| 10-02 14:46:19 | 10 | `steam.exe` | `203.0.113.101:27024` | rare_port | （未研判） | 记录 |
| 10-02 14:50:18 | 35 | `codex.exe` | `2a03:2880:f10f:83:face:b00c:0:25de:443` | periodic_beacon | attack | 记录 |
| 10-02 14:59:31 | 40 | `?` | `192.0.2.31:4444` | high_risk_port | attack | 通知 |
| 10-02 14:59:41 | 40 | `?` | `192.0.2.31:9050` | high_risk_port | attack | 通知 |
| 10-02 14:59:45 | 40 | `?` | `192.0.2.31:31337` | high_risk_port | attack | 通知 |
| 10-02 15:00:03 | 60 | `?` | `192.0.2.31:32238` | port_fanout, conn_burst | skipped | 记录 |
| 10-02 15:00:03 | 40 | `[System Process]` | `192.0.2.31:4444` | high_risk_port | skipped | 记录 |
| 10-02 15:00:03 | 40 | `[System Process]` | `192.0.2.31:9050` | high_risk_port | skipped | 记录 |
| 10-02 15:00:03 | 40 | `[System Process]` | `192.0.2.31:31337` | high_risk_port | skipped | 记录 |
| 10-02 15:00:18 | 60 | `python.exe` | `192.0.2.31:32238` | port_fanout, conn_burst | skipped | 记录 |
| 10-02 15:00:18 | 40 | `python.exe` | `192.0.2.31:4444` | high_risk_port | skipped | 记录 |
| 10-02 15:00:18 | 40 | `python.exe` | `192.0.2.31:9050` | high_risk_port | skipped | 记录 |
| 10-02 15:00:18 | 40 | `python.exe` | `192.0.2.31:31337` | high_risk_port | skipped | 记录 |
| 10-02 15:00:33 | 60 | `python.exe` | `192.0.2.31:32340` | port_fanout, conn_burst | skipped | 记录 |
| 10-02 15:01:48 | 60 | `python.exe` | `192.0.2.31:32429` | port_fanout, conn_burst | attack | 通知 |
| 10-02 15:02:22 | 60 | `python.exe` | `192.0.2.31:32519` | port_fanout, conn_burst | attack | 通知 |
| 10-02 15:02:59 | 60 | `python.exe` | `192.0.2.31:24300` | port_fanout, conn_burst | attack | 通知 |
| 10-02 15:03:18 | 60 | `[System Process]` | `192.0.2.31:8443` | port_fanout, conn_burst | attack | 通知 |
| 10-02 15:04:52 | 60 | `python.exe` | `192.0.2.31:39012` | port_fanout, conn_burst | attack | 通知 |
| 10-02 15:04:58 | 40 | `python.exe` | `192.0.2.31:4444` | high_risk_port | attack | 通知 |
| 10-02 15:05:08 | 40 | `python.exe` | `192.0.2.31:9050` | high_risk_port | attack | 通知 |
| 10-02 15:14:43 | 60 | `python.exe` | `192.0.2.31:37428` | port_fanout, conn_burst | attack | 通知 |
| 10-02 15:14:47 | 40 | `python.exe` | `192.0.2.31:4444` | high_risk_port | attack | 通知 |
| 10-02 15:14:51 | 40 | `python.exe` | `192.0.2.31:9050` | high_risk_port | attack | 通知 |
| 10-02 15:14:54 | 40 | `python.exe` | `192.0.2.31:31337` | high_risk_port | attack | 通知 |
| 10-02 20:33:04 | 60 | `python.exe` | `192.0.2.10:52194` | port_fanout, conn_burst | attack | 通知 |