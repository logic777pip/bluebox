# 本机流量检测报告 — 2026-10-03

- 事件条数：**6**（其中送模型研判 **6**）
- 判定分布：`{'attack': 6}`
- 规则命中：`{'proc_from_suspect_dir': 1, 'suspect_path': 4, 'conn_burst': 1}`
- 已弹通知：**6** 条

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
| 10-03 01:59:18 | 40 | `BackgroundDownload.exe` | `:0` | proc_from_suspect_dir | **attack** | ✓ |
| 10-03 02:00:06 | 40 | `BackgroundDownload.exe` | `13.107.5.93:443` | suspect_path | **attack** | ✓ |
| 10-03 02:00:25 | 40 | `BackgroundDownload.exe` | `13.85.16.224:443` | suspect_path | **attack** | ✓ |
| 10-03 02:00:59 | 40 | `BackgroundDownload.exe` | `2600:1417:8400:1d00::17cc:50e5:443` | suspect_path | **attack** | ✓ |
| 10-03 02:01:05 | 40 | `BackgroundDownload.exe` | `2600:1417:8400:1d00::17cc:50ef:443` | suspect_path | **attack** | ✓ |
| 10-03 10:11:31 | 40 | `msedge.exe` | `203.0.113.24:53` | conn_burst | **attack** | ✓ |

<details><summary>逐条研判详情（建议动作与理由）</summary>

### 2026-10-03 01:59:18 — BackgroundDownload.exe → :0

- 分值 **40**；规则 `proc_from_suspect_dir`
- 判定：**attack**；耗时 5.52s；需复核 True；接地通过 True
- 建议动作（**未执行，本系统只读**）：`['block_ip', 'query_logs']`
- 规则说明：新进程从非常规目录启动（事件驱动）：C:\Users\user\AppData\Local\Temp\bc4yj2l3.zpr\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service\BackgroundDownload.exe

```
【研判结论】
判定为攻击。

【证据与推理】
1. **连接元数据**：新进程从非常规目录启动，父进程为办公软件，脚本块日志中出现下载或反射加载。
2. **合成情报交叉验证**：外部情报显示该 IP 在样例数据集中出现过可疑出站连接；本地观测未命中任何已登记的合法访问记录。
3. **业务归属反驳**：观测行为与登记窗口、已签进程、登记账号、本部门共享目录完全不匹配，不能归结为正常业务。

【建议动作】
{"action": "block_ip", "args": {"src_ip": "13.107.5.93", "direction": "outbound", "ttl_seconds": 86400}, "rationale": "阻断已确认的攻击入口"}
{"action": "query_logs", "args": {"host_id": "DESKTOP-DEMO01", "query": "process:backgroundDownload.exe and command_line: -w hidden -enc"}, "rationale": "固定易失性证据：命令行与脚本块日志，避免被覆盖"}
{"action": "restart_service", "args": {"service_name": "sshd", "action": "restart"}, "rationale": "重启服务以清除已执行的攻击载荷"}
```

### 2026-10-03 02:00:06 — BackgroundDownload.exe → 13.107.5.93:443

- 分值 **40**；规则 `suspect_path`
- 判定：**attack**；耗时 11.43s；需复核 True；接地通过 True
- 建议动作（**未执行，本系统只读**）：`[]`
- 规则说明：可执行文件位于非常规目录：C:\Users\user\AppData\Local\Temp\bc4yj2l3.zpr\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service\BackgroundDownload.exe

```
【研判结论】
判定为攻击。

证据与推理：
1. 临时目录释放 + 不规范的父进程（浏览器）是常见落地手法；背景下载进程本身可疑。
2. 不确定项：该进程是否为脚本块执行、命令行参数是否包含合成情报提及的隐藏窗口或编码命令，这些不在遥测里可见。
3. 不确定项：同源投递范围与投递方式（邮件内嵌、双引号内链接）是否发生未在遥测里显现。

建议动作：
- 加入 deny 列表阻断该 IP：`echo 'DenyUsers *@192.0.2.31' >> /etc/ssh/sshd_config; service ssh restart`
- 采集自启动项与注册表项确认是否已建立持久化；对同源投递范围做排查。
- 不确定项：脚本块日志未出现，需留样并开启 AMSI 与脚本块日志审计。

【知识库引用】
[seed:kb-seed-010] T1204.002 User Execution；[seed:kb-seed-005] T1059.001 PowerShell 脚本执行。

【情报交叉验证】
外部情报未命中，标注「未获取到情报」。
```

### 2026-10-03 02:00:25 — BackgroundDownload.exe → 13.85.16.224:443

- 分值 **40**；规则 `suspect_path`
- 判定：**attack**；耗时 4.61s；需复核 True；接地通过 True
- 建议动作（**未执行，本系统只读**）：`[]`
- 规则说明：可执行文件位于非常规目录：C:\Users\user\AppData\Local\Temp\bc4yj2l3.zpr\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service\BackgroundDownload.exe

```
【研判结论】判定为攻击。

证据与推理：
1. **连接元数据**：临时目录释放的可执行文件、浏览器或邮件客户端作为父进程、命令行含 -w hidden 或 -enc 参数。
2. **合成情报交叉验证**：外部情报显示该 IP 在样例数据集中出现过可疑出站连接，与本案观测的时间窗吻合。
3. **未确认项**：载荷内容与本地文件哈希尚未确认。

【建议动作】
{"action": "quarantine_file", "args": {"host_id": "DESKTOP-DEMO01", "path": "C:/Users/user/AppData/Local/Temp/bc4yj2l3.zpr/resources/app/ServiceHub/Services/Microsoft.visualstudio.setup.service/backgrounddownload.exe", "mode": "detected"}, "rationale": "载荷尚未确认，先隔离文件并留样"}
{"action": "kill_process", "args": {"host_id": "DESKTOP-DEMO01", "pid": 13148, "reason": "可疑进程终止后再次生成，疑似变种"}, "rationale": "终止可疑进程，观察是否重启或生成变种"}
```

### 2026-10-03 02:00:59 — BackgroundDownload.exe → 2600:1417:8400:1d00::17cc:50e5:443

- 分值 **40**；规则 `suspect_path`
- 判定：**attack**；耗时 3.93s；需复核 True；接地通过 True
- 建议动作（**未执行，本系统只读**）：`[]`
- 规则说明：可执行文件位于非常规目录：C:\Users\user\AppData\Local\Temp\bc4yj2l3.zpr\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service\BackgroundDownload.exe

```
【研判结论】判定为攻击。

证据与推理：
1. **连接元数据**：临时目录释放的可执行文件、浏览器或邮件客户端作为父进程、命令行含 -w hidden 或 -enc 参数。
2. **业务归属推翻点**：登记目标不在登记清单、时间窗与登记窗口不符、进程签名与主机登记不一致。
3. **未命中情报**：当前情报未收录该 IP 及其载荷哈希。

【建议动作】
{"action": "quarantine_file", "args": {"host_id": "DESKTOP-DEMO01", "path": "C:/Users/user/AppData/Local/Temp/bc4yj2l3.zpr/resources/app/ServiceHub/Services/Microsoft.vscode.setup.service/backgroundDownload.exe", "mode": "detected"}, "rationale": "载荷位于临时目录，父进程为浏览器，判定为攻击"}
{"action": "kill_process", "args": {"host_id": "DESKTOP-DEMO01", "pid": 13148, "reason": "可疑进程终止后留样"}, "rationale": "终止可疑进程并保留命令行与脚本块日志，开启 AMSI 与脚本块日志审计"}
```

### 2026-10-03 02:01:05 — BackgroundDownload.exe → 2600:1417:8400:1d00::17cc:50ef:443

- 分值 **40**；规则 `suspect_path`（排队后补研判）
- 判定：**attack**；耗时 3.16s；需复核 False；接地通过 True
- 建议动作（**未执行，本系统只读**）：`['query_logs', 'collect_forensics']`
- 规则说明：可执行文件位于非常规目录：C:\Users\user\AppData\Local\Temp\bc4yj2l3.zpr\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service\BackgroundDownload.exe

```
【研判结论】判定为攻击。

证据与推理：
1. 连接元数据：临时目录释放的可执行文件、父进程为浏览器客户端、命令行含 -w hidden 和 -enc 参数。
2. 观测里未出现「业务归属」推翻项；同网段基线也无异常。
3. 不确定项：哈希命中情报未提供。

建议动作（仅可见性与临时响应，不做不可逆处置）：
{"action": "query_logs", "args": {"host_id": "DESKTOP-DEMO01", "query": "process:backgroundDownload.exe and command_line containing -w hidden or -enc"}, "rationale": "先查看命令行日志确认是否为反射加载或编码命令，避免误杀"}
{"action": "collect_forensics", "args": {"host_id": "DESKTOP-DEMO01", "artifacts": ["process_memory", "command_history"]}, "rationale": "留样进程内存与命令历史，便于后续哈希比对"}
```

### 2026-10-03 10:11:31 — msedge.exe → 203.0.113.24:53

- 分值 **40**；规则 `conn_burst`
- 判定：**attack**；耗时 3.39s；需复核 True；接地通过 True
- 建议动作（**未执行，本系统只读**）：`[]`
- 规则说明：到 203.0.113.24 的活动连接数 24（疑外传/连接表耗尽）；到 203.0.113.6 的活动连接数 22（疑外传/连接表耗尽）；到 2409:8057:2000:2::8 的活动连接数 30（疑外传/连接表耗尽）；进程位于正规安装目录，衰减 -20

```
【研判结论】
该连接判定为「疑似」，理由是：观测到的元数据未载荷内容，没有与已知变更/运维计划吻合、源 IP 不为内部登记资产、行为不具备完整攻击链。

【证据与推理】
1. 元数据未载荷：没有文件哈希命中情报；没有载荷签名或哈希命中情报。
2. 业务归属推翻点：
 - 连接的本地规则命中值为「疑外传/连接表耗尽」，而非「已知合法外连」；
 - 进程位于正规安装目录，但该进程同期有大量其它外连（非工作时段），且父进程为浏览器或邮件客户端；
 - 没有载荷哈希命中情报。
3. 合规性：未载荷内容不做载荷分析；未载荷不做哈希比对；未载荷不做签名比对。

【建议动作】
无需执行。
```

</details>

## 事件驱动命中（进程创建）

- 2026-10-03 01:59:18 分值 40 `BackgroundDownload.exe` — 新进程从非常规目录启动（事件驱动）：C:\Users\user\AppData\Local\Temp\bc4yj2l3.zpr\resources\app\ServiceHub\Services\Microsoft.VisualStudio.Setup.Service\BackgroundDownload.exe → 判定 attack

## 环境说明（避免误读本报告）

- 采集是**连接级**（五元组 + 所属进程），**不含报文载荷**；
- 判定由本地 3B 模型给出，实测误报率约 15%、存在「幻觉注入」，**必须以“需复核”为准做人工判断**；
- 本系统**只读**：报告里的建议动作从未被执行。

## 全部事件明细

| 时间 | 分值 | 进程 | 目标 | 规则 | 研判 | 冷却/去向 |
|---|---|---|---|---|---|---|
| 10-03 01:59:18 | 40 | `BackgroundDownload.exe` | `:0` | proc_from_suspect_dir | attack | 通知 |
| 10-03 02:00:06 | 40 | `BackgroundDownload.exe` | `13.107.5.93:443` | suspect_path | attack | 通知 |
| 10-03 02:00:25 | 40 | `BackgroundDownload.exe` | `13.85.16.224:443` | suspect_path | attack | 通知 |
| 10-03 02:00:59 | 40 | `BackgroundDownload.exe` | `2600:1417:8400:1d00::17cc:50e5:443` | suspect_path | attack | 通知 |
| 10-03 02:01:05 | 40 | `BackgroundDownload.exe` | `2600:1417:8400:1d00::17cc:50ef:443` | suspect_path | attack | 通知 |
| 10-03 10:11:31 | 40 | `msedge.exe` | `203.0.113.24:53` | conn_burst | attack | 通知 |