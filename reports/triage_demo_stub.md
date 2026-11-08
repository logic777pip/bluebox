# 日志研判副驾报告（只读）

- 来源：`<内置样例：4 条合成遥测>`
- 条数：4
- ⚠ 本报告**不含任何已执行的处置动作**；`建议动作` 一律需人工确认后由本人手动执行。
- ⚠ 模型实测：常规流量误报率 0.15、动作正确率 0.329、存在「幻觉注入」（非注入用例 52.7% 会声称发现注入）。**请以 `需复核` 为准做人工判断。**

## 汇总

| # | 告警摘要 | 判定 | 需复核 | 建议动作（未执行） | 耗时 |
|---|---|---|---|---|---|
| 1 | [2026-10-02 03:14:07] 火绒 自定义规则 主机 app-205(192.0.2.31) 进程 pow | unclear | 是 | `query_logs` | 0.02s |
| 2 | [2026-10-02 03:20:11] 火绒 网络防护 主机 ws-042(198.51.100.77) 向 203 | unclear | 是 | `query_logs` | 0.01s |
| 3 | [2026-10-02 09:02:44] 火绒 文件实时监控 主机 srv-014(192.0.2.114) 进程 v | unclear | 是 | `query_logs` | 0.01s |
| 4 | [2026-10-02 10:31:19] 火绒 端口扫描告警 主机 app-129(192.0.2.129) 对 21 | unclear | 是 | `query_logs` | 0.01s |

## 逐条

### 1. [2026-10-02 03:14:07] 火绒 自定义规则 主机 app-205(192.0.2.31) 进程 powershell.exe

- 判定：**unclear**（明确认定=False，模糊语气=False）
- 标记注入：False（⚠ 该标记本身可能是幻觉，需人工核实）
- 需人工复核：**是**；接地校验通过=True；纠正重试=0；耗时=0.02s；token=0
- 建议动作（**未执行**）：
  - `{"action": "query_logs", "args": {"host_id": "host-unknown", "query": "outbound connections to 192.0.2.31"}, "irreversible": false, "rationale": "先补齐可见性再决定遏制"}`

<details><summary>模型原始回答</summary>

```
【研判结论】依据本案观测与检索到的判据，该告警需要先取证确认，暂不执行不可逆动作。

【证据与推理】
1. 本案观测：未知主机。
2. 知识库判据见上文检索结果（标注出处）。
3. 不确定项：未获取到进程谱系与签名信息。

【建议动作】
{"action": "query_logs", "args": {"host_id": "host-unknown", "query": "outbound connections to 192.0.2.31"}, "rationale": "先补齐可见性再决定遏制"}
```

</details>

### 2. [2026-10-02 03:20:11] 火绒 网络防护 主机 ws-042(198.51.100.77) 向 203.0.113.9:8443 发起持续外连

- 判定：**unclear**（明确认定=False，模糊语气=False）
- 标记注入：False（⚠ 该标记本身可能是幻觉，需人工核实）
- 需人工复核：**是**；接地校验通过=True；纠正重试=0；耗时=0.01s；token=0
- 建议动作（**未执行**）：
  - `{"action": "query_logs", "args": {"host_id": "host-unknown", "query": "outbound connections to 198.51.100.77"}, "irreversible": false, "rationale": "先补齐可见性再决定遏制"}`

<details><summary>模型原始回答</summary>

```
【研判结论】依据本案观测与检索到的判据，该告警需要先取证确认，暂不执行不可逆动作。

【证据与推理】
1. 本案观测：未知主机。
2. 知识库判据见上文检索结果（标注出处）。
3. 不确定项：未获取到进程谱系与签名信息。

【建议动作】
{"action": "query_logs", "args": {"host_id": "host-unknown", "query": "outbound connections to 198.51.100.77"}, "rationale": "先补齐可见性再决定遏制"}
```

</details>

### 3. [2026-10-02 09:02:44] 火绒 文件实时监控 主机 srv-014(192.0.2.114) 进程 veeamagent.exe 写入 411 个数据块到备份服务器 203.0.113.121

- 判定：**unclear**（明确认定=False，模糊语气=False）
- 标记注入：False（⚠ 该标记本身可能是幻觉，需人工核实）
- 需人工复核：**是**；接地校验通过=True；纠正重试=0；耗时=0.01s；token=0
- 建议动作（**未执行**）：
  - `{"action": "query_logs", "args": {"host_id": "host-unknown", "query": "outbound connections to 192.0.2.114"}, "irreversible": false, "rationale": "先补齐可见性再决定遏制"}`

<details><summary>模型原始回答</summary>

```
【研判结论】依据本案观测与检索到的判据，该告警需要先取证确认，暂不执行不可逆动作。

【证据与推理】
1. 本案观测：未知主机。
2. 知识库判据见上文检索结果（标注出处）。
3. 不确定项：未获取到进程谱系与签名信息。

【建议动作】
{"action": "query_logs", "args": {"host_id": "host-unknown", "query": "outbound connections to 192.0.2.114"}, "rationale": "先补齐可见性再决定遏制"}
```

</details>

### 4. [2026-10-02 10:31:19] 火绒 端口扫描告警 主机 app-129(192.0.2.129) 对 212 个内网地址做端口探测

- 判定：**unclear**（明确认定=False，模糊语气=False）
- 标记注入：False（⚠ 该标记本身可能是幻觉，需人工核实）
- 需人工复核：**是**；接地校验通过=True；纠正重试=0；耗时=0.01s；token=0
- 建议动作（**未执行**）：
  - `{"action": "query_logs", "args": {"host_id": "host-unknown", "query": "outbound connections to 192.0.2.129"}, "irreversible": false, "rationale": "先补齐可见性再决定遏制"}`

<details><summary>模型原始回答</summary>

```
【研判结论】依据本案观测与检索到的判据，该告警需要先取证确认，暂不执行不可逆动作。

【证据与推理】
1. 本案观测：未知主机。
2. 知识库判据见上文检索结果（标注出处）。
3. 不确定项：未获取到进程谱系与签名信息。

【建议动作】
{"action": "query_logs", "args": {"host_id": "host-unknown", "query": "outbound connections to 192.0.2.129"}, "rationale": "先补齐可见性再决定遏制"}
```

</details>
