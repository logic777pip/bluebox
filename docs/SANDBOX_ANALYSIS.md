# 沙箱联动：载荷只读固化 · 静态取证 · 最小影响封锁 · 人工动态分析

> 一句话：**AI 负责不变的部分，人负责需要承担责任的部分。**
> 检测到威胁后，系统把载荷**按字节复制**进只读库、报警、做静态取证分析、
> 封锁该威胁的**精确对端出向**（不干扰其它业务），并生成一份交接包 ——
> 然后停下来，把「要不要执行这个样本」交给人工。

---

## 1. 边界：AI 不做动态分析（这是结构性的，不是配置）

需求是「禁止 AI 进行动态分析」。如果只把它写成配置项（`execute_enabled: false`）
或文档约定，那条约束随时会被一行改动绕过。所以这里做成**四道结构性保证**，
任何一道都不是"注意一下"能过的：

| # | 保证 | 位置 | 怎么验证 |
|---|---|---|---|
| 1 | 动作白名单里**不存在** `detonate_payload` 之类动作。模型即使写出这个名字，`validate_action` 也会 default-deny 直接拒绝 | `security/action_schema.py` `ACTION_SPECS` | `python -c "from security.action_schema import ACTION_SPECS as A; print('detonate_payload' in A)"` → `False` |
| 2 | 机制层有**运行时守卫**：任何参数落在只读库（vault）内的子进程调用直接抛异常；且只允许白名单程序进盒子 | `sandbox/sandboxie.py` `_guard_argv()` | `python -m sandbox.sandboxie --selftest`（含 4 条守卫反面用例） |
| 3 | 交接模块**连 `subprocess` 都不 import**，AST 断言证明它没有任何执行类调用 | `sandbox/dynamic_handoff.py` `assert_no_execution()` | `python -m sandbox.dynamic_handoff --audit` |
| 4 | 编排模块自身也不含执行类调用（通知与防火墙在别的模块里，各自有自己的守卫） | `sandbox/pipeline.py` `_assert_no_execution()` | `python -m sandbox.pipeline --selftest` |

要加"自动引爆"能力，得同时改这四处并让三个自检全部失败。这才叫约束。

**另外**：仿真靶场（`actions/adapters/simulated.py`）也**不**实现引爆动作 ——
否则评测会跑出一个"AI 可以引爆样本"的假象，那是量具本身在骗人。

---

## 2. 流水线：检测 → 固化 → 报警 → 静态分析 → 封锁 → 交接

```
传感器 / 旁路 IDS 判定为威胁（route=auto_attack，或"攻击判定 + 分值达标 + 高置信"）
    │
    ├─① extract_to_vault     载荷按字节复制进只读库（**复制不移动**）
    │                        MD5/SHA-1/SHA-256 + 只读属性 + manifest.json
    ├─② 报警                  Windows 通知：已固定载荷、附哈希
    ├─③ analyze_payload       静态取证（哈希/PE 结构/熵/导入表/签名/字符串/指标）
    │                        → payload_report.md + payload_report.json
    ├─④ contain_threat        最小影响封锁（默认**只出计划**）
    ├─⑤ build_handoff         人工动态分析交接包（AI 不执行）
    └─⑥ 落审计                 logs/sandbox/cases/<案例>/CASE.md + pipeline_audit.jsonl
```

### 为什么固化要"复制不移动"

移动会改变受害者机器上的证据状态（文件在不在、路径空不空本身就是线索），
而且一旦移动失败可能把唯一的样本弄丢。取证第一原则是**先固定、不改现场**。
固化后立刻设只读属性，这样之后任何时刻重算哈希都能对得上，证据链才成立。

### 威胁判定为什么复用 `forensics/collect.py`

"什么算检测到威胁"必须**只有一个定义**。另写一套阈值判断，两套迟早漂移
（一边认为要处理、一边认为不用），在生产里就表现为"有些告警有取证、有些没有"，
且没人说得清原因。所以直接 import 那三个 trigger 函数，判定逻辑单点维护。

### 两个流水线的分工

| | `forensics/collect.py`（KAPE） | `sandbox/pipeline.py`（本流水线） |
|---|---|---|
| 目标 | 整机产物（Prefetch/注册表/日志…） | **载荷本身** |
| 量级 | 分钟级、数百 MB | 秒级、KB~MB |
| 建议顺序 | 后 | **先** |

先固定载荷：攻击者会自我删除，用户也可能顺手清空下载目录。
KAPE 可以随后慢慢采。

---

## 3. 最小影响封锁：把"不干扰业务"写成代码

「封锁威胁但不影响业务」如果只当原则写在文档里，实际很容易退化成
"封一个 C 段省事""顺手把 445 全封了""干脆隔离主机"。所以这里把
**会造成业务中断的做法全部变成代码里的拒绝条件**（`sandbox/contain.py`）：

| 规则 | 拒绝条件 | 为什么 |
|---|---|---|
| 只封精确对端 | 目标比 `/32` 宽（任何网段）→ 拒绝 | 封网段会连带打掉同段内正常业务对端，而且攻击者换个地址就绕过了 |
| 只封出向 | 规则固定 `Outbound / Block`，不加任何入向规则 | 入向规则会打到本机正在提供的服务 |
| 不封本机自己 | 目标是本机地址 → 拒绝 | 封自己 = 自断网 |
| 不封默认网关 | 目标是默认网关 → 拒绝 | 封网关 = 整机断网 |
| 不封 DNS 服务器 | 目标是本机 DNS → 拒绝 | 封 DNS = 域名解析全挂，业务立刻报错。而 DNS 出向流量在日志里跟 C2 心跳极像，误判有现实基础 |
| 网络事实未知时 fail-closed | 查不到地址/网关/DNS → 拒绝全部目标 | "不知道网关是谁"时贸然封锁，风险是整机断网。确需放行要显式 `--allow-unverified`（记入审计） |
| 带 TTL 自动到期 | 默认 4 小时，上限 7 天 | 基础设施 IP 会变（CDN、云主机），长期规则很快变成"封着一个已经不属于攻击者的地址" |
| 规则名可审计可回滚 | 统一前缀 `BlueTeamAgent-Contain-` | 一条命令列全、一条命令撤销，且**绝不会误删别人的规则** |

**默认只出计划，不改防火墙。** 真封锁需要 `sandbox.execute: true`（与 KAPE 采集同一纪律：
有实际影响的动作需要一次写在配置里的显式批准）。

真执行后会**读回验证**（`Get-NetFirewallRule` 查得到才算成功）—— 不读回就等于"以为封了"。

### 常用命令

```powershell
# 列出本系统建的所有封锁规则
python -m sandbox.contain --list

# 演练：只出计划（这是默认）
python -m sandbox.contain 203.0.113.77 --case C-001 --reason "C2 心跳"

# 真封锁（需管理员）
python -m sandbox.contain 203.0.113.77 --case C-001 --ttl 7200 --apply

# 回收已到期规则
python -m sandbox.contain --expire

# 撤销本系统建的全部规则
python -m sandbox.contain --uncontain
```

---

## 4. 静态分析做了什么（以及它看不到什么）

`python -m sandbox.payload <文件>`，或作为动作 `analyze_payload`。

| 维度 | 内容 |
|---|---|
| 哈希 | MD5 / SHA-1 / SHA-256（SHA-256 是 IOC 交换标准；MD5/SHA-1 用于跟老平台对得上） |
| 类型 | PE32/PE32+ EXE/DLL、脚本、容器格式 |
| PE 结构 | 节区表、每节**熵**（≥7.2 提示压缩/加密/加壳）、W+X 节区、导入表、编译时间戳、overlay、ASLR/DEP/CFG |
| 数字签名 | Authenticode 状态与签发者（复用 `tools/proc_watch.signature_status`，带缓存） |
| 字符串 | ASCII 与 **UTF-16LE**（含非 ASCII 宽字符，即中文路径） |
| 指标 | 编码命令、certutil 下载、卷影删除、Defender 排除项、凭据转储、C2 框架串、挖矿协议、勒索信文本；提取 URL / 公网 IP / 域名（私有地址被排除，避免把内网地址当 C2） |

**打分只用于排优先级，不是判决。** 签名有效会**降 30 分但不归零** ——
恶意软件也买证书（这与 `net_sensor` 的签名降级是同一套逻辑）。
所有报告里 `verdict` 都明确写"需人工确认"。

**静态分析看不到什么**：解密后的代码、实际外连、运行时落地物、反沙箱对抗。
加壳样本尤其如此。这就是为什么还需要人工动态分析 —— 而风险也正是从这里来的。

### 工程上的两个坑（都已修，见自检）

1. **宽字符串对齐**：最初只按 `data[1::2]` 取高字节，等价于假设宽字符串总从偶数偏移开始。
   真实样本里对齐是任意的（前面一段 ASCII 长度为奇数就整体错位），
   于是字节对被读错，产出 `瀀漀眀攀爀猀栀攀氀氀` 这类垃圾字符串混进报告。
   现在两种对齐都跑。
2. **控制台编码**：样本里提取出的字符串什么字符都可能有，打印到 GBK 控制台会
   `UnicodeEncodeError`，表现为"分析跑到一半崩在打印上"。
   现在 CLI 入口把 stdout/stderr 的错误处理器设成 `replace`（不动编码，中文照常显示）。

---

## 5. 人工动态分析怎么做

系统生成的是**交接包**，不是自动化步骤：

```
logs/sandbox/cases/<案例>/
    run_dynamic_analysis.cmd     ← 人工双击执行（纯 ASCII，cmd 在 936 代码页下才不乱码）
    HANDOFF.md                   ← 中文操作手册（前置条件、观察重点、回填方式）
    handoff.json                 ← 机器可读记录，含 executed_by_ai: false
```

`.cmd` 的逻辑：自检 Sandboxie → **打印载荷哈希供人工核对**（不一致就停）→
在沙箱内启动载荷 → 人工观察 → 按任意键终止盒子 → 导出沙箱内的落地物存档。

### 动手前的硬性前置

1. **差分断网验证必须通过**：

   ```powershell
   python -m sandbox.sandboxie --verify-net
   ```

   它同时测两件事：**沙箱内连不出去** 且 **沙箱外连得出去**。
   只测盒内是不够的 —— 本机可能根本没网，那么测试必然"通过"但什么都没证明。
   所以判定是：

   | 盒外 | 盒内 | 判定 |
   |---|---|---|
   | 连得出去 | 连不出去 | `isolated`（通过） |
   | 连得出去 | 连得出去 | `not_isolated`（**禁止引爆**） |
   | 连不出去 | 连不出去 | `inconclusive`（本机没网，**没验证出来**） |
   | 探针无结果 | — | `inconclusive` |

   宁可说"没验证出来"，也不能给人工一个假的绿灯笼 —— 人工据此引爆，后果由这个绿灯笼承担。

2. 优先在**虚拟机快照**上做。沙箱不是绝对保证（尤其 Sandboxie 是用户态沙箱 +
   内核驱动，配置不当或沙箱逃逸漏洞都可能让"分析样本"变成"替攻击者重新上线"）。
3. 载荷镜像必须只读且哈希与交接单一致。
4. 准备好记录：C2 的 IP:端口、落地文件路径、持久化位置。

### 观察重点（按价值排序）

| 观察点 | 为什么重要 | 怎么看 |
|---|---|---|
| 外连目标 IP:端口 | 这就是 C2，是封锁与情报的直接输入 | `netstat -ano` 找载荷 PID |
| 落地的文件 | 说明有释放阶段，通常还能找到更多样本 | 沙箱导出目录 `drive\` 下的新增文件 |
| 持久化动作 | 决定清除范围 | 沙箱内的注册表/启动目录/计划任务改动 |
| 子进程 | 白利用（LOLBin）通常有父子链 | 任务管理器加「命令行」列 |
| 是否自我删除 | 说明是投递器而非最终载荷 | 载荷文件是否消失 |

---

## 6. Sandboxie-Plus 已安装并**跑通**（2026-10-05）

### 6.1 安装事实（可复核）

| 项 | 值 |
|---|---|
| 版本 | v1.18.5（`Sandboxie-Plus-x64-v1.18.5.exe`，23.7 MB） |
| SHA-256 | `bd984db71900ecb9fc22e4bbffda4363a92cd755840a8792c2422d6d42fd6fa3` |
| 校验 | 与官方 `sha256-checksums.txt` **逐字节一致** |
| 数字签名 | **Valid**，签发者 `NOVASYNC LABS PTE. LTD.`，DigiCert 时间戳 |
| 安装方式 | `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-`，退出码 0 |
| 驱动/服务 | `SbieDrv` **RUNNING**、`SbieSvc` **RUNNING** |
| 驱动初始化 | 系统日志：`SBIE1101 Sandboxie 驱动程序 (SbieDrv) 版本 5.73.2 已初始化`，筛选器注册成功，**无错误** |
| 配置文件 | `C:\Windows\Sandboxie.ini`（首次写入时才创建） |

### 6.2 根因：盒子必须有 `Enabled=y`，否则 Sandboxie 认不出这个名字

症状很误导人：`Start.exe /box:<盒> cmd.exe /c ...` **返回退出码 0**，但目标进程
根本没起来（进程列表找不到、`C:\Sandbox` 始终不创建、Sandboxie 辅助进程一次都没出现）。
只靠退出码完全查不出来。

实际发生的是 `Start.exe` **弹了一个对话框**：

```
Invalid box name parameter:  <盒名>          ← 中文界面：无效沙盒名参数
```

定位过程（都可复现）：

1. 从 `SbieMsg.dll` 的字符串表里找到这条消息的英文原文
   `"Invalid box name parameter:  %2"` —— 它带一个参数，说明 Start.exe 是
   **拿这个名字去查盒子列表**后失败的。
2. `SbieIni.exe query /boxes *` 返回**空**，而 `query *` 能列出 `[BlueTeamDynamic]`。
   即：**section 在配置里，但 Sandboxie 不认为它是一个沙箱。**
3. 实验：给该 section 加一行 `Enabled=y` → `query /boxes *` 立刻列出它。

**结论（文档里没写、只有实测才知道）：一个 section 只有当它有 `Enabled=y`
时才被 Sandboxie 当作沙箱。** 只执行 `SbieIni set <名字> NetworkAccess "*,Block"`
建出的 section 不算数。

补上之后立即正常，证据三条：

| 证据 | 观测 |
|---|---|
| 进程被沙箱化 | 盒内 `ping` 进程的模块里有 **`SbieDll.dll`** |
| 盒子文件区建立 | `C:\Sandbox\user\BlueTeamDynamic\`（含 `RegHive`） |
| 写入被重定向 | 盒内写 `C:\Users\user\_sbie_w1.txt` → 主机侧**不存在**，落在盒内 `...\BlueTeamDynamic\user\current\_sbie_w1.txt` |

这条已固化成 `ensure_box()`（建盒 + 置 `Enabled=y` + 设断网 + **读回验证**）。

### 6.2.0 快速恢复：已关闭（默认行为）

实测新建盒子后，Sandboxie 会自动补上这些默认设置（来自其默认盒子模板）：

```
ConfigLevel=9        AutoRecover=y
RecoverFolder=%{374DE290-...}%      ← 下载目录
RecoverFolder=%Personal%            ← 文档
RecoverFolder=%Desktop%             ← 桌面
```

`RecoverFolder` + `AutoRecover` 组合出的是「**快速恢复**」：沙箱界面上会提供
「把文件恢复到真实系统」的入口。**用于分析恶意样本时这是个大坑** —— 人工在
沙箱里引爆后，界面会**主动提议**把落地物搬回真实桌面/文档/下载目录，
一次误点就等于亲手把样本放回主机，前面所有隔离工作全白做。

`ensure_box()` **默认就把它关掉**（`disable_recovery=True`）：

```
AutoRecover=n
RecoverFolder=            ← 三条全部删除（下载/文档/桌面）
```

且有**读回验证**：实测复跑会报
`读回确认：AutoRecover=n 且无 RecoverFolder（快速恢复已关）`；
若关闭不干净（残留 RecoverFolder 或 AutoRecover 仍为 y）**直接判失败**，
不会“默默当它已经关了”。

关闭后复验：盒子仍在 `/boxes` 列表中、盒内进程仍加载 `SbieDll.dll`、
写入仍被重定向到盒内、差分断网验证仍为 `isolated` —— 关快速恢复
不影响任何隔离能力，只是去掉了那个危险的“搬回真实系统”入口。

⚠ 一个实现细节：`SbieIni query <盒> <设置名>` 对**多值设置返回多行**
（`RecoverFolder` 返回三条），所以必须逐行 delete。

### 6.2.1 顺带修掉的三个实现 bug（都是“看着在跑、其实无效”）

| # | 缺陷 | 后果 |
|---|---|---|
| 1 | 探针结果只按 `C:` 盘映射盒内路径（`box_root/drive/<相对C:>`）；而探针写在 **D:** 盘 → `relative_to("C:/")` 抛异常，候选表为空 | 盒内探针“没产出结果文件”，差分验证**永远** inconclusive |
| 2 | 启动盒内进程后**立刻**去找结果文件 —— 而 `Start.exe` 是**异步**的，它一返回盒内 python 还没跑完 | 同上。看着像沙箱不工作，其实是读得太早 |
| 3 | 探针目标写死 `1.1.1.1:443` —— 本网络**不可达**（实测只有 `223.5.5.5:443` 通） | 对照侧永远失败 → 差分验证同样永远给不出结论 |

修完之后的实测结果：

```json
{"ok": true, "verdict": "isolated", "inside": "blocked", "outside": "reachable",
 "detail": "差分验证通过：盒外 reachable / 盒内 blocked（目标 223.5.5.5:443）"}
```

**另外一条教训**：`Sandboxie.ini` **不要手工编辑**。实测手工删掉一个 section 之后，
Sandboxie 服务会按内存里的状态把文件**规范化重写**（还会自动补上全局 Template
与盒子默认设置），改动被覆盖。要用官方工具（`SbieIni` / `SandMan`）。
`SbieIni` 没有“删除 section”的命令，所以清理盒子用 `set <盒> Enabled n`
（它不再是盒子，就不会出现在 `/boxes` 里）。

### 6.3 已核实的 CLI 语法（从二进制里提取 + 逐条实演）

未安装时无法验证的 API 拼写，现已**全部核对完毕**。用法文本不是猜的，
是从 `SbieIni.exe` / `Start.exe` 的字符串表里提取出来的（这两个工具无参数运行
不打印用法，但**二进制里带着**）：

```
SbieIni.exe <query|queryex|set|append|insert|delete> ...
  query[ex] [/expand] [/boxes] <section> [setting]
    - section 传 * → 列出配置里所有 section
    - /boxes     → 只列对应沙箱的 section
    - setting 传 * → 列出该 section 的所有设置
  set|append|insert|delete <section> <setting> <value>
Start.exe /box:<盒名> <程序> [参数]
```

实演结果（每一条都跑过）：

| 调用 | 结果 |
|---|---|
| `set BlueTeamDynamic NetworkAccess "*,Block"` | 退出码 0 |
| `query BlueTeamDynamic NetworkAccess` | 读回 `*,Block` ✓（读回验证成立） |
| `query *` | 返回 `GlobalSettings` |
| `query /boxes *` | 返回空（盒子尚未成功跑起来） |
| `Start.exe /box:X cmd.exe ...` | 退出码 0，但进程未起（见 6.2） |

**断网设置名也已核实：`NetworkAccess`**，语法：

```
NetworkAccess=<进程>,<动作>[;Port=...][;Protocol=...][;Address=...]
```

依据是官方 `Templates.ini` 里的实例：
`NetworkAccess=*,Block;Port=137,138,139,445`、
`NetworkAccess=*,Block;Address=127.0.0.0-127.255.255.255;Protocol=Any`。
所以“封掉盒内全部网络”就是 **`NetworkAccess=*,Block`**（已写入 `[BlueTeamDynamic]`）。

仍未证实的只有一项：`Start.exe /box:X /terminate`。Start.exe 字符串表里有
`terminate` / `terminate_all`，但没有 `/terminate` 这个开关字样；本机盒子起不来
也没法实演。该假设已集中在 `sandbox/sandboxie.py` 的 `START_ARGS_TERMINATE` 一处。

### 6.4 探针目标必须自动选（已修）

实测本机网络：`1.1.1.1` / `8.8.8.8` / `119.29.29.29` / `220.181.38.148` **全部超时**，
只有 `223.5.5.5:443` 可达。最初把探针目标写死成 `1.1.1.1`，后果是**对照侧永远失败**
→ 差分验证永远 `inconclusive`（功能看着在跑，实际永远给不出结论）。
现在改成逐个试候选并自动选可达的那个；全不可达就如实报“没有可达的对照”。

### 装好之后要做的第一件事

```powershell
# 1. 探测安装与盒配置
python -m sandbox.sandboxie --probe
python -m sandbox.sandboxie --settings --box BlueTeamDynamic

# 2. 差分断网验证（这一步之前不要引爆任何东西）
python -m sandbox.sandboxie --verify-net
```

### CLI 假设的当前状态

原先这里列的是“未核实的 CLI 假设”。现已全部核实（见 §6.3），只有
`/terminate` 一项仍未证实，它集中在 `sandbox/sandboxie.py` 的
`START_ARGS_TERMINATE` 一处。

断网验证的探针结果文件可能被 Sandboxie **写入重定向**到盒子文件区
（`C:\Sandbox\<用户>\<盒>\drive\...`），所以实现会在两个位置找结果文件，
找不到就判 `inconclusive`（不是"通过"）。

---

## 7. 已验证 vs 未验证

| 项 | 状态 |
|---|---|
| `sandbox.payload` 静态分析（含畸形 PE 不崩、真 PE 解析、指标匹配） | ✅ 33/33，用系统自带 `notepad.exe` 与自造畸形输入验证 |
| `sandbox.dynamic_handoff` 交接包（纯 ASCII + CRLF、`executed_by_ai=false`、AST 无执行能力） | ✅ 23/23 + `--audit` 通过 |
| `sandbox.sandboxie` 机制层（守卫、只读固化、幂等、缺件如实报不可用） | ✅ 28/28 |
| `sandbox.contain` 最小影响封锁（8 条拒绝条件、TTL 边界、默认演练） | ✅ 33/33 |
| `sandbox.pipeline` 端到端（固化→报警→分析→封锁计划→交接→审计→冷却去重） | ✅ 21/21 |
| 动作系统接入（4 个新动作、路由到真实适配器、`detonate_payload` 不存在） | ✅ `actions.cli` 38/38 |
| **真实加防火墙规则并读回** | ✅ 已实演：规则创建 → 读回确认 → 独立通道读到 `方向=出站/动作=Block/远程=目标` → 撤销干净（残留 0 条）。并实测了**幂等性**（重复应用不产生同名重复规则） |
| **Sandboxie 安装** | ✅ v1.18.5；SHA-256 与官方校验文件一致；签名 Valid（NOVASYNC LABS）；驱动与服务均 RUNNING；驱动初始化无错误 |
| **Sandboxie 盒内进程真实运行** | ✅ 实测：盒内进程加载 `SbieDll.dll`；`C:\Sandbox\<用户>\<盒>\` 建立；**写入被重定向**（主机侧无文件，盒内 `user\current\` 有副本） |
| **沙箱内真实断网** | ✅ 差分验证通过：盒外 `reachable` / 盒内 `blocked` → `isolated` |
| **Sandboxie 内引爆载荷** | ⬜ 未执行，**且按设计不由 AI 执行** —— 交接包已能生成，等人工按 `HANDOFF.md` 做 |
| 在**真实恶意样本**上的静态分析效果 | ❌ 未验证（只用系统程序与自造输入验证过解析正确性） |

---

## 8. 命令速查

```powershell
# 静态分析一个文件
python -m sandbox.payload <文件> --out report.md --json report.json

# 固化到只读库
python -m sandbox.sandboxie --extract <文件> --case C-001

# 生成人工动态分析交接包
python -m sandbox.dynamic_handoff --case C-001 --payload <库内镜像> --out logs/sandbox/cases/C-001

# 自动联动（只处理现有事件后退出；--bench 完全不改任何东西）
python -m sandbox.pipeline --once --from-file logs/net_sensor_events.jsonl
python -m sandbox.pipeline --once --bench

# 常驻
python -m sandbox.pipeline --loop --interval 30

# 封锁（默认演练）
python -m sandbox.contain 203.0.113.77 --case C-001
```

## 9. 需要人工决定的事

1. **恢复火绒**（本轮为排除 HIPS 拦截注入而关掉了）。现在已证实沙箱可用，
   建议把它开回来，并把 `C:\Program Files\Sandboxie-Plus\` 加入信任 ——
   否则每次用沙箱都得先关杀软，那是更大的风险。
2. **是否打开真封锁**（`sandbox.execute: true`）。打开前建议先用
   `python -m sandbox.pipeline --once --bench` 在真实告警上跑一轮，
   看它打算封哪些地址 —— 确认没有误封网关/DNS 家族。
3. 谁负责动态分析（需要有人有意愿、有时间、在快照上做）。交接包现在会带着
   **`box_verified: true`** 与断网验证结论一起交付，人工拿到就能开工。
4. 清理实验盒子的残留 section（`TestBox` 已置 `Enabled=n` 所以不再是盒子，
   但 section 还在；`SbieIni` 没有删除 section 的命令，要用 SandMan 删）。

> 「关掉快速恢复」已完成（见 §6.2.0），不再列入待定项。

