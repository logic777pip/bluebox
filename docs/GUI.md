# 本地控制台（GUI）

一个**纯标准库**的本地 Web 控制台：白色、简洁、离线可用，随开机静默启动，
从通知区域（托盘）图标打开。

```
gui/
├── __init__.py        分层说明
├── core.py            服务层：所有能力（49 项自检）
├── server.py          HTTP 层：127.0.0.1 + 令牌 + 只读模式（40 项 HTTP 自检）
├── tray.py            纯 ctypes 托盘图标（20 项自检）
└── static/            index.html / style.css / app.js（零外部资源）
```

```powershell
# 手动跑（前台，方便调试）
.\.venv\Scripts\python.exe gui\server.py --open

# 只读模式（只能看，所有写接口 403）
.\.venv\Scripts\python.exe gui\server.py --read-only --open

# 全项自检（不起服务器、不开端口；HTTP 部分用临时端口自测）
.\.venv\Scripts\python.exe gui\server.py --selftest
```

---

## 1. 为什么是本地 Web 界面，不是 tkinter

本机 tkinter 可用，仍然选了本地 Web：

* **不引新依赖。** `http.server` 是标准库；托盘也是自己用 ctypes 写的（见 §5）。
  项目一直的纪律是"能用标准库就不装包"。
* **"白色简洁"能真正做到。** tkinter 的主题与观感几乎不可控。
* **可以被验证。** 这是最重要的理由：Web 界面我能真的打开、渲染、点按钮、截图，
  确认页面上显示的是**真实数据**而不是一层好看的壳。tkinter 做不到。

代价是引入了一个 HTTP 监听端口，所以有了下面这三条约束。

---

## 2. 三条安全约束（不是"可以商量"的配置项）

### 2.1 只绑 127.0.0.1

`serve()` 里有一道硬检查：`host` 不是回环地址就直接拒绝启动并返回 2。

理由：这个界面能创建真实防火墙规则、能写配置文件、能发起 KAPE 采集。
监听 `0.0.0.0` 等于把主机的安全控制权交给整个局域网。

> 项目另一条线路确实在树莓派上做了网络传感器，但那是**只读上报**，方向相反，
> 不能类比。

`-Status` 会顺带检查是否有非回环监听，有就红字告警。

### 2.2 令牌是必需的

本机上有浏览器、有别的进程。没有令牌的话，任何网页里的 JS 都能
`fetch('http://127.0.0.1:8720/api/...')` 把封锁规则删掉。

* 令牌每次启动随机生成（`secrets.token_urlsafe(18)`），重启即换。
* 首屏用 `?token=` 取一次，页面存进 `sessionStorage` 后立刻
  `history.replaceState` 把 URL 里的令牌抹掉（避免出现在历史记录/截图里）。
* 之后所有 API 调用走 `X-Token` 头。
* 比对用 `secrets.compare_digest`（防时序侧信道）。

无令牌/错令牌 → 401。**静态资源可以匿名取**（只是空壳，没有任何数据）。

### 2.3 写操作必须 POST，且可一键只读

写接口用 GET 会返回 405。理由：`<img src="http://127.0.0.1:8720/api/containment/remove">`
这种写法会让浏览器替你发一个 GET —— 如果写接口吃 GET，一个网页就能触发它。

`--read-only` 时 `WRITE_ROUTES` 里全部返回 403。**界面不只靠 CSS 灰掉按钮**：
按钮真的不发请求，服务端也真的拒绝（两层）。

---

## 3. 界面是薄壳，不是旁路

每个有副作用的操作都调用既有模块的既有函数，因此硬拒绝条件照旧生效：

| 界面操作 | 落到的既有实现 | 仍然生效的拒绝条件 |
|---|---|---|
| 封锁 / 解禁 | `sandbox.contain.plan_contain` / `apply_contain` / `remove_rules` | 网段、网关、DNS、本机地址、prefixlen<32 一律拒绝 |
| 白名单增删 | `security.whitelist.WhiteList.add/remove` | 临时/下载/公共目录、系统进程裸名、通配符 |
| 配置编辑 | 直接写 YAML | 先校验 YAML → 备份 → 原子替换 |
| 撤销动作 | `sandbox.contain.remove_rules` | 只删带本系统前缀的规则 |
| KAPE | `forensics.kape.run` | **两道配置开关 + 管理员检查**（见 §4） |

### 3.1 配置编辑为什么是"校验 → 备份 → 原子替换"

GUI 把配置写坏一次，整套系统（传感器/动作/白名单）都会起不来，
而操作员通常是在"急着改个值"的时候点保存的。所以：

1. 新内容必须先能 `yaml.safe_load` 才允许落盘（防手滑写坏缩进）；
2. 落盘前备份到 `logs/gui_backups/<文件>.<时间戳>`；
3. 走临时文件 + `Path.replace`，避免写到一半断电留下半个文件。

**界面只能编辑固定白名单里的 5 个配置文件**（`EDITABLE_CONFIGS`），
不接受任意路径 —— 否则一个 `../../` 就能把它变成一个任意文件读写器。

### 3.2 前端转义顺序（先转义，再渲染）

报告和日志里会出现攻击者可控的字符串（进程名、路径、命令行）。
所以 Markdown 渲染的顺序是 `escapeHTML()` → 再转标签。

反过来的话，一个名叫 `<img onerror=...>` 的进程就能在控制台里执行脚本 ——
**一个安全工具自己成了 XSS 载体**，没有比这更难看的了。

链接只允许 `http/https/#`，挡掉 `javascript:` / `data:`。

---

## 4. KAPE 真实采集的两道闸门（踩坑记录）

本项目为真实采集设了两道开关，都为 `true` 才允许真跑：

| 开关 | 位置 |
|---|---|
| 工具层（第二道） | `actions/config.yaml → adapters.kape.execute_enabled` |
| 联动层 | `agent/config.yaml → forensics.execute` |

### 4.1 出过的事

第一版 `gui/core.py` 是这样写的：

```python
cfg = KapeConfig()                      # ← 只读了 dataclass 默认值
res = run(job, cfg, dry_run=not execute)  # ← 直接越过闸门
```

后果有**两个**，第二个才要命：

1. **界面在骗人。** 它显示"真实采集开关：未允许（会拒绝执行）"，
   但那个值来自 `KapeConfig()` 的默认值，跟配置里写了什么毫无关系。
   真实配置里 `module: !EZParser` 也被显示成空 —— 同一个 bug 的另一个症状。
2. **闸门是假的。** 我点了一下"真实采集"，**真的跑了一次采集**：
   `WRITE /api/kape/run {'execute': True} -> ok (29.79s)`，产出了 972 个文件 /
   420.3 MB 才被我杀掉。

根因：`execute_enabled` 是在**调用方**（`actions/adapters/kape.py` 的
`dry = ctx.dry_run or not self.cfg.execute_enabled`）拦的，
而 `forensics.kape.run()` 自己**故意不读配置** —— 它的 `dry_run=False`
就等于命令行上的 `--execute`，本来就是"调用者明确要真跑"的意思。

### 4.2 修法

* `_kape_cfg()` 用 `KapeConfig.from_dict()` 从**真实配置**构造（与动作适配器同源）。
* `kape_run(execute=True)` 在执行前检查两道开关，任一未开就 `GuiError`，
  消息里点名**具体哪个配置键**（否则操作员不知道去哪改）。
* 前端把两道开关都列出来，"真实采集"按钮直接 `disabled` 并写明原因。
* 自检里加了回归守卫：开关关着时 `execute=True` 必须被拒，
  **且断言没有拉起 `kape.exe` 进程**（用 `Get-CimInstance` 前后计数比对）。

### 4.3 闸门放在哪一层

放在 `gui/core.py`，**不**改 `forensics.kape.run()`。理由：

* `run()` 是底层工具，改它会影响已核验的 CLI 行为（`--execute` 语义）；
* `execute_enabled` 的语义是"动作层的第二道开关"，属于调用方职责。

但如果以后再加调用方（新的适配器、pipeline），**必须自己过这道闸门**。
这是这套设计里唯一的薄弱点：闸门在调用方，靠自觉。

---

## 5. 托盘图标：纯 ctypes

不用 pystray / PyQt —— Win32 原生就有（`Shell_NotifyIconW`），ctypes 调即可。

解决的具体问题：GUI 以 `pythonw.exe` **无窗口**方式开机自启。
无窗口意味着用户没有任何可见入口 —— **托盘图标就是这个入口**。
没有它，"后台静默自启"等于"用户再也找不到它"。

### 5.1 四个踩过的坑

1. **必须有一个真窗口**（不能是 message-only 窗口）：Explorer 重启后会广播
   `TaskbarCreated`，收不到就该重新 `NIM_ADD`；message-only 窗口收不到广播，
   图标会就此消失直到进程重启。
2. **弹菜单前要 `SetForegroundWindow`**：否则菜单点了别处不消失。
3. **退出前一定要 `NIM_DELETE`**：否则任务栏留一个"僵尸图标"，
   鼠标划过才消失。（进程被 `Stop-Process` 强杀时也会留，属预期。）
4. **`cbSize` 必须填对**：结构体随版本变长，填错 → 调用静默失败
   （返回 False 但不告诉你为什么）。自检里把 x64 完整版的 **976 字节**钉死。

### 5.2 自检写错过一次（记录下来免得重复）

用外部 P/Invoke `FindWindow('BlueTeamAgentTrayWnd', $null)` 探测托盘窗口
**不可靠**：PowerShell 会把 `$null` 的标题参数变成空字符串，
于是变成"类名匹配且标题为空"的查找，而窗口标题是"蓝队 Agent 控制台"，必然找不到。

正确做法：**让代码自己报告**。`TrayIcon._say()` → `logs/gui.log`：

```
2026-10-06 06:40:55 托盘图标已挂上（窗口类 BlueTeamAgentTrayWnd，hwnd=1181174）
```

这比任何外部探测都可靠，也是出问题时唯一真正有用的线索。

### 5.3 一个隐蔽的 bug 类别

`_say()` 里 `TrayIcon.logger or self.logger` —— 但类属性 `logger` 当时没加上，
会 `AttributeError`，而它在 `run()` 里被调用 → 异常冒到 `serve()` 的
`except Exception` → **静默降级成"无托盘模式"**。
用户看到的是"托盘图标没出来"，日志里只有一句"托盘启动失败"。

所以自检里补了三条：类属性存在、`_say` 会调 logger、**未配 logger 时 `_say` 不抛**。

---

## 6. 性能：为什么首屏曾经要等 15 秒

`/api/status` 里有五项互不依赖的状态查询，但当初是**串行**的：

| 查询 | 耗时 | 原因 |
|---|---|---|
| KAPE 探测 | ~8s | `kape.exe --help` 打印完横幅**不退出**，只能等超时 |
| 传感器探测 | ~3s | 起一次 PowerShell 查进程 |
| 防火墙规则 | ~3s | 起一次 PowerShell 查 `Get-NetFirewallRule` |
| 适配器健康 | 可变 | 可能含 HTTP 探测 |
| Sandboxie 探测 | ~1s | 调 `SbieIni` |

加起来 15 秒，而界面上这只是"打一页"。

### 修法（三件事，缺一不可）

1. **并行**：`_parallel()` 用线程池跑这五项，冷启动降到最慢的一项（8.3s）。
2. **短 TTL 缓存 + 单飞**：`_cached(key, ttl, fn)`，同一键同时只允许一个线程去算。
   没有单飞的话，启动预热线程和用户首次请求会**各跑一遍** 8 秒探测。
   TTL 取秒级，操作员看到的仍是"接近实时"。
3. **启动时后台预热**：`serve()` 起一个 daemon 线程先跑一遍 `status()` / `threat_model()`。

结果：冷启动 8.3s、缓存命中 **0.002s**。加上前端**渐进渲染**
（先出骨架并写明"在探测什么"），等待变成可理解的。

**写操作后必须 `invalidate_cache("containment")`** —— 否则刚封的 IP 不出现在列表里，
用户会以为没生效然后重复点。这种"看起来没反应"最容易引发误操作。

---

## 7. 两个"状态页在骗人"的坑

状态页给出**假告警**比不给状态更糟：操作员会去"修复"一个没坏的东西，
然后开始不信任这个页面。

### 7.1 `Get-Process` 在 PS 5.1 下没有 `CommandLine`

```powershell
# ✗ 永远匹配不到 → 恒定显示"传感器已停止"
Get-Process -Name pythonw | Where-Object { $_.CommandLine -like '*net_sensor.py*' }
```

那是 PS 7 / .NET Core 才有的属性，PS 5.1 下恒为 `$null`。

```powershell
# ✓ 用 CIM
Get-CimInstance Win32_Process -Filter "Name='pythonw.exe'" |
    Where-Object { $_.CommandLine -like '*net_sensor.py*' }
```

实测：改用 CIM 后立刻正确报出 `running: True`、`task_state: Running`、`procs: 2`。

> 关于 `procs: 2`：本机 `.venv\Scripts\pythonw.exe` 是 **uv 的转发器**，
> 它和真实解释器会同时出现在进程表里，属同一实例。
> 据此判断"重复实例"会误报。`-Status` 里对 GUI 自身也做了同样的处理。

自检里加了**源码级守卫**（`inspect.getsource(_probe_sensor)` 必须含
`Win32_Process`、不含 `Get-Process -Name`），防止被改回去。

### 7.2 日志中文乱码

`logs/gui.log` 写成 UTF-8，但 `Get-Content logs\gui.log`（PS 5.1 默认）
按 ANSI（本机 GBK）解码 → 满屏乱码，看起来像程序坏了。

`_ensure_bom()` 保证文件带 UTF-8 BOM（老文件也补一次）。现在 PS 默认参数就能正确显示。

---

## 8. 页面清单

| 页面 | 做了什么 | 数据来源 |
|---|---|---|
| 概览 | 传感器/封锁/白名单/只读库 指标 + 执行环境 + 适配器表 | `core.status()` |
| 配置 | 编辑 5 个配置文件（校验→备份→原子替换） | `EDITABLE_CONFIGS` |
| 报告 | 报告与案例文档，自动渲染 Markdown | `reports/`、`logs/**/CASE.md` |
| 日志 | 8 个日志尾部查看（只读） | `VIEWABLE_LOGS` |
| 威胁建模 | 资产 / 检测能力 / 实际观测 / 覆盖缺口 / PDCERF | 见 §8.1 |
| 封锁 | 查看、新增（计划/立即）、解除、全部解除 | `sandbox.contain` |
| 白名单 | 增删条目，校验规则可视化 | `security.whitelist` |
| AI 动作 | 动作台账 + 撤销入口 + 待确认动作 | `logs/action_audit.jsonl` |
| KAPE | 环境、两道开关、演练/真实采集、唤起 gkape | `forensics.kape` |

### 8.1 威胁建模页为什么不"编内容"

安全看板最容易变成"指标陈列"，看完不知道该怎么办。这一页按三栏组织，
每栏直接对应一个决策：

* **要保护什么** ← `actions/config.yaml → executor.policy` 的实际值
* **能看见什么** ← 直接读 `tools/net_sensor._RULE_BASE` 的规则表，
  **不是抄文档**（抄文档必然与实现漂移）
* **看不见什么** ← 硬编码的诚实边界（短连接盲区、加密流量、白名单双刃剑、
  签名≠无害、遏制有限、动态分析不由 AI 执行）

> 打开这一页时发现：`protected_hosts / accounts / domains / ips / paths`
> **全部为空** —— 也就是说策略保护目前**不生效**。
> 这是页面该暴露的东西，不是页面该隐藏的东西。

### 8.2 "AI 动作"页的可撤销性判定

建立在既有的 `logs/action_audit.jsonl` 上，**不另建一套记录**（两套必然漂移）。
按动作语义分类，拿不准的一律标成不可撤销（fail-closed）：

| 动作 | 可撤销性 |
|---|---|
| `contain_threat` | ✅ 删掉本系统建的防火墙规则 |
| `collect_forensics` / `extract_payload` | ⚠️ **证据固化**，默认不可撤。删证据比留着更危险（案子复核时找不到东西），需显式勾选确认 |
| `dry_run` 的条目 | 无副作用，标"无需撤销" |
| 遏制占位类 | 本部署没真执行，无可撤内容 |

界面上给个"撤销"按钮、点下去却没效果，比没有按钮更糟。

---

## 9. 开机静默自启

```powershell
# 注册（需要管理员：RunLevel=Highest 从非提权 shell 注册会 access denied）
powershell -ExecutionPolicy Bypass -File tools\install_gui_autostart.ps1 -Start

# 只读模式自启（只能看）
... -ReadOnly

# 只看不启
... -NoAutoStart

# 查看 / 控制 / 卸载
... -Status
... -Start
... -Stop
... -Uninstall
```

### 9.1 为什么用计划任务而不是启动文件夹

* 启动文件夹的快捷方式**无法在每次登录时静默提权**（会弹 UAC）。
  计划任务可以：`RunLevel Highest` 的任务静默以管理员启动。
* 还能拿到重启重试、"无时间限制"、`IgnoreNew`（否则登录几次就有三份实例）。

### 9.2 为什么是 `pythonw.exe`

它**没有控制台子系统** → 启动时不闪黑框、不出现任何窗口。
用 `python.exe` 会在每次登录时闪一个黑窗口，"静默"就废了。

用户唯一能看到的入口就是托盘图标：**左键单击打开控制台**，右键出菜单
（打开/复制地址/状态/输出目录/退出）。

### 9.3 脚本里两个刻意的设计

* **冒烟测试**：注册前先真起一次、等 4 秒确认进程还活着、确认监听。
  一个"每次开机都静默失败"的任务比没有任务更糟。失败就拒绝注册并打印
  `logs/gui.log` 末尾。
* **参数只拼一次**：`$argPreview` 同时用于冒烟测试和任务注册，
  保证"验证过的"就是"开机会跑的"。

### 9.4 提权的取舍（说清楚）

界面只绑回环 + 每次随机令牌，网络不可达。但**以管理员常驻**仍是一个真实取舍：
进程能改防火墙规则、能改配置文件。

如果不想常驻一个提权监听，用 `-RunLevel Limited` 注册，
需要真封锁时再手动起一个提权的：

```powershell
powershell -ExecutionPolicy Bypass -File tools\install_gui_autostart.ps1 -Uninstall
... -RunLevel Limited -Start
```

---

## 10. 已验证 / 未验证

| 项 | 状态 |
|---|---|
| `gui/core.py` 自检 49/49 · `gui/tray.py` 20/20 · HTTP 自检 40/40 | ✅ 实测通过 |
| 托盘图标真的挂上通知区域 | ✅ `hwnd=1181174`（代码自报，非外部探测） |
| 只绑 127.0.0.1（无外部可达监听） | ✅ `Get-NetTCPConnection` 实测 |
| 令牌保护：无令牌/错令牌 → 401 | ✅ 实测 |
| 静态资源拒绝目录穿越（含上游穿越） | ✅ 实测 |
| 只读模式下 10 个写接口全部 403 | ✅ 实测 |
| 封锁网段被硬拒绝，界面显示具体原因 | ✅ 浏览器点击实测 |
| 白名单拒绝覆盖 `C:\Users\Public`，界面显示原因 | ✅ 浏览器点击实测 |
| **KAPE 执行闸门真的拦住，且未拉起 kape.exe** | ✅ 自检断言 + 实测 |
| 开机静默自启（任务注册 + 立即启动 + 托盘就绪） | ✅ 实测 |
| 前端逐页渲染（概览/威胁建模/封锁/白名单/KAPE） | ✅ 浏览器实测 |
| **重启电脑后是否真的自动起来** | ⬜ **未验证**（需要一次真实重启） |
| 托盘菜单各项点击（打开/复制/状态/输出目录/退出） | ⬜ 未逐个点（左键单击路径逻辑与菜单同源） |
| 配置页保存流程（校验/备份/原子替换） | ✅ 服务层自检覆盖；⬜ 浏览器点击未走完整 |

### 10.1 遗留问题

* `logs/forensics/` 下每点一次"演练"、每跑一次自检都会留一个
  `<时间戳>_gui-<时间戳>/` 目录（只有 `run_kape.cmd` + `job.json`）。
  累积起来会变成目录垃圾，建议加个保留策略。
* `logs/forensics/` 里有 27 个早期阶段的 dry-run 目录，未清理。
* 本次 GUI 测试产生并被中止的 420.3 MB 残缺产物**已删除**。
