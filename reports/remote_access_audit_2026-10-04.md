# 远控软件审计报告

> 采集时间：2026-10-04 13:54:39　工具：`tools/remote_access_audit.py`（**只读**）

## 风险排序

| 产品 | 风险 | 正在运行 | 被控记录 | 依据 |
|---|---|---|---|---|
| 远辰 GameViewer | **高** | 是 | 29 条（最近 2026-10-04 13:51） | 进程正在运行；配置了开机自启；有正在运行的服务（可在无人值守时接受连接）；日志中存在 **29** 个被远程连接/会话的记录文件（最近 2026-10-04 13:51） |
| 向日葵 / AweSun (Oray) | **高** | 是 | 0 条 | 进程正在运行；配置了开机自启；有正在运行的服务（可在无人值守时接受连接） |
| UU远程 | **低** | 否 | 0 条 | — |

## 向日葵 / AweSun (Oray)

- **进程**
  - `{"pid": 17668, "name": "AweSun", "path": "C:\\Program Files\\Oray\\AweSun\\flutter\\AweSun.exe", "start": "/Date(1790422510126)/"}`
- **服务**
  - `{"name": "AweSunService", "state": "Running", "start": "Auto", "path": "\"C:\\Program Files\\Oray\\AweSun\\AweSun.exe\" --mod=service"}`
  - `{"name": "SunloginService", "state": "Stopped", "start": "Manual", "path": "C:\\Program Files\\Oray\\AweSun\\OldAweSun.exe"}`
- **自启项**
  - `{"hive": "HKLM:", "name": "AweSun", "value": "\"C:\\Program Files\\Oray\\AweSun\\AweSun.exe\" --cmd=autorun"}`
- **签名状态**
  - `Valid`　C:\Program Files\Oray\AweSun\flutter\AweSun.exe
- **被控/会话相关日志（60 个）**
  - 2026-10-04 13:54　0.29 MB　`C:\Users\user\AppData\Roaming\Oray\AweSun\log\shell.log`
  - 2026-10-04 05:31　5.0 MB　`C:\Users\user\AppData\Roaming\Oray\AweSun\log\shell.20261004-053147.log`
  - 2026-09-26 19:20　0.36 MB　`C:\Users\user\AppData\Roaming\Oray\AweSun\log\shell.20260926-193510.log`
  - 2026-09-26 02:07　0.01 MB　`C:\Users\user\AppData\Roaming\Oray\AweSun\log\shell.20260926-091826.log`
  - 2026-09-26 01:53　0.02 MB　`C:\Users\user\AppData\Roaming\Oray\AweSun\log\shell.20260926-020614.log`
  - 2026-09-26 01:51　0.0 MB　`C:\Users\user\AppData\Roaming\Oray\AweSun\log\shell.20260926-015117.log`
  - 2026-09-26 01:47　0.03 MB　`C:\Users\user\AppData\Roaming\Oray\AweSun\log\shell.20260926-015118.log`
  - 2026-09-26 01:21　0.66 MB　`C:\Users\user\AppData\Roaming\Oray\AweSun\log\shell.20260926-012428.log`
  - 2026-09-24 22:38　0.0 MB　`C:\Users\user\AppData\Roaming\Oray\AweSun\log\shell.20260924-223826.log`
  - 2026-09-21 14:03　0.01 MB　`C:\Users\user\AppData\Roaming\Oray\AweSun\log\shell.20260924-223827.log`
  - 2026-09-21 13:59　0.0 MB　`C:\Users\user\AppData\Roaming\Oray\AweSun\log\shell.20260921-135955.log`
  - 2026-09-21 13:53　1.53 MB　`C:\Users\user\AppData\Roaming\Oray\AweSun\log\shell.20260921-135956.log`

## 远辰 GameViewer

- **进程**
  - `{"pid": 14568, "name": "crashpad_handler", "path": "D:\\yuanchen\\GameViewer\\bin\\crashpad_handler.exe", "start": "/Date(1790422513155)/"}`
  - `{"pid": 19364, "name": "GameViewer", "path": "D:\\yuanchen\\GameViewer\\bin\\GameViewer.exe", "start": "/Date(1790422512990)/"}`
- **服务**
  - `{"name": "GameViewerService", "state": "Running", "start": "Auto", "path": "\"D:\\yuanchen\\GameViewer\\GameViewerService.exe\" --service"}`
- **自启项**
  - `{"hive": "HKCU:", "name": "GameViewer", "value": "\"D:\\yuanchen\\GameViewer\\GameViewer.exe\" --auto-run"}`
- **签名状态**
  - `Valid`　D:\tools\yuanchen\GameViewer\bin\crashpad_handler.exe
  - `Valid`　D:\tools\yuanchen\GameViewer\bin\GameViewer.exe
- **被控/会话相关日志（43 个）**
  - 2026-10-04 13:51　1.36 MB　`D:\tools\yuanchen\GameViewer\log\server\log\streamer_log_controlled_20260926193444068_7468.slog`
  - 2026-10-03 21:56　9.31 MB　`D:\tools\yuanchen\GameViewer\log\server\log\connection_log_controlled_20260926193444068_7468.slog`
  - 2026-09-26 19:35　0.0 MB　`D:\tools\yuanchen\GameViewer\log\client\Log\connection_log_controller_20260926193513101_19364.slog`
  - 2026-09-26 19:35　0.0 MB　`D:\tools\yuanchen\GameViewer\log\client\Sentry\5684c7c8-887d-4b4d-a3c8-961c6a5ab40e.run\session.json`
  - 2026-09-26 19:34　0.0 MB　`D:\tools\yuanchen\GameViewer\log\Healthd\Sentry\bef6a344-fe29-444b-5b39-759b4ff633e8.run\session.json`
  - 2026-09-26 19:34　0.0 MB　`D:\tools\yuanchen\GameViewer\log\server\Sentry\2b05c4a1-7171-42c7-6106-26f728f64aaa.run\session.json`
  - 2026-09-26 19:34　0.0 MB　`D:\tools\yuanchen\GameViewer\log\service\Sentry\872f8f3d-8e99-4a1f-c22e-f7e2fae23666.run\session.json`
  - 2026-09-26 19:19　0.16 MB　`D:\tools\yuanchen\GameViewer\log\server\log\streamer_log_controlled_20260926091759144_3328.slog`
  - 2026-09-26 11:43　0.2 MB　`D:\tools\yuanchen\GameViewer\log\server\log\connection_log_controlled_20260926091759144_3328.slog`
  - 2026-09-26 09:18　0.0 MB　`D:\tools\yuanchen\GameViewer\log\client\Log\connection_log_controller_20260926091829340_2608.slog`
  - 2026-09-26 02:11　0.1 MB　`D:\tools\yuanchen\GameViewer\log\server\log\connection_log_controlled_20260926020600161_7368.slog`
  - 2026-09-26 02:11　0.0 MB　`D:\tools\yuanchen\GameViewer\log\server\log\connection_log_controlled_20260926021135305_11528.slog`

## UU远程

- **安装记录**
  - `{"name": "UU远程", "version": "4.25.0.8082", "location": null}`

## 远程访问通道

- RDP `fDenyTSConnections = 1`（**1 = 已禁用**，0 = 允许）
- 远程协助 `fAllowToGetHelp = (未读到)`

## 处置建议（需要你自己执行；本工具不代替你操作）

**有高风险项。先确认这些是不是你自己装的、自己用的。**

1. **先看连接记录再卸载** —— 卸载后日志就没了，而日志是判定「谁连过」的唯一证据：
   - 向日葵：登录 Oray 账号后台看「连接记录/登录日志」（来源、时间、时长）
   - GameViewer：看 `D:\tools\yuanchen\GameViewer\log\` 下 `*_controlled_*.slog` 的时间分布
2. **不是你用的就卸载干净**，并逐项确认删除：
   - 远辰 GameViewer
   - 向日葵 / AweSun (Oray)
   卸载后复查：服务是否消失、Run 项是否删除（本工具再跑一次即可）
3. **改密码 + 开两步验证**：远控账号、邮箱、以及这台机器上所有用过的账号
4. **如果确认是被他人远控**：备份数据后**重装系统**是最稳妥的处理（管理员权限下无法穷举所有后门）
5. 用当前杀软做一次全盘扫描（注意：若 Defender 已被其它杀软接管，它自己不会扫描）

### 本次审计**没有**覆盖的范围（别把它当成「已排除入侵」）

- 非管理员运行时读不到安全事件日志（登录 4624 / 进程创建 4688 / 服务安装 7045）
- 不做全盘病毒扫描，也不替代杀软
- 只查已知远控产品；自研/改名的远控工具不会被这张表命中
- 「不能控屏但能读写文件」的窃密类恶意软件不在本工具范围内