#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gui/server.py — 本地控制台 HTTP 服务端（纯标准库）。

设计取舍
--------

**只绑定 127.0.0.1。** 不监听 0.0.0.0 —— 这个界面能改封锁规则、能写配置、
能发起 KAPE 采集，暴露到局域网等于把主机的安全控制权交出去。
（本项目的另一条线路确实在树莓派上做了网络传感器，但那是**只读上报**的，
方向相反，不能混为一谈。）

**令牌是必需的，不是可选的。** 本机上有浏览器、有别的进程；没有令牌的话，
任何一个网页里的 JS 都能 `fetch('http://127.0.0.1:8720/api/...')` 把封锁规则删掉。
令牌随启动随机生成、每次重启都换，页面通过 `?token=` 拿到后存进 sessionStorage，
之后的 API 调用走 `X-Token` 头。

**默认只读。** `--read-only` 不是默认值，但所有写操作都集中在一处 `WRITE_ROUTES`
里，方便审计"这个界面到底能改变什么"。

无控制台运行（pythonw.exe）时不能 print，所以日志统一落到 `logs/gui.log`。
"""

from __future__ import annotations

import argparse
import html
import json
import mimetypes
import os
import secrets
import socket
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gui import core  # noqa: E402

__all__ = ["serve", "build_server", "LOG_FILE"]

STATIC_DIR = Path(__file__).resolve().parent / "static"
LOG_FILE = PROJECT_ROOT / "logs/gui.log"
DEFAULT_PORT = 8720

#: 会改变系统状态的接口。`--read-only` 时全部 403。
WRITE_ROUTES = {
    "/api/config": "写配置文件（自动备份 + YAML 校验）",
    "/api/containment/add": "创建真实防火墙封锁规则",
    "/api/containment/remove": "删除本系统建的封锁规则",
    "/api/whitelist/add": "加入白名单（会降低告警敏感度）",
    "/api/whitelist/remove": "移出白名单",
    "/api/undo": "撤销动作 / 删除证据",
    "/api/kape/run": "发起 KAPE 采集（可能写数百 MB）",
    "/api/kape/gui": "拉起 KAPE 图形界面",
    "/api/quit": "退出控制台进程",
}


_LOG_PREPPED = False


def _ensure_bom() -> None:
    """保证 `logs/gui.log` 带 UTF-8 BOM（只在每次进程启动后做一次）。

    为什么值得为这个写代码：Windows 上免不了有人用 PowerShell 5.1 的
    `Get-Content logs\\gui.log` 看日志，而那个 cmdlet 没有 BOM 就按 ANSI（本机 GBK）
    解码 —— 满屏乱码，看起来像程序坏了。它是唯一会被"顺手打开看看"的文件，
    所以必须能被最土的方式正确读出。老文件没 BOM 也补一次。
    """
    p = LOG_FILE
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        if p.exists() and p.stat().st_size >= 3:
            with p.open("rb") as fh:
                if fh.read(3) == b"\xef\xbb\xbf":
                    return
            p.write_bytes(b"\xef\xbb\xbf" + p.read_bytes())
        elif p.exists() and p.stat().st_size > 0:
            p.write_bytes(b"\xef\xbb\xbf" + p.read_bytes())
        else:
            p.write_bytes(b"\xef\xbb\xbf")
    except OSError:
        pass


def _log(msg: str) -> None:
    """无窗口运行时也留痕（pythonw.exe 下 stdout 是黑洞）。"""
    global _LOG_PREPPED
    if not _LOG_PREPPED:
        _ensure_bom()
        _LOG_PREPPED = True
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass
    if sys.stdout and hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
        print(line)


class ApiError(Exception):
    def __init__(self, message: str, code: int = 400) -> None:
        super().__init__(message)
        self.code = code


def _bool(v: Any, default: bool = False) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on", "y")


# --------------------------------------------------------------------------- #
# 路由处理：每个函数只做参数抽取 + 调用 core
# --------------------------------------------------------------------------- #

def h_status(_q: Dict[str, Any]) -> Any:
    return core.status()


def h_configs(_q: Dict[str, Any]) -> Any:
    return {"configs": core.list_configs(), "editable": list(core.EDITABLE_CONFIGS)}


def h_config(q: Dict[str, Any]) -> Any:
    return core.read_config(q.get("path", ""), parsed=_bool(q.get("parsed")))


def h_reports(_q: Dict[str, Any]) -> Any:
    return {"reports": core.list_reports()}


def h_report(q: Dict[str, Any]) -> Any:
    return core.read_report(q.get("path", ""))


def h_logs(_q: Dict[str, Any]) -> Any:
    return {"logs": core.list_logs(), "viewable": list(core.VIEWABLE_LOGS)}


def h_log(q: Dict[str, Any]) -> Any:
    try:
        n = int(q.get("lines") or 300)
    except (TypeError, ValueError):
        n = 300
    return core.tail_log(q.get("path", ""), n)


def h_threat(_q: Dict[str, Any]) -> Any:
    return core.threat_model()


def h_containment(_q: Dict[str, Any]) -> Any:
    return core.containment_state()


def h_whitelist(_q: Dict[str, Any]) -> Any:
    return core.whitelist_state()


def h_actions(_q: Dict[str, Any]) -> Any:
    return core.actions_journal()


def h_kape(_q: Dict[str, Any]) -> Any:
    return core.kape_state()


def h_meta(_q: Dict[str, Any]) -> Any:
    """给界面用的元信息：哪些接口会改状态（界面据此决定是否禁用按钮）。"""
    return {"write_routes": WRITE_ROUTES}


# --- 写操作 ---

def h_config_write(q: Dict[str, Any]) -> Any:
    return core.write_config(q.get("path", ""), q.get("text", ""))


def h_containment_add(q: Dict[str, Any]) -> Any:
    try:
        ttl = int(q.get("ttl_seconds") or 14400)
    except (TypeError, ValueError):
        ttl = 14400
    return core.containment_add(
        q.get("indicator", ""),
        ttl_seconds=ttl,
        reason=q.get("reason", ""),
        case_id=q.get("case_id") or "gui",
        apply_now=_bool(q.get("apply")),
        allow_unverified=_bool(q.get("allow_unverified")),
    )


def h_containment_remove(q: Dict[str, Any]) -> Any:
    names = q.get("names")
    if isinstance(names, str):
        names = [x.strip() for x in names.split(",") if x.strip()]
    return core.containment_remove(names or None)


def h_whitelist_add(q: Dict[str, Any]) -> Any:
    try:
        ttl = int(q.get("ttl_days") or 0)
    except (TypeError, ValueError):
        ttl = 0
    return core.whitelist_add(q.get("kind", ""), q.get("value", ""),
                              note=q.get("note", ""), ttl_days=ttl)


def h_whitelist_remove(q: Dict[str, Any]) -> Any:
    return core.whitelist_remove(q.get("kind", ""), q.get("value", ""))


def h_undo(q: Dict[str, Any]) -> Any:
    payload = q.get("payload") or {}
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except ValueError:
            raise ApiError("payload 不是合法 JSON")
    return core.action_undo(q.get("kind", ""), payload,
                            confirm_evidence=_bool(q.get("confirm_evidence")))


def h_kape_run(q: Dict[str, Any]) -> Any:
    return core.kape_run(execute=_bool(q.get("execute")), sim=_bool(q.get("sim")),
                         module=q.get("module", ""), target=q.get("target", ""))


def h_kape_gui(_q: Dict[str, Any]) -> Any:
    return core.kape_launch_gui()


def h_open(q: Dict[str, Any]) -> Any:
    return core.open_in_explorer(q.get("path", ""))


#: path → (处理函数, 是否需要写权限)
ROUTES: Dict[str, Tuple[Callable[[Dict[str, Any]], Any], bool]] = {
    "/api/status": (h_status, False),
    "/api/meta": (h_meta, False),
    "/api/configs": (h_configs, False),
    "/api/config": (h_config, False),
    "/api/reports": (h_reports, False),
    "/api/report": (h_report, False),
    "/api/logs": (h_logs, False),
    "/api/log": (h_log, False),
    "/api/threat": (h_threat, False),
    "/api/containment": (h_containment, False),
    "/api/whitelist": (h_whitelist, False),
    "/api/actions": (h_actions, False),
    "/api/kape": (h_kape, False),
    "/api/open": (h_open, True),
    # 写操作（同一路径的 POST 走这里）
    "/api/config/write": (h_config_write, True),
    "/api/containment/add": (h_containment_add, True),
    "/api/containment/remove": (h_containment_remove, True),
    "/api/whitelist/add": (h_whitelist_add, True),
    "/api/whitelist/remove": (h_whitelist_remove, True),
    "/api/undo": (h_undo, True),
    "/api/kape/run": (h_kape_run, True),
    "/api/kape/gui": (h_kape_gui, True),
}


# --------------------------------------------------------------------------- #
# HTTP 层
# --------------------------------------------------------------------------- #

class Handler(BaseHTTPRequestHandler):
    server_version = "BlueTeamAgentGUI/1.0"
    protocol_version = "HTTP/1.1"

    # -- 让日志走文件而不是 stderr（pythonw 下 stderr 无效） --
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        if getattr(self.server, "verbose", False):  # type: ignore[attr-defined]
            _log(f"{self.client_address[0]} {fmt % args}")

    # -- 工具 --
    @property
    def token(self) -> str:
        return getattr(self.server, "token", "")  # type: ignore[attr-defined]

    @property
    def read_only(self) -> bool:
        return bool(getattr(self.server, "read_only", False))  # type: ignore[attr-defined]

    def _auth(self, q: Dict[str, Any]) -> bool:
        """令牌校验：`X-Token` 头优先，其次 `?token=`（首次加载页面用）。"""
        given = self.headers.get("X-Token") or q.get("token") or ""
        return bool(given) and secrets.compare_digest(str(given), self.token)

    def _send_json(self, obj: Any, code: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # 本地界面不需要被别的站点嵌入
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text: str, code: int = 200, ctype: str = "text/plain; charset=utf-8") -> None:
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _static(self, rel: str) -> None:
        """静态文件。**路径必须落在 gui/static 内**（防穿越）。"""
        rel = urllib.parse.unquote(rel).lstrip("/")
        if rel in ("", "/"):
            rel = "index.html"
        p = (STATIC_DIR / rel).resolve()
        if not str(p).startswith(str(STATIC_DIR.resolve())) or not p.is_file():
            self._send_text("404 Not Found", 404)
            return
        ctype = mimetypes.guess_type(str(p))[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript",):
            ctype += "; charset=utf-8"
        body = p.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _params(self) -> Dict[str, Any]:
        q: Dict[str, Any] = {}
        parsed = urllib.parse.urlparse(self.path)
        for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
            q[k] = v
        return q

    def _dispatch(self, method: str) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        # 静态资源
        if method == "GET" and (path == "/" or path.startswith("/static/")):
            self._static(path[len("/static/"):] if path.startswith("/static/") else path)
            return

        if path == "/api/quit":
            if not self._auth(self._params()):
                self._send_json({"error": "令牌无效"}, 401)
                return
            if self.read_only:
                self._send_json({"error": "只读模式：禁止退出控制台"}, 403)
                return
            self._send_json({"ok": True, "detail": "正在退出"})
            threading.Timer(0.4, getattr(self.server, "shutdown_all", lambda: None)).start()
            return

        route = ROUTES.get(path)
        if not route:
            self._send_json({"error": f"未知接口 {path}"}, 404)
            return
        fn, needs_write = route

        q = self._params()
        if method == "POST":
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            if raw:
                try:
                    body = json.loads(raw.decode("utf-8"))
                    if isinstance(body, dict):
                        q.update(body)
                except (ValueError, UnicodeDecodeError):
                    self._send_json({"error": "请求体不是合法 JSON"}, 400)
                    return

        if not self._auth(q):
            self._send_json({"error": "令牌无效或缺失（用启动时打印的地址打开）"}, 401)
            return
        if needs_write and self.read_only:
            self._send_json({"error": f"只读模式：禁止 {path}"}, 403)
            return
        if needs_write and method == "GET":
            # 写接口必须用 POST：避免被 <img src> 之类的方式误触发
            self._send_json({"error": f"{path} 只接受 POST"}, 405)
            return

        try:
            started = time.time()
            out = fn(q)
            if needs_write:
                out = {"ok": True, **(out if isinstance(out, dict) else {"result": out})}
                _log(f"WRITE {path} {str(q)[:200]} -> ok ({time.time()-started:.2f}s)")
            self._send_json(out)
        except core.GuiError as exc:
            self._send_json({"error": str(exc), "kind": "refused"}, 400)
            if needs_write:
                _log(f"WRITE {path} -> 拒绝：{exc}")
        except PermissionError as exc:
            self._send_json({"error": f"需要管理员权限：{exc}", "kind": "privilege"}, 403)
        except Exception as exc:  # noqa: BLE001
            _log(f"ERROR {path} {type(exc).__name__}: {exc}")
            self._send_json({"error": f"{type(exc).__name__}: {exc}", "kind": "error"}, 500)

    def do_GET(self) -> None:  # noqa: N802
        try:
            self._dispatch("GET")
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # 客户端中途断开（刷新、关标签页、请求超时）不是服务端故障。
            # 默认行为是打一大段堆栈，把真正的错误淹掉 —— 所以在这里静默收尾。
            self.close_connection = True

    def do_POST(self) -> None:  # noqa: N802
        try:
            self._dispatch("POST")
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.close_connection = True


class GuiServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, *, token: str, read_only: bool,
                 verbose: bool = False) -> None:
        super().__init__(addr, handler)
        self.token = token
        self.read_only = read_only
        self.verbose = verbose
        self.shutdown_cb: Optional[Callable[[], None]] = None

    def shutdown_all(self) -> None:
        if self.shutdown_cb:
            self.shutdown_cb()
        threading.Thread(target=self.shutdown, daemon=True).start()


def build_server(*, host: str = "127.0.0.1", port: int = DEFAULT_PORT,
                 token: str = "", read_only: bool = False,
                 verbose: bool = False) -> GuiServer:
    return GuiServer((host, port), Handler,
                     token=token or secrets.token_urlsafe(18),
                     read_only=read_only, verbose=verbose)


def _free_port(host: str, port: int) -> int:
    """端口被占时自动往后找（开机自启最怕"上次没退干净"）。"""
    for cand in range(port, port + 20):
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((host, cand))
                return cand
            except OSError:
                continue
    raise RuntimeError(f"{host}:{port}~{port+20} 都被占用")


def status_line() -> str:
    """托盘菜单里"查看运行状态"用的一行摘要。"""
    try:
        st = core.status()
        c = st.get("containment", {}).get("count", 0)
        w = st.get("whitelist", {}).get("total", 0)
        v = st.get("vault", {}).get("cases", 0)
        sen = "运行中" if st.get("sensor", {}).get("running") else "未运行"
        return (f"传感器 {sen}｜封锁规则 {c} 条｜白名单 {w} 条｜"
                f"只读库 {v} 个案件")
    except Exception as exc:  # noqa: BLE001
        return f"状态读取失败：{type(exc).__name__}"


# --------------------------------------------------------------------------- #
# HTTP 自检：真的起一次服务、真的发请求（不是 mock）
# --------------------------------------------------------------------------- #

def _req(base: str, path: str, token: str = "", method: str = "GET",
         body: Any = None, timeout: float = 30.0) -> Tuple[int, Any]:
    """最小 HTTP 客户端（只用标准库），返回 (状态码, 解析后的 JSON)。"""
    import urllib.error
    import urllib.request

    url = base + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if token:
        req.add_header("X-Token", token)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(raw)
            except ValueError:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw


def http_selftest() -> int:
    """起一个真实的服务器实例并打所有接口。这能抓住单元测试抓不到的错
    （路由拼错、令牌比对写反、静态文件穿越、只读开关漏掉某个写接口）。"""
    ok = fail = 0

    def chk(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok, fail
        if cond:
            ok += 1
            print(f"  [OK]   {name}")
        else:
            fail += 1
            print(f"  [FAIL] {name}  {str(detail)[:240]}")

    print("\n=== gui.server HTTP 自检 ===")

    token = "selftest-" + secrets.token_hex(6)
    srv = build_server(host="127.0.0.1", port=0, token=token, read_only=False,
                       verbose=False)
    port = srv.server_address[1]
    base = f"http://127.0.0.1:{port}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        # -- 静态资源 --
        code, body = _req(base, "/")
        chk("GET / 返回首页", code == 200 and "蓝队" in str(body), f"{code} {str(body)[:80]}")
        code, body = _req(base, "/static/style.css")
        chk("GET /static/style.css 正常", code == 200 and "--bg" in str(body), code)
        code, body = _req(base, "/static/../server.py")
        chk("静态服务拒绝目录穿越", code in (403, 404) or "import" not in str(body), code)
        code, body = _req(base, "/static/../../agent/config.yaml")
        chk("静态服务挡住上游穿越", code in (403, 404), code)

        # -- 令牌 --
        code, body = _req(base, "/api/status")
        chk("无令牌被拒绝（401）", code == 401, f"{code} {body}")
        code, body = _req(base, "/api/status", token="wrong-token")
        chk("错令牌被拒绝（401）", code == 401, code)
        code, body = _req(base, f"/api/status?token={token}")
        chk("URL 令牌可用（首屏加载路径）", code == 200 and "sensor" in body, f"{code} {str(body)[:80]}")

        # -- 各只读接口 --
        for path, key in (("/api/meta", "write_routes"), ("/api/status", "sensor"),
                          ("/api/configs", "configs"), ("/api/reports", "reports"),
                          ("/api/logs", "logs"), ("/api/threat", "gaps"),
                          ("/api/containment", "count"), ("/api/whitelist", "entries"),
                          ("/api/actions", "items"), ("/api/kape", "exe")):
            code, body = _req(base, path, token=token)
            chk(f"{path} 返回 200 且含 {key}", code == 200 and key in body,
                f"{code} {str(body)[:120]}")

        # -- 报告/日志读取 --
        code, body = _req(base, "/api/report?path=reports/triage_demo.md", token=token)
        chk("能读一份已知报告", code == 200 and body.get("text"), f"{code} {str(body)[:120]}")
        code, body = _req(base, "/api/report?path=agent/config.yaml", token=token)
        chk("报告接口拒绝非报告路径", code == 400 and "error" in body, f"{code} {body}")
        code, body = _req(base, "/api/log?path=logs/net_sensor.log&lines=5", token=token)
        chk("能读日志尾部", code == 200, code)
        code, body = _req(base, "/api/log?path=../../etc/passwd", token=token)
        chk("日志接口拒绝越权路径", code == 400, f"{code} {body}")

        # -- 写接口必须 POST --
        code, body = _req(base, "/api/config/write?path=agent/config.yaml", token=token)
        chk("写接口用 GET 被拒（405，防 <img> 误触发）", code == 405, f"{code} {body}")

        # -- 真正的写操作：白名单（可逆，且会留下审计） --
        code, body = _req(base, "/api/whitelist/add", token=token, method="POST",
                          body={"kind": "process", "value": r"D:\gui-selftest\x.exe",
                                "note": "HTTP 自检", "ttl_days": 0})
        chk("通过 HTTP 加白名单成功", code == 200 and body.get("ok"), f"{code} {body}")
        code, body = _req(base, "/api/whitelist/add", token=token, method="POST",
                          body={"kind": "folder",
                                "value": r"C:\Users\user\AppData\Local\Temp"})
        chk("HTTP 加临时目录被硬拒绝（400 + 原因）",
            code == 400 and body.get("kind") == "refused" and "可疑的目录" in str(body.get("error")),
            f"{code} {body}")
        code, body = _req(base, "/api/whitelist/remove", token=token, method="POST",
                          body={"kind": "process", "value": r"D:\gui-selftest\x.exe"})
        chk("通过 HTTP 移除白名单成功", code == 200 and body.get("removed"), f"{code} {body}")

        # -- 封锁：拒绝条件必须照旧生效 --
        code, body = _req(base, "/api/containment/add", token=token, method="POST",
                          body={"indicator": "192.168.1.0/24", "apply": False})
        chk("HTTP 封锁网段被拒绝",
            code == 200 and body.get("status") == "denied" and body.get("refused"),
            f"{code} {str(body)[:160]}")

        # -- 撤销：证据类需显式确认 --
        code, body = _req(base, "/api/undo", token=token, method="POST",
                          body={"kind": "vault", "payload": {"path": "logs/sandbox/vault/x"}})
        chk("HTTP 撤销证据需显式确认（400）",
            code == 400 and "确认删除证据" in str(body.get("error")), f"{code} {body}")

        # -- 未知路由 --
        code, body = _req(base, "/api/nope", token=token)
        chk("未知接口返回 404", code == 404, code)

        # -- 只读模式：所有写接口必须 403 --
        ro = build_server(host="127.0.0.1", port=0, token=token, read_only=True)
        roport = ro.server_address[1]
        robase = f"http://127.0.0.1:{roport}"
        threading.Thread(target=ro.serve_forever, daemon=True).start()
        try:
            code, body = _req(robase, "/api/meta", token=token)
            chk("只读模式的 /api/meta 仍可读（界面据此禁用按钮）", code == 200, code)
            for path, payload in (
                ("/api/config/write", {"path": "agent/config.yaml", "text": ""}),
                ("/api/containment/add", {"indicator": "203.0.113.9"}),
                ("/api/containment/remove", {}),
                ("/api/whitelist/add", {"kind": "process", "value": r"D:\x.exe"}),
                ("/api/whitelist/remove", {"kind": "process", "value": r"D:\x.exe"}),
                ("/api/undo", {"kind": "firewall", "payload": {}}),
                ("/api/kape/run", {"execute": True}),
                ("/api/kape/gui", {}),
                ("/api/open", {"path": "logs"}),
                ("/api/quit", {}),
            ):
                code, body = _req(robase, path, token=token, method="POST", body=payload)
                chk(f"只读模式 {path} → 403", code == 403,
                    f"{code} {str(body)[:100]}")
            code, body = _req(robase, "/api/status", token=token)
            chk("只读模式下读接口不受影响", code == 200, code)
        finally:
            ro.shutdown()
    finally:
        srv.shutdown()

    print(f"\ngui.server HTTP 自检：{ok} 通过 / {fail} 失败")
    return 1 if fail else 0


def serve(*, host: str = "127.0.0.1", port: int = DEFAULT_PORT,
          read_only: bool = False, token: str = "",
          open_browser: bool = False, tray: bool = True,
          verbose: bool = False, auto_port: bool = True) -> int:
    """启动服务。`tray=True` 时消息循环占主线程，HTTP 跑后台线程。"""
    # 安全底线：这个界面能改封锁、能写配置，绝不能监听外部网卡
    if host not in ("127.0.0.1", "localhost", "::1"):
        _log(f"拒绝绑定 {host}：控制台只允许本机访问")
        print(f"错误：控制台只允许绑定 127.0.0.1（收到 {host}）", file=sys.stderr)
        return 2

    if auto_port:
        port = _free_port(host, port)
    srv = build_server(host=host, port=port, token=token, read_only=read_only,
                       verbose=verbose)
    url = f"http://{host}:{port}/?token={srv.token}"
    _log(f"启动：{url}  只读={read_only} 托盘={tray}")

    cfg = {
        "url": url,
        "host": host,
        "port": port,
        "read_only": read_only,
        "pid": os.getpid(),
        "started": time.strftime("%Y-%m-%d %H:%M:%S"),
        "token_hint": srv.token[:6] + "…",
    }
    (PROJECT_ROOT / "logs/gui_runtime.json").write_text(
        json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")

    if sys.stdout and hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
        print("=" * 72)
        print("  蓝队 Agent 控制台已启动" + ("（只读模式）" if read_only else ""))
        print(f"  地址：{url}")
        print("  托盘图标：左键单击打开控制台，右键出菜单")
        print("=" * 72)

    t = threading.Thread(target=srv.serve_forever, daemon=True, name="gui-http")
    t.start()

    # 后台预热（不阻塞启动）。第一次问状态时要把 KAPE 探测、防火墙查询、进程枚举
    # 都跑一遭，冷启动约 15 秒 —— 那正好是用户打开界面、盯着一排"…"的时候。
    # 服务自己起来时就把这些跑完，用户看到的就都是缓存值。
    def _warm() -> None:
        t0 = time.time()
        try:
            core.status()
            core.threat_model()
            _log(f"预热完成，耗时 {time.time() - t0:.1f}s（首屏状态查询将直接命中缓存）")
        except Exception as exc:  # noqa: BLE001
            _log(f"预热失败（不影响使用）：{type(exc).__name__}: {exc}")

    threading.Thread(target=_warm, daemon=True, name="gui-warmup").start()

    if open_browser:
        threading.Timer(0.6, lambda: _open(url)).start()

    if tray:
        try:
            from gui.tray import TrayIcon
            icon = TrayIcon(url=url, tooltip="蓝队 Agent 控制台",
                            status_text=status_line, logger=_log,
                            on_exit=lambda: (srv.shutdown(), _log("退出：托盘")))
            srv.shutdown_cb = icon.shutdown

            def _watch() -> None:            # HTTP 侧 /api/quit 也走同一条退出路径
                while not icon._stop.is_set():      # noqa: SLF001
                    time.sleep(0.5)
                _log("退出：HTTP /api/quit")
            threading.Thread(target=_watch, daemon=True, name="gui-quit-watch").start()

            icon.run()                      # 阻塞在消息循环
            srv.shutdown()
            _log("已退出")
            return 0
        except Exception as exc:  # noqa: BLE001
            _log(f"托盘启动失败，退回无托盘模式：{type(exc).__name__}: {exc}")
            print(f"  [警告] 托盘图标启动失败：{exc}", file=sys.stderr)
            print(f"  [提示] 直接从浏览器打开：{url}", file=sys.stderr)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        srv.shutdown()
        _log("已退出")
    return 0


def _open(url: str) -> None:
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:  # noqa: BLE001
        try:
            os.startfile(url)  # noqa: S606
        except Exception:  # noqa: BLE001
            pass


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(
        description="蓝队 Agent 本地控制台（只绑 127.0.0.1，令牌保护）")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--read-only", action="store_true",
                    help="只读模式：所有写操作返回 403")
    ap.add_argument("--token", default="", help="指定令牌（默认随机生成）")
    ap.add_argument("--open", dest="open_browser", action="store_true",
                    help="启动后自动打开浏览器")
    ap.add_argument("--no-tray", dest="tray", action="store_false", default=True,
                    help="不显示托盘图标（前台调试用）")
    ap.add_argument("--no-auto-port", dest="auto_port", action="store_false",
                    default=True, help="端口被占时直接报错，不自动换端口")
    ap.add_argument("-v", "--verbose", action="store_true", help="记录每个请求")
    ap.add_argument("--selftest", action="store_true", help="跑核心自检后退出")
    args = ap.parse_args(argv)

    if args.selftest:
        rc = core.selftest()
        try:
            from gui.tray import selftest as tselftest
            rc = max(rc, tselftest())
        except Exception as exc:  # noqa: BLE001
            print(f"托盘自检跳过：{exc}")
        rc = max(rc, http_selftest())
        return rc

    return serve(host=args.host, port=args.port, read_only=args.read_only,
                 token=args.token, open_browser=args.open_browser, tray=args.tray,
                 verbose=args.verbose, auto_port=args.auto_port)


if __name__ == "__main__":
    raise SystemExit(main())
