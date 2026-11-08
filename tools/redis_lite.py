"""极简 RESP（Redis 序列化协议）客户端 —— **只用标准库**。

为什么不用 `pip install redis`：
  1) 树莓派侧要装 Python 依赖会牵出一堆 apt/pip 版本问题（Ubuntu 22.04 的
     `python3-redis` 是 3.5.3，另装 pip 包又可能和系统包冲突）；
  2) PC 侧当前环境**没有** redis 包，本项目的原则是「能不加依赖就不加」；
  3) 我们只需要 5 个命令（PING / XADD / XLEN / XREADGROUP / XACK），
     写一个 200 行的协议实现比引入依赖更可控。

另外内置一个**内存假服务器**（`FakeRedisServer`），用于在没有树莓派、没有
Redis 的机器上端到端验证链路：`python tools/redis_lite.py --selftest`。

支持的命令子集：
    PING / AUTH / SELECT
    XADD   key [MAXLEN ~ n] * k v ...
    XLEN   key
    XRANGE key - + COUNT n
    XREADGROUP GROUP g c [COUNT n] [BLOCK ms] STREAMS key id...  (含 ">")
    XACK   key group id
    XPENDING key group
    XAUTOCLAIM key group consumer min-idle-time start [COUNT n]   （简化为可用的子集）
    DEL / FLUSHALL（仅假服务器）

⚠ 不实现集群、流水线批量返回的复杂分支、RESP3。够用即可，多余的一律不做。
"""
from __future__ import annotations

import argparse
import socket
import socketserver
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

__all__ = ["RedisError", "Redis", "FakeRedisServer", "encode_command", "selftest"]

CRLF = b"\r\n"


class RedisError(RuntimeError):
    pass


# ------------------------------------------------------------------ 编码

def encode_command(args: Sequence[Union[str, bytes, int]]) -> bytes:
    """把命令编成 RESP 数组（客户端 -> 服务器）。"""
    out = [b"*" + str(len(args)).encode() + CRLF]
    for a in args:
        b = a if isinstance(a, bytes) else str(a).encode("utf-8")
        out.append(b"$" + str(len(b)).encode() + CRLF)
        out.append(b + CRLF)
    return b"".join(out)


def _read_line(fh) -> bytes:
    line = fh.readline()
    if not line.endswith(CRLF):
        raise RedisError(f"协议错误：行未以 CRLF 结束（收到 {line[:40]!r}）")
    return line[:-2]


def _read_reply(fh) -> Any:
    """解析一条 RESP 回复。返回 str/int/None/list/bytes。"""
    t = fh.read(1)
    if not t:
        raise RedisError("连接被对端关闭")
    if t == b"+":
        return _read_line(fh).decode("utf-8", "replace")
    if t == b"-":
        raise RedisError(_read_line(fh).decode("utf-8", "replace"))
    if t == b":":
        return int(_read_line(fh))
    if t == b"$":
        n = int(_read_line(fh))
        if n == -1:
            return None
        data = fh.read(n + 2)
        return data[:-2]
    if t == b"*":
        n = int(_read_line(fh))
        if n == -1:
            return None
        return [_read_reply(fh) for _ in range(n)]
    raise RedisError(f"未知回复类型 {t!r}")


def _dec(x: Any) -> Any:
    """把 bytes 递归解成 str（保住数字/空值语义）。"""
    if isinstance(x, bytes):
        return x.decode("utf-8", "replace")
    if isinstance(x, list):
        return [_dec(i) for i in x]
    return x


# ------------------------------------------------------------------ 客户端

class Redis:
    """阻塞式 RESP 客户端。**一个实例只能被一个线程用**。

    原因：RESP 是「请求-回复」串行协议，阻塞式 `XREADGROUP ... BLOCK` 会占住整条
    连接。如果在另一个线程用同一个实例发命令，它会等前一个命令返回才能写出去 ——
    表现为「永远等超时」。需要并发就**多建几个实例**（各一条连接），
    这也是本项目 bridge 的做法（读线程 / 心跳线程分开）。
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 6379,
                 password: str = "", db: int = 0, connect_timeout: float = 5.0,
                 read_timeout: float = 30.0) -> None:
        self.host, self.port = host, int(port)
        self.password, self.db = password, db
        self.connect_timeout, self.read_timeout = connect_timeout, read_timeout
        self._sock: Optional[socket.socket] = None
        self._fh: Any = None
        self._lock = threading.RLock()
        # 最近一次被"降级处理"的错误。**不要静默吞掉错误**：
        # 早期版本把 NOGROUP 直接当成「没数据」返回 {}，
        # 结果掩盖了服务端参数解析 bug，排查花了很久。
        self.last_error: Optional[str] = None

    # -- 连接管理 --------------------------------------------------
    def _connect(self) -> None:
        s = socket.create_connection((self.host, self.port), timeout=self.connect_timeout)
        s.settimeout(self.read_timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._sock, self._fh = s, s.makefile("rb")
        if self.password:
            self._send_raw(["AUTH", self.password])
        if self.db:
            self._send_raw(["SELECT", self.db])

    def close(self) -> None:
        with self._lock:
            try:
                if self._sock:
                    self._sock.close()
            except OSError:
                pass
            self._sock = self._fh = None

    def ping(self) -> bool:
        return self.cmd("PING") in ("PONG", b"PONG")

    # -- 通用执行 --------------------------------------------------
    def cmd(self, *args: Union[str, bytes, int], timeout: Optional[float] = None) -> Any:
        with self._lock:
            return self._send_raw(list(args), timeout=timeout)

    def _send_raw(self, args: List[Any], timeout: Optional[float] = None) -> Any:
        last: Optional[Exception] = None
        for attempt in (1, 2):  # 第一次失败就重连再试一次（网络抖动保护）
            try:
                if self._sock is None:
                    self._connect()
                if timeout is not None:
                    self._sock.settimeout(timeout)
                self._sock.sendall(encode_command(args))
                return _dec(_read_reply(self._fh))
            except (RedisError, OSError, ValueError) as exc:
                last = exc
                self.close()
                if attempt == 2:
                    break
                time.sleep(0.2)
        raise RedisError(f"命令 {args[0] if args else '?'} 失败：{last}")

    # -- Streams 便捷方法 ------------------------------------------
    def xadd(self, key: str, fields: Dict[str, Any], maxlen: int = 0,
             approximate: bool = True) -> str:
        args: List[Any] = ["XADD", key]
        if maxlen > 0:
            args += ["MAXLEN", "~" if approximate else "=", int(maxlen)]
        args.append("*")
        for k, v in fields.items():
            args += [k, v if isinstance(v, bytes) else str(v)]
        return str(self.cmd(*args))

    def xlen(self, key: str) -> int:
        try:
            return int(self.cmd("XLEN", key))
        except RedisError:
            return 0

    def xrange(self, key: str, count: int = 100) -> List[Tuple[str, Dict[str, str]]]:
        r = self.cmd("XRANGE", key, "-", "+", "COUNT", int(count))
        return [_flat(item) for item in (r or [])]

    def ensure_group(self, key: str, group: str, mkstream: bool = True) -> bool:
        """建消费组；已存在返回 False。从 `$` 开始（只看新事件）。"""
        try:
            self.cmd("XGROUP", "CREATE", key, group, "$", "MKSTREAM" if mkstream else "")
            return True
        except RedisError as exc:
            if "BUSYGROUP" in str(exc):
                return False
            # MKSTREAM 传空串在老版本会被拒，退回不带该参数
            try:
                self.cmd("XGROUP", "CREATE", key, group, "$")
                return True
            except RedisError as exc2:
                if "BUSYGROUP" in str(exc2):
                    return False
                raise

    def read_group(self, group: str, consumer: str, keys: Sequence[str],
                   count: int = 32, block_ms: int = 5000) -> Dict[str, List[Tuple[str, Dict[str, str]]]]:
        """XREADGROUP。返回 {stream: [(id, fields), ...]}；超时返回 {}。"""
        args: List[Any] = ["XREADGROUP", "GROUP", group, consumer, "COUNT", int(count)]
        if block_ms > 0:
            args += ["BLOCK", int(block_ms)]
        args += ["STREAMS", *keys, *([">"] * len(keys))]
        try:
            r = self.cmd(*args, timeout=(block_ms / 1000.0 + self.read_timeout) if block_ms else None)
        except RedisError as exc:
            # 组不存在（尚未创建）或阻塞读超时都算「这轮没数据」。
            # 但**记下原因**，否则真出问题时表现成“一直没数据”，无从下手。
            if "NOGROUP" in str(exc) or "timeout" in str(exc).lower():
                self.last_error = str(exc)
                return {}
            raise
        self.last_error = None
        if not r:
            return {}
        out: Dict[str, List[Tuple[str, Dict[str, str]]]] = {}
        for stream, items in r:
            out[str(stream)] = [_flat(i) for i in items]
        return out

    def ack(self, key: str, group: str, ids: Iterable[str]) -> int:
        ids = list(ids)
        if not ids:
            return 0
        return int(self.cmd("XACK", key, group, *ids))

    def pending_count(self, key: str, group: str) -> int:
        try:
            r = self.cmd("XPENDING", key, group)
            return int(r[0]) if isinstance(r, list) and r else 0
        except (RedisError, TypeError, ValueError):
            return 0

    def pending_range(self, key: str, group: str, count: int = 100,
                      consumer: str = "") -> List[Dict[str, Any]]:
        """XPENDING 的扩展形式：列出未确认条目的 (id, 消费者, 空闲毫秒)。

        ⚠ 为什么不用 XAUTOCLAIM：它是 **Redis 6.2** 才有的，
        Ubuntu 22.04 自带的是 6.0.16 —— 直接用它会在真机上报
        "ERR unknown command"。所以这里走 6.0 就支持的
        XPENDING(扩展) + XCLAIM 组合。
        """
        args: List[Any] = ["XPENDING", key, group, "-", "+", int(count)]
        if consumer:
            args.append(consumer)
        try:
            rows = self.cmd(*args)
        except RedisError:
            return []
        out: List[Dict[str, Any]] = []
        for row in rows or []:
            if isinstance(row, list) and len(row) >= 4:
                out.append({"id": str(row[0]), "consumer": str(row[1]),
                            "idle_ms": int(row[2]), "deliveries": int(row[3])})
        return out

    def xclaim(self, key: str, group: str, consumer: str, min_idle_ms: int,
               ids: Sequence[str], justid: bool = False) -> List[Any]:
        """把别人（或上一次运行留下的）未确认条目改归自己。"""
        if not ids:
            return []
        args: List[Any] = ["XCLAIM", key, group, consumer, int(min_idle_ms), *ids]
        if justid:
            args.append("JUSTID")
        r = self.cmd(*args)
        if justid:
            return list(r or [])
        return [_flat(i) for i in (r or [])]


def _flat(item: Any) -> Tuple[str, Dict[str, str]]:
    """XRANGE/XREADGROUP 的条目 -> (id, {field: value})。"""
    if hasattr(item, "id"):  # redis-py 风格
        return str(item.id), dict(item.fields)
    if isinstance(item, list) and len(item) == 2:
        return str(item[0]), {str(item[1][i]): str(item[1][i + 1])
                              for i in range(0, len(item[1]) - 1, 2)}
    if isinstance(item, tuple) and len(item) == 2:
        return _flat(list(item))
    return "", {}


# ------------------------------------------------------- 内存假服务器（仅测试）

class _StreamStore:
    def __init__(self) -> None:
        self.streams: Dict[str, List[Tuple[str, Dict[str, str]]]] = {}
        self.groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.lock = threading.RLock()
        # BLOCK 语义靠条件变量实现：XADD 唤醒等待中的 XREADGROUP。
        # 不实现 BLOCK 的话，消费端只能空转轮询（CPU 白烧）。
        self.cond = threading.Condition(self.lock)
        self.seq = 0

    def next_id(self, key: str) -> str:
        self.seq += 1
        return f"{int(time.time() * 1000)}-{self.seq}"


class _Handler(socketserver.StreamRequestHandler):
    timeout = 60

    def handle(self) -> None:
        store: _StreamStore = self.server.store  # type: ignore[attr-defined]
        while True:
            try:
                cmd = _read_reply(self.rfile)
            except (RedisError, OSError, ValueError):
                return
            if not cmd:
                return
            cmd = _dec(cmd)  # 客户端发来的 bulk string 是 bytes，必须解码
            name = str(cmd[0]).upper()
            args = [str(a) for a in cmd[1:]]
            try:
                resp = self._dispatch(store, name, args)
            except RedisError as exc:
                self.wfile.write(b"-ERR " + str(exc).encode() + CRLF)
                continue
            self.wfile.write(_encode_reply(resp))

    @staticmethod
    def _dispatch(store: _StreamStore, name: str, a: List[str]) -> Any:
        with store.cond:
            if name == "PING":
                return "PONG"
            if name in ("AUTH", "SELECT"):
                return "OK"
            if name == "FLUSHALL":
                store.streams.clear()
                store.groups.clear()
                return "OK"
            if name == "DEL":
                return sum(1 for k in a if store.streams.pop(k, None) is not None)
            if name == "XLEN":
                return len(store.streams.get(a[0], []))
            if name == "XADD":
                key = a[0]
                i = 1
                maxlen = 0
                while i < len(a) and a[i].upper() in ("MAXLEN", "NOMKSTREAM"):
                    if a[i].upper() == "MAXLEN":
                        i += 1
                        if a[i] in ("~", "="):
                            i += 1
                        maxlen = int(a[i])
                    i += 1
                if a[i] == "*":
                    i += 1
                fields = {a[j]: a[j + 1] for j in range(i, len(a) - 1, 2)}
                sid = store.next_id(key)
                store.streams.setdefault(key, []).append((sid, fields))
                if maxlen > 0:
                    store.streams[key] = store.streams[key][-maxlen:]
                store.cond.notify_all()   # 唤醒阻塞中的消费者
                return sid
            if name == "XRANGE":
                items = store.streams.get(a[0], [])
                cnt = int(a[a.index("COUNT") + 1]) if "COUNT" in a else len(items)
                return [[i, [x for kv in f.items() for x in kv]] for i, f in items[:cnt]]
            if name == "XGROUP":
                sub, key, group = a[0].upper(), a[1], a[2]
                if sub != "CREATE":
                    raise RedisError("不支持该 XGROUP 子命令")
                gk = (key, group)
                if gk in store.groups:
                    raise RedisError("BUSYGROUP Consumer Group name already exists")
                items = store.streams.setdefault(key, [])
                # `$` 必须在**建组时刻**解析成当时 stream 的末位 id（真 Redis 也是这个语义），
                # 否则组会永远停在 "$" 上、新事件永远投递不出去。
                last = a[3] if len(a) > 3 else "$"
                if last == "$":
                    last = items[-1][0] if items else "0-0"
                store.groups[gk] = {"last": last, "pending": {}}
                return "OK"
            if name == "XREADGROUP":
                gi = a.index("STREAMS")
                si = a.index("GROUP")
                group, consumer = a[si + 1], a[si + 2]
                cnt = int(a[a.index("COUNT") + 1]) if "COUNT" in a else 100
                # ⚠ STREAMS 后面是「前半 key + 后半 id」，必须对半切。
                # 早期版本把 id（如 ">"）也当成 key 去查消费组，
                # 结果第一条 key 已经投递、第二条 key 报 NOGROUP，
                # 而客户端又把 NOGROUP 当成「组不存在」静默返回 {} ——
                # 症状是「pending 有值但读不到数据」，极难排查。
                rest = a[gi + 1:]
                half = len(rest) // 2
                keys = rest[:half]
                block_ms = int(a[a.index("BLOCK") + 1]) if "BLOCK" in a else 0
                deadline = time.monotonic() + block_ms / 1000.0 if block_ms > 0 else 0.0

                def _collect() -> List[Any]:
                    acc: List[Any] = []
                    for key in keys:
                        gk = (key, group)
                        if gk not in store.groups:
                            raise RedisError("NOGROUP No such key or consumer group")
                        g = store.groups[gk]
                        items = store.streams.get(key, [])
                        new = ([x for x in items if _id_gt(x[0], str(g["last"]))]
                               if g["last"] != "$" else [])
                        if new:
                            g["last"] = new[-1][0]
                        new = new[:cnt]
                        for sid, f in new:
                            g["pending"][sid] = {"consumer": consumer,
                                                 "since": time.monotonic(),
                                                 "deliveries": 1}
                        if new:
                            acc.append([key, [[i, [x for kv in f.items() for x in kv]]
                                              for i, f in new]])
                    return acc

                out = _collect()
                while not out and deadline and time.monotonic() < deadline:
                    store.cond.wait(timeout=min(0.25, max(0.01, deadline - time.monotonic())))
                    out = _collect()
                return out or None
            if name == "XACK":
                g = store.groups.get((a[0], a[1]))
                if not g:
                    return 0
                n = 0
                for sid in a[2:]:
                    if g["pending"].pop(sid, None) is not None:
                        n += 1
                return n
            if name == "XPENDING":
                g = store.groups.get((a[0], a[1]))
                if not g:
                    raise RedisError("NOGROUP")
                if len(a) <= 2:                       # 简介形式
                    return [len(g["pending"]), None, None, []]
                cnt = int(a[4]) if len(a) > 4 and a[4].lstrip("-").isdigit() else 100
                only = a[5] if len(a) > 5 else ""
                now = time.monotonic()
                rows = []
                for sid in list(g["pending"].keys()):
                    rec = g["pending"][sid]
                    if only and rec["consumer"] != only:
                        continue
                    rows.append([sid, rec["consumer"],
                                 int((now - rec["since"]) * 1000), rec["deliveries"]])
                return rows[:cnt]
            if name == "XCLAIM":
                key, group_name, consumer = a[0], a[1], a[2]
                min_idle = int(a[3])
                rest = a[4:]
                justid = "JUSTID" in rest
                ids = [x for x in rest if not x.isupper() or x in ("-", "+")]
                g = store.groups.get((key, group_name))
                if not g:
                    raise RedisError("NOGROUP")
                now = time.monotonic()
                items = {i: f for i, f in store.streams.get(key, [])}
                taken = []
                for sid in ids:
                    rec = g["pending"].get(sid)
                    if rec is None:
                        continue
                    if rec["consumer"] == consumer or \
                            (now - rec["since"]) * 1000 >= min_idle:
                        rec["consumer"] = consumer
                        rec["since"] = now
                        rec["deliveries"] = rec.get("deliveries", 1) + 1
                        taken.append(sid)
                if justid:
                    return taken
                return [[i, [x for kv in items.get(i, {}).items() for x in kv]]
                        for i in taken]
            raise RedisError(f"假服务器不支持命令 {name}")


def _id_gt(x: str, y: str) -> bool:
    def key(s: str) -> Tuple[int, int]:
        p = s.split("-")
        return int(p[0]), int(p[1]) if len(p) > 1 else 0
    return key(x) > key(y)


def _encode_reply(x: Any) -> bytes:
    if x is None:
        return b"$-1" + CRLF
    if isinstance(x, bool):
        x = int(x)
    if isinstance(x, int):
        return b":" + str(x).encode() + CRLF
    if isinstance(x, (str, bytes)):
        b = x if isinstance(x, bytes) else x.encode()
        return b"$" + str(len(b)).encode() + CRLF + b + CRLF
    if isinstance(x, (list, tuple)):
        body = b"".join(_encode_reply(i) for i in x)
        return b"*" + str(len(x)).encode() + CRLF + body
    raise RedisError(f"无法编码类型 {type(x)}")


class FakeRedisServer:
    """内存 Redis 子集，用来在无 Pi / 无 Redis 的机器上跑通整条链路。"""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._srv = socketserver.ThreadingTCPServer((host, port), _Handler)
        self._srv.daemon_threads = True
        self._srv.store = _StreamStore()  # type: ignore[attr-defined]
        self.host, self.port = self._srv.server_address[0], self._srv.server_address[1]
        self._th = threading.Thread(target=self._srv.serve_forever, daemon=True)

    def start(self) -> "FakeRedisServer":
        self._th.start()
        return self

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()

    def __enter__(self) -> "FakeRedisServer":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()


# ------------------------------------------------------------------ 自检

def selftest() -> int:
    ok = fail = 0

    def chk(name: str, cond: bool, extra: str = "") -> None:
        nonlocal ok, fail
        if cond:
            ok += 1
            print(f"  [OK] {name}")
        else:
            fail += 1
            print(f"  [FAIL] {name} {extra}")

    # 编码
    # 5 个参数 -> 数组头必须是 *5（这里曾经把期望值写成 *6，自检立刻抓到）
    chk("命令编码", encode_command(["XADD", "s", "*", "a", "1"])
        == b"*5\r\n$4\r\nXADD\r\n$1\r\ns\r\n$1\r\n*\r\n$1\r\na\r\n$1\r\n1\r\n")
    chk("非 ASCII 编码", b"$3\r\n\xe5\xa5\xbd\r\n" in encode_command(["x", "好"]))

    with FakeRedisServer() as srv:
        r = Redis(srv.host, srv.port, read_timeout=5)
        chk("PING", r.ping())

        # `$` 的语义：**建组时刻**的末位 id 才算"已有"。
        # 所以必须先有事件再建组，否则空 stream 上 `$` 解析为 0-0，第一条新事件也会被投递。
        r.xadd("suricata:eve", {"kind": "before"})
        chk("建组", r.ensure_group("suricata:eve", "g1") is True)
        chk("重复建组返回 False", r.ensure_group("suricata:eve", "g1") is False)
        got = r.read_group("g1", "c1", ["suricata:eve"], block_ms=0)
        chk("建组不投递历史事件", got == {}, str(got))

        i1 = r.xadd("suricata:eve", {"kind": "alert", "msg": "ET TROJAN 好"})
        chk("XADD 返回 id", "-" in i1, i1)
        chk("XLEN", r.xlen("suricata:eve") == 2, str(r.xlen("suricata:eve")))

        got = r.read_group("g1", "c1", ["suricata:eve"], count=10, block_ms=0)
        items = got.get("suricata:eve", [])
        chk("新事件被投递", len(items) == 1, str(got))
        chk("字段还原（含中文）", items and items[0][1].get("msg") == "ET TROJAN 好", str(items))
        chk("待确认数=1", r.pending_count("suricata:eve", "g1") == 1)

        # 未 ACK 前不应重复投递（> 只投递新事件）
        again = r.read_group("g1", "c1", ["suricata:eve"], block_ms=0)
        chk("已投递未 ACK 不重复投递", again == {}, str(again))

        chk("XACK", r.ack("suricata:eve", "g1", [items[0][0]]) == 1)
        chk("ACK 后 pending 归零", r.pending_count("suricata:eve", "g1") == 0)

        # ---- 未确认条目的回收（Redis 6.0 没有 XAUTOCLAIM，必须走 XPENDING+XCLAIM）----
        r.xadd("suricata:eve", {"kind": "crash-leftover"})
        got = r.read_group("g1", "c1", ["suricata:eve"], block_ms=0)
        left = (got.get("suricata:eve") or [])
        chk("拿到一条待处理", len(left) == 1, str(got))
        pend = r.pending_range("suricata:eve", "g1", count=10)
        chk("XPENDING 扩展形式可见未确认条目", len(pend) == 1 and pend[0]["consumer"] == "c1",
            str(pend))
        chk("min-idle 未到时不被抢", r.xclaim("suricata:eve", "g1", "c2", 60000,
                                              [pend[0]["id"]]) == [])
        claimed = r.xclaim("suricata:eve", "g1", "c2", 0, [pend[0]["id"]])
        chk("XCLAIM 接手遗留条目并带回字段",
            len(claimed) == 1 and claimed[0][1].get("kind") == "crash-leftover",
            str(claimed))
        chk("接手后归属变更",
            (r.pending_range("suricata:eve", "g1", 10) or [{}])[0].get("consumer") == "c2")
        r.ack("suricata:eve", "g1", [pend[0]["id"]])
        chk("再 ACK 后清空", r.pending_count("suricata:eve", "g1") == 0)

        # MAXLEN 修剪
        for n in range(20):
            r.xadd("trim", {"n": n}, maxlen=5)
        chk("MAXLEN 修剪到 5", r.xlen("trim") == 5, str(r.xlen("trim")))
        # XRANGE 从最旧往新返回，所以要断言**最后一条**是 19（修剪先丢最旧的）
        chk("修剪保留最新", r.xrange("trim", 5)[-1][1]["n"] == "19",
            str(r.xrange("trim", 5)))

        # XRANGE
        chk("XRANGE 计数", len(r.xrange("trim", 3)) == 3)

        # 断线自动重连
        r.close()
        chk("重连后仍可用", r.xlen("trim") == 5)

        # 超时 BLOCK 不应抛异常
        t0 = time.time()
        chk("BLOCK 超时返回空", r.read_group("g1", "c1", ["suricata:eve"], block_ms=300) == {})
        chk("BLOCK 真的等了", 0.2 < time.time() - t0 < 5, f"{time.time() - t0:.2f}s")

        # BLOCK 期间有新事件应立即返回（不是等满超时）
        writer = Redis(srv.host, srv.port)   # ⚠ 必须用**独立连接**：
        # 同一个实例在阻塞读期间是占住的，另一线程用它发命令会一直等到超时。

        def _late_add() -> None:
            time.sleep(0.3)
            writer.xadd("suricata:eve", {"kind": "late"})

        threading.Thread(target=_late_add, daemon=True).start()
        t0 = time.time()
        got = r.read_group("g1", "c1", ["suricata:eve"], count=5, block_ms=5000)
        spent = time.time() - t0
        chk("阻塞中被新事件唤醒", bool(got), str(got))
        chk("唤醒比超时早得多", spent < 2.0, f"{spent:.2f}s")
        writer.close()

        # 组不存在 -> 空而非崩
        chk("未知组不崩", r.read_group("nogroup", "c", ["suricata:eve"], block_ms=0) == {})

        # 连不上的服务器要抛 RedisError（而不是卡死）
        bad = Redis("127.0.0.1", 1, connect_timeout=0.5, read_timeout=0.5)
        try:
            bad.ping()
            chk("连不上抛异常", False, "未抛")
        except RedisError:
            chk("连不上抛异常", True)

    print(f"\nredis_lite 自检：{ok} 通过 / {fail} 失败")
    return 1 if fail else 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="极简 RESP 客户端 + 内存假服务器（零依赖）")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--serve-fake", action="store_true", help="起一个内存假 Redis（测试用）")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0, help="假服务器端口（0=随机）")
    ap.add_argument("--smoke", action="store_true", help="对真实 Redis 做一次连通性检查")
    ap.add_argument("--password", default="")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if args.serve_fake:
        srv = FakeRedisServer(args.host, args.port).start()
        print(f"假 Redis 已监听 {srv.host}:{srv.port}（Ctrl+C 退出）", flush=True)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            srv.stop()
        return 0
    if args.smoke:
        r = Redis(args.host, args.port or 6379, password=args.password)
        print("PING:", r.ping())
        print("XLEN suricata:eve:", r.xlen("suricata:eve"))
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
