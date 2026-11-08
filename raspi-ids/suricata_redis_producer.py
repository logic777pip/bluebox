#!/usr/bin/env python3
"""Suricata eve 事件 -> Redis Stream 转发器（树莓派侧，**仅用 Python 标准库**）。

设计要点（每一条都是刻意的）：

1) **单文件自包含**：内置极简 RESP 客户端，树莓派上不需要 `pip install redis`，
   也不需要本项目仓库。拷贝这一个文件 + 一个 systemd unit 就能跑。
   （Ubuntu 22.04 的 `python3-redis` 是 3.5.3，另装 pip 包又和系统包打架，
   而标准库版本没有任何依赖问题。）

2) **不做载荷上传**：Suricata 的 `payload` / `payload_printable` 字段一律丢弃。
   - 带宽：镜像口全量载荷转发会打爆 LAN，且 PC 侧也消化不了；
   - 隐私：PC 上只存放"元数据 + 规则名"。
   PC 侧 AI 需要的是"哪条规则命中、什么五元组、什么应用层特征（SNI/UA/域名）"，
   这些字段足够研判。

3) **Pi 上只做归一化与限速，不做判定**。判定权在 PC 的 AI 系统。
   这里唯一做的"过滤"是带宽控制（按事件类型、按 severity），不是安全判定。

4) **断连不丢数据**：Redis 不可达时写入本地 spool 文件（有上限，满了丢最旧），
   恢复后按序补发。否则 PC 侧只是重启一下 Redis，就会静默丢掉整段流量。

5) **默认不转发 `flow` 事件**：一个镜像口每秒能产生上万条 flow，
   转发它们既没信息量（AI 看的是 alert + 应用层事件）又会把 LAN 打满。

用法：
    python3 suricata_redis_producer.py --broker 192.168.1.50:6379 --password XXX
    python3 suricata_redis_producer.py --selftest
    python3 suricata_redis_producer.py --dry-run --eve-path /var/log/suricata/eve.json
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, Iterator, List, Optional, Sequence, Tuple

VERSION = "1.0"
CRLF = b"\r\n"

# 默认转发的事件类型。flow 刻意不在其中（见文件头第 5 条）。
DEFAULT_FORWARD = ("alert", "dns", "tls", "http", "ssh", "fileinfo", "anomaly",
                   "smb", "dcerpc", "krb5", "nfs", "ikev2")

# 每种事件只保留这些字段（None 表示"整段保留但受 max_bytes 限制"）
KEEP: Dict[str, List[str]] = {
    "alert": ["timestamp", "event_type", "flow_id", "in_iface", "src_ip", "src_port",
              "dest_ip", "dest_port", "proto", "app_proto", "pkt_src", "host", "direction",
              "alert", "flow", "http", "dns", "tls", "ssh", "fileinfo", "payload_dropped"],
    "dns": ["timestamp", "event_type", "flow_id", "src_ip", "src_port", "dest_ip",
            "dest_port", "proto", "dns", "app_proto"],
    "tls": ["timestamp", "event_type", "flow_id", "src_ip", "src_port", "dest_ip",
            "dest_port", "proto", "tls", "app_proto"],
    "http": ["timestamp", "event_type", "flow_id", "src_ip", "src_port", "dest_ip",
             "dest_port", "proto", "http", "app_proto"],
    "ssh": ["timestamp", "event_type", "flow_id", "src_ip", "src_port", "dest_ip",
            "dest_port", "proto", "ssh", "app_proto"],
    "fileinfo": ["timestamp", "event_type", "flow_id", "src_ip", "src_port", "dest_ip",
                 "dest_port", "proto", "fileinfo", "app_proto"],
    "anomaly": ["timestamp", "event_type", "flow_id", "src_ip", "src_port", "dest_ip",
                "dest_port", "proto", "anomaly", "app_proto"],
}

# 这些字段是"大块内容"，一律丢弃（隐私 + 带宽）
DROP_KEYS = {"payload", "payload_printable", "packet", "packet_info", "stream",
             "data", "raw", "response_body", "request_body"}

# 单条 JSON 最大字节（eve.json 里 DNS 应答可以很长；不做上限会把内存吃光）
MAX_LINE = 256 * 1024


# ==================================================== 极简 RESP 客户端（内置）

class RespError(RuntimeError):
    pass


class Resp:
    """极简 RESP 客户端。一个实例 = 一条连接，**不要跨线程共用**。"""

    def __init__(self, host: str, port: int, password: str = "", db: int = 0,
                 connect_timeout: float = 5.0, read_timeout: float = 10.0) -> None:
        self.host, self.port = host, int(port)
        self.password, self.db = password, db
        self.connect_timeout, self.read_timeout = connect_timeout, read_timeout
        self._sock: Optional[socket.socket] = None
        self._fh: Any = None

    def _connect(self) -> None:
        s = socket.create_connection((self.host, self.port), timeout=self.connect_timeout)
        s.settimeout(self.read_timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._sock, self._fh = s, s.makefile("rb")
        if self.password:
            self._exec(["AUTH", self.password])
        if self.db:
            self._exec(["SELECT", str(self.db)])

    def close(self) -> None:
        try:
            if self._sock:
                self._sock.close()
        except OSError:
            pass
        self._sock = self._fh = None

    def cmd(self, *args: Any) -> Any:
        try:
            return self._exec([str(a) for a in args])
        except (RespError, OSError, ValueError):
            self.close()          # 出错就断开，下次调用重连
            raise

    def _exec(self, args: List[str]) -> Any:
        if self._sock is None:
            self._connect()
        buf = [b"*" + str(len(args)).encode() + CRLF]
        for a in args:
            b = a.encode("utf-8", "replace")
            buf.append(b"$" + str(len(b)).encode() + CRLF + b + CRLF)
        self._sock.sendall(b"".join(buf))
        return self._read()

    def _read(self) -> Any:
        t = self._fh.read(1)
        if not t:
            raise RespError("连接被对端关闭")
        if t == b"+":
            return self._line()
        if t == b"-":
            raise RespError(self._line())
        if t == b":":
            return int(self._line())
        if t == b"$":
            n = int(self._line())
            if n == -1:
                return None
            d = self._fh.read(n + 2)
            return d[:-2].decode("utf-8", "replace")
        if t == b"*":
            n = int(self._line())
            if n == -1:
                return None
            return [self._read() for _ in range(n)]
        raise RespError(f"未知回复类型 {t!r}")

    def _line(self) -> str:
        line = self._fh.readline()
        if not line.endswith(CRLF):
            raise RespError("协议错误：行未以 CRLF 结束")
        return line[:-2].decode("utf-8", "replace")

    def ping(self) -> bool:
        return self.cmd("PING") == "PONG"

    def xadd(self, key: str, fields: Dict[str, str], maxlen: int = 0) -> str:
        args: List[str] = ["XADD", key]
        if maxlen > 0:
            args += ["MAXLEN", "~", str(int(maxlen))]
        args.append("*")
        for k, v in fields.items():
            args += [k, v]
        return str(self.cmd(*args))


# ==================================================== 事件归一化

def _trunc(v: Any, limit: int) -> Any:
    if isinstance(v, str) and len(v) > limit:
        return v[:limit] + "…"
    return v


def _scrub(obj: Any, depth: int = 0) -> Any:
    """递归删除载荷类字段、截断超长字符串、限制嵌套深度。"""
    if depth > 6:
        return None
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in DROP_KEYS:
                continue
            if k == "answers" and isinstance(v, list):
                out[k] = [{"rrname": _trunc(a.get("rrname"), 200), "rrtype": a.get("rrtype"),
                           "ttl": a.get("ttl")} for a in v[:8] if isinstance(a, dict)]
                continue
            out[k] = _scrub(v, depth + 1)
        return out
    if isinstance(obj, list):
        return [_scrub(i, depth + 1) for i in obj[:16]]
    if isinstance(obj, str):
        return _trunc(obj, 300)
    return obj


def compact(ev: Dict[str, Any], forward: Sequence[str]) -> Optional[Dict[str, str]]:
    """把一条 eve 事件压成扁平字段字典（Redis Stream 的字段只能是字符串）。

    返回 None 表示"这条不该转发"。
    """
    etype = str(ev.get("event_type") or "")
    if etype == "stats":
        return _compact_stats(ev)
    if etype not in forward:
        return None

    if etype == "alert":
        al = ev.get("alert") or {}
        # severity 3 是低级告警（多为 policy/protocol 噪音）。
        # ⚠ 这里不是安全判定，只是带宽控制；AI 侧仍然会看到 3 级事件（如果配了）。
        if int(al.get("severity") or 3) > 3:
            return None

    keep = KEEP.get(etype)

    fields: Dict[str, str] = {"v": VERSION, "t": str(ev.get("timestamp") or "")}
    fields["type"] = etype
    if "flow_id" in ev:
        fields["flow_id"] = str(ev["flow_id"])
    for k in ("in_iface", "src_ip", "dest_ip", "proto", "app_proto", "pkt_src", "host"):
        if k in ev:
            fields[k] = str(ev[k])[:200]
    for k in ("src_port", "dest_port"):
        if k in ev:
            fields[k] = str(ev[k])

    if etype == "alert":
        fields["sig"] = str(al.get("signature") or "")[:300]
        fields["sig_id"] = str(al.get("signature_id") or "")
        fields["category"] = str(al.get("category") or "")[:120]
        fields["severity"] = str(al.get("severity") or "")
        fields["action"] = str(al.get("action") or "")
        if al.get("rev") is not None:
            fields["sig_rev"] = str(al["rev"])
        if al.get("metadata"):
            fields["meta"] = json.dumps(al["metadata"], ensure_ascii=False)[:400]
        # 流量方向：判断"内网被外网打"还是"内网往外打"，对研判很关键
        fields["direction"] = str(ev.get("direction") or "")
        fields["payload_dropped"] = "1" if any(k in ev for k in ("payload", "payload_printable")) else "0"

    elif etype == "dns":
        d = ev.get("dns") or {}
        for k in ("type", "rrname", "rrtype", "rcode", "opcode"):
            if d.get(k) is not None:
                fields[f"dns_{k}"] = str(d[k])[:200]
        if d.get("answers"):
            fields["dns_answers"] = json.dumps(_scrub(d["answers"]), ensure_ascii=False)[:600]

    elif etype == "tls":
        tl = ev.get("tls") or {}
        for k in ("sni", "version", "subject", "issuerdn", "fingerprint", "ja3s",
                  "notbefore", "notafter", "serial"):
            if tl.get(k):
                fields[f"tls_{k}"] = str(tl[k])[:300]
        j = tl.get("ja3")
        if isinstance(j, dict):           # 新版 Suricata 把 ja3 变成对象
            fields["tls_ja3"] = str(j.get("hash") or "")[:120]
            if j.get("string"):
                fields["tls_ja3_str"] = str(j["string"])[:300]
        elif j:
            fields["tls_ja3"] = str(j)[:120]

    elif etype == "http":
        h = ev.get("http") or {}
        for k in ("hostname", "url", "http_method", "protocol", "status", "length",
                  "http_user_agent", "http_content_type", "http_refer"):
            if h.get(k):
                # Suricata 自己的键名有的带 http_ 前缀有的不带，统一掉重复前缀：
                # 否则会拼出 http_http_user_agent 这种既难认也不好查的名字。
                name = k[5:] if k.startswith("http_") else k
                fields[f"http_{name}"] = str(h[k])[:300]

    elif etype == "ssh":
        s = ev.get("ssh") or {}
        cs = s.get("client") or {}
        ss = s.get("server") or {}
        if cs.get("software_version"):
            fields["ssh_client"] = str(cs["software_version"])[:200]
        if ss.get("software_version"):
            fields["ssh_server"] = str(ss["software_version"])[:200]
        if s.get("proto_version"):
            fields["ssh_proto"] = str(s["proto_version"])[:40]

    elif etype == "fileinfo":
        fi = ev.get("fileinfo") or {}
        for k in ("filename", "magic", "size", "state", "md5", "sha1", "sha256", "gaps"):
            if fi.get(k):
                fields[f"file_{k}"] = str(fi[k])[:300]

    elif etype == "anomaly":
        an = ev.get("anomaly") or {}
        for k in ("type", "event", "layer"):
            if an.get(k):
                fields[f"anomaly_{k}"] = str(an[k])[:200]

    else:
        # 其它类型：整段塞进 j（已 scrub），但受长度限制
        body = {k: _scrub(ev[k]) for k in keep if k in ev} if keep else _scrub(ev)
        fields["j"] = json.dumps(body, ensure_ascii=False, separators=(",", ":"))[:1500]
        return fields

    if etype == "alert":
        # alert 也可能带 app-layer 上下文（很有价值：告警同时证明用了什么协议）
        for key, pref in (("http", "http"), ("tls", "tls"), ("dns", "dns"), ("ssh", "ssh"),
                          ("fileinfo", "file")):
            sub = ev.get(key)
            if isinstance(sub, dict):
                for k in ("hostname", "url", "http_user_agent", "sni", "subject", "issuerdn",
                          "rrname", "rrtype", "filename", "sha256"):
                    if sub.get(k):
                        cname = k[5:] if k.startswith("http_") else k
                        fields[f"ctx_{pref}_{cname}"] = str(sub[k])[:200]
        fl = ev.get("flow") or {}
        for k in ("pkts_toserver", "pkts_toclient", "bytes_toserver", "bytes_toclient",
                  "start", "end", "state", "reason"):
            if fl.get(k) is not None:
                fields[f"flow_{k}"] = str(fl[k])
    return fields


def _compact_stats(ev: Dict[str, Any]) -> Dict[str, str]:
    st = ev.get("stats") or {}
    out: Dict[str, str] = {"v": VERSION, "type": "stats", "t": str(ev.get("timestamp") or "")}
    out["uptime"] = str(ev.get("uptime") or "")
    cap = st.get("capture") or {}
    dec = st.get("decoder") or {}
    flw = st.get("flow") or {}
    out["cap_kernel_pkts"] = str(cap.get("kernel_packets") or 0)
    out["cap_kernel_drops"] = str(cap.get("kernel_drops") or 0)
    out["cap_errors"] = str(cap.get("errors") or 0)
    out["dec_pkts"] = str(dec.get("pkts") or 0)
    out["dec_bytes"] = str(dec.get("bytes") or 0)
    out["dec_invalid"] = str(dec.get("invalid") or 0)
    out["flow_emerg"] = str(flw.get("emerg_mode_entered") or 0)
    out["flow_total"] = str(flw.get("total") or 0)
    return out


# ==================================================== 输入源

def iter_file(path: str, poll: float = 0.5, from_end: bool = False) -> Iterator[str]:
    """跟随文件（含 logrotate 轮转与截断处理）。

    轮转处理后必须**重新打开**文件（inode 变了）。早期版本在这里写了一行
    无意义的表达式，导致轮转后直接断流 —— 而且断得佷安静（不报错也不出数据）。
    """
    p = Path(path)
    while not p.exists():
        print(f"[producer] 等待 {path} 出现…", file=sys.stderr, flush=True)
        time.sleep(2)
    first = True
    while True:
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            if from_end and first:
                fh.seek(0, os.SEEK_END)
            first = False
            try:
                ino = p.stat().st_ino
            except OSError:
                ino = 0
            while True:
                raw = fh.readline(MAX_LINE)
                if raw:
                    # 超长行：readline 会截断，剩余部分不是合法 JSON，必须整行丢掉
                    if not raw.endswith("\n") and len(raw) >= MAX_LINE:
                        while True:
                            rest = fh.readline(MAX_LINE)
                            if not rest or rest.endswith("\n"):
                                break
                        print("[producer] 丢弃一条超长事件行", file=sys.stderr, flush=True)
                        continue
                    yield raw
                    continue
                try:
                    st = p.stat()
                except OSError:
                    break                      # 文件被删/改名 -> 外层重开
                if st.st_ino != ino or st.st_size < fh.tell():
                    print("[producer] 检测到轮转/截断，重新打开", file=sys.stderr, flush=True)
                    break
                time.sleep(poll)


def iter_socket(path: str, retry: float = 3.0) -> Iterator[str]:
    """从 Suricata 的 unix_stream 输出读（不落盘，省 SD 卡寿命）。"""
    while True:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(path)
            print(f"[producer] 已连接 Suricata socket {path}", file=sys.stderr, flush=True)
            buf = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    raise ConnectionError("socket 关闭")
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line:
                        yield line.decode("utf-8", "replace")
                if len(buf) > MAX_LINE:
                    buf = b""   # 超长单行，丢弃避免内存膨胀
        except (OSError, ConnectionError) as exc:
            print(f"[producer] socket 断开（{exc}），{retry}s 后重连", file=sys.stderr, flush=True)
            time.sleep(retry)
        finally:
            s.close()


# ==================================================== 限速 + spool

class RateLimiter:
    """滑动窗口限速。超限就丢（并计数），不排队 —— 排队只会把内存吃光。"""

    def __init__(self, max_per_sec: int) -> None:
        self.max = max(1, int(max_per_sec))
        self.hits: Deque[float] = deque()
        self.dropped = 0

    def allow(self) -> bool:
        now = time.monotonic()
        while self.hits and now - self.hits[0] > 1.0:
            self.hits.popleft()
        if len(self.hits) >= self.max:
            self.dropped += 1
            return False
        self.hits.append(now)
        return True


class Spool:
    """Redis 不可达时的本地落盘缓冲（有上限，满了丢最旧）。"""

    def __init__(self, path: Path, max_bytes: int = 64 * 1024 * 1024) -> None:
        self.path, self.max_bytes = path, int(max_bytes)
        self.spooled = 0
        self.replayed = 0
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    def write(self, stream: str, fields: Dict[str, str]) -> None:
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"s": stream, "f": fields}, ensure_ascii=False) + "\n")
            self.spooled += 1
            self._trim()
        except OSError:
            pass

    def _trim(self) -> None:
        try:
            if self.path.stat().st_size <= self.max_bytes:
                return
            lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()
            keep = lines[len(lines) // 4:]          # 丢最旧 1/4
            self.path.write_text("\n".join(keep) + "\n", encoding="utf-8")
            print(f"[producer] spool 超限，丢弃最旧 {len(lines) - len(keep)} 条",
                  file=sys.stderr, flush=True)
        except OSError:
            pass

    def pending(self) -> int:
        try:
            return sum(1 for _ in self.path.open("r", encoding="utf-8", errors="replace"))
        except OSError:
            return 0

    def replay(self, push) -> int:
        """把 spool 里的补发出去；push(stream, fields) 需返回 True 表示成功。"""
        if not self.path.exists():
            return 0
        tmp = self.path.with_suffix(".replay")
        try:
            self.path.rename(tmp)
        except OSError:
            return 0
        n = 0
        failed: List[str] = []
        with tmp.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if push(rec.get("s") or "", rec.get("f") or {}):
                    n += 1
                else:
                    failed.append(line)
        tmp.unlink(missing_ok=True)
        if failed:
            # 补发又失败：写回 spool，别丢
            with self.path.open("a", encoding="utf-8") as fh:
                fh.writelines(failed)
        self.replayed += n
        return n


# ==================================================== 主循环

def run(args: argparse.Namespace) -> int:
    forward = tuple(t.strip() for t in args.forward.split(",") if t.strip())
    limiter = RateLimiter(args.max_events_per_sec)
    spool = Spool(Path(args.spool), args.spool_max_mb * 1024 * 1024)
    r: Optional[Resp] = None
    connected = False
    sent = failed = skipped = parsed = 0
    last_stat = time.monotonic()

    def connect() -> Optional[Resp]:
        nonlocal r, connected
        try:
            c = Resp(args.host, args.port, args.password, args.db)
            c.ping()
            if not connected:
                print(f"[producer] 已连接 Redis {args.host}:{args.port}", file=sys.stderr, flush=True)
                # 上线横幅：PC 侧据此知道传感器(重)启了，而不是"一直没数据"
                try:
                    c.xadd(args.stream, {"v": VERSION, "type": "banner",
                                         "t": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                                         "host": socket.gethostname(), "msg": "producer 启动"},
                           maxlen=args.maxlen)
                except RespError:
                    pass
                if spool.pending():
                    n = spool.replay(lambda s, f: _push_raw(c, s, f, args))
                    if n:
                        print(f"[producer] spool 补发 {n} 条", file=sys.stderr, flush=True)
            connected = True
            r = c
            return c
        except (RespError, OSError) as exc:
            connected = False
            r = None
            if args.verbose:
                print(f"[producer] Redis 不可达：{exc}", file=sys.stderr, flush=True)
            return None

    def push(stream: str, fields: Dict[str, str]) -> bool:
        nonlocal sent, failed
        c = r if (r is not None) else connect()
        if c is None:
            failed += 1
            spool.write(stream, fields)     # 落盘，恢复后补发
            return False
        try:
            c.xadd(stream, fields, maxlen=args.maxlen)
            sent += 1
            return True
        except (RespError, OSError):
            failed += 1
            spool.write(stream, fields)
            return False

    if not connect() and not args.allow_spool_start:
        print("[producer] 启动时 Redis 不可达。数据会先进 spool，恢复后补发。",
              file=sys.stderr, flush=True)

    source = iter_socket(args.socket_path) if args.input == "socket" else \
        iter_file(args.eve_path, args.poll, args.from_end)

    print(f"[producer] 开始转发：input={args.input} forward={','.join(forward)} "
          f"stream={args.stream} maxlen={args.maxlen} 限速={args.max_events_per_sec}/s",
          file=sys.stderr, flush=True)

    try:
        for raw in source:
            raw = raw.strip()
            if not raw:
                continue
            try:
                ev = json.loads(raw)
            except json.JSONDecodeError:
                skipped += 1
                continue
            parsed += 1
            fields = compact(ev, forward)
            if fields is None:
                continue
            if not limiter.allow():
                continue
            stream = args.stats_stream if fields.get("type") == "stats" else args.stream
            if args.dry_run:
                print(json.dumps(fields, ensure_ascii=False)[:400])
                sent += 1
                continue
            push(stream, fields)

            if time.monotonic() - last_stat > args.report_every:
                last_stat = time.monotonic()
                print(f"[producer] 解析 {parsed} 转发 {sent} 失败 {failed} 限速丢弃 "
                      f"{limiter.dropped} spool {spool.pending()}", file=sys.stderr, flush=True)
    except KeyboardInterrupt:
        print("[producer] 退出", file=sys.stderr, flush=True)
    finally:
        if r is not None:
            r.close()
    return 0


def _push_raw(c: Resp, stream: str, fields: Dict[str, str], args: argparse.Namespace) -> bool:
    if not stream:
        return True
    try:
        c.xadd(stream, fields, maxlen=args.maxlen)
        return True
    except (RespError, OSError):
        return False


# ==================================================== 自检

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

    forward = ("alert", "dns", "tls", "http")

    # 1) alert 压缩：保留关键字段
    ev = {"timestamp": "2026-10-04T10:00:00.000000+0800", "event_type": "alert",
          "flow_id": 123, "src_ip": "10.0.0.9", "src_port": 51000, "dest_ip": "45.1.2.3",
          "dest_port": 4444, "proto": "TCP", "app_proto": "tls", "direction": "outbound",
          "alert": {"signature": "ET TROJAN Cobalt Strike Beacon", "signature_id": 2024,
                    "category": "A Network Trojan was detected", "severity": 1,
                    "action": "allowed", "rev": 4},
          "payload": "HACKEYSECRETBASE64", "payload_printable": "GET / HTTP/1.1",
          "flow": {"pkts_toserver": 12, "bytes_toserver": 900, "state": "established"}}
    f = compact(ev, forward)
    chk("alert 被转发", f is not None)
    chk("签名保留", f and f.get("sig") == "ET TROJAN Cobalt Strike Beacon")
    chk("severity 保留", f and f.get("severity") == "1")
    chk("五元组保留", f and f.get("dest_port") == "4444" and f.get("src_ip") == "10.0.0.9")
    chk("方向保留", f and f.get("direction") == "outbound")
    chk("流统计保留", f and f.get("flow_bytes_toserver") == "900")
    chk("**载荷被丢弃**", f and "HACKEYSECRETBASE64" not in json.dumps(f)
        and "payload_printable" not in json.dumps(f))
    chk("载荷丢弃被标记", f and f.get("payload_dropped") == "1")

    # 2) 未在转发清单里的事件被丢弃
    chk("flow 事件默认丢弃", compact({"event_type": "flow", "src_ip": "1.2.3.4"}, forward) is None)

    # 3) DNS 压缩
    dns = compact({"timestamp": "t", "event_type": "dns", "src_ip": "10.0.0.5",
                   "dest_ip": "8.8.8.8", "dns": {"type": "query", "rrname": "evil.example",
                                                 "rrtype": "A", "rcode": "NOERROR",
                                                 "answers": [{"rrname": "evil.example",
                                                              "rrtype": "A", "ttl": 60}]}}, forward)
    chk("DNS 域名保留", dns and dns.get("dns_rrname") == "evil.example")
    chk("DNS 应答保留(rrname/rrtype/ttl)", dns and "evil.example" in dns.get("dns_answers", ""))
    chk("DNS 应答丢弃无关字段", dns and "rdata" not in dns.get("dns_answers", ""))

    # 4) TLS：JA3 两种形态都要能取到
    tls = compact({"timestamp": "t", "event_type": "tls", "src_ip": "a",
                   "tls": {"sni": "c2.bad.tld", "version": "TLS 1.2",
                           "subject": "CN=bad", "issuerdn": "CN=Let's Encrypt",
                           "ja3": {"hash": "abc123", "string": "771,4865,..."}}}, forward)
    chk("TLS SNI 保留", tls and tls.get("tls_sni") == "c2.bad.tld")
    chk("TLS JA3 hash 保留", tls and tls.get("tls_ja3") == "abc123")
    chk("TLS 证书签发者保留", tls and "Let's Encrypt" in tls.get("tls_issuerdn", ""))

    # 5) HTTP
    h = compact({"timestamp": "t", "event_type": "http", "src_ip": "a",
                 "http": {"hostname": "x.com", "url": "/a?b=1", "http_method": "POST",
                          "status": 200, "http_user_agent": "curl/8.4.0"}}, forward)
    chk("HTTP 字段保留", h and h.get("http_user_agent") == "curl/8.4.0" and h.get("http_status") == "200")

    # 6) stats 压缩 + drop 计数
    st = compact({"timestamp": "t", "event_type": "stats", "uptime": 600,
                  "stats": {"capture": {"kernel_packets": 1000000, "kernel_drops": 250},
                            "decoder": {"pkts": 999000, "bytes": 123456789, "invalid": 3},
                            "flow": {"total": 500}}}, forward)
    chk("stats 转发到独立流", st and st.get("type") == "stats")
    chk("捕获丢包数保留", st and st.get("cap_kernel_drops") == "250")
    chk("解码字节数保留", st and st.get("dec_bytes") == "123456789")

    # 7) 超长字符串截断
    long_ev = compact({"timestamp": "t", "event_type": "http",
                       "http": {"url": "A" * 5000}}, forward)
    chk("超长字段被截断", long_ev and len(long_ev.get("http_url", "")) < 400,
        str(len(long_ev.get("http_url", ""))))

    # 8) 限速
    lim = RateLimiter(5)
    allowed = sum(1 for _ in range(20) if lim.allow())
    chk("限速生效", allowed == 5, str(allowed))
    chk("限速如实计数", lim.dropped == 15, str(lim.dropped))

    # 9) RESP 客户端对假 Redis 端到端（若本机有 Redis 可跳过）
    try:
        c = Resp("127.0.0.1", 63790, connect_timeout=0.4, read_timeout=0.4)
        c.ping()
        chk("RESP 连通（本机 Redis）", True)
        c.close()
    except (RespError, OSError):
        chk("RESP 连不上时抛异常而非卡死", True)

    # 10) spool 写入 + 补发
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        sp = Spool(Path(td) / "spool.jsonl")
        for i in range(3):
            sp.write("s", {"type": "alert", "n": str(i)})
        chk("spool 落盘计数", sp.pending() == 3, str(sp.pending()))
        got: List[str] = []
        n = sp.replay(lambda s, f: (got.append(f["n"]), True)[1])
        chk("spool 补发", n == 3 and got == ["0", "1", "2"], f"{n} {got}")
        chk("补发后清空", sp.pending() == 0)

    print(f"\nsuricata_redis_producer 自检：{ok} 通过 / {fail} 失败")
    return 1 if fail else 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Suricata eve -> Redis Stream 转发器（树莓派侧）")
    ap.add_argument("--broker", default="127.0.0.1:6379",
                    help="Redis 地址（本机=树莓派自己；也可指向 PC）")
    ap.add_argument("--host", default=None, help="覆盖 broker 的主机部分")
    ap.add_argument("--port", type=int, default=None, help="覆盖 broker 的端口部分")
    ap.add_argument("--password", default=os.environ.get("IDS_REDIS_PASSWORD", ""),
                    help="Redis 密码（默认读环境变量 IDS_REDIS_PASSWORD，避免写进命令行）")
    ap.add_argument("--db", type=int, default=0)
    ap.add_argument("--stream", default="suricata:eve")
    ap.add_argument("--stats-stream", default="suricata:stats")
    ap.add_argument("--maxlen", type=int, default=200000,
                    help="流长度上限（近似修剪），防止 Pi 内存涨满")
    ap.add_argument("--input", choices=("file", "socket"), default="file")
    ap.add_argument("--eve-path", default="/var/log/suricata/eve.json")
    ap.add_argument("--socket-path", default="/var/run/suricata/eve.sock")
    ap.add_argument("--from-end", action="store_true", help="从文件末尾开始（忽略历史）")
    ap.add_argument("--poll", type=float, default=0.5)
    ap.add_argument("--forward", default=",".join(DEFAULT_FORWARD),
                    help="转发哪些事件类型（逗号分隔）。默认不含 flow —— 镜像口上 flow 量极大且信息量低")
    ap.add_argument("--max-events-per-sec", type=int, default=600,
                    help="转发限速，保护 LAN 与 PC（超限丢弃并计数）")
    ap.add_argument("--spool", default="/var/lib/suricata-redis/spool.jsonl")
    ap.add_argument("--spool-max-mb", type=int, default=64)
    ap.add_argument("--allow-spool-start", action="store_true",
                    help="Redis 不在线也照常启动（写 spool 等待恢复）")
    ap.add_argument("--report-every", type=float, default=60.0)
    ap.add_argument("--dry-run", action="store_true", help="只打印将要转发的字段，不发 Redis")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if args.host or args.port:
        h, _, p = args.broker.partition(":")
        args.host = args.host or h
        args.port = args.port or int(p or 6379)
    else:
        h, _, p = args.broker.partition(":")
        args.host, args.port = h or "127.0.0.1", int(p or 6379)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
