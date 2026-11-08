#!/usr/bin/env python3
"""按「块 + 键」方式给发行版自带的 suricata.yaml 打补丁（树莓派 4B 调优）。

为什么不去生成一份"完整配置"：
    发行版的 suricata.yaml 是**和该版本 Suricata 二进制配套验证过的**。
    自己手写一份完整 yaml，在某个版本上少一个必需键就会起不来，而我没法在
    开发机上用真 Suricata 验证（Windows 上没有）。所以这里只做**最小改动**：
    找到原有的块与键，改值；改完**读回来核对**；再由 `suricata -T` 做硬校验。
    补丁打不中不静默通过，而是明确报 MISMATCH。

用法：
    python3 tune_suricata.py --profile pi4b --iface eth0          # 应用
    python3 tune_suricata.py --profile pi4b --iface eth0 --dry-run
    python3 tune_suricata.py --set af-packet.ring-size=20000
    python3 tune_suricata.py --check                               # 只跑 suricata -T
    python3 tune_suricata.py --restore                             # 回滚
"""
from __future__ import annotations

import argparse
import difflib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

DEFAULT_CFG = "/etc/suricata/suricata.yaml"
BACKUP_SUFFIX = ".orig-blueteam"

# ---------------------------------------------------------------- 小工具

KEY_RE = re.compile(r"^([A-Za-z0-9_./-]+)\s*:(.*)$")
DASH_KEY_RE = re.compile(r"^-\s+([A-Za-z0-9_./-]+)\s*:(.*)$")


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _strip_value(raw: str) -> str:
    """把 `value  # 注释` 里的值取出来并去引号。"""
    v = raw.split("#", 1)[0].strip().rstrip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        v = v[1:-1]
    return v


# YAML 里以这些字符开头的标量必须加引号，否则会被当成标签/锚点/流式集合。
# 踩过：`EXTERNAL_NET: !$HOME_NET` 里的 `!$HOME_NET` 被 YAML 解析器当成 **tag**，
# 直接报 "could not determine a constructor for the tag"。发行版原文件写的是带引号的。
_QUOTE_HEADS = set("!*&%@`[{>,|")


def _fmt_value(v: str) -> str:
    if v == "" or v[0] in _QUOTE_HEADS or " #" in v or v != v.strip():
        return '"' + v.replace('"', '\\"') + '"'
    return v


class Block:
    """一个 YAML 块的位置信息。

    缩进规则（这是本文件最容易搞错的地方，suricata.yaml 两种写法都用了）::

        af-packet:
          - interface: eth0      # 列表项**带内联值** -> 同级键在 indent+2
            cluster-id: 99

        outputs:
          - eve-log:             # 列表项**不带内联值** -> 子键在 indent+4
              enabled: yes

    早期版本没区分这两种，结果把 `interface:` 插成了 `to af-packet` 列表的同级
    映射键 —— 生成的是**非法 YAML**（序列里混映射）。自检里的 PyYAML 解析
    就是专门抓这个的。
    """

    __slots__ = ("head", "end", "key_indent", "head_key", "inline")

    def __init__(self, head: int, key_indent: int, head_key: str, inline: bool) -> None:
        self.head = head
        self.end = head + 1
        self.key_indent = key_indent
        self.head_key = head_key
        self.inline = inline


def _match_at(line: str, indent: int, name: str) -> Optional[Tuple[int, str, bool]]:
    """在缩进 indent 处匹配 `name:` 或 `- name:`。

    返回 (子键缩进, 键名, 是否内联值)；不匹配返回 None。
    """
    if _indent_of(line) != indent:
        return None
    body = line[indent:]
    dash = body.startswith("- ")
    if dash:
        body = body[2:]
    # 剥掉 "- " 之后就是普通 `key:` 形式 —— 这里必须用 KEY_RE。
    # 踩过：在这里继续用 DASH_KEY_RE，结果 `- eve-log:` 这类整个章节都打不中，
    # 而“打不中”表现为全部 eve 相关补丁静默跳过。
    m = KEY_RE.match(body)
    if not m or m.group(1) != name:
        return None
    rest = m.group(2).split("#", 1)[0].strip()
    inline = rest != ""
    # 列表项带内联值 -> 同级键与内联键对齐（indent+2）
    # 列表项不带值   -> 子映射再缩进一级（indent+4）
    # 普通映射       -> 子键 indent+2
    key_indent = indent + 2 if (inline or not dash) else indent + 4
    return key_indent, m.group(1), inline


class YamlBlockEditor:
    """极简 YAML 块编辑器：按缩进定位块，在块内取/设键。

    只支持本项目需要的子集（映射、`- key:` 列表项、`- key` 标量项），
    **不追求通用**。行级操作的好处是原样保留注释与格式 ——
    管理员后面是要读这份配置的。
    """

    def __init__(self, text: str) -> None:
        self.lines: List[str] = text.split("\n")

    # -- 定位 ------------------------------------------------------
    def _extent(self, head: int, key_indent: int) -> int:
        """块结束行号（不含）。注释行与空行视为块内，不当作结束。"""
        i = head + 1
        while i < len(self.lines):
            s = self.lines[i].strip()
            if s == "" or s.startswith("#"):
                i += 1
                continue
            if _indent_of(self.lines[i]) < key_indent:
                break
            i += 1
        return i

    def find(self, path: Sequence[str], descend_item: bool = False) -> Optional[Block]:
        """按路径定位块。空路径表示"整个文件的顶层"。

        ``descend_item=True``：如果最后定位到的块的直接子行是**列表项**
        （`af-packet:` 下面就是 `- interface: eth0`），就下探到**第一项**。
        少了这一步，`set("interface")` 会在 indent 2 找不到内联键，
        于是往列表里插一行 `interface: eth0` —— 生成非法 YAML。
        """
        if not path:
            b = Block(-1, 0, "", False)
            b.end = len(self.lines)      # ⚠ 必须是整个文件；end=head+1 会让它
            return b                     # 的插入位置落到文件最开头（踩过）
        lo, hi, indent = 0, len(self.lines), 0
        blk: Optional[Block] = None
        for name in path:
            blk = None
            for i in range(lo, hi):
                m = _match_at(self.lines[i], indent, name)
                if m:
                    blk = Block(i, m[0], m[1], m[2])
                    break
            if blk is None:
                return None
            blk.end = self._extent(blk.head, blk.key_indent)
            lo, hi, indent = blk.head, blk.end, blk.key_indent
        return self._item_block(blk) if descend_item else blk

    def _item_block(self, blk: Block) -> Block:
        """把一个"元素是列表项的块"转成"第一项"的块视图。"""
        for i in range(blk.head + 1, blk.end):
            s = self.lines[i].strip()
            if s == "" or s.startswith("#"):
                continue
            if _indent_of(self.lines[i]) != blk.key_indent or not s.startswith("- "):
                return blk                      # 子级不是列表项，原样返回
            m = DASH_KEY_RE.match(s)
            if not m:
                return blk
            inline = m.group(2).split("#", 1)[0].strip() != ""
            key_indent = blk.key_indent + (2 if inline else 4)
            item = Block(i, key_indent, m.group(1), inline)
            item.end = self._extent(i, key_indent)
            return item
        return blk

    def get(self, path: Sequence[str], key: str) -> Optional[str]:
        blk = self.find(path, descend_item=True)
        if blk is None:
            return None
        if blk.inline and blk.head_key == key:
            m = DASH_KEY_RE.match(self.lines[blk.head].strip()) or \
                KEY_RE.match(self.lines[blk.head].strip())
            return _strip_value(m.group(2)) if m else None
        for i in range(blk.head + 1, blk.end):
            line = self.lines[i]
            if _indent_of(line) != blk.key_indent:
                continue
            m = KEY_RE.match(line.strip())
            if m and m.group(1) == key:
                return _strip_value(m.group(2))
        return None

    # -- 修改 ------------------------------------------------------
    def set(self, path: Sequence[str], key: str, value: str, create: bool = True) -> bool:
        blk = self.find(path, descend_item=True)
        if blk is None:
            return False
        # 1) 列表项的内联键（`- interface: eth0`）
        if blk.inline and blk.head_key == key:
            line = self.lines[blk.head]
            pad = " " * _indent_of(line)
            dash = "- " if line.lstrip().startswith("- ") else ""
            self.lines[blk.head] = f"{pad}{dash}{key}: {_fmt_value(value)}"
            return True
        # 2) 块内同名键
        for i in range(blk.head + 1, blk.end):
            line = self.lines[i]
            if _indent_of(line) != blk.key_indent:
                continue
            m = KEY_RE.match(line.strip())
            if m and m.group(1) == key:
                tail = "  #" + line.split("#", 1)[1] if "#" in line else ""
                self.lines[i] = " " * blk.key_indent + f"{key}: {_fmt_value(value)}{tail}"
                return True
        if not create:
            return False
        # 3) 追加到块末尾。**必须用 blk.key_indent**，不能凭感觉 +2，
        #    否则会插出非法缩进（列表项里插成同级映射键）。
        j = blk.end
        while j - 1 > blk.head and self.lines[j - 1].strip() == "":
            j -= 1
        self.lines.insert(j, " " * blk.key_indent + f"{key}: {_fmt_value(value)}")
        return True

    # -- eve-log types 专用 ----------------------------------------
    def _type_entry(self, name: str) -> Optional[Tuple[int, int, int, bool]]:
        """定位 types 里的某个类型项。

        返回 (头行, 结束行, 键缩进, 是否标量项)；找不到返回 None。
        """
        blk = self.find(["outputs", "eve-log", "types"], descend_item=False)
        if blk is None:
            return None
        for i in range(blk.head + 1, blk.end):
            if _indent_of(self.lines[i]) != blk.key_indent:
                continue
            s = self.lines[i].strip()
            if s in (f"- {name}", f"- {name}:"):
                # `- flow` 标量项：等价于"默认启用"，必须整体替换才能关掉
                if s == f"- {name}":
                    return i, i + 1, blk.key_indent + 4, True
                return i, self._extent(i, blk.key_indent + 4), blk.key_indent + 4, False
        return None

    def enable_type(self, aliases: Sequence[str], enabled: bool,
                    extra: Optional[Dict[str, str]] = None) -> Tuple[bool, str]:
        """打开/关掉 eve-log types 里的类型。

        **不新增未知类型**：如果发行版里没有这个类型，就跳过而不是追加 ——
        给 Suricata 塞一个它不认识的 eve 类型会让它启动失败。
        `extra` 里的键也只改**已存在**的（create=False），同理。
        """
        val = "yes" if enabled else "no"
        for name in aliases:
            ent = self._type_entry(name)
            if ent is None:
                continue
            head, end, key_indent, scalar = ent
            if scalar:
                if enabled:
                    return True, f"{name}（标量项，本来就是启用）"
                pad = " " * _indent_of(self.lines[head])
                self.lines[head:head + 1] = [f"{pad}- {name}:",
                                            " " * key_indent + f"enabled: no"]
                return True, name
            changed = self.set(["outputs", "eve-log", "types", name], "enabled", val, create=True)
            for k, v in (extra or {}).items():
                self.set(["outputs", "eve-log", "types", name], k, v, create=False)
            return changed, name
        return False, ""

    def text(self) -> str:
        return "\n".join(self.lines)


# ---------------------------------------------------------------- 配置档

def profile_pi4b(iface: str) -> List[Tuple[Any, ...]]:
    """Pi 4B / 4GB / 旁路镜像口 的调优补丁。

    每一项是 (块路径, 键, 值, 必填?)。必填项打不中会报警告（说明该版本没这个键，
    需要人工确认），非必填打不中就算了。
    """
    return [
        # ---- 变量：外网 = 非内网 ----
        (("vars", "address-groups"), "EXTERNAL_NET", "!$HOME_NET", False),

        # ---- 采集：af-packet ----
        (("af-packet",), "interface", iface, True),
        # cluster_flow：同一条流固定交给同一个线程，避免流状态在多线程间来回搬
        (("af-packet",), "cluster-type", "cluster_flow", True),
        (("af-packet",), "cluster-id", "99", True),
        # mmap + tpacket-v3：减少内存拷贝，是降低内核丢包的主要手段
        (("af-packet",), "use-mmap", "yes", True),
        (("af-packet",), "tpacket-v3", "yes", True),
        # 镜像口会出现突发（镜像口速率可能高于 Pi 的采集速率），
        # 缓冲给大一点吸收突发，否则 kernel_drops 会持续增长。
        (("af-packet",), "ring-size", "10000", True),
        (("af-packet",), "block-size", "131072", True),
        (("af-packet",), "buffer-size", "262144", True),
        # 旁路采集必须开混杂模式（镜像口会送来非本机 MAC 的帧）
        (("af-packet",), "disable-promisc", "no", False),
        (("af-packet",), "defrag", "yes", False),
        # Pi 4B 是 4 核。留 1~2 核给 Redis/转发器/系统，否则整体抖动变大。
        (("af-packet",), "threads", "2", True),

        # ---- 运行模式 ----
        ((), "runmode", "autofp", True),
        ((), "max-pending-packets", "8192", True),
        ((), "default-log-dir", "/var/log/suricata", True),

        # ---- 内存上限：4GB 机器上必须封顶，否则流表涨满会 OOM ----
        (("stream",), "memcap", "256mb", True),
        (("flow",), "memcap", "128mb", True),
        (("flow-timeouts", "tcp"), "established", "1800", False),

        # ---- 检测档位：medium 比 high 省很多 CPU，对本场景够用 ----
        (("detect",), "profile", "medium", True),

        # ---- 统计：丢包率是 IDS 可用性的前提，必须定期上报 ----
        (("stats",), "enabled", "yes", True),
        (("stats",), "interval", "30 seconds", False),

        # ---- eve 输出 ----
        (("outputs", "eve-log"), "enabled", "yes", True),
        (("outputs", "eve-log"), "filetype", "regular", False),
        (("outputs", "eve-log"), "filename", "/var/log/suricata/eve.json", True),
        # community-id 把 Suricata 的流与其它工具（Zeek/Arkime）对得上，
        # PC 侧做关联时这是最稳的键之一
        (("outputs", "eve-log"), "community-id", "true", False),
        # **不落载荷**：隐私 + 省 SD 卡写入（PC 侧只需要元数据）
        (("outputs", "eve-log"), "payload", "false", False),
        (("outputs", "eve-log"), "payload-printable", "false", False),
        (("outputs", "eve-log"), "metadata", "yes", False),
        (("outputs", "eve-log"), "pcap", "no", False),

        # ---- 应用层：TLS/JA3 对识别 C2 很关键 ----
        (("app-layer", "protocols", "tls"), "enabled", "yes", False),
        # 值用 "auto"（6.0/7.x 自带的写法），不用 yes/no —— 老式布尔虽然多数
        # 版本还认，但跟着发行版写是最稳的。
        (("app-layer", "protocols", "tls"), "ja3-fingerprints", "auto", False),
    ]


# 转发器需要的事件类型（与 suricata_redis_producer.py 的 --forward 对应）
#
# 三个原则：
#   1) 用别名兼容不同版本（6.0 叫 fileinfo、7.x 叫 files）；
#   2) **绝不新增发行版里没有的类型** —— 塞一个 Suricata 不认识的 eve 类型
#      会让它启动失败，宁可跳过；
#   3) extra 里的键只改**已存在**的（create=False），避免写入该版本不支持的键。
WANTED_TYPES: List[Tuple[Tuple[str, ...], bool, Optional[Dict[str, str]]]] = [
    (("alert",), True, {"metadata": "yes"}),
    (("anomaly",), True, None),      # 默认 no，但开销小、对规避行为信号强
    (("dns",), True, None),
    (("tls",), True, {"extended": "yes"}),
    (("http",), True, {"extended": "yes"}),
    (("ssh",), True, None),
    (("fileinfo", "files"), True, None),
    # flow 刻意关闭：镜像口上 flow 事件每秒上万，信息量低却最占地盘。
    # PC 侧的连接级信息已由本机传感器覆盖，走 Suricata 转 flow 是重复劳动。
    (("flow",), False, None),
    (("netflow",), False, None),
    (("stats",), True, None),
]


# ---------------------------------------------------------------- 执行

def run(cmd: List[str]) -> Tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, str(exc)


def check_config(cfg: Path, iface: Optional[str]) -> Tuple[bool, str]:
    """用 `suricata -T` 做硬校验 —— 这是防"手改配置改坏"的最后一道闸。"""
    cmd = ["suricata", "-T", "-c", str(cfg)]
    if iface:
        cmd.append(f"--af-packet={iface}")
    rc, out = run(cmd)
    tail = "\n".join(out.strip().splitlines()[-12:])
    return rc == 0, tail


def apply(cfg: Path, patches: List[Tuple[Any, ...]], dry: bool) -> Tuple[int, int, int]:
    text = cfg.read_text(encoding="utf-8")
    ed = YamlBlockEditor(text)
    applied = missed = required_missed = 0

    for item in patches:
        path, key, value = item[0], item[1], item[2]
        required = bool(item[3]) if len(item) > 3 else False
        ok = ed.set(path, key, value, create=True)
        label = ".".join(path) + (f".{key}" if key else "")
        if ok:
            applied += 1
            print(f"  [补丁] {label} = {value}")
        else:
            missed += 1
            if required:
                required_missed += 1
                print(f"  [!警告] 打不中必填项 {label} —— 可能是该版本没有这个键，"
                      f"请人工确认（不静默通过）")
            else:
                print(f"  [跳过] 该版本无此项 {label}")

    # eve-log types
    for aliases, enabled, extra in WANTED_TYPES:
        ok, name = ed.enable_type(aliases, enabled, extra)
        if ok:
            applied += 1
            print(f"  [类型] {name} -> {'开' if enabled else '关'}")
        else:
            missed += 1
            print(f"  [跳过] eve-log types 里没有 {'/'.join(aliases)}（该版本不支持，不新增）")

    new_text = ed.text()
    if not dry:
        shutil.copy2(cfg, Path(str(cfg) + BACKUP_SUFFIX))
        cfg.write_text(new_text, encoding="utf-8")
    return applied, missed, required_missed


def verify(cfg: Path, patches: List[Tuple[Any, ...]]) -> int:
    """读回校验：把刚落盘的补丁逐个重新解析，确认真的写进去了。"""
    ed = YamlBlockEditor(cfg.read_text(encoding="utf-8"))
    bad = 0
    for item in patches:
        path, key, want = item[0], item[1], item[2]
        got = ed.get(path, key)
        if got is None:
            continue          # 本来就没这个键（非必填）
        if str(got) != str(want):
            bad += 1
            print(f"  [MISMATCH] {'.'.join(path)}.{key}: 期望 {want!r} 实得 {got!r}")
    # types 也核一遍
    for aliases, enabled, _ in WANTED_TYPES:
        for name in aliases:
            got = ed.get(["outputs", "eve-log", "types", name], "enabled")
            if got is not None and str(got) != ("yes" if enabled else "no"):
                bad += 1
                print(f"  [MISMATCH] eve-log.types.{name}.enabled: "
                      f"期望 {'yes' if enabled else 'no'} 实得 {got}")
                break
    print(f"  读回校验：{'全部一致' if bad == 0 else f'{bad} 处不一致'}")
    return bad


# ---------------------------------------------------------------- 自检

def _dig(doc: Any, path: Sequence[Any]) -> Any:
    cur = doc
    for k in path:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        elif isinstance(cur, list) and isinstance(k, int) and k < len(cur):
            cur = cur[k]
        else:
            return None
    return cur


def _eve_type(doc: Any, name: str) -> Any:
    """从 eve-log.types 里取某类型的配置（可能是标量项或映射项）。"""
    types = _dig(doc, ["outputs"]) or []
    for item in types:
        if isinstance(item, dict) and "eve-log" in item:
            for t in (item["eve-log"].get("types") or []):
                if isinstance(t, str) and t == name:
                    return "scalar"
                if isinstance(t, dict) and name in t:
                    return t[name]
    return None


def selftest() -> int:
    """验证块/键定位正确、结果是合法 YAML、且值落在正确的键上。

    开发机上没有 Suricata，用不了 `suricata -T`。退一步做两件事：
      1) 用 PyYAML 确认打补丁后**仍然是合法 YAML**（能抓住"往列表里插映射键"
         这类致命错误——早期版本就会这么干）；
      2) 逐条断言值落在期望的路径上，并且**没碰坏兄弟项**
         （比如 af-packet 的第二项 `- interface: default` 必须原样保留）。
    """
    import contextlib
    import io
    import json
    import tempfile

    ok = fail = 0

    def chk(name: str, cond: bool, extra: str = "") -> None:
        nonlocal ok, fail
        if cond:
            ok += 1
            print(f"  [OK] {name}")
        else:
            fail += 1
            print(f"  [FAIL] {name} {extra}")

    fixture = Path(__file__).resolve().parent / "tests" / "suricata-stock-sample.yaml"
    chk("夹具存在", fixture.exists(), str(fixture))
    if not fixture.exists():
        print(f"\ntune_suricata 自检：{ok} 通过 / {fail} 失败")
        return 1

    try:
        import yaml  # type: ignore
    except ImportError:
        yaml = None

    patches = profile_pi4b("eth0")
    with tempfile.TemporaryDirectory() as td:
        cfg = Path(td) / "suricata.yaml"
        shutil.copy2(fixture, cfg)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            applied, missed, req_missed = apply(cfg, patches, dry=False)
            bad = verify(cfg, patches)
        if applied <= 25 or req_missed or bad:
            print(buf.getvalue().rstrip())      # 失败时把被抑制的输出放出来，否则没法排查
        chk("补丁实际应用数 > 25", applied > 25, f"{applied}")
        chk("没有必填项打不中", req_missed == 0, f"{req_missed} 项缺失")
        chk("读回校验全部一致", bad == 0, f"{bad} 处不一致")

        text = cfg.read_text(encoding="utf-8")
        doc: Any = None
        if yaml is None:
            print("  [跳过] 没装 PyYAML，跳过 YAML 合法性校验")
        else:
            try:
                doc = yaml.safe_load(text)
                chk("结果仍是合法 YAML", isinstance(doc, dict))
            except Exception as exc:  # noqa: BLE001
                chk("结果仍是合法 YAML", False, str(exc))

        if doc:
            # ---- af-packet：列表项内联键 + 兄弟项不被破坏 ----
            chk("af-packet 仍是 2 项（没往列表里插映射键）",
                isinstance(doc.get("af-packet"), list) and len(doc["af-packet"]) == 2,
                str(type(doc.get("af-packet"))))
            chk("af-packet[0].interface 就地替换", _dig(doc, ["af-packet", 0, "interface"]) == "eth0",
                str(_dig(doc, ["af-packet", 0, "interface"])))
            chk("af-packet[0].ring-size", _dig(doc, ["af-packet", 0, "ring-size"]) == 10000)
            chk("af-packet[0].cluster-type", _dig(doc, ["af-packet", 0, "cluster-type"]) == "cluster_flow")
            chk("af-packet[0].threads", _dig(doc, ["af-packet", 0, "threads"]) == 2)
            chk("af-packet[0] 补了 use-mmap", _dig(doc, ["af-packet", 0, "use-mmap"]) is True)
            chk("af-packet[1] 兄弟项未被破坏",
                _dig(doc, ["af-packet", 1, "interface"]) == "default",
                str(_dig(doc, ["af-packet", 1])))

            # ---- 顶层 ----
            chk("runmode", doc.get("runmode") == "autofp", str(doc.get("runmode")))
            chk("max-pending-packets", doc.get("max-pending-packets") == 8192)
            chk("default-log-dir", doc.get("default-log-dir") == "/var/log/suricata")
            chk("stats.enabled", _dig(doc, ["stats", "enabled"]) is True)
            chk("stats.interval", str(_dig(doc, ["stats", "interval"])) == "30 seconds")

            # ---- 内存上限 ----
            chk("stream.memcap", _dig(doc, ["stream", "memcap"]) == "256mb")
            chk("flow.memcap", _dig(doc, ["flow", "memcap"]) == "128mb")
            chk("flow.hash-size 未被破坏", _dig(doc, ["flow", "hash-size"]) == 65536)

            # ---- 变量 / 检测档位 ----
            chk("EXTERNAL_NET", _dig(doc, ["vars", "address-groups", "EXTERNAL_NET"]) == "!$HOME_NET")
            chk("HOME_NET 未被破坏",
                _dig(doc, ["vars", "address-groups", "HOME_NET"]).startswith("[192.168"))
            chk("detect.profile", _dig(doc, ["detect", "profile"]) == "medium")
            chk("detect.custom-values 未被破坏",
                _dig(doc, ["detect", "custom-values", "toserver-groups"]) == 25)
            chk("tls.ja3-fingerprints", _dig(doc, ["app-layer", "protocols", "tls",
                                                   "ja3-fingerprints"]) == "auto")

            # ---- eve-log ----
            chk("eve-log.filename 绝对路径",
                _dig(doc, ["outputs", 1, "eve-log", "filename"]) == "/var/log/suricata/eve.json")
            chk("eve-log.community-id", _dig(doc, ["outputs", 1, "eve-log", "community-id"]) is True)
            chk("outputs[0] fast-log 未被破坏",
                _dig(doc, ["outputs", 0, "fast", "enabled"]) is True)
            chk("http-log 段未被吞掉",
                _dig(doc, ["outputs", 2, "http-log", "filename"]) == "http.log")

            # ---- types 开关 ----
            chk("alert 仍开", (_eve_type(doc, "alert") or {}).get("metadata") is True)
            chk("anomaly 被打开", (_eve_type(doc, "anomaly") or {}).get("enabled") is True)
            chk("dns 被打开", (_eve_type(doc, "dns") or {}).get("enabled") is True)
            chk("tls.extended 被设置", (_eve_type(doc, "tls") or {}).get("extended") is True)
            flow_t = _eve_type(doc, "flow")
            chk("flow 标量项被转成映射并关闭",
                isinstance(flow_t, dict) and flow_t.get("enabled") is False, repr(flow_t))
            chk("aliases 命中 files （6.0 叫 fileinfo，7.x 叫 files）",
                _eve_type(doc, "files") is not None)
            chk("未列出的类型保持标量原样（ssh）", _eve_type(doc, "ssh") == "scalar")
            chk("不在清单里的类型不被新增（netflow 保持标量或关闭）",
                _eve_type(doc, "netflow") in ("scalar", None) or
                (_eve_type(doc, "netflow") or {}).get("enabled") is False)

            # ---- 幂等：再打一遍不应改变结构 ----
            cfg2 = Path(td) / "suricata2.yaml"
            shutil.copy2(cfg, cfg2)
            with contextlib.redirect_stdout(io.StringIO()):
                apply(cfg2, patches, dry=False)
            doc2 = yaml.safe_load(cfg2.read_text(encoding="utf-8"))
            same = json.dumps(doc, sort_keys=True, default=str) == \
                json.dumps(doc2, sort_keys=True, default=str)
            chk("补丁幂等（重复应用不改变结构）", same)

        # ---- dry-run 不写文件 ----
        cfg3 = Path(td) / "suricata3.yaml"
        shutil.copy2(fixture, cfg3)
        before = cfg3.read_text(encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            apply(cfg3, patches, dry=True)
        chk("dry-run 不改文件", cfg3.read_text(encoding="utf-8") == before)

    print(f"\ntune_suricata 自检：{ok} 通过 / {fail} 失败")
    return 1 if fail else 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="给 suricata.yaml 打 Pi 4B 调优补丁")
    ap.add_argument("--config", default=DEFAULT_CFG)
    ap.add_argument("--iface", default="eth0", help="镜像口（采集口）网卡名")
    ap.add_argument("--profile", choices=("pi4b", "none"), default="pi4b")
    ap.add_argument("--set", action="append", default=[],
                    help="额外补丁，形如 outputs.eve-log.filename=/x/eve.json（可多次）")
    ap.add_argument("--dry-run", action="store_true", help="只打印将要做的改动")
    ap.add_argument("--check", action="store_true", help="只跑 suricata -T")
    ap.add_argument("--restore", action="store_true", help="回滚到备份")
    ap.add_argument("--selftest", action="store_true", help="验证块/键定位与 YAML 合法性")
    ap.add_argument("--no-check", action="store_true", help="跳过 suricata -T（不建议）")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    cfg = Path(args.config)
    backup = Path(str(cfg) + BACKUP_SUFFIX)

    if args.restore:
        if not backup.exists():
            print(f"没有备份 {backup}")
            return 1
        shutil.copy2(backup, cfg)
        print(f"已回滚 {cfg} <- {backup}")
        return 0

    if args.check:
        ok, tail = check_config(cfg, args.iface)
        print(("配置校验通过\n" if ok else "配置校验失败\n") + tail)
        return 0 if ok else 1

    if not cfg.exists():
        print(f"找不到 {cfg}（先 apt install suricata）")
        return 1

    patches: List[Tuple[Any, ...]] = []
    if args.profile == "pi4b":
        patches += profile_pi4b(args.iface)
    for spec in args.set:
        if "=" not in spec:
            print(f"--set 格式错误（应为 a.b.c=值）：{spec}")
            return 1
        lhs, _, val = spec.partition("=")
        parts = lhs.split(".")
        if len(parts) < 2:
            print(f"--set 至少要 块.键：{spec}")
            return 1
        patches.append((tuple(parts[:-1]), parts[-1], val, False))

    print(f"目标配置：{cfg}")
    applied, missed, req_missed = apply(cfg, patches, args.dry_run)
    print(f"应用 {applied} 项，跳过 {missed} 项（其中必填缺失 {req_missed} 项）")

    if args.dry_run:
        print("\n--dry-run：未写入文件")
        return 0

    if req_missed:
        print("\n⚠ 有必填项没打中。配置可能不完整，建议人工检查后再启用服务。")

    bad = verify(cfg, patches)
    if bad:
        print("\n⚠ 读回校验有不一致，请查看上面的 MISMATCH 行。")
        return 2

    if not args.no_check:
        print("\n执行 suricata -T 校验…")
        ok, tail = check_config(cfg, args.iface)
        print(tail)
        if not ok:
            print(f"\n[X] 配置校验失败。已保留备份 {backup}，可用 --restore 回滚。"
                  f"\n  服务**不会**被启用，请先修配置。")
            return 1
        print("\n[OK] 配置校验通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
