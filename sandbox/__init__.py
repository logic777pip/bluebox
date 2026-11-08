"""sandbox —— 「检测到威胁 → 载荷只读固化 → 沙箱内引爆（可选）→ 静态取证分析」的封包。

分层
----

    sandbox/sandboxie.py   Sandboxie-Plus 机制层：探测安装、box 管理、差分断网验证、
                           载荷提取与只读固化、沙箱内引爆、产物导出
    sandbox/payload.py     载荷的静态取证分析：哈希、PE 结构、数字签名、字符串、可疑指标
    sandbox/pipeline.py    编排：传感器事件触发 → 提取 → 报警 → 分析 →（可选）引爆 → 审计
    actions/adapters/sandboxie.py   把上述能力接进 PDCERF 动作系统（R3 白名单 + R5 两阶段确认）

安全边界（这是本包最重要的部分）
--------------------------------

1. **默认不执行任何载荷。** 默认路径是「只读固化 + 静态分析」：把载荷按字节复制进
   只读库（`vault/`），算出哈希与 PE 元数据，提取字符串，匹配可疑指标。这条路径
   不运行样本，因此不存在"样本反过来影响本机"的通路。

2. **引爆（执行活体样本）默认关闭，且需要三重条件同时成立**，缺一即拒绝：
     ① 配置显式 `execute_enabled: true`（不是跟着全局 dry_run 走）；
     ② `sandboxie.verify_network_isolation()` 的**差分断网验证**通过
        （沙箱内连不出去 **且** 沙箱外连得出去 —— 两个条件都要，否则视为"测不出"，
        因为探针本身失败可能只是本机没网，那就什么都没证明）；
     ③ 该动作在动作系统里是**不可逆**动作，必须走 R5 两阶段人工确认。
   为什么这么严：引爆的样本会主动寻找 C2、横向移动、加密文件。沙箱不是保证，
   尤其 Sandboxie 是用户态沙箱 + 内核驱动，配置不当（例如放行网络）会让
   "分析样本"变成"替攻击者重新上线"。

3. **载荷镜像一律去掉可执行权**（Windows `FILE_ATTRIBUTE_READONLY`），
   并且**不存在**任何"运行着顺便分析"的隐式动作 —— 提取、分析、引爆是三个
   可以分别审计的独立动作，各自有独立的开关。

4. **所有静态结论都是指标，不是判决。** 高熵可能是压缩包，可疑字符串可能来自
   无害的安装器，签名有效也不等于无害（恶意软件也买证书）。所以报告里
   `indicators` 与 `verdict` 分开存放，`verdict` 明确写"需人工判断"。

产物布局
--------

    logs/sandbox/
        vault/<sha256前12位>_<原文件名>/     只读载荷镜像 + manifest.json
        cases/<case_id>/
            payload_report.md / payload_report.json
            detonation/                     引爆时从沙箱导出的落地物
            audit.jsonl                     本案例的审计轨迹

目录相对项目根解析（与 `forensics/` 的约定一致）。
"""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

__all__ = ["PROJECT_ROOT", "sandbox_root", "vault_dir", "case_dir"]

#: 沙箱相关的产物根目录（相对项目根）
DEFAULT_ROOT = "logs/sandbox"


def sandbox_root(root: Path | str | None = None) -> Path:
    """沙箱产物根目录。相对路径按项目根解析（不是按 CWD）。"""
    p = Path(root) if root else Path(DEFAULT_ROOT)
    return p if p.is_absolute() else (PROJECT_ROOT / p)


def vault_dir(root: Path | str | None = None) -> Path:
    """只读载荷固化区。"""
    return sandbox_root(root) / "vault"


def case_dir(case_id: str, root: Path | str | None = None) -> Path:
    """某个案例的分析产物目录。"""
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in (case_id or "case"))
    return sandbox_root(root) / "cases" / safe[:80]
