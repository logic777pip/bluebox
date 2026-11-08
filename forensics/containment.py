#!/usr/bin/env python3
"""遏制动作的**占位实现** —— 永不执行任何真实变更。

为什么遏制必须是占位（用户明确要求，同时也是一开始就该这么做）：
    遏制动作（隔离主机 / 封 IP / 禁用账号 / 杀进程）**全部不可逆**。
    自动执行不可逆动作的风险远大于收益：
      * 打错目标 = 自己制造一次事故（本项目评审里实测过：block_ip 打到受害主机
        自己 IP 的比例 41.7%，方向写反 95.8%）；
      * 「隔离一台你正在远程管理的机器」会**切断你自己的通路**，
        包括切断取证与恢复的通道；
      * 没有经过演练的预案，一旦自动执行就没人知道怎么回滚。
    所以这里只把「该做什么、为什么、代价是什么」完整记下来，把
    「要不要做」留给人。返回值里 `executed` 永远是 False。

本模块**没有任何执行能力**：不 import subprocess、不调用任何系统变更 API。
这是刻意写死的 —— 想改成真执行，必须先改这个文件并且被人 review 出来。

用法：
    python -m forensics.containment --action isolate_host --arg host_id=THISPC
    python -m forensics.containment --selftest
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

PLACEHOLDER_BANNER = "【遏制-占位】未执行任何变更"

# 每个遏制动作：目标 / 为什么 / 是否可逆 / 计划命令模板 / 前置条件 / 已知坑
#
# “已知坑”这一栏不是装饰：每一条都对应真实会踩的错，
# 是给人看的最有价值的部分 —— 命令本身谁都会写，代价往往没人提醒。
CONTAINMENT_ACTIONS: Dict[str, Dict[str, Any]] = {
    "isolate_host": {
        "goal": "切断受影响主机的对外通路，限制攻击者横向移动与数据外传",
        "reversible": True,
        "planned": ('New-NetFirewallRule -DisplayName "IR-Isolate-{case_id}" '
                    '-Direction Outbound -Action Block -Profile Any'),
        "prereqs": ["已确认受影响资产与责任人（PDCERF P）",
                    "已固定易失证据（内存/连接表/进程），否则隔离会销毁证据",
                    "**已有主机外的管理通路**（否则你也进不去了）"],
        "pitfalls": [
            "隔离会切断你自己的远程会话 —— 若你正用远程桌面/远控操作这台机器，"
            "执行瞬间就失联，且无法自行解除",
            "只封 Outbound 通常不够：C2 回连是出向，但横向可能入向，需一起评估",
            "业务影响必须先算清楚：隔离一台生产服务器可能比事件本身损失更大"],
    },
    "block_ip": {
        "goal": "阻断与已知恶意对端的通信",
        "reversible": True,
        "planned": ('New-NetFirewallRule -DisplayName "IR-Block-{src_ip}" '
                    '-RemoteAddress {src_ip} -Direction {direction} -Action Block'),
        "prereqs": ["对端 IP 已确认恶意（不是共享 IP / CDN / 云中转）",
                    "方向已确认：C2 回连堵**出向**，攻击入站堵**入向**"],
        "pitfalls": [
            "**不要把受害主机自己的 IP 封掉**（实测发生概率 41.7%）",
            "方向写反等于没封（实测 95.8% 写反）：回连是出向",
            "共享 IP/云中转被封会影响无辜第三方",
            "攻击者换 IP 即绕过 —— 封 IP 是止血，不是根治"],
    },
    "block_domain": {
        "goal": "阻断对恶意域名的解析/访问",
        "reversible": True,
        "planned": ('Add-Content C:\\Windows\\System32\\drivers\\etc\\hosts '
                    '"0.0.0.0 {domain}"  # 或 DNS 侧封禁'),
        "prereqs": ["域名已确认恶意（不是被入侵的正规站点的子域）"],
        "pitfalls": ["改 hosts 只对本机有效；全内网要动 DNS",
                     "若域名属于被入侵的正规站点，封禁会掩盖真实问题"],
    },
    "disable_account": {
        "goal": "阻断被滥用的账号（停止攻击者使用被盗凭据）",
        "reversible": True,
        "planned": "net user {account} /active:no   （域环境：Disable-ADAccount -Identity {account}）",
        "prereqs": ["确认该账号确实被滥用（不是正常用户的正常登录）"],
        "pitfalls": ["禁用服务账号会**直接中断业务**（先确认用途与责任人）",
                     "禁用后攻击者若已在内存里持有凭据，仍可能继续 —— 需配 reset_credential"],
    },
    "revoke_session": {
        "goal": "吊销已建立的会话令牌",
        "reversible": True,
        "planned": "query session　然后　logoff <会话ID>（域环境：Revoke-AzureADUserAllRefreshToken / klist purge）",
        "prereqs": ["确认会话归属"],
        "pitfalls": ["可能踢掉正常用户；对已持久化的窃取凭据无效"],
    },
    "restrict_account": {
        "goal": "按最小权限原则给账号降权",
        "reversible": True,
        "planned": "Remove-ADGroupMember -Identity '<特权组>' -Members {account}",
        "prereqs": ["确认账号原有权限的必要性（别把业务打断了）"],
        "pitfalls": ["降权可能破坏服务账号的自动化任务"],
    },
    "kill_process": {
        "goal": "终止恶意进程",
        "reversible": False,
        "planned": "Stop-Process -Id {pid} -Force",
        "prereqs": ["**先取证**：进程镜像/命令行/加载模块/网络连接要先固定下来",
                    "已确认 pid 归属（pid 会被重用，用创建时间+路径二次确认）"],
        "pitfalls": ["杀掉进程会销毁内存证据（配置、密钥、解密后的载荷）",
                     "有守护机制的恶意程序会立刻重启，杀进程基本无效",
                     "pid 重用可能误杀无辜进程"],
    },
    "quarantine_file": {
        "goal": "隔离恶意文件，阻止再次执行",
        "reversible": True,
        "planned": ("Move-Item -LiteralPath '{path}' -Destination "
                    "'C:\\Quarantine\\<case>'　然后　icacls 拒绝所有人读取"),
        "prereqs": ["**先算哈希并留档**（否则后面无法做情报比对与溯源）",
                    "已确认文件确为恶意（签名有效的正规程序不要隔离）"],
        "pitfalls": ["隔离被系统占用的文件可能失败，需要先停服务",
                     "**签名有效 ≠ 无害，但签名有效的文件误隔离代价很高**"
                     "（本项目实测过：VS 安装器解压到 %TEMP% 的签名程序被误判）"],
    },
}

# 事件 → 建议的遏制动作（**只是建议**，占位记录，不执行）
RECOMMEND_BY_RULE: Dict[str, List[str]] = {
    "high_risk_port": ["block_ip"],
    "c2": ["block_ip", "block_domain"],
    "egress_intranet_to_internet": ["block_ip"],
    "lateral_intranet": ["isolate_host"],
    "conn_burst": ["isolate_host"],
    "port_fanout": ["isolate_host"],
    "proc_from_suspect_dir": ["kill_process", "quarantine_file"],
    "suspect_path": ["kill_process", "quarantine_file"],
    "correlated_local_process": ["block_ip"],
    "credential": ["disable_account", "reset_credential"],
}


def _fill(tpl: str, args: Dict[str, Any]) -> str:
    out = tpl
    for k, v in args.items():
        out = out.replace("{" + k + "}", str(v))
    # 未提供的占位保留原样并标出来，避免"看起来像完整命令"造成误用
    for miss in ("case_id", "src_ip", "direction", "domain", "account", "session_id",
                 "pid", "path", "host_id"):
        if "{" + miss + "}" in out:
            out = out.replace("{" + miss + "}", f"<{miss}未提供>")
    return out


def plan(action: str, args: Optional[Dict[str, Any]] = None,
         reason: str = "", case_id: str = "") -> Dict[str, Any]:
    """产出一份遏制**计划**（不执行）。未知动作如实返回 unknown。"""
    args = dict(args or {})
    if case_id and "case_id" not in args:
        args["case_id"] = case_id
    spec = CONTAINMENT_ACTIONS.get(action)
    if not spec:
        return {"action": action, "known": False, "executed": False,
                "banner": PLACEHOLDER_BANNER,
                "note": f"未登记的遏制动作 `{action}`：本模块不臆造命令，"
                        f"请人工评估后手动处置"}
    return {
        "action": action,
        "known": True,
        "executed": False,                      # 恒定 False：占位
        "banner": PLACEHOLDER_BANNER,
        "goal": spec["goal"],
        "reversible": spec["reversible"],
        "planned_command": _fill(spec["planned"], args),
        "prereqs": spec["prereqs"],
        "pitfalls": spec["pitfalls"],
        "args": args,
        "reason": reason,
        "planned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "execute_hint": ("取证完成、人工确认后再执行。"
                         "本系统只登记计划，不做处置。"),
    }


def recommend(rules: List[str], case_id: str = "", reason: str = "",
              context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """按规则命中给出遏制建议计划（去重、保序）。"""
    ctx = dict(context or {})
    ordered: List[str] = []
    for r in rules:
        for a in RECOMMEND_BY_RULE.get(r, []):
            if a not in ordered:
                ordered.append(a)
    out = []
    for a in ordered:
        if a == "reset_credential":
            # 该动作不在本模块的占位表里（属根除阶段 E，不是遏制 C），如实说明
            out.append({"action": a, "known": False, "executed": False,
                        "banner": PLACEHOLDER_BANNER,
                        "note": "reset_credential 属**根除(E)**阶段而非遏制，"
                                "本模块不代拟命令"})
            continue
        out.append(plan(a, ctx, reason=f"{reason}（由规则 {'、'.join(rules)} 触发）",
                        case_id=case_id))
    return out


def assert_never_executes() -> bool:
    """自检用：确认本模块**确实**没有引入任何执行能力。

    ⚠ 用 AST 而不是搜字符串。第一版是 `if "import subprocess" in 源码:
    return False`，结果**被本文件自己的文档字符串误伤** ——
    上面注释里写着"不 import subprocess"，于是一搜就中，自检假失败。
    用纯文本匹配去做"代码审计"本来就不靠谱（注释/字符串/同形字都能绕过或误伤），
    这里走 AST：只看真正的 import 与函数调用。
    """
    import ast
    try:
        tree = ast.parse(open(__file__, encoding="utf-8").read())
    except (OSError, SyntaxError):
        return False
    banned_modules = {"subprocess"}
    banned_calls = {("os", "system"), ("os", "popen"), ("os", "spawn"),
                    ("subprocess", "run"), ("subprocess", "call"),
                    ("subprocess", "Popen"), ("subprocess", "check_output")}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] in banned_modules:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in banned_modules:
                return False
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and isinstance(node.func.value, ast.Name):
            if (node.func.value.id, node.func.attr) in banned_calls:
                return False
            if node.func.value.id == "ctypes" and node.func.attr == "windll":
                return False
    return True


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

    chk("本模块**没有任何执行能力**（无 subprocess/os.system 等）",
        assert_never_executes())

    p = plan("block_ip", {"src_ip": "203.0.113.9", "direction": "outbound"}, "C2 回连", "C-1")
    chk("计划里 executed 恒为 False", p["executed"] is False)
    chk("计划里有醒目的占位横幅", PLACEHOLDER_BANNER in p["banner"])
    chk("计划里代入参数生成命令", "203.0.113.9" in p["planned_command"], p["planned_command"])
    chk("计划里有前置条件与已知坑", p["prereqs"] and p["pitfalls"])
    chk("block_ip 的坑里点名'不要封受害主机自己'",
        any("受害主机自己" in x for x in p["pitfalls"]))
    chk("isolate_host 的坑里点名'会切断你自己的远程会话'",
        any("切断你自己" in x for x in plan("isolate_host", {"host_id": "H"})["pitfalls"]))
    chk("kill_process 标记为不可逆", plan("kill_process", {"pid": 1})["reversible"] is False)

    miss = plan("block_ip", {}, "x", "C-2")
    chk("缺参数时命令里明确标出未提供，不伪装成完整命令",
        "<src_ip未提供>" in miss["planned_command"], miss["planned_command"])

    unk = plan("nuke_everything", {}, "x")
    chk("未登记动作不臆造命令", unk["known"] is False and "executed" in unk
        and unk["executed"] is False)

    rec = recommend(["proc_from_suspect_dir", "high_risk_port"], "C-3", "可疑")
    acts = [r["action"] for r in rec]
    chk("按规则给出建议动作且去重保序",
        acts == ["kill_process", "quarantine_file", "block_ip"], str(acts))
    chk("全部建议都不执行", all(r["executed"] is False for r in rec))
    rec2 = recommend(["credential"], "C-4", "r")
    rc = next((x for x in rec2 if x["action"] == "reset_credential"), None)
    chk("跨阶段动作如实说明（reset_credential 属 E 阶段，不代拟命令）",
        rc is not None and rc["known"] is False and "根除" in rc["note"],
        str(rc)[:120])
    chk("同一规则里的可处置动作仍然给出计划",
        any(x["action"] == "disable_account" and x.get("known") for x in rec2))

    print(f"\nforensics.containment 自检：{ok} 通过 / {fail} 失败")
    return 1 if fail else 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="遏制动作占位（永不执行）")
    ap.add_argument("--action", default="")
    ap.add_argument("--arg", action="append", default=[], help="形如 key=value，可多次")
    ap.add_argument("--reason", default="")
    ap.add_argument("--case", default="")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.action:
        ap.print_help()
        return 0
    kv = dict(a.split("=", 1) for a in args.arg if "=" in a)
    print(json.dumps(plan(args.action, kv, args.reason, args.case),
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
