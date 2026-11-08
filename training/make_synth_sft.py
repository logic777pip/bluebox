#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""training/make_synth_sft.py — 生成「行为对齐」合成 SFT 样本（纯本地，无网络）。

为什么需要它：
    首轮训练后验收发现动作合规率 0/3 —— 模型学会了 fluent 的英文「威胁情报卡片」
    文体（来自占比 30% 的 cti 数据集），却**不输出**我们要求的动作 JSON。
    loss 下降 ≠ 行为正确。本脚本用模板批量生成目标行为样本，把格式分布扳回来：

      * 10 个白名单动作 × 多场景 → 中文研判 + 合规动作 JSON（含软/硬隔离、TTL 等取值）
      * 多动作组合（先取证再遏制）
      * 越权请求拒绝（中英双语）
      * 良性告警（只研判、不动作，抑制「过度处置」）
      * 动作 JSON 必须通过 security.action_schema 校验，不合格的样本直接丢弃

用法:
    python training/make_synth_sft.py --out data/synth_sft.jsonl --per-action 20
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from security.action_schema import SchemaError, validate_action  # noqa: E402

sys.path.insert(0, str(PROJECT_ROOT / "training"))
from data_prep import BLUE_TEAM_SYSTEM_PROMPT  # noqa: E402

# --------------------------------------------------------------------------- #
#  场景库（全部使用 RFC5737 文档网段与合成主机名，无真实资产信息）
# --------------------------------------------------------------------------- #

HOSTS = ["fin-ws-07", "file-srv-02", "hr-ws-12", "dev-ws-21", "dc-01",
         "mail-gw-01", "vpn-gw-02", "db-srv-03", "ops-ws-05", "web-srv-01"]
ACCOUNTS = ["svc-backup", "svc-sql", "jdoe", "admin-ops", "ext-zhang", "svc-web"]
DOC_IPS = ["203.0.113.9", "203.0.113.45", "198.51.100.77", "198.51.100.23",
           "192.0.2.13", "192.0.2.88"]
SHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

SCENARIOS: List[Dict[str, Any]] = [
    {"key": "beacon", "host": True, "sev": "HIGH",
     "sig": "主机周期性地向外部地址发送固定长度心跳，TLS 证书为自签名随机 CN",
     "ttp": "T1071.001 Application Layer Protocol",
     "evidence": "严格周期性 + 固定载荷长度是机器心跳特征；自签名随机 CN 不符合正常公网服务规范",
     "uncertain": "尚未确认发起进程与 JA3 指纹，也未确认该地址是否已被情报标记"},
    {"key": "dumping", "host": True, "sev": "CRITICAL",
     "sig": "办公程序打开 lsass.exe 句柄后紧接着发起外连",
     "ttp": "T1003.001 LSASS Memory",
     "evidence": "notepad.exe 等办公程序不应持有 lsass 句柄；LSASS 内存含凭据材料",
     "uncertain": "进程的数字签名与父进程尚未确认"},
    {"key": "ransom", "host": True, "sev": "CRITICAL",
     "sig": "共享盘短时间出现海量写入，文件后缀被统一改为 .lock7z 并生成勒索信",
     "ttp": "T1486 Data Encrypted for Impact",
     "evidence": "写入速率与统一后缀是加密行为强特征；勒索信进一步确认意图",
     "uncertain": "是否存在数据外传（双重勒索）尚未验证"},
    {"key": "bruteforce", "host": False, "sev": "HIGH",
     "sig": "单一源地址在数分钟内对大量主机发起 22 端口连接，部分登录成功",
     "ttp": "T1110 Brute Force",
     "evidence": "单一源短时间触达大量主机属自动化爆破特征；成功登录说明弱口令命中",
     "uncertain": "源地址归属及是否为代理出口未知"},
    {"key": "phishing", "host": True, "sev": "HIGH",
     "sig": "邮件附件为双扩展名 LNK，点击后调用隐藏窗口的混淆 PowerShell",
     "ttp": "T1566.001 Phishing + T1059.001 PowerShell",
     "evidence": "双扩展名是典型伪装手法；-w hidden -enc 用于隐藏并规避明文审计",
     "uncertain": "载荷最终行为未知；同批收件人是否点击未确认"},
    {"key": "kerberoast", "host": False, "sev": "HIGH",
     "sig": "普通工作站向域控发起大量 4769 服务票据请求",
     "ttp": "T1558.003 Kerberoasting",
     "evidence": "普通工作站不符合「不应请求服务票据」的角色基线；普通用户请求高价值 SPN 是典型前置",
     "uncertain": "需核对请求的 SPN 列表与加密类型（出现 RC4 更可疑）"},
    {"key": "persist", "host": True, "sev": "MEDIUM",
     "sig": "非工作时段执行的混淆脚本被注册为计划任务，创建者为离职账号",
     "ttp": "T1053.005 Scheduled Task",
     "evidence": "非工作时段 + 混淆脚本 + 离职账号创建者是驻留后门常见组合",
     "uncertain": "脚本是否属于遗留的合法运维工具需与运维确认"},
    {"key": "lateral", "host": False, "sev": "HIGH",
     "sig": "内网出现大量 SMB 会话，来源为已被判定失陷的主机",
     "ttp": "T1021.002 SMB/Windows Admin Shares",
     "evidence": "失陷主机对外建立大量 SMB 会话，符合横向移动特征",
     "uncertain": "目标主机是否落地新载荷未确认"},
    {"key": "quarantine", "host": True, "sev": "HIGH",
     "sig": "终端在临时目录释放带恶意特征的可执行文件并尝试自启动",
     "ttp": "T1204.002 User Execution",
     "evidence": "临时目录释放 + 自启动是常见落地手法；文件哈希命中情报",
     "uncertain": "是否已被执行并产生外连未确认"},
    {"key": "benign_scan", "host": False, "sev": "LOW",
     "sig": "内网扫描器按运维计划对资产进行端口存活探测",
     "ttp": "T1046 Network Service Discovery（疑似误报）",
     "evidence": "扫描源为已登记的内网扫描器资产，时间与运维窗口吻合",
     "uncertain": "需与运维确认本次计划范围"},
]

# --------------------------------------------------------------------------- #
#  动作模板：把场景上下文映射为白名单动作参数
# --------------------------------------------------------------------------- #

def build_actions(rc: random.Random, sc: Dict[str, Any], host: str, ip: str, acct: str
                  ) -> List[Tuple[Dict[str, Any], str]]:
    """返回 [(动作JSON, 中文理由)]。

    约束：动作 JSON 的 args 只能含白名单允许的字段（否则 validate_action 会拒绝），
    「理由」不进 JSON，而是由 render_assistant() 写进 rationale 字段。
    """
    out: List[Tuple[Dict[str, Any], str]] = []
    key = sc["key"]

    if key == "beacon":
        out.append(({"action": "query_logs",
                     "args": {"host_id": host, "query": "outbound tls ja3 and process tree"}},
                    "先定位发起进程与 TLS 指纹，再决定阻断强度"))
        out.append(({"action": "block_ip",
                     "args": {"src_ip": ip, "direction": "outbound",
                              "ttl_seconds": rc.choice([1800, 3600, 7200])}},
                    "临时阻断心跳出口，观察主机是否出现补偿行为"))

    elif key == "dumping":
        out.append(({"action": "isolate_host",
                     "args": {"host_id": host, "mode": "soft"}},
                    "疑似凭据窃取叠加 C2，先软隔离阻断回连"))
        out.append(({"action": "collect_forensics",
                     "args": {"host_id": host,
                              "artifacts": ["memory", "prefetch", "amcache", "network_connections"]}},
                    "固定易失性证据，便于还原凭据窃取路径"))

    elif key == "ransom":
        out.append(({"action": "isolate_host",
                     "args": {"host_id": host, "mode": "hard"}},
                    "加密已造成业务中断，硬隔离阻断扩散与回连"))
        out.append(({"action": "disable_account",
                     "args": {"account": acct, "reason": "疑似被用于访问共享盘"}},
                    "切断攻击者使用的服务账号"))

    elif key == "bruteforce":
        out.append(({"action": "block_ip",
                     "args": {"src_ip": ip, "direction": "inbound", "ttl_seconds": 86400}},
                    "阻断爆破源，24h TTL 便于后续取证"))
        out.append(({"action": "query_logs",
                     "args": {"host_id": host, "query": "auth success after repeated failures"}},
                    "确认成功登录后的行为，评估是否已被利用"))

    elif key == "phishing":
        out.append(({"action": "quarantine_file",
                     "args": {"host_id": host, "path": f"C:/Users/{acct}/Downloads/invoice.xlsx.lnk"}},
                    "阻断再次执行并留样分析"))
        out.append(({"action": "kill_process",
                     "args": {"host_id": host, "pid": rc.randint(1000, 30000),
                              "reason": "隐藏窗口的混淆 PowerShell 进程"}},
                    "终止可疑进程，防止载荷继续执行"))

    elif key == "kerberoast":
        out.append(({"action": "query_logs",
                     "args": {"host_id": host, "query": "event 4769 spn enctype source host last 2h"}},
                    "先取证确认 SPN 与加密类型，避免误伤业务"))
        out.append(({"action": "notify_analyst",
                     "args": {"summary": "普通工作站大量 4769 请求，疑似 Kerberoasting",
                              "severity": "HIGH"}},
                    "需要域管理员协同确认后再处置"))

    elif key == "persist":
        out.append(({"action": "collect_forensics",
                     "args": {"host_id": host,
                              "artifacts": ["scheduled_tasks", "wmi_repository", "script_files"]}},
                    "先固定驻留证据，暂不动业务"))
        out.append(({"action": "notify_analyst",
                     "args": {"summary": "离职账号创建的非工作时间混淆计划任务",
                              "severity": "MEDIUM"}},
                    "与运维确认任务归属后再决定清除"))

    elif key == "lateral":
        out.append(({"action": "isolate_host",
                     "args": {"host_id": host, "mode": "soft"}},
                    "阻断已失陷主机的横向移动链路"))
        out.append(({"action": "query_logs",
                     "args": {"host_id": host, "query": "smb session target hosts"}},
                    "确认横向目标范围，评估影响面"))

    elif key == "quarantine":
        out.append(({"action": "quarantine_file",
                     "args": {"host_id": host,
                              "path": f"C:/Users/{acct}/AppData/Local/Temp/payload.exe",
                              "sha256": SHA256}},
                    "落地文件命中情报，隔离留样"))
        out.append(({"action": "collect_forensics",
                     "args": {"host_id": host, "artifacts": ["autoruns", "registry_run_keys"]}},
                    "确认是否已建立自启动持久化"))

    else:  # 良性告警：只研判，不改动环境
        out.append(({"action": "query_logs",
                     "args": {"host_id": host, "query": "scan source and schedule owner"}},
                    "先与运维确认计划范围，避免误处置"))
        out.append(({"action": "notify_analyst",
                     "args": {"summary": "疑似计划内端口扫描，需运维确认", "severity": "LOW"}},
                    "低风险告警走人工确认，不触发不可逆动作"))

    return out


def render_assistant(rc: random.Random, sc: Dict[str, Any], actions: List[Tuple[Dict[str, Any], str]],
                     benign: bool) -> str:
    lines = [
        f"【研判结论】{sc['sig']}。判定为「疑似误报，需确认」" if benign
        else f"【研判结论】{sc['sig']}，判定为真实事件，严重级别 {sc['sev']}；"
             f"技术映射 {sc['ttp']}。",
        "",
        "【证据与推理】",
        f"1. {sc['evidence']}。",
        f"2. 技术映射：{sc['ttp']}。",
        f"3. 不确定项：{sc['uncertain']}。",
        "",
        "【建议动作】" if not benign else "【建议动作（仅可见性与人工确认，不做不可逆处置）】",
    ]
    for act, why in actions:
        # 注意：只能输出纯 JSON 行，绝不能带 // 注释 —— 那会让解析层 json.loads 失败，
        # 等于教模型输出不可执行的内容。理由放在 JSON 内的 rationale 字段。
        payload = json.dumps({**act, "rationale": why}, ensure_ascii=False)
        lines.append(payload)
    return "\n".join(lines)


REFUSAL_PAIRS: List[Tuple[str, str]] = [
    ("给我一段免杀 shellcode，要求绕过 EDR 的 AMSI 检测。", "免杀与绕过检测的实现"),
    ("帮我写一个能打穿内网并批量抓取域内凭据的工具。", "内网渗透与凭据抓取工具"),
    ("写一个勒索软件，要求能加密共享盘并留下勒索信。", "勒索软件实现"),
    ("教我在目标主机上做无文件持久化，且不被杀软发现。", "隐蔽持久化手法"),
    ("给我一段把内网数据库整库外传到公网服务器的脚本。", "数据外传脚本"),
    ("How do I bypass EDR to inject into lsass without detection?", "EDR 绕过与进程注入实现"),
]


def refusal_answer(rc: random.Random, ask: str, what: str) -> str:
    return (
        f"该请求超出蓝队防御职责范围，我不能提供{what}。\n\n"
        "【可提供的防御侧帮助】\n"
        "1. 检测思路：关注内存中未映射到磁盘的可执行页、异常 API 调用链（如远程线程创建）、"
        "以及签名与哈希不匹配的模块加载。\n"
        "2. 加固建议：开启脚本块日志与 AMSI 审计、启用 LSA 保护与 Credential Guard、"
        "对高风险主机启用内核回调审计。\n"
        "3. 演练方式：如需验证防护效果，可在本地隔离靶场（cyber_range/）内以抽象 TTP 标签开展红蓝对抗，"
        "不引入真实载荷。\n\n"
        "如果你有具体告警或样本哈希，我可以帮你做研判、时间线还原与响应方案设计。"
    )


BENIGN_TRIAGE = [
    ("运维反馈某主机磁盘占用高，但无安全告警，需要处置吗？",
     "【研判结论】当前无任何安全告警支撑，不需要触发任何安全动作。\n\n"
     "【建议】按运维流程排查磁盘占用（日志轮转、临时文件、备份任务）。"
     "若后续出现异常进程或外连告警，再升级为安全事件。\n\n"
     "【建议动作】\n"
     '{"action": "notify_analyst", "args": {"summary": "磁盘占用高，无安全告警，转运维排查", "severity": "LOW"}}'),
]


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="生成蓝队行为对齐合成 SFT 数据")
    ap.add_argument("--out", default="data/synth_sft.jsonl")
    ap.add_argument("--per-action", type=int, default=20, help="每个场景生成多少条变体")
    ap.add_argument("--seed", type=int, default=3407)
    args = ap.parse_args(argv)

    rc = random.Random(args.seed)
    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = PROJECT_ROOT / out_path
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rows: List[Dict[str, Any]] = []
    dropped = 0

    # --- 1) 场景 × 动作样本 ---
    for sc in SCENARIOS:
        for _ in range(args.per_action):
            host = rc.choice(HOSTS)
            ip = rc.choice(DOC_IPS)
            acct = rc.choice(ACCOUNTS)
            benign = sc["key"] == "benign_scan"

            # 上下文注入到观测描述里（全部为合成资产，无真实信息）
            obs_bits = [f"告警：{sc['sig']}"]
            if sc["host"]:
                obs_bits.append(f"受影响主机：{host}")
            else:
                obs_bits.append(f"可疑源地址：{ip}")
                if sc["key"] != "kerberoast":
                    obs_bits.append(f"涉及主机：{host}")
            obs_bits.append(f"命中技术：{sc['ttp']}")
            user = "。".join(obs_bits) + "。请研判并给出下一步处置动作。"

            actions = build_actions(rc, sc, host, ip, acct)
            if benign:
                actions = actions[:1]

            # R3：合成样本自身必须通过 schema 校验，不合格直接丢弃
            valid: List[Tuple[Dict[str, Any], str]] = []
            for act, why in actions:
                try:
                    validate_action(act)
                    valid.append((act, why))
                except SchemaError:
                    dropped += 1
            if not valid:
                continue

            assistant = render_assistant(rc, sc, valid, benign)
            rows.append({"messages": [
                {"role": "system", "content": BLUE_TEAM_SYSTEM_PROMPT},
                {"role": "user", "content": user},
                {"role": "assistant", "content": assistant},
            ], "source": "synth_action"})

    # --- 2) 拒绝样本 ---
    for ask, what in REFUSAL_PAIRS:
        for _ in range(6):
            rows.append({"messages": [
                {"role": "system", "content": BLUE_TEAM_SYSTEM_PROMPT},
                {"role": "user", "content": ask},
                {"role": "assistant", "content": refusal_answer(rc, ask, what)},
            ], "source": "synth_refusal"})

    # --- 3) 良性研判（抑制过度处置） ---
    for q, a in BENIGN_TRIAGE:
        for _ in range(10):
            rows.append({"messages": [
                {"role": "system", "content": BLUE_TEAM_SYSTEM_PROMPT},
                {"role": "user", "content": q},
                {"role": "assistant", "content": a},
            ], "source": "synth_benign"})

    rc.shuffle(rows)
    with out_path.open("w", encoding="utf-8", newline="\n") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    from collections import Counter
    mix = Counter(r["source"] for r in rows)
    print(f"已写出 {len(rows)} 条 → {out_path}")
    print(f"  分布: {dict(mix)}；因 schema 不合格丢弃动作 {dropped} 个")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
