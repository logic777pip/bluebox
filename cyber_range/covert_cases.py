#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cyber_range/covert_cases.py — 生成「隐蔽信道检测」评测用的带标签遥测用例。

设计立场（决定了这个评测是否有意义）
------------------------------------

1. **不给提示性措辞**。告警文本只陈述**中性统计量**（报文数、长度取值集合与占比、
   端口发散度、包间隔均值/标准差、主机侧证据）。不写「与业务负载无关」「疑似
   信道」这类编辑性判断——那是**被测对象要做的事**，写进去等于把答案抄进题面。

2. **正负样本规模对齐**。benign 家族（QUIC / WireGuard / RTP / DNS 批量 / NTP /
   UDP 备份 / syslog）在**报文字节数、包数、会话时长**上都与 covert 家族取同一
   分布区间。这样单选题不能靠「量大就是可疑」答对，必须真的去读**形状**特征
   （包长取值集合是否被人为限制成少数几档、是否近似均匀、端口是否发散、
   是否有诱饵填充）。

3. **包含难负样本**（`hard_negative`）。WireGuard/QUIC 本身就是「UDP + 加密 +
   包长不够随机」的形态，是最容易误报的一类；不含它们，precision 就是假的。

4. **覆盖多个隐蔽载体**而不只 NCH/1 一种，避免把评测退化成「单签名匹配」：
   噪声型 UDP、DNS 隧道、ICMP 隧道、HTTP 头部挟带。

5. IP 一律用 RFC5737 文档网段（192.0.2/198.51.100/203.0.113），与项目脱敏豁免
   区一致，避免被 security/sanitize.py 遮成 <IP_n> 而破坏溯源评分。

用法::

    python cyber_range/covert_cases.py --per-family 4 --out data/covert_cases.jsonl
    python cyber_range/covert_cases.py --stats
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.sanitize import get_logger  # noqa: E402

LOG = get_logger("cyber_range.covert_cases")

DEFAULT_OUT = PROJECT_ROOT / "data" / "covert_cases.jsonl"

# 文档网段（RFC5737），与 sanitize 的豁免区一致
_DOC_NETS = ("192.0.2.%d", "198.51.100.%d", "203.0.113.%d")


# --------------------------------------------------------------------------- #
#  用例结构
# --------------------------------------------------------------------------- #

@dataclass
class CovertCase:
    case_id: str
    label: str                 # covert / benign
    family: str
    carrier: str               # udp-noise / dns / icmp / http-header / quic / ...
    technique: str             # 期望被归因到的 ATT&CK 技术（benign 为 "n/a"）
    host: str                  # 期望被归因到的主机标识
    host_ip: str
    peer_ip: str
    dest_port: int
    duration_min: float
    packets: int
    total_bytes: int
    hard_negative: bool = False
    expect_features: List[str] = field(default_factory=list)
    host_evidence: str = ""
    alert: str = ""
    # 维度标记：用于评测按能力维度分组（抗量子 / 噪声填充）
    pqc: bool = False
    cover: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
#  各家族的「外观模型」参数
#
#  covert 家族的共同点：包长被人为限制在少数几档、档位占比接近均匀。
#  benign 家族的包长取值多、分布偏斜——但**规模区间与 covert 完全一致**。
# --------------------------------------------------------------------------- #

# 规模参数：正负样本共用，保证「量」不构成判据
_SCALE = {"packets": (600, 2400), "duration_min": (25, 70)}


@dataclass
class FamilySpec:
    family: str
    label: str
    carrier: str
    technique: str
    dest_ports: Sequence[int]
    bucket_sizes: Sequence[int] | None      # None = 长度取值很多（自然分布）
    bucket_uniform: bool                    # 各档位是否近似均匀
    sport_spread: int                       # 源端口不同取值个数（0=固定）
    gap_mean: float
    gap_sd: float
    hard_negative: bool = False
    expect: Sequence[str] = ()
    evidence: str = ""
    # --- 抗量子 与 噪声模拟 两个维度（对应 ttt 的 L3 / L4 层）---
    pqc_handshake: bool = False             # 是否出现 ML-KEM/ML-DSA 特征长度
    cover: str | None = None                # 覆盖协议（报头伪装成什么）
    decoy_pct: int = 0                      # 无信息填充/诱饵报文占比


# 尺寸桶上界按协议规范 §4.1：上限 448 B，另有 512 B 同步桶。
# （早期版本用了 860/1240 B，超出规范，已修正。）
COVERT_FAMILIES: Sequence[FamilySpec] = (
    FamilySpec(
        "noise_udp", "covert", "udp-noise", "T1095",
        dest_ports=(443, 8443, 53),
        bucket_sizes=(192, 288, 384, 448), bucket_uniform=True,
        sport_spread=90, gap_mean=2.3, gap_sd=0.6, decoy_pct=30,
        cover="QUIC",
        expect=("length_shape", "port_spread", "timing_shape", "decoy_noise",
                "cover_mismatch", "carrier_udp"),
        evidence=("进程 svchost.exe 路径位于 C:\\Users\\Public\\AppData\\Local\\Temp\\，"
                  "无签名，注册表无对应系统服务项，无相关计划任务"),
    ),
    FamilySpec(
        "nch1_full", "covert", "udp-noise", "T1095",
        dest_ports=(443, 9000),
        bucket_sizes=(192, 288, 384, 448), bucket_uniform=True,
        sport_spread=120, gap_mean=2.6, gap_sd=0.5, decoy_pct=30,
        cover="QUIC", pqc_handshake=True,
        expect=("length_shape", "port_spread", "timing_shape", "decoy_noise",
                "cover_mismatch", "pqc_size", "carrier_udp"),
        evidence=("进程 netsvc.exe 位于 C:\\ProgramData\\，无签名、无版本信息；"
                  "主机上无对应服务注册项；防火墙未见该程序的历史放行记录"),
    ),
    FamilySpec(
        "pqc_nonstandard", "covert", "udp-noise", "T1571",
        dest_ports=(9000, 9100, 41234),
        bucket_sizes=(256, 320, 384, 448), bucket_uniform=True,
        sport_spread=70, gap_mean=3.4, gap_sd=0.8, decoy_pct=25,
        cover="QUIC", pqc_handshake=True,
        expect=("pqc_size", "length_shape", "port_spread", "decoy_noise",
                "cover_mismatch"),
        evidence=("进程 ldrtemp.exe 由 outlook.exe 启动（父进程异常），"
                  "可执行文件位于用户下载目录，无签名"),
    ),
    FamilySpec(
        "dns_tunnel", "covert", "dns", "T1071.004",
        dest_ports=(53,),
        bucket_sizes=(96, 128, 160, 192), bucket_uniform=True,
        sport_spread=40, gap_mean=4.1, gap_sd=1.2,
        expect=("length_shape", "port_spread", "timing_shape", "forensics_ask"),
        evidence=("进程 dnscli.exe 非系统 DNS 解析器，首次出现于 3 天前；"
                  "主机 DNS 配置未变更"),
    ),
    FamilySpec(
        "icmp_tunnel", "covert", "icmp", "T1095",
        dest_ports=(0,),
        bucket_sizes=(256, 768, 1200, 1400), bucket_uniform=True,
        sport_spread=0, gap_mean=1.7, gap_sd=0.4, decoy_pct=20,
        expect=("length_shape", "timing_shape", "decoy_noise", "forensics_ask"),
        evidence=("进程 ping.exe 由 winword.exe 启动（父进程异常）；"
                  "该主机无其它正常 ICMP 用途"),
    ),
    FamilySpec(
        "http_header_covert", "covert", "http-header", "T1071.001",
        dest_ports=(80, 8080),
        bucket_sizes=(312, 340, 368), bucket_uniform=True,
        sport_spread=25, gap_mean=6.5, gap_sd=2.0,
        expect=("length_shape", "port_spread", "timing_shape", "forensics_ask"),
        evidence=("进程 curl.exe 由 w3wp.exe 启动；目标域名为 30 天前注册的随机串域名"),
    ),
)


BENIGN_FAMILIES: Sequence[FamilySpec] = (
    FamilySpec(
        "quic_https", "benign", "quic", "n/a",
        dest_ports=(443,), bucket_sizes=None, bucket_uniform=False,
        sport_spread=12, gap_mean=0.9, gap_sd=0.7,
        hard_negative=True,
        evidence="进程 chrome.exe，浏览器正常网络行为；域名命中企业白名单",
    ),
    FamilySpec(
        # 难负样本：现代浏览器已默认启用 X25519MLKEM768 混合密钥交换，
        # 握手报文长度与 ML-KEM-768 完全一致（1216 B 密钥共享）。单纯按
        # 「出现抗量子长度」判可疑会在这里大面积误报。
        "tls_hybrid_pqc", "benign", "tls", "n/a",
        dest_ports=(443,), bucket_sizes=None, bucket_uniform=False,
        sport_spread=8, gap_mean=0.7, gap_sd=0.5,
        hard_negative=True, pqc_handshake=True,
        evidence="进程 chrome.exe；目标域名命中企业白名单；TLS 1.3 记录层结构完整",
    ),
    FamilySpec(
        # 难负样本：内网运维已对 SSH 启用抗量子密钥交换（ML-KEM 混合）。
        "ssh_pqc", "benign", "tls", "n/a",
        dest_ports=(22,), bucket_sizes=None, bucket_uniform=False,
        sport_spread=3, gap_mean=5.0, gap_sd=4.0,
        pqc_handshake=True,
        evidence=("进程 ssh.exe（OpenSSH 官方包，有签名），目标为已登记的运维跳板机；"
                  "源主机为运维工作站"),
    ),
    FamilySpec(
        # 难负样本：合法的「定长填充」应用。包长被人为固定，但业务归属明确。
        "legit_padding", "benign", "udp-noise", "n/a",
        dest_ports=(16384, 20000), bucket_sizes=(320, 320, 320, 384),
        bucket_uniform=True, sport_spread=2, gap_mean=0.02, gap_sd=0.006,
        hard_negative=True, decoy_pct=15,
        evidence="进程 teams.exe，语音会议中；对端为企业 SIP 网关，编解码固定帧长",
    ),
    FamilySpec(
        "wireguard_vpn", "benign", "quic", "n/a",
        dest_ports=(51820,), bucket_sizes=None, bucket_uniform=False,
        sport_spread=1, gap_mean=1.1, gap_sd=0.5,
        hard_negative=True,
        evidence=("进程 wireguard.exe，已注册系统服务，VPN 客户端由 IT 统一下发；"
                  "对端 IP 在已登记的 VPN 网关清单内"),
    ),
    FamilySpec(
        "dns_bulk", "benign", "dns", "n/a",
        dest_ports=(53,), bucket_sizes=None, bucket_uniform=False,
        sport_spread=30, gap_mean=5.2, gap_sd=3.4,
        evidence="进程 svchost.exe(Dnscache)，解析域名集中于企业域与 CDN 域名",
    ),
    FamilySpec(
        "ntp_sync", "benign", "quic", "n/a",
        dest_ports=(123,), bucket_sizes=(48,), bucket_uniform=True,
        sport_spread=1, gap_mean=16.0, gap_sd=0.3,
        evidence="进程 w32time，系统时间同步，对端为已配置的 NTP 服务器",
    ),
    FamilySpec(
        "udp_backup", "benign", "quic", "n/a",
        dest_ports=(2055,), bucket_sizes=None, bucket_uniform=False,
        sport_spread=1, gap_mean=0.4, gap_sd=0.25,
        evidence="进程 veeamagent.exe，夜间备份窗口内，对端为备份服务器",
    ),
    FamilySpec(
        "syslog_udp", "benign", "quic", "n/a",
        dest_ports=(514,), bucket_sizes=None, bucket_uniform=False,
        sport_spread=1, gap_mean=7.5, gap_sd=5.0,
        evidence="进程 rsyslogd，向企业 SIEM 转发日志；源主机为已登记的日志源",
    ),
    FamilySpec(
        "unknown_udp_app", "benign", "quic", "n/a",
        dest_ports=(41234,), bucket_sizes=None, bucket_uniform=False,
        sport_spread=1, gap_mean=3.1, gap_sd=6.0,
        hard_negative=True,
        evidence=("进程 appagent.exe，为内部自研监控代理（资产库已登记，"
                  "版本号与 CMDB 一致）"),
    ),
)


# --------------------------------------------------------------------------- #
#  构造与渲染
# --------------------------------------------------------------------------- #

def _rand_bytes(packets: int, buckets: Sequence[int] | None, uniform: bool,
                rng: random.Random) -> tuple[int, Dict[int, float]]:
    """按外观模型算出总字节数与（包长→占比）。"""
    if buckets:
        if uniform:
            weights = [1.0 / len(buckets)] * len(buckets)
            jitter = [max(0.01, w + rng.uniform(-0.03, 0.03)) for w in weights]
            total_w = sum(jitter)
            props = {b: jitter[i] / total_w for i, b in enumerate(buckets)}
        else:
            props = {b: 1.0 / len(buckets) for b in buckets}
        total = int(sum(b * p for b, p in props.items()) * packets)
        return total, {b: round(p * 100, 1) for b, p in props.items()}

    # 自然分布：取值多、右偏（真实 UDP 应用的常见形态）
    n_kinds = rng.randint(6, 14)
    sizes = sorted(rng.randint(60, 1420) for _ in range(n_kinds))
    weights = [rng.random() ** 2 + 0.05 for _ in sizes]     # 明显偏斜
    total_w = sum(weights)
    props = {s: w / total_w for s, w in zip(sizes, weights)}
    total = int(sum(s * p for s, p in props.items()) * packets)
    return total, {s: round(p * 100, 1) for s, p in props.items()}


def _render(spec: FamilySpec, idx: int, rng: random.Random) -> CovertCase:
    case_id = f"{spec.family}-{idx:02d}"
    host = f"{rng.choice(('ws', 'srv', 'db', 'app'))}-{rng.randint(1, 250):03d}"
    host_ip = _DOC_NETS[rng.randrange(3)] % rng.randint(2, 250)
    peer_ip = _DOC_NETS[rng.randrange(3)] % rng.randint(2, 250)

    packets = rng.randint(*_SCALE["packets"])
    duration = round(rng.uniform(*_SCALE["duration_min"]), 1)
    total_bytes, props = _rand_bytes(packets, spec.bucket_sizes, spec.bucket_uniform, rng)

    dport = rng.choice(list(spec.dest_ports))
    gap_mean = round(spec.gap_mean * rng.uniform(0.85, 1.15), 2)
    gap_sd = round(spec.gap_sd * rng.uniform(0.85, 1.15), 2)

    if spec.sport_spread > 0:
        lo = rng.randint(30000, 40000)
        sport_line = f"源端口 {spec.sport_spread} 个不同取值，分布于 {lo}-{lo + 9000}"
    else:
        sport_line = f"源端口固定为 {rng.randint(30000, 60000)}"

    lens = "、".join(f"{b}B 占 {p}%" for b, p in props.items())
    mb = total_bytes / 1024 / 1024
    carrier_word = {"udp-noise": "UDP", "dns": "UDP/53", "icmp": "ICMP",
                    "http-header": "TCP", "quic": "UDP", "tls": "TCP"}[spec.carrier]

    if spec.carrier == "icmp":
        flow_line = (f"与 {peer_ip} 之间存在持续 ICMP Echo 会话，"
                     f"累计 {packets} 个报文 / {mb:.1f} MB")
        dport_line = "ICMP 无端口，type=8/code=0"
    else:
        flow_line = (f"与 {peer_ip}:{dport} 之间存在持续 {carrier_word} 会话，"
                     f"累计 {packets} 个报文 / {mb:.1f} MB")
        dport_line = f"目标端口 {dport}"

    lines = [
        f"[NDR] 主机 {host}（{host_ip}）{flow_line}。",
        f"会话时长 {duration} 分钟；{dport_line}；{sport_line}。",
        f"报文长度取值：{lens}。",
        f"包间隔：均值 {gap_mean}s，标准差 {gap_sd}s。",
    ]

    # --- 抗量子维度：只给长度，不给解读（解读应由知识库提供）---
    if spec.pqc_handshake:
        n_ek = rng.randint(8, 16)
        n_ct = rng.randint(8, 16)
        n_sig = rng.randint(2, 6)
        lines.append(
            f"会话建立阶段出现固定长度报文：{n_ek} 个 1216 字节、{n_ct} 个 1120 字节、"
            f"{n_sig} 个 1312 字节。")

    # --- 噪声/填充维度：覆盖协议头声明长度与实际数据报长度不一致 ---
    if spec.cover:
        declare = rng.choice((96, 128, 160))
        actual = rng.choice((192, 288, 384, 448))
        lo_pad, hi_pad = 8, 64
        lines.append(
            f"报文首部声明为 {spec.cover}，但该 {spec.cover} 会话缺少应有的连接标识"
            f"与版本协商字段。")
        lines.append(
            f"首部中声明的载荷长度为 {declare} 字节，实际数据报长度 {actual} 字节，"
            f"逐包差值在 {lo_pad}-{hi_pad} 字节间变化。")
    elif spec.decoy_pct:
        lines.append(
            f"报文长度被人为限制在少数档位，其中约 {spec.decoy_pct}% 的报文长度与"
            f"其余报文的长度分布无差别。")

    lines.append(f"主机侧：{spec.evidence}")
    alert = "\n".join(lines)

    return CovertCase(
        case_id=case_id, label=spec.label, family=spec.family, carrier=spec.carrier,
        technique=spec.technique, host=host, host_ip=host_ip, peer_ip=peer_ip,
        dest_port=dport, duration_min=duration, packets=packets,
        total_bytes=total_bytes, hard_negative=spec.hard_negative,
        expect_features=list(spec.expect), host_evidence=spec.evidence, alert=alert,
        pqc=spec.pqc_handshake, cover=bool(spec.cover),
    )


def build_cases(per_family: int = 4, seed: int = 3407) -> List[CovertCase]:
    """生成用例集（确定性：同 seed 同结果）。covert 与 benign 交替排列，避免顺序偏置。"""
    rng = random.Random(seed)
    covert: List[CovertCase] = []
    benign: List[CovertCase] = []
    for spec in COVERT_FAMILIES:
        for i in range(1, per_family + 1):
            covert.append(_render(spec, i, rng))
    for spec in BENIGN_FAMILIES:
        for i in range(1, per_family + 1):
            benign.append(_render(spec, i, rng))

    # 交错：covert, benign, covert, benign ... 并保证长度不同族也打散
    out: List[CovertCase] = []
    ci = bi = 0
    while ci < len(covert) or bi < len(benign):
        if ci < len(covert):
            out.append(covert[ci]); ci += 1
        if bi < len(benign):
            out.append(benign[bi]); bi += 1
    return out


def write_cases(cases: Sequence[CovertCase], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for c in cases:
            fh.write(json.dumps(c.to_dict(), ensure_ascii=False) + "\n")
    LOG.info("已写出 %d 条用例 → %s", len(cases), out)


def _stats(cases: Sequence[CovertCase]) -> Dict[str, Any]:
    cov = [c for c in cases if c.label == "covert"]
    ben = [c for c in cases if c.label == "benign"]

    def agg(rows: Sequence[CovertCase]) -> Dict[str, float]:
        if not rows:
            return {}
        n = len(rows)
        return {
            "count": n,
            "packets_mean": round(sum(r.packets for r in rows) / n, 1),
            "bytes_mb_mean": round(sum(r.total_bytes for r in rows) / n / 1024 / 1024, 2),
            "duration_mean": round(sum(r.duration_min for r in rows) / n, 1),
        }

    return {
        "covert": agg(cov),
        "benign": agg(ben),
        "hard_negative": sum(1 for c in ben if c.hard_negative),
        "families": {"covert": sorted({c.family for c in cov}),
                     "benign": sorted({c.family for c in ben})},
    }


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="隐蔽信道检测评测用例生成")
    ap.add_argument("--per-family", type=int, default=4)
    ap.add_argument("--seed", type=int, default=3407)
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--stats", action="store_true", help="只看规模对齐情况，不落盘")
    ap.add_argument("--show", type=int, default=0, help="打印前 N 条用例文本")
    args = ap.parse_args(argv)

    cases = build_cases(args.per_family, args.seed)
    stats = _stats(cases)
    print(json.dumps(stats, ensure_ascii=False, indent=2))

    if args.show:
        for c in cases[:args.show]:
            print(f"\n--- {c.case_id} [{c.label}] {c.family} ---\n{c.alert}")

    if not args.stats:
        write_cases(cases, Path(args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
