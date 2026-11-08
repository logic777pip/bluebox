#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/add_benign_seeds.py — 向知识库追加「**良性判据**」种子（幂等）。

依据（对应 `D:\\vvv.txt` 里 SecLLM 的做法）
------------------------------------------

材料里说：**用 RAG 给模型提供上下文知识，把误报升级量减少 42%**；
消融实验里移除 RAG 会让遏制时间减慢 19%。

但本项目原来的 26 条种子**全是攻击判据**（technique/playbook），
检索时只会给模型「怎么算攻击」，不会给「这些看起来像攻击的其实是正常业务」。
结果是模型拿不到反证知识 —— 这正是我们实测误报的直接成因。

本脚本补的是一批 **`kind: benign_pattern`** 的「像攻击的正常业务」判据，
全部来自本项目**实测误报**（VS 安装器自解压、浏览器 DNS 突发、开发工具
非标端口、厂商心跳、交付优化、定长媒体流、抗量子握手长度等）。

幂等：已存在的 doc_id 不会重复追加。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SEED_FILE = PROJECT_ROOT / "rag" / "seeds" / "blue_team_seed.jsonl"

# doc_id 统一前缀，便于识别与清理
BENIGN_SEEDS: List[Dict[str, Any]] = [
    {"doc_id": "kb-benign-001", "text":
     "【像攻击的正常业务】安装器/更新器自解压到临时目录再运行："
     "Visual Studio 安装器会把签名的组件（如 BackgroundDownload.exe）解压到 "
     "%LOCALAPPDATA%\\Temp\\<随机串>\\ 后执行，并对外连接 Microsoft/Akamai 的 443。"
     "判据：进程位于 Temp 但**数字签名有效**、父进程为已安装的安装器/更新器、"
     "目标为厂商 CDN。**只有「位于临时目录」不足以定性**，必须叠加签名与父进程证据。",
     "metadata": {"source": "seed", "kind": "benign_pattern",
                  "tags": ["benign", "installer", "temp", "fp-reduction"],
                  "evidence": "实测误报（2026-10-03 01:59 BackgroundDownload.exe）"}},

    {"doc_id": "kb-benign-002", "text":
     "【像攻击的正常业务】浏览器向本地 DNS 服务器大量解析：浏览器多标签/预取会产生"
     "短时间内对同一台 DNS 的**大量 UDP 查询**，每条查询使用一个新的本地源端口。"
     "因此「对同一目标出现几十条连接」在 UDP 上是**计数假象**，不是连接爆发。"
     "判据：协议为 UDP、目的端口 53/5353、目标是环境内已配置的 DNS 服务器。",
     "metadata": {"source": "seed", "kind": "benign_pattern",
                  "tags": ["benign", "dns", "udp", "fp-reduction"],
                  "evidence": "实测误报（2026-10-03 10:11 msedge.exe → DNS:53）"}},

    {"doc_id": "kb-benign-003", "text":
     "【像攻击的正常业务】开发工具使用非标准端口外连：VS Code、JetBrains 系列、"
     "Electron 应用、包管理器会连接 3000-9999 区间的端口（如 3333、5555、8080、"
     "9229），用于扩展市场、调试桥、语言服务或自建代理。"
     "判据：进程为已安装的编辑器/开发工具、路径在正规安装目录、目标为 CDN/市场域名。",
     "metadata": {"source": "seed", "kind": "benign_pattern",
                  "tags": ["benign", "devtool", "rare-port", "fp-reduction"],
                  "evidence": "实测误报（Code.exe → :3333）"}},

    {"doc_id": "kb-benign-004", "text":
     "【像攻击的正常业务】厂商/云服务的固定周期心跳：OneDrive、Teams、Slack、"
     "企业 IM、杀软更新模块会以固定间隔连接**厂商自己的域名**。形状与 C2 信标相同，"
     "周期本身不能区分。⚠ **本条只在同时满足下列全部条件时才适用**："
     "① 目标端口为 443/80 等标准端口；② 域名为可核验的厂商域名（非新注册、非随机 CN）；"
     "③ TLS 证书链有效；④ 进程已签名且在正规安装目录。"
     "若目标为新注册域名、自签名证书、或进程无签名，则**不适用本条**，按信标处理。",
     "metadata": {"source": "seed", "kind": "benign_pattern",
                  "tags": ["benign", "beacon", "heartbeat", "fp-reduction"],
                  "evidence": "实测误报（codex.exe → IPv6 :443 每 20 秒）；已收紧为需四项同时成立"}},

    {"doc_id": "kb-benign-005", "text":
     "【像攻击的正常业务】Windows 更新与交付优化：svchost.exe/DeliveryOptimization"
     "会从 Microsoft 与 Akamai 的多个地址（13.107.x.x、13.85.x.x、88.202.x.x、"
     "2600:1417::/32）并行下载，产生大量并发连接与大流量上行/下行。"
     "判据：目标是微软/运营商 CDN 段、进程为系统更新组件、有签名的更新包哈希。",
     "metadata": {"source": "seed", "kind": "benign_pattern",
                  "tags": ["benign", "update", "cdn", "fp-reduction"]}},

    {"doc_id": "kb-benign-006", "text":
     "【像攻击的正常业务】VPN/零信任客户端的周期性重协商："
     "wireguard/openvpn/AnyConnect 等客户端会按固定间隔做隧道重协商，"
     "表现为长时间稳定速率的 UDP 流 + 周期性小包。"
     "判据：进程为 IT 统一下发的已签名 VPN 客户端、对端为环境内登记的 VPN 网关。",
     "metadata": {"source": "seed", "kind": "benign_pattern",
                  "tags": ["benign", "vpn", "udp", "fp-reduction"]}},

    {"doc_id": "kb-benign-007", "text":
     "【像攻击的正常业务】定长 UDP 媒体流（会议/直播/游戏）：Teams、Zoom、腾讯会议等"
     "使用 RTP 定长载荷，包长集中在少数档位、间隔极规律、源端口多个。"
     "这与「形状塑形的隐蔽信道」外观高度相似。"
     "判据：进程为已签名会议/游戏客户端、对端为厂商媒体服务器、"
     "**存在会议日程或实时音频特征**、无对外文件读取。",
     "metadata": {"source": "seed", "kind": "benign_pattern",
                  "tags": ["benign", "media", "shape", "fp-reduction"],
                  "evidence": "隐蔽信道评测里误伤最重的家族（legit_padding FPR 1.00）"}},

    {"doc_id": "kb-benign-008", "text":
     "【像攻击的正常业务】抗量子/混合密钥交换的握手长度：现代浏览器 TLS 1.3 默认"
     "启用 X25519MLKEM768，握手包长度约 1216/1120 字节（ML-KEM-768 封装公钥 1184+32、"
     "密文 1088+32）。⚠ **本条只在 443 标准端口 + 可核验域名 + 有效证书链 + 已签名浏览器/"
     "客户端进程**时适用。若出现抗量子长度但同时伴随：非标准端口、未签名进程、"
     "无业务归属、自签名或随机 CN 证书 —— 则**不适用本条**，应作为可疑处理"
     "（这正是隐蔽信道伪装成 TLS 时的手法）。",
     "metadata": {"source": "seed", "kind": "benign_pattern",
                  "tags": ["benign", "pqc", "tls", "fp-reduction"],
                  "evidence": "隐蔽信道评测里反复出现该形状；已收紧为需四项同时成立"}},

    {"doc_id": "kb-benign-009", "text":
     "【像攻击的正常业务】备份/同步/杀软扫描窗口：veeamagent、rsync、OneDrive、"
     "杀软全盘扫描会在登记的维护窗口内产生大量文件读写与网络传输。"
     "判据：处于资产库登记的窗口、任务 ID 与历史一致、目标为登记的备份/更新服务器。"
     "**「非工作时段」不等于恶意** —— 备份与更新本来就安排在非工作时段。",
     "metadata": {"source": "seed", "kind": "benign_pattern",
                  "tags": ["benign", "backup", "window", "fp-reduction"],
                  "evidence": "实测误报（backup_window / file_share 被判横向移动）"}},

    {"doc_id": "kb-benign-010", "text":
     "【误报抑制判据】把「异常」升级为「攻击」必须要有**区分性证据**："
     "能推翻正常业务解释的具体事实，例如：账号与主机登记使用人不符、"
     "进程无签名或签名无效、可执行文件路径位于 Temp/Public/Downloads 且父进程异常、"
     "目标不在任何登记清单内、时间窗与登记窗口不符、出现已知恶意域名/IP 情报命中。"
     "反面清单（**不能**作为攻击判据）：「次数多」「数值高」「非工作时段」"
     "「超出同网段基线」「未命中情报」「地址属文档网段」。",
     "metadata": {"source": "seed", "kind": "benign_pattern",
                  "tags": ["benign", "fp-reduction", "discriminator"],
                  "evidence": "本项目实测：无区分性证据的攻击判定占 62-71%"}},
]


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="追加/刷新良性判据种子（幂等）")
    ap.add_argument("--file", default=str(SEED_FILE))
    ap.add_argument("--check", action="store_true", help="只检查不写入")
    ap.add_argument("--refresh", action="store_true",
                    help="用当前定义**覆盖**已存在的同 doc_id 条目（用于收紧措辞后刷新）")
    args = ap.parse_args(argv)

    path = Path(args.file)
    if not path.exists():
        raise SystemExit(f"种子文件不存在：{path}")

    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    have = set()
    for l in lines:
        try:
            have.add(json.loads(l).get("doc_id"))
        except json.JSONDecodeError:
            continue

    todo = [s for s in BENIGN_SEEDS if s["doc_id"] not in have]
    print(f"现有种子 {len(lines)} 条；待追加良性判据 {len(todo)} 条")
    if args.check:
        for s in todo:
            print(f"  + {s['doc_id']}  {s['text'][:60]}…")
        return 0

    if args.refresh:
        # 用当前定义覆盖同 doc_id 的旧条目：收紧措辞后必须能刷新，
        # 否则「改了种子文件但知识库里还是旧文本」会让人以为改动没生效。
        by_id = {s["doc_id"]: s for s in BENIGN_SEEDS}
        out_lines: List[str] = []
        replaced = 0
        for l in lines:
            try:
                did = json.loads(l).get("doc_id")
            except json.JSONDecodeError:
                out_lines.append(l)
                continue
            if did in by_id:
                out_lines.append(json.dumps(by_id[did], ensure_ascii=False))
                replaced += 1
            else:
                out_lines.append(l)
        path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
        print(f"已用当前定义覆盖 {replaced} 条；本次定义共 {len(BENIGN_SEEDS)} 条")
        if len(todo) > 0:
            with path.open("a", encoding="utf-8") as fh:
                for s in todo:
                    fh.write(json.dumps(s, ensure_ascii=False) + "\n")
            print(f"另追加新条目 {len(todo)} 条")
        return 0

    if not todo:
        print("已全部存在，无需追加")
        return 0

    # 校验后追加（不允许写坏已有文件）
    for s in todo:
        json.dumps(s, ensure_ascii=False)
    with path.open("a", encoding="utf-8") as fh:
        for s in todo:
            fh.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"已追加 {len(todo)} 条 → {path}")

    # 回读校验
    now = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    bad = 0
    for l in now:
        try:
            json.loads(l)
        except json.JSONDecodeError:
            bad += 1
    print(f"回读校验：共 {len(now)} 条，JSON 损坏 {bad} 条")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
