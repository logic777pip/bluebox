#!/usr/bin/env python3
"""端到端测试：Suricata eve 文件 → 生产者 → **真实 RESP 协议** → bridge。

为什么值得单独写这个测试：
    本机没有树莓派、也没有 Redis，所以两侧的真实交互最容易"各自单测都过、
    合起来不通"。这里用内存假 Redis 服务器 + 真的把生产者当**子进程**跑起来，
    走的是和树莓派上完全一样的代码路径与 RESP 报文，
    只有"网线"和"交换机"是假的。

验证内容：
  1) 生产者确实转发了 alert/dns/tls/http/fileinfo/anomaly，**且丢掉了 flow**
  2) 生产者**没有上传载荷**（payload 字段不进 stream）
  3) bridge 能读出来、打分、过滤低信噪类别、算丢包率
  4) 与本机传感器事件**关联命中**（这是两端同时运行的核心价值）
  5) 低于阈值的事件会被记录但不占用模型配额
  6) 报告能生成

用法：python raspi-ids/tests/e2e_local.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
RASPI = HERE.parent
ROOT = RASPI.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from redis_lite import FakeRedisServer, Redis                     # noqa: E402
from suricata_bridge import Bridge, build_parser                  # noqa: E402

OK = FAIL = 0


def chk(name: str, cond: bool, extra: str = "") -> None:
    global OK, FAIL
    if cond:
        OK += 1
        print(f"  [OK] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {extra}")


def main() -> int:
    fixture = HERE / "eve-sample.jsonl"
    if not fixture.exists():
        print(f"缺少样本 {fixture}")
        return 1
    print(f"样本：{fixture}（{len(fixture.read_text(encoding='utf-8').splitlines())} 行）")

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        with FakeRedisServer() as srv:
            print(f"\n[1] 假 Redis 已监听 {srv.host}:{srv.port}（真实 RESP 协议）")

            # ---- 真跑生产者（子进程）----
            env = dict(os.environ)
            cmd = [sys.executable, str(RASPI / "suricata_redis_producer.py"),
                   "--broker", f"{srv.host}:{srv.port}",
                   "--eve-path", str(fixture),
                   "--stream", "suricata:eve",
                   "--stats-stream", "suricata:stats",
                   "--max-events-per-sec", "10000",
                   "--spool", str(tdp / "spool.jsonl"),
                   "--report-every", "60"]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, encoding="utf-8", errors="replace", env=env)

            r = Redis(srv.host, srv.port)
            deadline = time.time() + 20
            while time.time() < deadline:
                if r.xlen("suricata:eve") >= 8 and r.xlen("suricata:stats") >= 1:
                    break
                time.sleep(0.2)
            time.sleep(0.5)
            eve_rows = r.xrange("suricata:eve", count=500)
            stats_rows = r.xrange("suricata:stats", count=50)
            proc.terminate()
            try:
                out = proc.communicate(timeout=5)[0]
            except subprocess.TimeoutExpired:
                proc.kill()
                out = ""

            print(f"\n[2] 生产者转发了 {len(eve_rows)} 条事件 / {len(stats_rows)} 条统计")
            if not eve_rows:
                print("生产者输出：\n" + (out or "(无)")[-2000:])
            types = [f.get("type") for _sid, f in eve_rows]
            chk("告警被转发", types.count("alert") == 3, str(types))
            chk("dns 被转发", types.count("dns") == 2, str(types))
            chk("tls 被转发", types.count("tls") == 2, str(types))
            chk("http 被转发", "http" in types, str(types))
            chk("fileinfo 被转发", "fileinfo" in types, str(types))
            chk("anomaly 被转发", "anomaly" in types, str(types))
            chk("**flow 被丢弃**（镜像口上量最大且信息量最低）", "flow" not in types, str(types))
            chk("stats 走独立流", len(stats_rows) == 2, str(len(stats_rows)))
            blob = json.dumps([f for _s, f in eve_rows], ensure_ascii=False)
            chk("**载荷没有被上传**",
                "BASE64PAYLOADSHOULDNEVERBEUPLOADED" not in blob
                and "GET /api/v1/beacon" not in blob, "载荷泄漏")

            # ---- 造本机传感器事件（模拟"这台 PC 上也有进程在连同一个对端"）----
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            sensor = tdp / "net_sensor_events.jsonl"
            sensor.write_text("\n".join(json.dumps(x, ensure_ascii=False) for x in [
                {"ts": now, "score": 40, "rules": ["high_risk_port"], "pid": 4242,
                 "proc": "updater.exe", "remote": "45.1.2.3:443",
                 "detail": "疑似 C2 回连"},
                {"ts": now, "score": 20, "rules": ["rare_port"], "pid": 99,
                 "proc": "unrelated.exe", "remote": "1.1.1.1:53"},
            ]) + "\n", encoding="utf-8")

            # ---- 用生产同一套参数跑 bridge（不叫模型）----
            args = build_parser().parse_args([
                "--no-llm", "--no-baseline",
                "--broker", f"{srv.host}:{srv.port}",
                "--out", str(tdp / "findings.jsonl"),
                "--log-file", "", "--heartbeat", "0", "--heartbeat-sec", "9999",
                "--sensor-events", str(sensor),
                "--threshold", "30", "--cooldown", "0",
                "--stream", "suricata:eve", "--stats-stream", "suricata:stats",
            ])
            br = Bridge(args)
            br.ensure_groups()
            print(f"\n[3] bridge 消费（阈值 {args.threshold}，不叫模型）")
            for sid, fields in stats_rows:
                br.handle(fields, sid, ack_key="suricata:stats", group=args.group + "-stats")
            for sid, fields in eve_rows:
                br.handle(fields, sid, ack_key="suricata:eve", group=args.group)

            recs = [json.loads(x) for x in
                    (tdp / "findings.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
            by_sig = {str(rec.get("sig") or rec.get("type")): rec for rec in recs}
            print("\n[4] 结果")
            for rec in recs:
                print(f"    {rec.get('score'):>3}  {str(rec.get('sig') or rec.get('type'))[:52]:<52}"
                      f" {'关联' if rec.get('correlated') else '    '} {rec.get('rules')}")

            trojan = by_sig.get("ET TROJAN Observed Malicious SSL Cert (Cobalt Strike C2)")
            chk("高危告警被识别并打高分", trojan is not None and trojan["score"] >= 45,
                str(trojan and trojan["score"]))
            chk("**与本机进程关联命中**（报文+主机证据闭合）",
                bool(trojan and trojan.get("correlated"))
                and (trojan.get("corr") or {}).get("proc") == "updater.exe",
                json.dumps(trojan.get("corr") if trojan else None, ensure_ascii=False))
            chk("关联把 correlated_local_process 写进规则",
                bool(trojan and "correlated_local_process" in trojan["rules"]))
            chk("应用层上下文被补上（SNI/JA3 来自同期 tls 事件）",
                bool(trojan and trojan.get("ctx", {}).get("tls_sni") == "cdn-metrics.example.net"
                     and trojan.get("ctx", {}).get("tls_ja3")),
                json.dumps(trojan.get("ctx") if trojan else None, ensure_ascii=False))

            policy = by_sig.get("ET POLICY SMB2 NT Create AndX Request For an Executable File")
            chk("策略类低信噪告警被打低分", policy is not None and policy["score"] < 30,
                str(policy and policy["score"]))
            chk("低信噪类别标记生效", bool(policy and "category_low_signal" in policy["rules"]),
                str(policy and policy["rules"]))
            chk("低于阈值的事件**仍被记录**（便于回溯）", policy is not None)

            tls_self = next((x for x in recs if x.get("rules") == ["tls_selfsigned_nonstandard_port"]),
                            None)
            chk("自签证书非标准端口启发式被记录", tls_self is not None and tls_self["score"] == 28,
                str(tls_self and tls_self.get("score")))
            chk("启发式低于阈值 → 不占用模型配额（无 triage）",
                bool(tls_self and not tls_self.get("triage")))

            dns_long = next((x for x in recs if x.get("rules") == ["dns_very_long_label"]), None)
            chk("超长 DNS 标签启发式被记录", dns_long is not None and dns_long["score"] == 25,
                str(dns_long and dns_long.get("score")))
            chk("正常域名不触发启发式",
                not any("www.microsoft.com" in json.dumps(x, ensure_ascii=False) for x in recs))

            chk("丢包率被算出", abs((br.stats.drop_rate() or 0) - 0.02476) < 0.01,
                str(br.stats.drop_rate()))
            chk("无告警时也不会把 stats 当成告警",
                not any(x.get("type") == "stats" for x in recs))

            # ---- 报告 ----
            ins = Bridge(args)
            from suricata_bridge import report
            date = time.strftime("%Y-%m-%d")
            rc = report(ins_args(args, tdp / "findings.jsonl"), date)
            chk("报告生成成功", rc == 0)
            rp = ROOT / "reports" / f"suricata_{date}.md"
            chk("报告文件存在且非空", rp.exists() and rp.stat().st_size > 400,
                str(rp if rp.exists() else "缺失"))

    print(f"\n端到端测试：{OK} 通过 / {FAIL} 失败")
    return 1 if FAIL else 0


def ins_args(args, out: Path):
    """报告函数只用到 out/stream，直接复用同一命名空间再改 out，避免参数漂移。"""
    args.out = str(out)
    args.stream = "suricata:eve"
    return args


if __name__ == "__main__":
    raise SystemExit(main())
