#!/bin/bash
# 蓝队 IDS 装置自检（在树莓派上跑）。
#
# 为什么自检里把**丢包率**放在最前面：
#   一台"看起来在跑"的 IDS 可能丢掉了 30% 的流量 —— 它的告警看着正常，
#   但实际是瞎的。丢包率是判断这套装置能不能被信任的前提指标，
#   比"有没有告警"重要得多。丢包来源有两处，都要看：
#     capture.kernel_drops  —— 内核/驱动层没接住（缓冲不够、CPU 跟不上）
#     decoder.invalid       —— 接到了但解不了（校验和错、截断帧）
#
# 用法：
#   sudo ./verify_pi.sh                       # 全项检查
#   sudo ./verify_pi.sh --iface eth0
#   sudo ./verify_pi.sh --top-sigs 20         # 看最近告警里最高频的签名（调优用）
#   sudo ./verify_pi.sh --test-push           # 往 stream 发一条测试事件，验证 PC 侧能收到
set -uo pipefail

IFACE="eth0"
ENVFILE=/etc/default/blueteam-ids
EVE=/var/log/suricata/eve.json
TOP=0
TEST_PUSH=0

while [ $# -gt 0 ]; do
  case "$1" in
    --iface) IFACE="${2:?}"; shift 2 ;;
    --eve) EVE="${2:?}"; shift 2 ;;
    --top-sigs) TOP="${2:?}"; shift 2 ;;
    --test-push) TEST_PUSH=1; shift ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "未知参数 $1" >&2; exit 2 ;;
  esac
done

if [ -r "$ENVFILE" ]; then
  # shellcheck disable=SC1090
  . "$ENVFILE"
  IFACE="${IDS_IFACE:-$IFACE}"
  EVE="${IDS_EVE_PATH:-$EVE}"
fi

BROKER="${IDS_BROKER:-127.0.0.1:6379}"
STREAM="${IDS_STREAM:-suricata:eve}"
PASS="${IDS_REDIS_PASSWORD:-}"

FAIL=0
ok()   { printf '\033[32m  ✓\033[0m %s\n' "$*"; }
bad()  { printf '\033[31m  ✗\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
warn() { printf '\033[33m  !\033[0m %s\n' "$*"; }
hdr()  { printf '\n\033[1m%s\033[0m\n' "$*"; }

hdr "1. 采集口 $IFACE"
if [ -d "/sys/class/net/$IFACE" ]; then
  ok "网卡存在"
  if ip -4 addr show dev "$IFACE" | grep -q 'inet '; then
    bad "采集口上有 IP 地址 —— 被动采集口不应该配地址（netplan 未生效？）"
  else
    ok "无 IP 地址（纯采集）"
  fi
  if ip link show "$IFACE" | grep -q PROMISC; then
    ok "混杂模式已开启"
  else
    warn "未处于混杂模式（Suricata 启动后会置位；若 Suricata 在跑还没置位就是异常）"
  fi
  for feat in gro lro; do
    val="$(ethtool -k "$IFACE" 2>/dev/null | awk -v f="$feat" '$1==f":"{print $2}')"
    if [ "$val" = "off" ]; then
      ok "$feat 已关闭（否则 Suricata 看到的是被合并的伪包）"
    elif [ -n "$val" ]; then
      bad "$feat = $val —— 必须关掉，否则检测质量下降（systemctl status ids-capture）"
    fi
  done
else
  bad "网卡 $IFACE 不存在"
fi

hdr "2. 管理链路是否安全"
MGMT="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')"
if [ -n "$MGMT" ]; then
  if [ "$MGMT" = "$IFACE" ]; then
    bad "默认路由在采集口上 —— 管理链路与采集口混用了，这不该发生"
  else
    ok "默认路由在 $MGMT（与采集口分开）"
  fi
else
  warn "没有默认路由（纯离线采集场景属正常）"
fi

hdr "3. Suricata"
if systemctl is-active --quiet suricata-ids.service; then
  ok "suricata-ids.service 运行中"
else
  bad "suricata-ids.service 未运行：journalctl -u suricata-ids -n 50"
fi
if [ -x /usr/sbin/suricata ] && [ -x /usr/bin/suricata ]; then :; fi
if suricata -T -c /etc/suricata/suricata.yaml --af-packet="$IFACE" >/tmp/ids-t.log 2>&1; then
  ok "配置校验通过（suricata -T）"
else
  bad "配置校验失败：tail /tmp/ids-t.log"
fi
RULES=/var/lib/suricata/rules/suricata.rules
if [ -s "$RULES" ]; then
  ok "规则集 $(wc -l <"$RULES") 行"
else
  warn "没有规则集（suricata-update 还没成功跑过？）—— 只有解码统计，不会告警"
fi
if [ -n "${IDS_IFACE:-}" ]; then :; fi
if grep -q "^disable-promisc: no" /etc/suricata/suricata.yaml; then
  ok "suricata.yaml 已允许混杂模式"
else
  warn "suricata.yaml 里没看到 disable-promisc: no"
fi

hdr "4. 采集统计与丢包率（能不能信这台设备）"
if [ -s "$EVE" ]; then
  ok "eve 输出存在：$EVE（$(du -h "$EVE" | cut -f1)）"
  python3 - "$EVE" <<'PY'
import json, sys
last = None
with open(sys.argv[1], encoding="utf-8", errors="replace") as fh:
    for line in fh:
        if '"stats"' in line:
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("event_type") == "stats":
                last = ev
if not last:
    print("  ! 还没有 stats 事件（Suricata 刚起？stats 间隔 30s）")
    sys.exit(0)
cap = (last.get("stats") or {}).get("capture") or {}
dec = (last.get("stats") or {}).get("decoder") or {}
pk = int(cap.get("kernel_packets") or 0)
dr = int(cap.get("kernel_drops") or 0)
by = int(dec.get("bytes") or 0)
inv = int(dec.get("invalid") or 0)
up = float(last.get("uptime") or 0) or 1
rate = dr / pk * 100 if pk else 0.0
mbps = by * 8 / up / 1e6
print(f"  内核收包 {pk:,}  丢包 {dr:,}  丢包率 {rate:.4f}%  解码字节 {by:,}  平均速率 {mbps:.2f} Mbps")
print(f"  无效包(decoder.invalid) {inv:,}")
if rate > 1.0:
    print("  ✗ 丢包率 > 1% —— 这台设备看不到全量流量，告警不可全信。"
          "先调 af-packet 的 ring-size/block-size 与 threads，再考虑换机器。")
elif rate > 0.1:
    print("  ! 丢包率 0.1%~1%：可接受但已偏高，建议在流量高峰复查。")
else:
    print("  ✓ 丢包率极低，采集可信")
if mbps > 400:
    print("  ! 采集速率 >400Mbps：树莓派 4B 在这个量级上很容易丢包，建议降规则集或换硬件。")
PY
else
  bad "没有 $EVE —— 采集链路是断的（先确认镜像口真的有流量）"
fi

hdr "5. 采集口确实有流量吗"
if command -v tcpdump >/dev/null 2>&1; then
  N="$(timeout 5 tcpdump -ni "$IFACE" -c 5 2>/dev/null | wc -l)"
  if [ "$N" -gt 0 ]; then
    ok "5 秒内抓到 $N 行（镜像口在工作）"
  else
    bad "5 秒内一个包都没抓到 —— 镜像口没配好，或线接错口。先解决这个，后面全是空转"
  fi
else
  warn "没装 tcpdump，跳过"
fi

hdr "6. Redis 与事件流"
HOST="${BROKER%%:*}"; PORT="${BROKER##*:}"
if redis-cli -h "$HOST" -p "$PORT" ${PASS:+-a "$PASS"} --no-auth-warning PING 2>/dev/null | grep -q PONG; then
  ok "Redis $BROKER 连通"
  LEN="$(redis-cli -h "$HOST" -p "$PORT" ${PASS:+-a "$PASS"} --no-auth-warning XLEN "$STREAM" 2>/dev/null)"
  ok "stream \"$STREAM\" 长度 = ${LEN:-0}"
  echo "  消费组："
  redis-cli -h "$HOST" -p "$PORT" ${PASS:+-a "$PASS"} --no-auth-warning \
    XINFO GROUPS "$STREAM" 2>/dev/null | paste - - - - - - - - 2>/dev/null | sed 's/^/    /' || true
  MEM="$(redis-cli -h "$HOST" -p "$PORT" ${PASS:+-a "$PASS"} --no-auth-warning \
        INFO memory 2>/dev/null | awk -F: '/used_memory_human/{print $2}' | tr -d '\r')"
  [ -n "$MEM" ] && ok "Redis 内存占用 $MEM"
else
  bad "连不上 Redis $BROKER（密码不对？--no-redis 模式下 HOST 应为 PC）"
fi

hdr "7. 转发器"
if systemctl is-active --quiet ids-producer.service; then
  ok "ids-producer.service 运行中"
else
  bad "ids-producer.service 未运行：journalctl -u ids-producer -n 50"
fi
SPOOL=/var/lib/suricata-redis/spool.jsonl
if [ -f "$SPOOL" ] && [ -s "$SPOOL" ]; then
  N="$(wc -l <"$SPOOL")"
  if redis-cli -h "$HOST" -p "$PORT" ${PASS:+-a "$PASS"} --no-auth-warning PING 2>/dev/null | grep -q PONG; then
    bad "spool 里堆了 $N 条 —— Redis 通着却补发不出去，检查权限/密码"
  else
    warn "spool 里堆了 $N 条（Redis 不可达，属于预期行为，恢复后会补发）"
  fi
else
  ok "spool 为空（说明没有积压）"
fi
journalctl -u ids-producer -n 3 --no-pager 2>/dev/null | sed 's/^/    /' || true

# ------------------------------------------------------------------ 可选：高频签名
if [ "$TOP" != 0 ]; then
  hdr "8. 最近告警里最高频的签名（调优输入，前 $TOP 条）"
  if [ -s "$EVE" ]; then
    python3 - "$EVE" "$TOP" <<'PY'
import collections, json, sys
c = collections.Counter()
sids = {}
with open(sys.argv[1], encoding="utf-8", errors="replace") as fh:
    for line in fh:
        if '"alert"' not in line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("event_type") != "alert":
            continue
        a = ev.get("alert") or {}
        sig = a.get("signature") or "?"
        c[sig] += 1
        sids.setdefault(sig, a.get("signature_id"))
if not c:
    print("  还没有告警事件。可能是镜像口没流量，或规则集为空。")
else:
    print(f"  共 {sum(c.values()):,} 条告警，{len(c)} 个不同签名")
    for sig, n in c.most_common(int(sys.argv[2])):
        print(f"  {n:>6}  sid={sids.get(sig)}  {sig[:100]}")
    print("\n  调优提示：不要看到高频就抑制。先判断『这条规则在这个网络里可能代表"
          "\n  真实入侵吗』：不可能 → 加到 disable.conf（整组剔除）；可能但太吵 →"
          "\n  在 threshold.config 里限频。详见 suricata/threshold-ids.conf 的说明。")
PY
  else
    bad "没有 eve.json 可用"
  fi
fi

# ------------------------------------------------------------------ 可选：端到端推送
if [ "$TEST_PUSH" = 1 ]; then
  hdr "9. 端到端测试：往 stream 推一条测试事件"
  python3 - "$HOST" "$PORT" "$PASS" "$STREAM" <<'PY'
import socket, sys, time
host, port, pw, stream = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
CRLF = b"\r\n"

def cmd(sock, fh, args):
    buf = [b"*" + str(len(args)).encode() + CRLF]
    for a in args:
        b = str(a).encode()
        buf.append(b"$" + str(len(b)).encode() + CRLF + b + CRLF)
    sock.sendall(b"".join(buf))
    return read(fh)

def read(fh):
    t = fh.read(1)
    if t in (b"+", b"-"):
        return fh.readline()[:-2].decode()
    if t == b":":
        return int(fh.readline()[:-2])
    if t == b"$":
        n = int(fh.readline()[:-2])
        return None if n == -1 else fh.read(n + 2)[:-2].decode()
    if t == b"*":
        n = int(fh.readline()[:-2])
        return None if n == -1 else [read(fh) for _ in range(n)]
    return None

try:
    s = socket.create_connection((host, port), timeout=5)
    fh = s.makefile("rb")
    if pw:
        cmd(s, fh, ["AUTH", pw])
    fields = {"v": "verify", "type": "selftest", "t": time.strftime("%Y-%m-%dT%H:%M:%S"),
              "msg": "verify_pi.sh 端到端测试", "host": socket.gethostname()}
    args = ["XADD", stream, "MAXLEN", "~", "100000", "*"]
    for k, v in fields.items():
        args += [k, v]
    print("  已写入，事件 ID =", cmd(s, fh, args))
    print("  → 到 PC 侧看 logs/suricata_bridge.log 是否出现这条 selftest（或看通知）")
except Exception as exc:
    print(f"  ✗ 写入失败：{exc}")
    sys.exit(1)
PY
fi

hdr "结论"
if [ "$FAIL" = 0 ]; then
  printf '\033[32m全部关键项通过。\033[0m\n'
else
  printf '\033[31m有 %d 项不通过\033[0m（标 ✗ 的行）。先修完再看告警，否则看到的是残缺流量。\n' "$FAIL"
fi
exit $([ "$FAIL" = 0 ] && echo 0 || echo 1)
