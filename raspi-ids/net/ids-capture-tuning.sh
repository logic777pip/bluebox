#!/bin/bash
# 采集口硬件层调优：关掉会"篡改/合并"帧的特性，并开混杂模式。
#
# 为什么必须关 GRO/LRO：
#   它们是**接收侧**的帧合并优化，会把多个小包合成一个大"包"交给上层。
#   对转发流量无所谓，对 IDS 是灾难 —— Suricata 看到的是合并后的伪包，
#   真正的包边界、TCP 分段、HTTP 请求切分全部失真，检测质量直接下降。
#   （这是被动采集最常见的隐性坑：抓到的包"看起来"完整，但规则匹配不到。）
#
# 关 rx/tx/tso/gso/sg 是配套动作：有些特性互相依赖，留着会让 gro 无法关闭。
#
# ⚠ 这些设置**不影响转发**（采集口本来就不转发），只是让 Suricata 看到真实帧。
set -u

IFACE="${1:?用法: ids-capture-tuning.sh <网卡名>}"
LOG_TAG="ids-capture"

log() { echo "[$LOG_TAG] $*"; }

if [ ! -d "/sys/class/net/$IFACE" ]; then
  log "网卡 $IFACE 不存在，跳过调优"
  exit 0
fi

# 1) 关硬件"帧改写/合并"特性。逐项尝试，失败不致命（不同驱动支持的项不同）。
FEATURES="rx tx sg tso gso gro lro rxvlan txvlan"
for feat in $FEATURES; do
  if ethtool -K "$IFACE" "$feat" off 2>/dev/null; then
    log "已关闭特性 $feat"
  fi
done

# 2) 关闭中断合并：降低时延抖动，避免突发时丢包
ethtool -C "$IFACE" rx-usecs 0 tx-usecs 0 2>/dev/null || true

# 3) 环形缓冲开大一点，吸收镜像口突发（失败就说明驱动上限更低，不算错误）
CUR=$(ethtool -g "$IFACE" 2>/dev/null | awk '/^RX:/{getline; print $1; exit}')
MAX=$(ethtool -g "$IFACE" 2>/dev/null | awk '/Pre-set maximums:/{getline; getline; print $1; exit}')
if [ -n "${MAX:-}" ]; then
  log "RX 环大小 当前=$CUR 上限=$MAX，尝试设为上限"
  ethtool -G "$IFACE" rx "$MAX" 2>/dev/null || \
    ethtool -G "$IFACE" rx "$CUR" 2>/dev/null || true
fi

# 4) 巨帧关掉：镜像口来的帧是"原样"的，MTU 保持一致避免解析歧义
ip link set dev "$IFACE" mtu 1500 2>/dev/null || true

# 5) 混杂模式。Suricata 自己也会置位（配置里 disable-promisc: no），
#    这里显式开一次是为了「即使 Suricata 没起来也能从 tcpdump 看到镜像流量」，
#    便于排查"到底有没有流量进来"。
ip link set dev "$IFACE" promisc on 2>/dev/null || true

# 6) 明确保证采集口不参与转发/不在协议栈上折腾
sysctl -qw "net.ipv4.conf.$IFACE.forwarding=0" 2>/dev/null || true
sysctl -qw "net.ipv4.conf.$IFACE.accept_redirects=0" 2>/dev/null || true
sysctl -qw "net.ipv6.conf.$IFACE.accept_ra=0" 2>/dev/null || true
sysctl -qw "net.ipv4.conf.$IFACE.rp_filter=0" 2>/dev/null || true

log "采集口调优完成：$IFACE（混杂=$(
  ip link show "$IFACE" | grep -c PROMISC || true
))"
exit 0
