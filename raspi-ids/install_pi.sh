#!/bin/bash
# 蓝队 IDS 装置 —— 树莓派 4B 一键安装（Ubuntu Server 22.04.5 LTS, 64-bit ARM）
#
# 装什么：
#   Suricata（旁路镜像口被动采集，不转发、不影响业务流量）
#   Redis Stream（告警流缓冲，PC 侧按消费组拉取）
#   eve -> Redis 转发器（只发元数据，不载荷）
#
# 设计取舍（都写在对应文件里了，这里列个索引）：
#   * 配置用"最小补丁 + 读回校验"，不整体替换发行版配置 —— 见 tune_suricata.py
#   * 采集口不配 IP、关 GRO/LRO —— 见 net/90-ids-capture.yaml, net/ids-capture-tuning.sh
#   * eve.json 放 tmpfs —— 不写 SD 卡（SD 卡写坏是这类装置最常见的死法）
#   * Redis 装在本机（Pi）而不是 PC —— PC 离线期间事件仍在流里，回来能补上
#
# 用法（在树莓派上，把整个 raspi-ids 目录拷过去）：
#   sudo ./install_pi.sh --iface eth0
#   sudo ./install_pi.sh --iface eth0 --broker 192.168.1.50:6379 --no-redis
#   sudo ./install_pi.sh --iface eth0 --dry-run
set -euo pipefail

# ------------------------------------------------------------------ 参数
IFACE="eth0"
BROKER="127.0.0.1:6379"
PASSWORD=""
HOME_NET=""
STREAM="suricata:eve"
STATS_STREAM="suricata:stats"
EVE_PATH="/var/log/suricata/eve.json"
MAX_EPS=600
MAXLEN=200000
INSTALL_REDIS=1
UPDATE_RULES=1
DRY=0
FORCE=0
MIRROR=""
PROXY=""
RULES_TARBALL=""
PREFIX=/opt/blueteam-ids
ENVFILE=/etc/default/blueteam-ids

usage() {
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'EOF'

可选参数：
  --iface NAME        采集口（镜像口）网卡名，默认 eth0
  --broker HOST:PORT  Redis 地址。默认 127.0.0.1:6379（Redis 装在树莓派本身）
  --password PW       Redis 密码。默认随机生成并写入 /etc/default/blueteam-ids(600)
  --home-net CIDR     内网网段，用于 Suricata 的 HOME_NET（默认沿用发行版默认值）
  --stream NAME       eve 事件流名，默认 suricata:eve
  --eve-path PATH     Suricata eve.json 路径
  --max-eps N         转发限速（条/秒），默认 600。保护 LAN 与 PC
  --maxlen N          流长度上限，默认 200000 条
  --no-redis          不在本机装 Redis（用 PC 上的 Redis 时用这个）
  --no-rules-update   跳过 suricata-update（离线部署时用）
  --rules-tarball PATH  用本地规则集包（emerging.rules.tar.gz）代替联网下载
  --mirror NAME       先把 apt 源换成国内镜像：tuna/ustc/aliyun/huawei/163/bfsu
  --proxy URL         给 suricata-update 用的代理（rules.emergingthreats.net 在国内常很慢）
  --force             跳过"采集口即管理链路"的安全检查（危险）
  --dry-run           只打印将要做什么
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --iface) IFACE="${2:?}"; shift 2 ;;
    --broker) BROKER="${2:?}"; shift 2 ;;
    --password) PASSWORD="${2:?}"; shift 2 ;;
    --home-net) HOME_NET="${2:?}"; shift 2 ;;
    --stream) STREAM="${2:?}"; shift 2 ;;
    --eve-path) EVE_PATH="${2:?}"; shift 2 ;;
    --max-eps) MAX_EPS="${2:?}"; shift 2 ;;
    --maxlen) MAXLEN="${2:?}"; shift 2 ;;
    --no-redis) INSTALL_REDIS=0; shift ;;
    --no-rules-update) UPDATE_RULES=0; shift ;;
    --rules-tarball) RULES_TARBALL="${2:?}"; shift 2 ;;
    --mirror) MIRROR="${2:?}"; shift 2 ;;
    --proxy) PROXY="${2:?}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数：$1（--help 看用法）" >&2; exit 2 ;;
  esac
done

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { printf '\033[36m[ids]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[ids:warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[ids:error]\033[0m %s\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1m=== %s ===\033[0m\n' "$*"; }
# dry-run 下的"执行"包装：所有会改系统的动作都走它
run() {
  if [ "$DRY" = 1 ]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi
}

# ------------------------------------------------------------------ 前置检查
step "前置检查"

[ "$(id -u)" = 0 ] || die "请用 sudo/root 运行（要改网络、装服务、读 /proc）"

ARCH="$(uname -m)"
[ "$ARCH" = "aarch64" ] || warn "当前架构是 $ARCH，本脚本针对 aarch64（Ubuntu Server 64-bit ARM）调过参。"

if [ -r /etc/os-release ]; then
  . /etc/os-release
  log "系统：${PRETTY_NAME:-未知}"
  case "${VERSION_ID:-}" in
    22.04) : ;;
    *) warn "本脚本按 Ubuntu 22.04 验证（Suricata 6.0 / Redis 6.0）。${VERSION_ID:-未知} 上请留意版本差异。" ;;
  esac
fi

MEM_MB=$(awk '/MemTotal/{printf "%d", $2/1024}' /proc/meminfo)
log "内存：${MEM_MB} MB"
[ "$MEM_MB" -lt 1800 ] && warn "内存偏小（<1.8GB）。本方案按 4GB 机型设计，可能需下调 memcap/流上限。"

[ -d "/sys/class/net/$IFACE" ] || die "网卡 $IFACE 不存在。用 'ip -br link' 看可用网卡名。"
log "采集口：$IFACE"

# ---- 安全闸：采集口不能是"你正在用的管理链路" ----
# 这一步很重要：后面会把采集口的 IP 配置整个去掉。如果那就是你 SSH 进来的网卡，
# 改完会立刻失联，而且树莓派没有屏幕，只能拔卡重刷。
MGMT_IFACE="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')"
SSH_IFACE=""
if [ -n "${SSH_CONNECTION:-}" ]; then
  SSH_IP="${SSH_CONNECTION%% *}"
  SSH_IFACE="$(ip route get "$SSH_IP" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1); exit}')"
fi
log "管理链路网卡：默认路由=${MGMT_IFACE:-无} SSH=${SSH_IFACE:-无}"

if [ "$FORCE" != 1 ]; then
  if [ "$IFACE" = "$MGMT_IFACE" ]; then
    die "采集口 $IFACE 就是当前默认路由所在网卡 —— 继续下去会把它改成无 IP，你会立刻失去连接。
     正确做法（二选一）：
       a) 管理走 WiFi（板载无线），采集走 $IFACE；然后加 --force 明确表示你知道了
       b) 买一个 USB3 千兆网卡做采集口，管理保持 $IFACE 不动
     想强制继续：--force"
  fi
  if [ -n "$SSH_IFACE" ] && [ "$IFACE" = "$SSH_IFACE" ]; then
    die "采集口 $IFACE 是你 SSH 会话所在网卡 —— 改完会掉线。用 WiFi 或 USB 网卡做管理口，或加 --force。"
  fi
fi

# 镜像口不应该有默认路由；有的话说明可能选错了网卡
[ -n "$MGMT_IFACE" ] || warn "没有默认路由 —— 如果这台机器是纯离线采集，这是正常的。"

if [ "$INSTALL_REDIS" = 0 ] && [ "${BROKER%%:*}" = "127.0.0.1" ]; then
  die "--no-redis 与 --broker 127.0.0.1 冲突：不在本机装 Redis 就得指向 PC 的地址。"
fi

if [ -z "$PASSWORD" ] && [ "$INSTALL_REDIS" = 1 ]; then
  PASSWORD="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24)"
  log "已生成随机 Redis 密码（写入 $ENVFILE，权限 600）"
fi

# ------------------------------------------------------------------ 0. 国内镜像源
# 放在最前面：后面每一步都依赖 apt，源不对的话所有步骤都是慢的。
if [ -n "$MIRROR" ]; then
  step "0/8 换国内镜像源（$MIRROR）"
  if [ -x "$SRC/mirrors/setup_mirrors.sh" ]; then
    if [ "$DRY" = 1 ]; then
      run "$SRC/mirrors/setup_mirrors.sh" --mirror "$MIRROR" ${PROXY:+--proxy "$PROXY"}
    else
      "$SRC/mirrors/setup_mirrors.sh" --mirror "$MIRROR" ${PROXY:+--proxy "$PROXY"} || \
        die "换源失败。可执行 '$SRC/mirrors/setup_mirrors.sh --restore' 回滚，或去掉 --mirror 用默认源。"
    fi
  else
    warn "找不到 $SRC/mirrors/setup_mirrors.sh，跳过换源"
  fi
fi

# ------------------------------------------------------------------ 1. 精简系统
step "1/8 精简系统（Ubuntu Server 上能砍的砍掉）"
# snapd 在树莓派上是常驻内存大户，而本装置一个 snap 都不用
run apt-get -qq purge -y snapd >/dev/null 2>&1 || warn "snapd 卸载失败或本就没有，忽略"
rm -rf /snap /var/snap /var/lib/snapd 2>/dev/null || true
for svc in ModemManager multipathd cloud-init cloud-init-local cloud-config cloud-final; do
  systemctl disable --now "$svc" >/dev/null 2>&1 || true
done
APTPKGS="wget curl"
# apt 每次跑都刷一堆 unnecessary 服务；这里只是让 apt 少占点常驻内存
run apt-get -qq update

# CPU 调频：默认 powersave/ondemand 在突发流量下会掉帧（比缺 CPU 更容易丢包）
apt-get -qq install -y cpufrequtils >/dev/null 2>&1 || warn "cpufrequtils 装不上，跳过调频"
cat > /etc/default/cpufrequtils <<'EOF'
GOVERNOR="performance"
EOF
systemctl restart cpufrequtils >/dev/null 2>&1 || true

# swap：Pi 用 SD 卡时 swap 抖动很伤；4GB + 已封顶的 memcap 不需要 swap
cat > /etc/sysctl.d/99-blueteam-ids.conf <<'EOF'
# 蓝队 IDS 装置：降低抖动 + 保护 SD 卡
vm.swappiness = 10
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
# 镜像口是全量收包，内核 socket 缓冲与 backlog 给足
net.core.rmem_max = 33554432
net.core.netdev_max_backlog = 5000
EOF
run sysctl --system >/dev/null
log "已启用性能调频、写入 sysctl 调优"

# ------------------------------------------------------------------ 2. 装包
step "2/8 安装 Suricata / Redis / ethtool / python3"
PKGS="suricata suricata-update ethtool python3 tcpdump"
[ "$INSTALL_REDIS" = 1 ] && PKGS="$PKGS redis-server"
run apt-get -qq install -y $PKGS

# 发行版自带的 suricata.service 用 /etc/default/suricata 的 IFACE，语义不明确，
# 我们用自己的 unit（显式 --af-packet=网卡），所以把它停掉避免两个实例抢同一个网卡。
systemctl disable --now suricata >/dev/null 2>&1 || true
log "已停用发行版 suricata.service，改用 suricata-ids.service"

SURICATA_VER="$(suricata -V 2>/dev/null | head -1 || echo '未知')"
log "Suricata：$SURICATA_VER"

# ------------------------------------------------------------------ 3. Redis
step "3/8 配置 Redis（Stream 缓冲）"
if [ "$INSTALL_REDIS" = 1 ]; then
  BIND_IP="127.0.0.1"
  # 只有一个监听地址：本机 + 采集/管理网段的地址由 PC 侧连过来
  LAN_IPS="$(ip -o -4 addr show | awk '$2!="lo"{split($4,a,"/"); printf "%s ", a[1]}')"
  [ -n "$LAN_IPS" ] && BIND_IP="127.0.0.1 $LAN_IPS"
  sed -e "s/__PASSWORD__/$PASSWORD/" -e "s/__BIND__/$BIND_IP/" \
      "$SRC/redis/redis-ids.conf" > /etc/redis/redis-ids.conf

  if ! grep -q 'include /etc/redis/redis-ids.conf' /etc/redis/redis.conf 2>/dev/null; then
    printf '\n# 蓝队 IDS 覆盖配置（后出现先赢）\ninclude /etc/redis/redis-ids.conf\n' >> /etc/redis/redis.conf
    log "已把覆盖配置 include 进 redis.conf"
  fi
  run systemctl enable --now redis-server >/dev/null 2>&1 || true
  sleep 1
  if [ "$DRY" = 0 ]; then
    if redis-cli -a "$PASSWORD" --no-auth-warning PING 2>/dev/null | grep -q PONG; then
      log "Redis 连通 ✓（监听 $BIND_IP）"
    else
      warn "Redis 连不上，检查 journalctl -u redis-server"
    fi
  fi
else
  log "按参数要求跳过本机 Redis（使用 PC 侧 $BROKER）"
fi

# ------------------------------------------------------------------ 4. 内存文件系统
step "4/8 eve.json 放 tmpfs（不写 SD 卡）"
if ! grep -q ' /var/log/suricata ' /etc/fstab 2>/dev/null; then
  run mkdir -p /var/log/suricata
  # 64M 足够：转发器实时消费，正常情况下驻留量很小
  printf 'tmpfs /var/log/suricata tmpfs rw,size=64M,mode=0750,nosuid,nodev,noatime 0 0\n' >> /etc/fstab
  run mount /var/log/suricata || warn "mount 失败，重启后会生效"
  log "已挂载 tmpfs 到 /var/log/suricata"
else
  log "tmpfs 已存在，跳过"
fi
run mkdir -p /var/lib/suricata-redis

# ------------------------------------------------------------------ 5. Suricata 配置
step "5/8 调优 suricata.yaml（最小补丁 + 读回校验 + suricata -T）"
if [ "$DRY" = 1 ]; then
  python3 "$SRC/tune_suricata.py" --iface "$IFACE" --dry-run
else
  python3 "$SRC/tune_suricata.py" --iface "$IFACE" || die \
    "suricata.yaml 调优或校验失败。原配置已备份为 /etc/suricata/suricata.yaml.orig-blueteam ，
     可用 'python3 $SRC/tune_suricata.py --restore' 回滚。服务不会被启用。"
  if [ -n "$HOME_NET" ]; then
    python3 "$SRC/tune_suricata.py" --profile none -c /etc/suricata/suricata.yaml \
      --set "vars.address-groups.HOME_NET=$HOME_NET" --no-check >/dev/null
    log "HOME_NET 设为 $HOME_NET"
  fi
fi

# threshold / disable 清单
run cp -f "$SRC/suricata/threshold-ids.conf" /etc/suricata/threshold.config
run cp -f "$SRC/suricata/disable.conf" /etc/suricata/disable.conf

# 规则集
if [ "$UPDATE_RULES" = 1 ]; then
  if [ "$DRY" = 0 ]; then
    # 代理：rules.emergingthreats.net 在国内直连经常超时，
    # 用 --proxy 或 mirrors/setup_mirrors.sh --proxy 写进 IDS_PROXY 都行。
    if [ -z "${PROXY:-}" ] && [ -r "$ENVFILE" ]; then
      # shellcheck disable=SC1090
      . "$ENVFILE"
      PROXY="${IDS_PROXY:-}"
    fi
    if [ -n "$RULES_TARBALL" ]; then
      if [ -f "$RULES_TARBALL" ]; then
        log "用本地规则集包：$RULES_TARBALL"
        if suricata-update --no-test --disable-conf /etc/suricata/disable.conf \
             --local "$RULES_TARBALL" >/tmp/su.log 2>&1; then
          log "规则集就绪：$(wc -l < /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo '?') 行"
        else
          warn "本地规则集导入失败，见 /tmp/su.log"
        fi
      else
        warn "--rules-tarball 指定的文件不存在：$RULES_TARBALL"
      fi
    else
      log "拉取并生成规则集（首次可能要几分钟）…"
      if HTTPS_PROXY="$PROXY" HTTP_PROXY="$PROXY" \
           suricata-update --no-test --disable-conf /etc/suricata/disable.conf \
           >/tmp/su.log 2>&1; then
        log "规则集就绪：$(wc -l < /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo '?') 行"
      else
        warn "suricata-update 失败（国内直连 emergentthreats 经常超时）。
     两个办法：
       a) 走代理：--proxy http://<你的代理>:<端口>
       b) 离线：在能上网的机器下 emerging.rules.tar.gz，scp 过来后用 \
          --rules-tarball /path/emerging.rules.tar.gz
     日志：/tmp/su.log（现在只有解码统计，不会告警）"
      fi
    fi
  fi
else
  log "按参数要求跳过规则更新"
fi

# ------------------------------------------------------------------ 6. 采集口
step "6/8 采集口置为纯被动（去掉 IP、关 GRO/LRO、开混杂）"
sed -e "s/__IFACE__/$IFACE/" "$SRC/net/90-ids-capture.yaml" > /etc/netplan/90-ids-capture.yaml
chmod 600 /etc/netplan/90-ids-capture.yaml
run netplan apply || warn "netplan apply 有告警，请检查 'netplan get'"

# ------------------------------------------------------------------ 7. 装文件与服务
step "7/8 安装转发器与服务"
run mkdir -p "$PREFIX"
run cp -f "$SRC/suricata_redis_producer.py" "$PREFIX/"
run cp -f "$SRC/tune_suricata.py" "$PREFIX/"
run cp -f "$SRC/net/ids-capture-tuning.sh" "$PREFIX/"
run chmod +x "$PREFIX/ids-capture-tuning.sh"

# 行尾防御：Windows 上编辑/传输过的文件可能带 CR。
# CRLF 的 .sh 会报 "bad interpreter: /bin/bash^M"，.service 会让 systemd 解析失败。
if [ "$DRY" = 0 ]; then
  for f in "$PREFIX/suricata_redis_producer.py" "$PREFIX/ids-capture-tuning.sh" \
           /etc/default/blueteam-ids /etc/netplan/90-ids-capture.yaml \
           /etc/redis/redis-ids.conf; do
    [ -f "$f" ] && sed -i 's/\r$//' "$f"
  done
  log "已修正潜在 CRLF（Windows 编辑残留）"
fi

# 环境文件（密码只放这里，600 权限；不进命令行、不进 systemd unit 文本）
umask 077
cat > "$ENVFILE" <<EOF
# 蓝队 IDS 装置配置。权限 600，密码只在这里。
# 注意：不要把这个文件内容贴进任何脚本或聊天记录。
IDS_IFACE=$IFACE
IDS_BROKER=$BROKER
IDS_STREAM=$STREAM
IDS_STATS_STREAM=$STATS_STREAM
IDS_EVE_PATH=$EVE_PATH
IDS_MAX_EPS=$MAX_EPS
IDS_MAXLEN=$MAXLEN
IDS_REDIS_PASSWORD=$PASSWORD
EOF
chmod 600 "$ENVFILE"
umask 022

# 转发器的密码走环境变量（producer 支持 IDS_REDIS_PASSWORD）
# 但 unit 里的 EnvironmentFile 只能给到 process 环境，producer 读的就是它 ✓
if [ "$INSTALL_REDIS" = 1 ]; then
  sed -i "s/^IDS_BROKER=.*/IDS_BROKER=$BROKER/" "$ENVFILE"
fi

run cp -f "$SRC/systemd/suricata-ids.service" /etc/systemd/system/
run cp -f "$SRC/systemd/ids-producer.service" /etc/systemd/system/
run cp -f "$SRC/systemd/ids-capture.service" /etc/systemd/system/
# unit 里用 ${IDS_IFACE} 展开：systemd 不会展开 EnvironmentFile 变量到 unit 文件里，
# 所以这里按实际网卡名生成（避免"配置文件里写了变量、systemd 当字面量"的坑）
sed -i "s/\${IDS_IFACE}/$IFACE/g" /etc/systemd/system/ids-capture.service \
  /etc/systemd/system/suricata-ids.service
run systemctl daemon-reload

if [ "$DRY" = 0 ]; then
  systemctl enable ids-capture.service >/dev/null 2>&1 || true
  systemctl start ids-capture.service || warn "采集口调优服务启动失败（不致命，先看 ip link）"
  systemctl enable --now suricata-ids.service || warn "Suricata 启动失败，见 journalctl -u suricata-ids"
  sleep 5
  systemctl enable --now ids-producer.service || warn "转发器启动失败，见 journalctl -u ids-producer"
else
  run systemctl enable ids-capture.service suricata-ids.service ids-producer.service
fi

# ------------------------------------------------------------------ 8. 汇总
step "8/8 完成"
cat <<EOF
采集口      : $IFACE（无 IP、混杂、GRO/LRO 已关）
Suricata    : 配置 /etc/suricata/suricata.yaml（原文件备份 .orig-blueteam）
eve 输出    : $EVE_PATH（tmpfs，不写 SD 卡）
Redis       : $BROKER 上的 stream "$STREAM"
转发器      : /opt/blueteam-ids/suricata_redis_producer.py
配置/密码   : $ENVFILE（权限 600）

下一步：
  1) 把交换机镜像口用网线接到 $IFACE，确认能看到流量：
       sudo tcpdump -ni $IFACE -c 20
     一条都没有 → 镜像口没配好（这一步失败后面全是空转，先解决它）
  2) 跑自检，重点看**丢包率**与采集速率：
       sudo $SRC/verify_pi.sh --iface $IFACE
  3) 在 PC 侧启动 AI 侧 bridge（见 docs/RASPI_IDS.md），
     用 --password 或 IDS_REDIS_PASSWORD 传上面的密码。
EOF
if [ "$INSTALL_REDIS" = 1 ] && [ -n "$PASSWORD" ]; then
  printf '\nRedis 密码（PC 侧需要）：%s\n' "$PASSWORD"
  printf '提示：上面这行只在你自己的终端里，不要贴到聊天/工单里。\n'
fi
[ "$DRY" = 1 ] && printf '\n（dry-run：以上都未真正执行）\n'
exit 0
