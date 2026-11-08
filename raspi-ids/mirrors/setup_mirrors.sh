#!/bin/bash
# 把树莓派的 apt / pip 源换成国内镜像，并为 suricata-update 配代理。
#
# ⚠ 最容易踩的坑：arm64 用的是 **ports** 仓库。
#   正确：https://mirrors.<x>/ubuntu-ports/
#   错误：https://mirrors.<x>/ubuntu/        <- 只有 amd64/i386，arm64 会 404
#   而且报错信息通常是 "Unable to locate package" 或 404，很容易误判成"包名写错了"，
#   白白排查半天。本脚本强制使用 ubuntu-ports。
#
# 用法：
#   sudo ./setup_mirrors.sh --mirror tuna
#   sudo ./setup_mirrors.sh --mirror aliyun --proxy http://192.168.1.10:7890
#   sudo ./setup_mirrors.sh --restore          # 回滚到原 sources
#   sudo ./setup_mirrors.sh --list             # 列出可选镜像
set -uo pipefail

MIRROR="tuna"
PROXY=""
RESTORE=0

# 名称 -> 镜像根地址（均提供 ubuntu-ports 与 pip 镜像）
mirror_base() {
  case "$1" in
    tuna)   echo "https://mirrors.tuna.tsinghua.edu.cn" ;;
    ustc)   echo "https://mirrors.ustc.edu.cn" ;;
    aliyun) echo "https://mirrors.aliyun.com" ;;
    huawei) echo "https://repo.huaweicloud.com" ;;
    163)    echo "https://mirrors.163.com" ;;
    bfsu)   echo "https://mirrors.bfsu.edu.cn" ;;
    *)      echo "" ;;
  esac
}

pip_index() {
  case "$1" in
    tuna)   echo "https://pypi.tuna.tsinghua.edu.cn/simple" ;;
    ustc)   echo "https://mirrors.ustc.edu.cn/pypi/web/simple" ;;
    aliyun) echo "https://mirrors.aliyun.com/pypi/simple/" ;;
    huawei) echo "https://repo.huaweicloud.com/repository/pypi/simple" ;;
    163)    echo "https://mirrors.163.com/pypi/simple/" ;;
    bfsu)   echo "https://mirrors.bfsu.edu.cn/pypi/web/simple" ;;
    *)      echo "" ;;
  esac
}

while [ $# -gt 0 ]; do
  case "$1" in
    --mirror) MIRROR="${2:?}"; shift 2 ;;
    --proxy) PROXY="${2:?}"; shift 2 ;;
    --restore) RESTORE=1; shift ;;
    --list) echo "可选：tuna ustc aliyun huawei 163 bfsu"; exit 0 ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "未知参数 $1" >&2; exit 2 ;;
  esac
done

log() { printf '\033[36m[mirror]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[mirror:error]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "需要 root"

# ---------------------------------------------------------------- 回滚
if [ "$RESTORE" = 1 ]; then
  for bak in /etc/apt/sources.list.blueteam-orig \
             /etc/apt/sources.list.d/ubuntu.sources.blueteam-orig; do
    if [ -f "$bak" ]; then
      cp -f "$bak" "${bak%.blueteam-orig}"
      log "已回滚 ${bak%.blueteam-orig}"
    fi
  done
  apt-get update -qq || true
  exit 0
fi

BASE="$(mirror_base "$MIRROR")"
[ -n "$BASE" ] || die "不认识的镜像名：$MIRROR（--list 看可选值）"
PORTS="$BASE/ubuntu-ports"

# ---------------------------------------------------------------- 校验镜像可用
log "检查 $PORTS 是否可用…"
if ! curl -fsSI --max-time 10 "$PORTS/dists/" >/dev/null 2>&1; then
  die "镜像不可达或路径不对：$PORTS/dists/
     换个镜像再试（--list），或先确认这台机器能上外网。"
fi
log "镜像可达 ✓"

# ---------------------------------------------------------------- 判定发行版
. /etc/os-release
CODENAME="${VERSION_CODENAME:?读不到 VERSION_CODENAME}"
log "发行版代号：$CODENAME（架构 $(dpkg --print-architecture)）"

if [ "$(dpkg --print-architecture)" != "arm64" ]; then
  log "注意：当前不是 arm64，但仍然使用 ubuntu-ports（它对所有非 amd64 架构生效）"
fi

# ---------------------------------------------------------------- 写源
# Ubuntu 22.04 用 /etc/apt/sources.list；24.04+ 用 deb822 的 ubuntu.sources。
# 两种都处理，免得换到 24.04 上脚本直接失效。
LEGACY=/etc/apt/sources.list
DEB822=/etc/apt/sources.list.d/ubuntu.sources

write_legacy() {
  [ -f "$LEGACY.blueteam-orig" ] || cp -a "$LEGACY" "$LEGACY.blueteam-orig" 2>/dev/null || true
  cat > "$LEGACY" <<EOF
# 由 blueteam-ids/setup_mirrors.sh 生成（原文件备份为 sources.list.blueteam-orig）
# ⚠ arm64 必须用 ubuntu-ports
deb $PORTS $CODENAME main restricted universe multiverse
deb $PORTS $CODENAME-updates main restricted universe multiverse
deb $PORTS $CODENAME-backports main restricted universe multiverse
deb $PORTS $CODENAME-security main restricted universe multiverse
EOF
}

write_deb822() {
  [ -f "$DEB822.blueteam-orig" ] || cp -a "$DEB822" "$DEB822.blueteam-orig" 2>/dev/null || true
  cat > "$DEB822" <<EOF
# 由 blueteam-ids/setup_mirrors.sh 生成
Types: deb
URIs: $PORTS
Suites: $CODENAME $CODENAME-updates $CODENAME-backports $CODENAME-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
}

if [ -f "$DEB822" ]; then
  write_deb822
  log "已写 deb822 源：$DEB822"
  # 同时清掉可能残留的 legacy 源，避免两处冲突
  if [ -f "$LEGACY" ] && grep -q 'ubuntu' "$LEGACY" 2>/dev/null; then
    cp -a "$LEGACY" "$LEGACY.blueteam-orig" 2>/dev/null || true
    : > "$LEGACY"
    log "已清空 legacy sources.list（避免与 deb822 冲突）"
  fi
else
  write_legacy
  log "已写 deb 源：$LEGACY"
fi

# ---------------------------------------------------------------- pip（本装置其实不需要）
PIP="$(pip_index "$MIRROR")"
if [ -n "$PIP" ]; then
  cat > /etc/pip.conf <<EOF
# 蓝队 IDS 本身**不需要任何 pip 包**（两处 Python 都只用标准库）。
# 这里配好只是为了以后临时排查时装包快一点。
[global]
index-url = $PIP
trusted-host = $(echo "$PIP" | awk -F/ '{print $3}')
EOF
  log "已配置 pip 镜像 /etc/pip.conf"
fi

# ---------------------------------------------------------------- 代理（给 suricata-update 用）
if [ -n "$PROXY" ]; then
  if [ ! -f /etc/default/blueteam-ids ]; then
    install -m 600 /dev/null /etc/default/blueteam-ids
  fi
  if grep -q '^IDS_PROXY=' /etc/default/blueteam-ids 2>/dev/null; then
    sed -i "s|^IDS_PROXY=.*|IDS_PROXY=$PROXY|" /etc/default/blueteam-ids
  else
    printf 'IDS_PROXY=%s\n' "$PROXY" >> /etc/default/blueteam-ids
  fi
  chmod 600 /etc/default/blueteam-ids
  log "已写入 IDS_PROXY=$PROXY（install_pi.sh 会用它拉规则集）"
fi

# ---------------------------------------------------------------- 生效
log "apt-get update…"
if apt-get update -qq; then
  log "换源成功 ✓（后续 apt 装包走 $PORTS）"
else
  die "apt-get update 失败。可执行 '$0 --restore' 回滚。"
fi
exit 0
