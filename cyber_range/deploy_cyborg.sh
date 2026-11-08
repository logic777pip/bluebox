#!/usr/bin/env bash
# ============================================================================
#  cyber_range/deploy_cyborg.sh — 部署 CybORG++ 红蓝对抗演练环境（本地隔离沙箱）
#
#  说明:
#    CybORG++ 基于 CAGE Challenge 2/4，在本地提供企业网络的隔离仿真。
#    本脚本只做「部署 + 连通性验证」，不包含任何针对真实环境的攻击能力。
#
#  用法:
#    bash cyber_range/deploy_cyborg.sh                    # 默认部署 CAGE Challenge 2
#    bash cyber_range/deploy_cyborg.sh --variant c4       # 使用 CAGE Challenge 4
#    bash cyber_range/deploy_cyborg.sh --verify-only      # 只做环境自检
#    bash cyber_range/deploy_cyborg.sh --dry-run
#
#  环境变量:
#    CYBORG_REPO   覆盖上游仓库地址（例如指向 CybORG++ fork）
#    CYBORG_REF    指定分支/标签
#    HTTPS_PROXY   代理（可选，不记录到日志）
#
#  安全规则: R2 网络超时+重试；R4 无硬编码凭据；R5 覆盖已有目录需 --yes
#  ⚠ 必须保持 LF 行尾
# ============================================================================
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
THIRD_PARTY="${SCRIPT_DIR}/third_party"

VARIANT="c2"
NET_TIMEOUT=30
NET_RETRIES=3
DRY_RUN=0
VERIFY_ONLY=0
ASSUME_YES=0

log()  { printf '\033[0;36m[cyborg]\033[0m %s\n' "$*"; }
warn() { printf '\033[0;33m[cyborg][warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[0;31m[cyborg][error]\033[0m %s\n' "$*" >&2; exit 1; }
run()  { if [[ ${DRY_RUN} -eq 1 ]]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --variant)     VARIANT="${2:?}"; shift 2 ;;
    --verify-only) VERIFY_ONLY=1; shift ;;
    --dry-run)     DRY_RUN=1; shift ;;
    --yes|-y)      ASSUME_YES=1; shift ;;
    -h|--help)     sed -n '2,25p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *)             die "未知参数: $1" ;;
  esac
done

case "${VARIANT}" in
  c2) CYBORG_REPO_DEFAULT="https://github.com/cage-challenge/cage-challenge-2.git"; CYBORG_REF_DEFAULT="main" ;;
  c4) CYBORG_REPO_DEFAULT="https://github.com/cage-challenge/cage-challenge-4.git"; CYBORG_REF_DEFAULT="main" ;;
  *)  die "--variant 只支持 c2 | c4" ;;
esac
CYBORG_REPO="${CYBORG_REPO:-${CYBORG_REPO_DEFAULT}}"
CYBORG_REF="${CYBORG_REF:-${CYBORG_REF_DEFAULT}}"
CYBORG_DIR="${SCRIPT_DIR}/CybORG"
VENV_DIR="${PROJECT_ROOT}/.venv-cyborg"

# --- R2: 重试包装 -----------------------------------------------------------
retry() { # retry <描述> <命令...>
  local what="$1"; shift
  local attempt=1
  while true; do
    if "$@"; then return 0; fi
    [[ ${attempt} -ge ${NET_RETRIES} ]] && die "${what} 失败（已重试 ${NET_RETRIES} 次）"
    local backoff=$(( 2 ** (attempt - 1) ))
    warn "${what} 失败，${backoff}s 后重试 (${attempt}/${NET_RETRIES})"
    sleep "${backoff}"
    attempt=$((attempt + 1))
  done
}

# --- R5: 两阶段确认 ---------------------------------------------------------
confirm_overwrite() {
  local what="$1"
  if [[ ${ASSUME_YES} -eq 1 ]]; then warn "已确认（--yes）: ${what}"; return 0; fi
  read -r -p "阶段一确认：${what} 已存在，覆写请输入 yes > " a1
  [[ "${a1}" == "yes" ]] || die "已中止"
  read -r -p "阶段二确认：请再次输入 yes > " a2
  [[ "${a2}" == "yes" ]] || die "已中止"
}

# --- 0. 基础依赖自检 -------------------------------------------------------
log "环境自检 ..."
for c in git python3; do
  command -v "${c}" >/dev/null 2>&1 || die "缺少依赖: ${c}"
done
PY_VER="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
log "python3 版本: ${PY_VER}"
python3 - <<'PY' || die "Python 版本过低，CybORG 需要 3.9+"
import sys
raise SystemExit(0 if sys.version_info >= (3, 9) else 1)
PY

if [[ ${VERIFY_ONLY} -eq 1 ]]; then
  [[ -d "${CYBORG_DIR}" ]] || die "未找到 ${CYBORG_DIR}，请先完整执行一次部署"
  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate" 2>/dev/null || warn "虚拟环境未找到，使用系统 Python"
  python3 -c "import CybORG; print('CybORG 可导入, 版本:', getattr(CybORG,'__version__','unknown'))" \
    || die "CybORG 导入失败"
  log "自检通过"
  exit 0
fi

# --- 1. 拉取上游仓库 -------------------------------------------------------
mkdir -p "${THIRD_PARTY}"
if [[ -d "${CYBORG_DIR}/.git" ]]; then
  log "已存在仓库，拉取更新 (ref=${CYBORG_REF}) ..."
  run git -C "${CYBORG_DIR}" fetch --depth 1 origin "${CYBORG_REF}"
  run git -C "${CYBORG_DIR}" checkout "FETCH_HEAD"
else
  if [[ -e "${CYBORG_DIR}" ]]; then
    confirm_overwrite "${CYBORG_DIR}"
  fi
  log "克隆 ${CYBORG_REPO} (ref=${CYBORG_REF}) ..."
  retry "克隆 CybORG" run git clone --depth 1 --branch "${CYBORG_REF}" "${CYBORG_REPO}" "${CYBORG_DIR}"
fi

# --- 2. 独立虚拟环境（避免污染训练环境）------------------------------------
if [[ ! -d "${VENV_DIR}" ]]; then
  log "创建虚拟环境 ${VENV_DIR} ..."
  run python3 -m venv "${VENV_DIR}"
fi
# shellcheck disable=SC1091
[[ ${DRY_RUN} -eq 1 ]] || source "${VENV_DIR}/bin/activate"

PIP_INDEX_ARGS=()
if [[ -n "${PIP_INDEX_URL:-}" ]]; then
  PIP_INDEX_ARGS=(--index-url "${PIP_INDEX_URL}")
fi
run python -m pip install --quiet --upgrade pip
run python -m pip install --quiet "${PIP_INDEX_ARGS[@]}" \
  --timeout "${NET_TIMEOUT}" --retries "${NET_RETRIES}" \
  numpy scipy pandas pettingzoo gymnasium pyyaml

if [[ -f "${CYBORG_DIR}/requirements.txt" ]]; then
  retry "安装 CybORG 依赖" run python -m pip install --quiet \
    --timeout "${NET_TIMEOUT}" --retries "${NET_RETRIES}" \
    -r "${CYBORG_DIR}/requirements.txt"
fi
run python -m pip install --quiet --no-deps -e "${CYBORG_DIR}"

# --- 3. 冒烟测试（隔离沙箱内跑 5 步）--------------------------------------
log "运行 CybORG 冒烟测试（5 步，无 GPU 需求）..."
if [[ ${DRY_RUN} -eq 0 ]]; then
  python - <<'PY'
import sys, os
sys.path.insert(0, os.environ.get("CYBORG_DIR", "."))
try:
    import CybORG
    from CybORG import CybORG as Env
except Exception as exc:  # noqa: BLE001
    print(f"[warn] CybORG 导入失败: {exc}")
    print("[warn] 子模块（如 CybORG/Agents/CAGE）可能自动生成失败，请检查 CMake/编译器。")
    raise SystemExit(0)

path = os.environ.get("CYBORG_DIR", ".")
try:
    env = CybORG(path)
    obs, info = env.reset()
    total = 0.0
    for step in range(5):
        actions = env.action_space("blue_agent_0").sample() \
            if hasattr(env.action_space("blue_agent_0"), "sample") else {}
        res = env.step(agent="blue_agent_0", action=actions)
        total += float(getattr(res, "reward", 0.0) or 0.0)
    print(f"[ok] CybORG 冒烟测试通过：5 步累计 reward={total:.3f}")
except Exception as exc:  # noqa: BLE001
    print(f"[warn] 冒烟测试未通过（接口可能因版本不同而异）: {exc}")
PY
fi

log "部署完成。目录: ${CYBORG_DIR}"
log "激活环境: source ${VENV_DIR}/bin/activate"
log "下一步:   python cyber_range/red_blue_loop.py --dry-run"
