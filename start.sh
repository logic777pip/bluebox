#!/usr/bin/env bash
# =============================================================================
#  start.sh — 蓝队 Agent 一键启动（Linux / macOS）
#
#  部署后端：llama.cpp（llama-server，OpenAI 兼容 API）—— **不依赖 Ollama**
#
#  用法:
#    ./start.sh                       # 全流程：setup → convert → serve → 健康检查 → Agent 测试
#    ./start.sh --action status
#    ./start.sh --action down
#    ./start.sh --action test
#    ./start.sh --accel cpu --port 8081
#    ./start.sh --skip-setup --skip-test
#
#  ⚠ 本文件必须保持 LF 行尾（见 .gitattributes），否则报 bad interpreter
#
#  CUDA 运行时（--cudart）：
#    auto（默认）能复用本机已有 CUDA 运行库（如 venv 里 torch/lib）就不下官方 cudart 包
#    bundle       总下官方 cudart 包（约 373MB）
#    none         只复用本地；找不到则报错
# =============================================================================
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
DEPLOY_PY="${PROJECT_ROOT}/deployment/llamacpp/deploy_llamacpp.py"

ACTION="up"
ACCEL="cuda"
CUDART="auto"
PORT=8080
CTX=4096
NGL=99
THREADS=6
SKIP_SETUP=0
SKIP_TEST=0
FORCE=0
MERGED=""

log()  { printf '\033[0;36m[step]\033[0m  %s\n' "$*"; }
ok()   { printf '\033[0;32m[ok]\033[0m    %s\n' "$*"; }
warn() { printf '\033[0;33m[warn]\033[0m  %s\n' "$*" >&2; }
die()  { printf '\033[0;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --action)     ACTION="${2:?}"; shift 2 ;;
    --accel)      ACCEL="${2:?}"; shift 2 ;;
    --cudart)     CUDART="${2:?}"; shift 2 ;;
    --port)       PORT="${2:?}"; shift 2 ;;
    --ctx)        CTX="${2:?}"; shift 2 ;;
    --ngl)        NGL="${2:?}"; shift 2 ;;
    --threads)    THREADS="${2:?}"; shift 2 ;;
    --merged)     MERGED="${2:?}"; shift 2 ;;
    --skip-setup) SKIP_SETUP=1; shift ;;
    --skip-test)  SKIP_TEST=1; shift ;;
    --force)      FORCE=1; shift ;;
    -h|--help)    sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *)            die "未知参数: $1" ;;
  esac
done

[[ -f "${DEPLOY_PY}" ]] || die "缺少部署工具: ${DEPLOY_PY}"

# --- 1. 找带依赖的解释器 -----------------------------------------------------
#
# ⚠ 必须**验证候选真的能启动**：Windows 的 `WindowsApps\python3` 是
#   Microsoft Store 的存根，存在且可执行，但只会打印「Python was not found」。
#   不验证就会出现「解释器找到了，但什么都不跑」的假失败。
_valid_python() {
  local exe="$1"
  [[ -n "${exe}" && -x "${exe}" ]] || return 1
  "${exe}" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1
}

find_python() {
  local candidates=(
    "${PYTHON:-}"                                  # 1. 环境变量显式指定
    "${VIRTUAL_ENV:-}/bin/python"                  # 2. 已激活的 venv
    "${PROJECT_ROOT}/.venv/bin/python"             # 3. 项目内 venv
    "${PROJECT_ROOT}/venv/bin/python"
    "$(command -v python3 2>/dev/null || true)"
    "$(command -v python 2>/dev/null || true)"
    /usr/bin/python3
    /usr/local/bin/python3
  )
  local c
  for c in "${candidates[@]}"; do
    if _valid_python "${c}"; then echo "${c}"; return 0; fi
  done
  die "未找到可用的 Python 3.8+ 解释器（可用 PYTHON=/path/to/python 指定）"
}
PYTHON="$(find_python)"
log "解释器: ${PYTHON}"

deploy() {
  "${PYTHON}" "${DEPLOY_PY}" "$@" || die "deploy_llamacpp.py 失败: $*"
}

health_wait() {
  log "等待 llama-server 就绪（端口 ${PORT}）…"
  deploy wait --host 127.0.0.1 --port "${PORT}" --timeout 180
}

agent_test() {
  log "Agent 冒烟测试（backend=llamacpp）…"
  # 中文告警放在 UTF-8 文件里（见 smoke_alert.txt）：模型主要在中西文安全数据上微调，
  # 英文告警实测会明显拖累检索与接地（曾拉回无关的 SSH 暴力破解语料，动作全被 schema 拒绝）。
  # 由 Python 以 UTF-8 读取，避免 shell/ps1 各自的编码差异。
  local alert_file="${PROJECT_ROOT}/deployment/llamacpp/smoke_alert.txt"
  [[ -f "${alert_file}" ]] || die "缺少冒烟告警文件: ${alert_file}"
  ( cd "${PROJECT_ROOT}" && PYTHONPATH="${PROJECT_ROOT}" \
      "${PYTHON}" agent/agent.py --backend llamacpp --alert-file "${alert_file}" ) \
    || warn "Agent 返回非零退出码（可忽略，详见输出）"
}

case "${ACTION}" in
  up)
    if [[ ${SKIP_SETUP} -eq 0 ]]; then
      log "llama.cpp setup（accel=${ACCEL}，cudart=${CUDART}，预编译）"
      deploy setup --mode prebuilt --accel "${ACCEL}" --cudart "${CUDART}"
    else
      warn "跳过 llama.cpp setup（--skip-setup）"
    fi

    conv_args=(convert --quant Q4_K_M)
    [[ ${FORCE} -eq 1 ]] && conv_args+=(--force)
    [[ -n "${MERGED}" ]] && conv_args+=(--merged "${MERGED}")
    log "转换 HF 全权重 → GGUF → Q4_K_M"
    deploy "${conv_args[@]}"

    log "启动 llama-server"
    deploy serve --host 127.0.0.1 --port "${PORT}" --ctx "${CTX}" \
                 --ngl "${NGL}" --threads "${THREADS}"

    health_wait
    ok "服务已就绪: http://127.0.0.1:${PORT}（OpenAI 兼容 /v1/chat/completions）"
    [[ ${SKIP_TEST} -eq 0 ]] && agent_test
    ok "完成。停止服务: ./start.sh --action down"
    ;;

  convert)
    conv_args=(convert --quant Q4_K_M)
    [[ ${FORCE} -eq 1 ]] && conv_args+=(--force)
    [[ -n "${MERGED}" ]] && conv_args+=(--merged "${MERGED}")
    deploy "${conv_args[@]}"
    ok "GGUF 转换完成"
    ;;

  status)
    deploy status --port "${PORT}"
    if curl -sf -m 5 "http://127.0.0.1:${PORT}/health" >/dev/null; then
      ok "健康检查通过: $(curl -sf -m 5 "http://127.0.0.1:${PORT}/health")"
    else
      warn "服务未响应 /health"
    fi
    ;;

  down)
    deploy stop
    ok "已停止"
    ;;

  test)
    agent_test
    ok "测试完成"
    ;;

  *)
    die "--action 只支持 up|convert|status|down|test"
    ;;
esac
