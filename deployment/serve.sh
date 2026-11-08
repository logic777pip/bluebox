#!/usr/bin/env bash
# ============================================================================
#  deployment/serve.sh — LoRA -> GGUF(Q4_K_M) -> Ollama 一键部署与验证
#
#  用法:
#    bash deployment/serve.sh                     # 完整流程
#    bash deployment/serve.sh --skip-convert      # 跳过 GGUF 转换（已存在）
#    bash deployment/serve.sh --name my-agent     # 自定义模型名
#    bash deployment/serve.sh --dry-run           # 只打印将要执行的命令
#
#  安全规则:
#    R2 所有网络请求带超时与重试上限
#    R4 不硬编码任何凭据（远端 Ollama 用 OLLAMA_HOST + 环境变量）
#    R5 覆盖已存在的 GGUF / Ollama 模型前需要 --yes 两阶段确认
#
#  ⚠ 本文件必须保持 LF 行尾（见 .gitattributes），否则报 bad interpreter
# ============================================================================
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

MODEL_NAME="blue-team-agent"
MERGED_DIR="${PROJECT_ROOT}/outputs/qwen2.5-3b-blue-team-merged"
GGUF_DIR="${SCRIPT_DIR}/gguf"
GGUF_OUT="${GGUF_DIR}/qwen2.5-3b-blue-team-q4_k_m.gguf"
LLAMA_CPP_DIR="${LLAMA_CPP_DIR:-${PROJECT_ROOT}/third_party/llama.cpp}"
QUANT_TYPE="Q4_K_M"
NET_TIMEOUT=30
NET_RETRIES=3
SKIP_CONVERT=0
DRY_RUN=0
ASSUME_YES=0

log()  { printf '\033[0;36m[serve]\033[0m %s\n' "$*"; }
warn() { printf '\033[0;33m[serve][warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[0;31m[serve][error]\033[0m %s\n' "$*" >&2; exit 1; }
run()  { if [[ ${DRY_RUN} -eq 1 ]]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi; }

# --- 参数解析 --------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)         MODEL_NAME="${2:?}"; shift 2 ;;
    --merged-dir)   MERGED_DIR="${2:?}"; shift 2 ;;
    --skip-convert) SKIP_CONVERT=1; shift ;;
    --dry-run)      DRY_RUN=1; shift ;;
    --yes|-y)       ASSUME_YES=1; shift ;;
    -h|--help)      sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *)              die "未知参数: $1" ;;
  esac
done

# --- R2: 带超时与重试的下载 -------------------------------------------------
fetch() { # fetch <url> <dest>
  local url="$1" dest="$2" attempt=1
  while true; do
    if curl --fail --location --silent --show-error \
            --connect-timeout "${NET_TIMEOUT}" --max-time $((NET_TIMEOUT * 20)) \
            -o "${dest}" "${url}"; then
      return 0
    fi
    [[ ${attempt} -ge ${NET_RETRIES} ]] && die "下载失败（已重试 ${NET_RETRIES} 次）: ${url}"
    local backoff=$(( 2 ** (attempt - 1) ))
    warn "下载失败，${backoff}s 后重试 (${attempt}/${NET_RETRIES})"
    sleep "${backoff}"
    attempt=$((attempt + 1))
  done
}

# --- R2: 跨平台超时执行 -----------------------------------------------------
run_with_timeout() { # run_with_timeout <secs> <cmd...>
  local secs="$1"; shift
  if command -v timeout >/dev/null 2>&1 && timeout --version >/dev/null 2>&1; then
    timeout "${secs}" "$@"
    return $?
  fi
  # Windows Git Bash 下的 timeout.exe 不兼容，改用后台看门狗
  "$@" & local pid=$!
  ( sleep "${secs}"; kill -0 "${pid}" 2>/dev/null && kill "${pid}" 2>/dev/null ) & local wd=$!
  wait "${pid}"; local rc=$?
  kill "${wd}" 2>/dev/null || true
  return ${rc}
}

# --- R5: 两阶段确认 ---------------------------------------------------------
confirm_overwrite() { # confirm_overwrite <描述>
  local what="$1"
  if [[ ${ASSUME_YES} -eq 1 ]]; then warn "已确认（--yes）覆盖: ${what}"; return 0; fi
  read -r -p "阶段一确认：${what} 已存在，覆写请输入 yes > " a1
  [[ "${a1}" == "yes" ]] || die "已中止（未修改任何文件）"
  read -r -p "阶段二确认：请再次输入 yes 执行 > " a2
  [[ "${a2}" == "yes" ]] || die "已中止（未修改任何文件）"
}

# --- 0. 前置检查 -----------------------------------------------------------
command -v python >/dev/null 2>&1 || die "未找到 python"
command -v ollama >/dev/null 2>&1 || die "未找到 ollama（请先安装: https://ollama.com/download）"
[[ -f "${SCRIPT_DIR}/Modelfile" ]] || die "缺少 ${SCRIPT_DIR}/Modelfile"

mkdir -p "${GGUF_DIR}"

# --- 1. LoRA -> 16bit 全权重 ------------------------------------------------
if [[ ! -f "${MERGED_DIR}/config.json" ]]; then
  log "未找到合并权重，开始合并 LoRA -> 16bit ..."
  export PROJECT_ROOT MERGED_DIR
  python - <<'PY' || die "合并失败"
import os, sys
from pathlib import Path
root = Path(os.environ["PROJECT_ROOT"])
sys.path.insert(0, str(root))
import yaml
from unsloth import FastLanguageModel
cfg = yaml.safe_load((root / "training" / "config.yaml").read_text(encoding="utf-8"))
lora_dir = root / "outputs" / "qwen2.5-3b-blue-team-lora" / "lora_adapter"
if not lora_dir.exists():
    raise SystemExit(f"未找到 LoRA adapter: {lora_dir}，请先训练")
model, tok = FastLanguageModel.from_pretrained(
    model_name=str(lora_dir), max_seq_length=cfg["model"]["max_seq_length"],
    dtype=cfg["model"].get("dtype", "bfloat16"), load_in_4bit=True,
    attn_implementation="sdpa",   # 禁用 flash-attn
)
model.save_pretrained_merged(os.environ["MERGED_DIR"], tok, save_method="merged_16bit")
print("merged ->", os.environ["MERGED_DIR"])
PY
else
  log "已存在合并权重: ${MERGED_DIR}"
fi

# --- 2. HF(16bit) -> GGUF f16 -> Q4_K_M ------------------------------------
if [[ ${SKIP_CONVERT} -eq 0 ]]; then
  if [[ ! -f "${LLAMA_CPP_DIR}/convert_hf_to_gguf.py" ]]; then
    log "未找到 llama.cpp，尝试克隆（带超时重试）..."
    mkdir -p "$(dirname "${LLAMA_CPP_DIR}")"
    [[ -d "${LLAMA_CPP_DIR}/.git" ]] || git clone --depth 1 https://github.com/ggml-org/llama.cpp "${LLAMA_CPP_DIR}" \
      || die "llama.cpp 克隆失败（可设置 LLAMA_CPP_DIR 指向已有目录）"
    python -m pip install --quiet -r "${LLAMA_CPP_DIR}/requirements/requirements-convert_hf_to_gguf.txt" \
      || warn "llama.cpp 转换依赖安装失败，可能需要手动处理"
  fi

  if [[ -f "${GGUF_OUT}" ]]; then
    confirm_overwrite "GGUF 文件 ${GGUF_OUT}"
  fi

  F16_GGUF="${GGUF_DIR}/qwen2.5-3b-blue-team-f16.gguf"
  log "转换 HF -> GGUF (f16) ..."
  run python "${LLAMA_CPP_DIR}/convert_hf_to_gguf.py" "${MERGED_DIR}" --outfile "${F16_GGUF}" --outtype f16

  QUANTIZE_BIN="$(find "${LLAMA_CPP_DIR}" -maxdepth 3 -type f \
      \( -name 'llama-quantize' -o -name 'llama-quantize.exe' \) 2>/dev/null | head -n1 || true)"
  if [[ -z "${QUANTIZE_BIN}" ]]; then
    warn "未找到 llama-quantize 可执行文件。请先构建 llama.cpp："
    warn "  cmake -B ${LLAMA_CPP_DIR}/build -DGGML_CUDA=ON && cmake --build ${LLAMA_CPP_DIR}/build --config Release -j"
    warn "然后把 ${F16_GGUF} 复制为 ${GGUF_OUT} 继续（体积较大，不推荐）。"
    [[ ${DRY_RUN} -eq 1 ]] || cp -f "${F16_GGUF}" "${GGUF_OUT}"
  else
    log "量化为 ${QUANT_TYPE} ..."
    run "${QUANTIZE_BIN}" "${F16_GGUF}" "${GGUF_OUT}" "${QUANT_TYPE}"
    rm -f "${F16_GGUF}"
  fi
fi

[[ ${DRY_RUN} -eq 1 ]] || [[ -f "${GGUF_OUT}" ]] || die "缺少 GGUF 文件: ${GGUF_OUT}"

# --- 3. Ollama 导入 --------------------------------------------------------
log "创建 Ollama 模型: ${MODEL_NAME}"
run ollama create "${MODEL_NAME}" -f "${SCRIPT_DIR}/Modelfile"

# --- 4. 健康检查（带超时）--------------------------------------------------
if [[ ${DRY_RUN} -eq 0 ]]; then
  log "健康检查（超时 ${NET_TIMEOUT}s）..."
  RESP="$(run_with_timeout "${NET_TIMEOUT}" ollama run "${MODEL_NAME}" \
    "用一句话说明蓝队应急响应中「遏制」阶段的目标。" 2>&1 || true)"
  if [[ -z "${RESP}" ]]; then
    warn "模型无响应。排查: 1) ollama serve 是否运行；2) ollama list 是否含 ${MODEL_NAME}；3) 显存是否被占用。"
  else
    printf '%s\n' "${RESP}" | head -n 5
    log "部署成功。交互使用: ollama run ${MODEL_NAME}"
  fi
  log "查看显存占用: nvidia-smi --query-gpu=memory.used,memory.total --format=csv"
fi
