#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""deployment/llamacpp/deploy_llamacpp.py — llama.cpp 部署（不依赖 Ollama）。

设计取舍：**真正的逻辑都放在这个 Python 文件里**，`setup.sh/.ps1`、`serve.sh/.ps1`
只做薄封装。两个平台各写一份完整逻辑必然漂移，Python 只写一次。

子命令：
    setup     下载 llama.cpp 预编译包（无编译器也能用）；有 cmake 时可选本地编译
    convert   合并后的 HF 全权重 → GGUF f16 → Q4_K_M 量化
    serve     启动 llama-server（OpenAI 兼容 API）
    wait      等待服务就绪（带超时）
    status    查看产物与服务状态
    stop      停止服务
    all       setup → convert → serve → wait（一键链路）

本机实测限制：没有 cmake/MSVC/nvcc，因此默认走**预编译二进制**（`--mode prebuilt`）。
`--mode build` 需要 cmake + 编译器 + CUDA toolkit。

用法:
    python deployment/llamacpp/deploy_llamacpp.py setup --mode prebuilt --accel cuda
    python deployment/llamacpp/deploy_llamacpp.py convert
    python deployment/llamacpp/deploy_llamacpp.py serve --port 8080 --ctx 4096
    python deployment/llamacpp/deploy_llamacpp.py all
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from security.sanitize import get_logger, mask_text  # noqa: E402

LOG = get_logger("llamacpp.deploy")

HERE = Path(__file__).resolve().parent
BIN_ROOT = HERE / "bin"                      # 预编译二进制解压到此
CACHE_DIR = HERE / "cache"                   # 下载缓存
MODEL_DIR = HERE / "models"                  # GGUF 产物
SRC_DIR = HERE / "src"                       # llama.cpp 源码（提供转换脚本）
PID_FILE = HERE / ".server.pid"
LOG_FILE = HERE / "server.log"

MERGED_DIR = PROJECT_ROOT / "outputs" / "qwen2.5-3b-blue-team-merged-v2"
GGUF_F16 = MODEL_DIR / "qwen2.5-3b-blue-team-f16.gguf"
GGUF_Q4 = MODEL_DIR / "qwen2.5-3b-blue-team-q4_k_m.gguf"

RELEASES_API = "https://api.github.com/repos/ggml-org/llama.cpp/releases?per_page=40"
NET_TIMEOUT = 30
NET_RETRIES = 3

# Windows / Linux 可执行文件名差异
EXE = ".exe" if os.name == "nt" else ""


# --------------------------------------------------------------------------- #
#  基础工具
# --------------------------------------------------------------------------- #

def run(cmd: List[str], cwd: Optional[Path] = None, check: bool = True,
        capture: bool = False, env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    LOG.info("$ %s", " ".join(str(c) for c in cmd))
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=check,
                          capture_output=capture, text=capture, env=env)


def _cuda_env() -> Dict[str, str]:
    """返回注入了 CUDA 运行时目录的 env。

    setup 复用本地 CUDA 运行库（如 venv 里 torch/lib）时，llama.cpp 的 EXE 启动时
    必须能在 PATH 里找到 cudart64_12.dll / cublas64_12.dll / cublasLt64_12.dll，
    否则 ggml-cuda.dll 会**静默**加载失败并退化成纯 CPU
    （实测 `--list-devices` 显示 "(none)" 且退出码仍为 0，很难发现）。
    serve 与 quantize 都要带上。
    """
    env = dict(os.environ)
    try:
        cuda_lib = _read_state().get("cuda_lib_dir")
    except Exception:  # noqa: BLE001
        cuda_lib = None
    if cuda_lib and Path(cuda_lib).is_dir():
        env["PATH"] = str(cuda_lib) + os.pathsep + env.get("PATH", "")
    return env


# --------------------------------------------------------------------------- #
#  GitHub 镜像回退
#
#  实测（中国大陆网络）：github.com 主站不可达，release 资产第一跳就断，
#  但 api.github.com 与 objects.githubusercontent.com（CDN）可达。
#  因此对 github.com/* 资产依次尝试「直连 → 各镜像」。可用环境变量
#  GITHUB_MIRROR 覆盖（逗号分隔，自定义镜像优先）。
# --------------------------------------------------------------------------- #
DEFAULT_GITHUB_MIRRORS = (
    "https://gh-proxy.com/",
    "https://ghproxy.net/",
)

_MIRROR_STATE_KEY = "github_mirror"
_GITHUB_HOSTS = ("https://github.com/", "https://raw.githubusercontent.com/",
                 "https://codeload.github.com/")


def _mirrors() -> List[str]:
    raw = os.environ.get("GITHUB_MIRROR")
    if raw:
        return [m.strip().rstrip("/") + "/" for m in raw.split(",") if m.strip()]
    return [m.rstrip("/") + "/" for m in DEFAULT_GITHUB_MIRRORS]


def _candidate_urls(url: str) -> List[str]:
    """为 github.com 资产生成候选 URL：已知可用镜像 → 直连 → 其他镜像。"""
    if not url.startswith(_GITHUB_HOSTS):
        return [url]
    known = str(_read_state().get(_MIRROR_STATE_KEY) or "")
    mirrors = _mirrors()
    # 去掉半截的下载文件名得到前缀（如 "https://gh-proxy.com/"）
    known_prefix = known.split("https://github.com/")[0] if known else ""
    ordered: List[str] = []
    if known_prefix and known_prefix in mirrors:
        ordered.append(known_prefix)
    ordered.append("")                       # 直连
    for m in mirrors:
        if m != known_prefix:
            ordered.append(m)
    return [(p + url if p else url) for p in ordered]


def _remember_mirror(url: str) -> None:
    prefix = url.split("https://github.com/")[0] if "https://github.com/" in url else ""
    if prefix:
        try:
            state = _read_state()
            if state.get(_MIRROR_STATE_KEY) != url:
                state[_MIRROR_STATE_KEY] = prefix
                _write_state(state)
                LOG.info("记住可用镜像: %s", prefix)
        except Exception:  # noqa: BLE001
            pass


def _fetch_urllib(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "blue-team-agent/1.0"})
    with urllib.request.urlopen(req, timeout=NET_TIMEOUT) as resp, dest.open("wb") as fh:
        total = int(resp.headers.get("Content-Length") or 0)
        got = 0
        next_tick = 0
        while True:
            chunk = resp.read(1024 * 256)
            if not chunk:
                break
            fh.write(chunk)
            got += len(chunk)
            if total and got >= next_tick:
                LOG.info("  …%.0f%%（%.1f MB）", got * 100 / total, got / 1024 / 1024)
                next_tick = got + max(total // 5, 4 * 1024 * 1024)


def _download_with_curl(url: str, dest: Path) -> bool:
    """用 curl 兜底下载（走系统 TLS 栈，处理重定向更稳）。"""
    curl = shutil.which("curl") or shutil.which("curl.exe")
    if not curl:
        return False
    args = [curl, "-L", "--fail", "--silent", "--show-error",
            "--connect-timeout", "20", "--max-time", "1800",
            "--retry", "2", "--retry-delay", "2",
            "-o", str(dest), url]
    try:
        r = subprocess.run(args, capture_output=True, text=True)
    except Exception as exc:  # noqa: BLE001
        LOG.warning("curl 调用异常: %s", mask_text(str(exc)))
        return False
    if r.returncode != 0:
        LOG.warning("curl 返回 %d: %s", r.returncode, mask_text((r.stderr or "").strip()[:160]))
        return False
    return dest.exists() and dest.stat().st_size > 1024


def _size_ok(dest: Path, expect_mb: Optional[float]) -> bool:
    if not dest.exists() or dest.stat().st_size <= 1024:
        return False
    if expect_mb and dest.stat().st_size < expect_mb * 1024 * 1024 * 0.5:
        return False
    return True


def download(url: str, dest: Path, expect_mb: Optional[float] = None) -> Path:
    """带镜像回退与重试的下载。已存在且大小合理则跳过。"""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 1024:
        LOG.info("已缓存: %s（%.1f MB）", dest.name, dest.stat().st_size / 1024 / 1024)
        return dest

    last: Optional[Exception] = None
    candidates = _candidate_urls(url)
    for attempt in range(1, NET_RETRIES + 1):
        for cand in candidates:
            label = "直连" if cand == url else f"镜像 {cand.split('https://github.com/')[0]}"
            LOG.info("下载 %s（%s，第 %d/%d 轮）", mask_text(dest.name), label, attempt, NET_RETRIES)
            try:
                _fetch_urllib(cand, dest)
                if _size_ok(dest, expect_mb):
                    _remember_mirror(cand)
                    return dest
                raise IOError(f"文件偏小: {dest.stat().st_size} 字节")
            except Exception as exc:  # noqa: BLE001
                last = exc
                dest.unlink(missing_ok=True)
                LOG.warning("urllib 失败（%s）: %s", label, mask_text(str(exc)))
            if _download_with_curl(cand, dest) and _size_ok(dest, expect_mb):
                _remember_mirror(cand)
                return dest
            dest.unlink(missing_ok=True)
        if attempt < NET_RETRIES:
            time.sleep(2 ** (attempt - 1))
    raise RuntimeError("下载失败（已尝试直连与全部镜像）: " + mask_text(str(last)))


def extract(archive: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)
    else:
        with tarfile.open(archive, "r:gz") as tf:
            tf.extractall(dest)
    LOG.info("解压完成 → %s", dest)


def find_exe(name: str) -> Optional[Path]:
    """在 BIN_ROOT 下递归查找可执行文件。"""
    target = f"{name}{EXE}"
    for p in BIN_ROOT.rglob(target):
        if p.is_file():
            return p
    return None


def _find_cuda_lib_dir() -> Optional[Path]:
    """查找本机**已有**的 CUDA 运行时目录（需同时含 cudart 与 cublas）。

    典型来源：本项目 venv 里 torch(cu128) 的 `torch/lib`，或系统 CUDA toolkit。
    找到就能免下 373MB 的官方 cudart 伴随包；找不到则由调用方回退到下载。
    """
    is_win = os.name == "nt"
    cudart_glob = "cudart64_*.dll" if is_win else "libcudart.so*"
    cublas_glob = "cublas64_*.dll" if is_win else "libcublas.so*"

    candidates: List[Path] = []
    explicit = os.environ.get("CUDA_LIB_DIR")
    if explicit:
        candidates.append(Path(explicit))
    try:
        import sysconfig  # noqa: PLC0415
        purelib = sysconfig.get_paths().get("purelib")
        if purelib:
            candidates.append(Path(purelib) / "torch" / "lib")
    except Exception:  # noqa: BLE001
        pass
    for sp in {sys.prefix, sys.base_prefix}:
        candidates.append(Path(sp) / "Lib" / "site-packages" / "torch" / "lib")
        candidates.append(Path(sp) / "lib" / "site-packages" / "torch" / "lib")
    cuda_path = os.environ.get("CUDA_PATH")
    if cuda_path:
        candidates.append(Path(cuda_path) / ("bin" if is_win else "lib64"))
    if not is_win:
        candidates += [Path("/usr/local/cuda/lib64"),
                       Path("/usr/local/cuda/targets/x86_64-linux/lib")]

    for d in candidates:
        try:
            if not d.is_dir():
                continue
            if not any(d.glob(cudart_glob)) or not any(d.glob(cublas_glob)):
                continue
            return d.resolve()
        except OSError:
            continue
    return None


def platform_key(accel: str) -> str:
    system = platform.system().lower()
    if system == "windows":
        return {"cuda": "win-cuda", "cpu": "win-cpu", "vulkan": "win-vulkan"}[accel]
    if system == "darwin":
        return "macos"
    return {"cuda": "linux-cuda", "cpu": "linux-cpu", "vulkan": "linux-vulkan"}[accel]


# --------------------------------------------------------------------------- #
#  setup
# --------------------------------------------------------------------------- #

def cmd_setup(args: argparse.Namespace) -> int:
    if args.mode == "build":
        return _setup_build(args)
    return _setup_prebuilt(args)


def _setup_prebuilt(args: argparse.Namespace) -> int:
    plat = platform_key(args.accel)
    LOG.info("平台=%s 加速=%s，使用预编译包", platform.system(), args.accel)

    # ① 取 releases 列表
    rel_json = CACHE_DIR / "llama_releases.json"
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if not rel_json.exists() or args.refresh:
        rel_json.unlink(missing_ok=True)
        download(RELEASES_API, rel_json)

    # ② 挑选资产（复用 tools/pick_llamacpp_release.py 的逻辑，避免两份实现）
    sys.path.insert(0, str(PROJECT_ROOT / "tools"))
    from pick_llamacpp_release import companions, load_releases, pick  # noqa: PLC0415

    releases = load_releases(rel_json)
    found = pick(releases, plat)
    if not found:
        LOG.error("未找到平台 %s 的预编译资产；可跑 --list-patterns 查看命名", plat)
        return 2
    rel, asset = found
    tag = str(rel.get("tag_name"))
    LOG.info("选定 %s / %s（%.1f MB）", tag, asset["name"], (asset.get("size") or 0) / 1024 / 1024)

    # ③ 下载主包（+ 必要时 cudart 伴随包）
    #
    # 为什么默认不一定下 cudart：本项目装了 torch(cu128)，其 `torch/lib` 已包含
    # cudart64_12.dll / cublas64_12.dll / cublasLt64_12.dll —— 正好就是 llama.cpp 的
    # CUDA 构建需要的那几个运行库。但官方 cudart 伴随包有 373MB（约 15 分钟），
    # 能复用就不该下。自检到就直接复用，并记进 state 供 serve 时拼 PATH。
    cudart_mode = str(getattr(args, "cudart", "auto"))
    cuda_lib_dir: Optional[Path] = None
    companions_wanted = companions(rel, plat)
    if args.accel == "cuda":
        if cudart_mode == "bundle":
            LOG.info("按 --cudart bundle 下载官方 cudart 伴随包")
        else:
            cuda_lib_dir = _find_cuda_lib_dir()
            if cuda_lib_dir:
                LOG.info("发现已有 CUDA 运行时，跳过 cudart 包: %s", cuda_lib_dir)
                companions_wanted = []
            elif cudart_mode == "none":
                LOG.error("--cudart none 但未找到可用的 CUDA 运行时（cudart + cublas）")
                return 3
            else:
                LOG.info("未发现本地 CUDA 运行时，改为下载官方 cudart 包")
    else:
        companions_wanted = []

    downloads: List[Tuple[Path, Dict[str, Any]]] = [
        (CACHE_DIR / str(asset["name"]), asset)
    ]
    for comp in companions_wanted:
        downloads.append((CACHE_DIR / str(comp["name"]), comp))

    target = BIN_ROOT / tag
    for path, meta in downloads:
        download(str(meta["browser_download_url"]), path,
                 expect_mb=(meta.get("size") or 0) / 1024 / 1024)
        extract(path, target)

    # ④ 自检
    server = find_exe("llama-server")
    quantize = find_exe("llama-quantize")
    LOG.info("llama-server: %s", server or "未找到")
    LOG.info("llama-quantize: %s", quantize or "未找到")
    if not server:
        LOG.error("解压后未找到 llama-server，包结构可能变化")
        return 3

    _write_state(_merge_state({"tag": tag, "platform": plat, "accel": args.accel,
                               "server": str(server),
                               "cuda_lib_dir": str(cuda_lib_dir) if cuda_lib_dir else None,
                               "quantize": str(quantize) if quantize else None}))
    return 0


def _setup_build(args: argparse.Namespace) -> int:
    """本地编译（需要 cmake + 编译器 + 可选 CUDA toolkit）。"""
    for tool in ("cmake",):
        if not shutil.which(tool):
            LOG.error("本地编译需要 %s，未找到。本机请改用 --mode prebuilt", tool)
            return 3
    if not SRC_DIR.exists():
        run(["git", "clone", "--depth", "1", "https://github.com/ggml-org/llama.cpp", str(SRC_DIR)])
    cmake_args = ["cmake", "-B", "build", "-DCMAKE_BUILD_TYPE=Release"]
    if args.accel == "cuda":
        cmake_args.append("-DGGML_CUDA=ON")
    run(cmake_args, cwd=SRC_DIR)
    run(["cmake", "--build", "build", "--config", "Release", "-j", str(args.jobs)], cwd=SRC_DIR)
    LOG.info("本地编译完成（产物在 %s/build/bin）", SRC_DIR)
    cuda_lib_dir = _find_cuda_lib_dir() if args.accel == "cuda" else None
    if cuda_lib_dir:
        LOG.info("运行期 CUDA 运行时目录: %s", cuda_lib_dir)
    _write_state(_merge_state({"tag": "local-build", "platform": platform_key(args.accel),
                               "accel": args.accel,
                               "cuda_lib_dir": str(cuda_lib_dir) if cuda_lib_dir else None,
                               "server": str(SRC_DIR / "build" / "bin" / f"llama-server{EXE}")}))
    return 0


def _state_path() -> Path:
    return HERE / "deploy_state.json"


def _write_state(data: Dict[str, Any]) -> None:
    _state_path().write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _merge_state(patch: Dict[str, Any]) -> Dict[str, Any]:
    """在现有状态上打补丁（避免覆盖掉已记住的 GitHub 镜像等键）。"""
    state = _read_state()
    state.update(patch)
    return state


def _read_state() -> Dict[str, Any]:
    p = _state_path()
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


# --------------------------------------------------------------------------- #
#  convert
# --------------------------------------------------------------------------- #

def _fetch_convert_src(tag: str) -> Path:
    """获取 llama.cpp 源码里的转换脚本（convert_hf_to_gguf.py 依赖 conversion/ 包）。"""
    if (SRC_DIR / "convert_hf_to_gguf.py").exists():
        return SRC_DIR
    url = f"https://github.com/ggml-org/llama.cpp/archive/refs/tags/{tag}.tar.gz"
    archive = CACHE_DIR / f"llama.cpp-{tag}.tar.gz"
    download(url, archive)
    tmp = CACHE_DIR / f"src-{tag}"
    extract(archive, tmp)
    inner = next(p for p in tmp.iterdir() if p.is_dir())
    if SRC_DIR.exists():
        shutil.rmtree(SRC_DIR)
    shutil.move(str(inner), str(SRC_DIR))
    LOG.info("转换脚本就绪: %s", SRC_DIR / "convert_hf_to_gguf.py")
    return SRC_DIR


def _ensure_chat_template(model_dir: Path) -> None:
    """确保 HF 目录里带 `chat_template`，否则 GGUF 里不会有 tokenizer.chat_template。

    实测：合并后的 `merged-v2/tokenizer_config.json` **没有** `chat_template` 字段
    （transformers 新约定把模板单独放 `chat_template.jinja`）。
    `convert_hf_to_gguf.py` 主要从 `tokenizer_config.json` 取模板，取不到就会写出
    不带 chat template 的 GGUF，于是 `llama-server --jinja` 直接报错。
    这里做前置修补（原文件备份为 *.json.bak，幂等）。
    """
    tc_path = model_dir / "tokenizer_config.json"
    jinja_path = model_dir / "chat_template.jinja"
    if not tc_path.exists():
        LOG.warning("缺少 tokenizer_config.json，跳过 chat_template 修补")
        return
    try:
        cfg = json.loads(tc_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        LOG.warning("无法解析 tokenizer_config.json: %s", mask_text(str(exc)))
        return
    if cfg.get("chat_template"):
        LOG.info("tokenizer_config.json 已含 chat_template，无需修补")
        return
    if not jinja_path.exists():
        LOG.warning("既无 chat_template 字段也无 chat_template.jinja；--jinja 可能不可用")
        return
    backup = tc_path.with_suffix(".json.bak")
    if not backup.exists():
        shutil.copy2(tc_path, backup)
    cfg["chat_template"] = jinja_path.read_text(encoding="utf-8")
    tc_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    LOG.info("已把 chat_template.jinja 注入 tokenizer_config.json（原文件备份为 %s）", backup.name)


def _gguf_has_chat_template(path: Path) -> Optional[bool]:
    """只读 GGUF 头部元数据，确认 tokenizer.chat_template 是否写进去了。"""
    try:
        import gguf  # noqa: PLC0415
        reader = gguf.GGUFReader(str(path))
        return "tokenizer.chat_template" in reader.fields
    except Exception as exc:  # noqa: BLE001
        LOG.warning("无法读取 GGUF 元数据: %s", mask_text(str(exc)))
        return None


def cmd_convert(args: argparse.Namespace) -> int:
    state = _read_state()
    tag = str(state.get("tag") or "b11254")
    quantize = Path(state["quantize"]) if state.get("quantize") else find_exe("llama-quantize")

    merged = Path(args.merged) if args.merged else MERGED_DIR

    # 0) 预置产物优先（发布包 / 离线包路径）：
    #    发布包里直接带 Q4_K_M，没有 merged 全权重也应能起服务。
    #    只有显式 --force 或显式指定 --merged 时才强制要求全权重。
    if GGUF_Q4.exists() and not args.force and not args.merged:
        size_q4 = GGUF_Q4.stat().st_size / 1024 ** 3
        has_tpl = _gguf_has_chat_template(GGUF_Q4)
        LOG.info("已存在 Q4_K_M（%.2f GB），跳过转换（无需合并权重）", size_q4)
        if has_tpl is False:
            LOG.warning("该 GGUF 缺少 tokenizer.chat_template，serve 时请用 --no-jinja 回退")
        return 0

    if not (merged / "config.json").exists():
        LOG.error("找不到合并后的全权重: %s（先跑 tools/merge_adapter.py，"
                  "或把预置的 Q4_K_M 放到 %s）", merged, GGUF_Q4)
        return 2

    # 0) 依赖：gguf 包
    try:
        import gguf  # noqa: F401,PLC0415
    except ImportError:
        LOG.info("安装转换依赖 gguf…")
        if run([sys.executable, "-m", "pip", "install", "-q", "gguf"], check=False).returncode != 0:
            LOG.error("gguf 安装失败，请手动 pip install gguf")
            return 3

    # 0.5) 确保 chat template 能被写进 GGUF（否则 --jinja 用不了）
    _ensure_chat_template(merged)

    src = _fetch_convert_src(tag)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    # 1) HF → GGUF f16
    if GGUF_F16.exists() and not args.force:
        LOG.info("已存在 f16 GGUF（%.2f GB），跳过转换", GGUF_F16.stat().st_size / 1024 ** 3)
    else:
        run([sys.executable, str(src / "convert_hf_to_gguf.py"), str(merged),
             "--outfile", str(GGUF_F16), "--outtype", "f16"])

    # 2) 量化 → Q4_K_M
    if GGUF_Q4.exists() and not args.force:
        LOG.info("已存在 Q4_K_M（%.2f GB），跳过量化", GGUF_Q4.stat().st_size / 1024 ** 3)
    else:
        if not quantize:
            LOG.error("未找到 llama-quantize，无法量化（可先跑 setup）")
            return 3
        run([str(quantize), str(GGUF_F16), str(GGUF_Q4), args.quant], env=_cuda_env())

    size_q4 = GGUF_Q4.stat().st_size / 1024 ** 3
    LOG.info("GGUF 产物: %s（%.2f GB）", GGUF_Q4.name, size_q4)

    # 3) 校验 chat template 真的写进了 GGUF（serve 的 --jinja 靠它）
    has_tpl = _gguf_has_chat_template(GGUF_Q4)
    if has_tpl is True:
        LOG.info("GGUF 元数据已含 tokenizer.chat_template（--jinja 可用）")
    elif has_tpl is False:
        LOG.error("GGUF 缺少 tokenizer.chat_template：llama-server --jinja 会失败。"
                  "请确认 %s 里有 chat_template 或 chat_template.jinja", merged)
    else:
        LOG.warning("未能校验 chat template，serve 时若 --jinja 报错请用 --no-jinja 回退")

    _write_state(_merge_state({"gguf": str(GGUF_Q4), "gguf_q4_gb": round(size_q4, 2),
                               "gguf_has_chat_template": has_tpl}))
    return 0


# --------------------------------------------------------------------------- #
#  serve / wait / status / stop
# --------------------------------------------------------------------------- #

def _server_exe() -> Optional[Path]:
    state = _read_state()
    if state.get("server") and Path(state["server"]).exists():
        return Path(state["server"])
    return find_exe("llama-server")


def _health_url(host: str, port: int) -> str:
    return f"http://{host}:{port}/health"


def cmd_serve(args: argparse.Namespace) -> int:
    server = _server_exe()
    if not server:
        LOG.error("未找到 llama-server（先跑 setup）")
        return 3
    gguf = Path(args.model) if args.model else (GGUF_Q4 if GGUF_Q4.exists() else GGUF_F16)
    if not gguf.exists():
        LOG.error("未找到 GGUF 模型: %s（先跑 convert）", gguf)
        return 2

    cmd = [str(server), "-m", str(gguf),
           "--host", args.host, "--port", str(args.port),
           "-c", str(args.ctx), "-ngl", str(args.ngl),
           "-t", str(args.threads), "-np", str(args.parallel),
           "--metrics"]
    if not getattr(args, "no_jinja", False):
        # 用模型自带的 chat template（必须能写进 GGUF，见 convert 的校验）
        cmd.append("--jinja")
    else:
        LOG.warning("已按 --no-jinja 启动：将退回 llama-server 内置模板，对话格式可能不匹配")
    if args.verbose:
        cmd.append("-v")
    LOG.info("启动 llama-server: ctx=%d ngl=%d port=%d", args.ctx, args.ngl, args.port)
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    log_fh = LOG_FILE.open("a", encoding="utf-8")

    # 若 setup 复用了本地 CUDA 运行时（如 torch/lib），启动前把它拼进 PATH，
    # 否则 Windows 会在加载 cudart64_12.dll / cublas64_12.dll 时直接失败。
    env = _cuda_env()
    cuda_lib = _read_state().get("cuda_lib_dir")
    if cuda_lib and Path(cuda_lib).is_dir():
        LOG.info("注入 CUDA 运行时到 PATH: %s", cuda_lib)

    creationflags = 0
    if os.name == "nt":
        # 独立进程组，便于之后按 pid 精确终止
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
    proc = subprocess.Popen(cmd, stdout=log_fh, stderr=subprocess.STDOUT,
                            cwd=str(server.parent), env=env,
                            creationflags=creationflags)
    PID_FILE.write_text(str(proc.pid), encoding="utf-8")
    LOG.info("服务已启动 pid=%d，日志: %s", proc.pid, LOG_FILE.relative_to(PROJECT_ROOT))
    return 0


def cmd_wait(args: argparse.Namespace) -> int:
    url = _health_url(args.host, args.port)
    deadline = time.time() + args.timeout
    last = ""
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                body = json.loads(resp.read().decode("utf-8", "replace"))
                if str(body.get("status")) == "ok":
                    LOG.info("服务就绪: %s", url)
                    return 0
                last = str(body)
        except Exception as exc:  # noqa: BLE001
            last = mask_text(str(exc))
        time.sleep(2)
    LOG.error("等待超时（%ds）。最后状态: %s；请看 %s", args.timeout, last, LOG_FILE.name)
    return 2


def _pid_alive(pid: int) -> bool:
    """安全地判断进程是否存活。

    ⚠ Windows 下**绝不能用** `os.kill(pid, 0)` 探活：CPython 文档说明
    Windows 上任何非 `CTRL_C_EVENT`/`CTRL_BREAK_EVENT` 的 sig 都会走
    `TerminateProcess`，即 `sig=0` 会**直接把目标进程杀掉**（POSIX 下 sig=0
    才是纯探测）。这里在 Windows 改用 OpenProcess + GetExitCodeProcess。
    """
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes  # noqa: PLC0415
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            return False
        try:
            code = ctypes.c_ulong(0)
            if kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return code.value == STILL_ACTIVE
            return True
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(int(pid), 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True      # 存在但无权限查询 → 视为存活


def _health(host: str, port: int, timeout: int = 5) -> Optional[str]:
    """探测 /health，返回 status 字符串（不可达返回 None）。"""
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/health", timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8", "replace"))
            return str(body.get("status"))
    except Exception:  # noqa: BLE001
        return None


def cmd_status(args: argparse.Namespace) -> int:
    state = _read_state()
    print("=== llama.cpp 部署状态 ===")
    print(f"  包版本     : {state.get('tag', '未安装')}")
    print(f"  平台/加速  : {state.get('platform', '-')} / {state.get('accel', '-')}")
    print(f"  llama-server: {state.get('server') or _server_exe() or '未找到'}")
    print(f"  CUDA 运行时 : {state.get('cuda_lib_dir') or '（用官方 cudart 包）'}")
    print(f"  gguf(f16)  : {GGUF_F16.name if GGUF_F16.exists() else '未生成'}"
          f"{f'（{GGUF_F16.stat().st_size / 1024 ** 3:.2f} GB）' if GGUF_F16.exists() else ''}")
    print(f"  gguf(q4)   : {GGUF_Q4.name if GGUF_Q4.exists() else '未生成'}"
          f"{f'（{GGUF_Q4.stat().st_size / 1024 ** 3:.2f} GB）' if GGUF_Q4.exists() else ''}")
    pid = PID_FILE.read_text(encoding="utf-8").strip() if PID_FILE.exists() else "-"
    alive = _pid_alive(int(pid)) if pid not in ("", "-") else False
    print(f"  服务进程   : pid={pid}{'（运行中）' if alive else '（未运行）'}")
    hs = _health(args.host, args.port)
    print(f"  健康检查   : {_health_url(args.host, args.port)}"
          f" → {('status=' + hs) if hs else '不可达'}")
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    if not PID_FILE.exists():
        LOG.info("没有记录的进程")
        return 0
    pid = int(PID_FILE.read_text(encoding="utf-8").strip())
    try:
        if os.name == "nt":
            run(["taskkill", "/PID", str(pid), "/T", "/F"], check=False, capture=True)
        else:
            os.kill(pid, 15)
        LOG.info("已停止 pid=%d", pid)
    except Exception as exc:  # noqa: BLE001
        LOG.warning("停止失败: %s", exc)
    PID_FILE.unlink(missing_ok=True)
    return 0


def cmd_all(args: argparse.Namespace) -> int:
    for fn in (lambda: cmd_setup(args), lambda: cmd_convert(args), lambda: cmd_serve(args)):
        code = fn()
        if code != 0:
            return code
    return cmd_wait(args)


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="llama.cpp 部署（不依赖 Ollama）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--host", default="127.0.0.1")
        p.add_argument("--port", type=int, default=8080)
        p.add_argument("--timeout", type=int, default=180)

    p = sub.add_parser("setup", help="下载/编译 llama.cpp")
    p.add_argument("--mode", choices=["prebuilt", "build"], default="prebuilt")
    p.add_argument("--accel", choices=["cuda", "cpu", "vulkan"], default="cuda")
    p.add_argument("--cudart", choices=["auto", "bundle", "none"], default="auto",
                   help="CUDA 运行时来源：auto=能复用本地就不下(默认) / bundle=总下官方 cudart 包(373MB) / none=必须复用本地")
    p.add_argument("--refresh", action="store_true", help="忽略缓存的 releases 列表")
    p.add_argument("--jobs", type=int, default=8, help="本地编译并行度")
    p.set_defaults(func=cmd_setup)

    p = sub.add_parser("convert", help="HF 全权重 → GGUF → Q4_K_M")
    p.add_argument("--merged", default=None)
    p.add_argument("--quant", default="Q4_K_M")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_convert)

    p = sub.add_parser("serve", help="启动 llama-server")
    add_common(p)
    p.add_argument("--model", default=None)
    p.add_argument("--ctx", type=int, default=4096)
    p.add_argument("--ngl", type=int, default=99, help="offload 到 GPU 的层数（99=全部）")
    p.add_argument("--threads", type=int, default=6)
    p.add_argument("--parallel", type=int, default=1)
    p.add_argument("--no-jinja", action="store_true",
                   help="不传 --jinja（GGUF 里没写进 chat template 时的回退）")
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("wait", help="等待服务就绪")
    add_common(p)
    p.set_defaults(func=cmd_wait)

    p = sub.add_parser("status", help="查看状态")
    add_common(p)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("stop", help="停止服务")
    p.set_defaults(func=cmd_stop)

    p = sub.add_parser("all", help="setup → convert → serve → wait")
    add_common(p)
    p.add_argument("--mode", choices=["prebuilt", "build"], default="prebuilt")
    p.add_argument("--accel", choices=["cuda", "cpu", "vulkan"], default="cuda")
    p.add_argument("--cudart", choices=["auto", "bundle", "none"], default="auto")
    p.add_argument("--refresh", action="store_true")
    p.add_argument("--jobs", type=int, default=8)
    p.add_argument("--merged", default=None)
    p.add_argument("--quant", default="Q4_K_M")
    p.add_argument("--force", action="store_true")
    p.add_argument("--model", default=None)
    p.add_argument("--ctx", type=int, default=4096)
    p.add_argument("--ngl", type=int, default=99)
    p.add_argument("--threads", type=int, default=6)
    p.add_argument("--parallel", type=int, default=1)
    p.add_argument("--no-jinja", action="store_true")
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_all)

    args = ap.parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
