#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/pick_llamacpp_release.py — 从 llama.cpp releases JSON 中挑选可用的预编译包。

背景：llama.cpp 的 `releases/latest` 现在指向 **nightly** 标签（只含 nightly-tag.txt，
没有二进制），因此不能直接用 latest，必须遍历 releases 找带资产的构建版本，
并且要跳过 nightly / 资产不全的版本。

用法:
    # 先取 releases JSON（脚本不做网络请求，保持可离线测试）
    curl -s "https://api.github.com/repos/ggml-org/llama.cpp/releases?per_page=40" -o releases.json

    python tools/pick_llamacpp_release.py --releases releases.json --list-patterns
    python tools/pick_llamacpp_release.py --releases releases.json --platform win-cuda
    python tools/pick_llamacpp_release.py --releases releases.json --platform linux-cpu --format url
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# 平台 -> 资产名匹配规则（按优先级）。
# ⚠ 主资产规则必须以 `^llama-` 锚定：cudart 伴随包的名字同样以
#    `bin-win-cuda-12.4-x64.zip` 结尾，不锚定会把 373MB 的 cudart 当成主程序包。
PLATFORM_PATTERNS: Dict[str, List[str]] = {
    "win-cuda": [r"^llama-b\d+-bin-win-cuda-12\.4-x64\.zip$", r"^llama-b\d+-bin-win-cuda-[\d.]+-x64\.zip$"],
    "win-cpu": [r"^llama-b\d+-bin-win-cpu-x64\.zip$", r"^llama-b\d+-bin-win-avx2-x64\.zip$"],
    "win-vulkan": [r"^llama-b\d+-bin-win-vulkan-x64\.zip$"],
    "linux-cuda": [r"^llama-b\d+-bin-ubuntu-cuda-12\.8-x64\.tar\.gz$",
                   r"^llama-b\d+-bin-ubuntu-cuda-[\d.]+-x64\.tar\.gz$"],
    "linux-cpu": [r"^llama-b\d+-bin-ubuntu-x64\.tar\.gz$", r"^llama-b\d+-bin-linux-x64\.tar\.gz$"],
    "linux-vulkan": [r"^llama-b\d+-bin-ubuntu-vulkan-x64\.tar\.gz$",
                     r"^llama-b\d+-bin-linux-vulkan-x64\.tar\.gz$"],
    "macos": [r"^llama-b\d+-bin-macos-arm64\.tar\.gz$", r"^llama-b\d+-bin-macos-x64\.tar\.gz$"],
}

# 需要一并下载的运行时依赖（CUDA 构建需配套的 cudart 包）
COMPANION_PATTERNS: Dict[str, List[str]] = {
    "win-cuda": [r"^cudart-llama-bin-win-cuda-12\.4-x64\.zip$", r"^cudart-llama-bin-win-cuda.*x64\.zip$"],
    "linux-cuda": [r"^cudart-llama-b\d+-bin-ubuntu-cuda-12\.8-x64\.tar\.gz$",
                   r"^cudart-llama-b\d+-bin-ubuntu-cuda.*x64\.tar\.gz$"],
}

_NIGHTLY_HINTS = ("nightly",)


def is_nightly(tag: str, name: str) -> bool:
    low = f"{tag} {name}".lower()
    return any(h in low for h in _NIGHTLY_HINTS)


def load_releases(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = [data]
    return [r for r in data if isinstance(r, dict)]


def pick(releases: List[Dict[str, Any]], platform: str) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """返回 (release, main_asset)；按 release 顺序取第一个匹配到的（API 默认按时间倒序）。"""
    patterns = [re.compile(p, re.I) for p in PLATFORM_PATTERNS.get(platform, [])]
    if not patterns:
        raise SystemExit(f"未知平台: {platform}（可选 {list(PLATFORM_PATTERNS)}）")

    for rel in releases:
        tag = str(rel.get("tag_name") or "")
        assets = rel.get("assets") or []
        if is_nightly(tag, rel.get("name") or ""):
            continue
        for rx in patterns:
            for a in assets:
                if rx.search(str(a.get("name") or "")):
                    return rel, a
    return None


def companions(release: Dict[str, Any], platform: str) -> List[Dict[str, Any]]:
    """返回需要一并下载的运行时依赖（**每个模式只取第一个匹配**）。

    ⚠ 不能返回所有匹配项：b11254 的 win-cuda 同时提供
    `cudart-llama-bin-win-cuda-12.4-x64.zip` 与 `...-13.4-x64.zip`（各 373MB），
    全下会平白多拉 373MB；主包是 cuda-12.4 构建，只该配 12.4 的 cudart。
    模式按精确→宽松排列，取第一个有命中的模式的第一项。
    """
    rxs = [re.compile(p, re.I) for p in COMPANION_PATTERNS.get(platform, [])]
    assets = release.get("assets") or []
    for rx in rxs:
        for a in assets:
            if rx.search(str(a.get("name") or "")):
                return [a]
    return []


def list_patterns(releases: List[Dict[str, Any]], limit: int = 3) -> None:
    """打印前几个非 nightly release 的资产名，便于确认命名规则是否变化。"""
    shown = 0
    for rel in releases:
        tag = str(rel.get("tag_name") or "")
        if is_nightly(tag, rel.get("name") or ""):
            continue
        names = [str(a.get("name")) for a in (rel.get("assets") or [])]
        print(f"--- {tag}（{len(names)} 个资产）")
        for n in sorted(names):
            print(f"    {n}")
        shown += 1
        if shown >= limit:
            break


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="从 releases JSON 挑选 llama.cpp 预编译包")
    ap.add_argument("--releases", required=True)
    ap.add_argument("--platform", default="win-cuda", choices=list(PLATFORM_PATTERNS))
    ap.add_argument("--format", choices=["url", "name", "json"], default="json")
    ap.add_argument("--list-patterns", action="store_true",
                    help="列出前几个 release 的资产名（确认命名规则）")
    args = ap.parse_args(argv)

    path = Path(args.releases)
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[1] / path
    releases = load_releases(path)

    if args.list_patterns:
        list_patterns(releases)
        return 0

    found = pick(releases, args.platform)
    if not found:
        print(f"[error] 在 {len(releases)} 个 release 中未找到平台 {args.platform} 的资产；"
              f"用 --list-patterns 查看实际命名", file=sys.stderr)
        return 2

    rel, asset = found
    extras = companions(rel, args.platform)
    payload = {
        "tag": rel.get("tag_name"),
        "name": asset.get("name"),
        "url": asset.get("browser_download_url"),
        "size_mb": round((asset.get("size") or 0) / 1024 / 1024, 1),
        "companions": [{"name": a.get("name"), "url": a.get("browser_download_url")} for a in extras],
    }

    if args.format == "url":
        print(payload["url"])
    elif args.format == "name":
        print(payload["name"])
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
