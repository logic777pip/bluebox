#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""agent/tool_runtime.py — **只读查询工具**运行时（让 Agent 先查再判，而不是一次猜完）。

与 `actions/` 的关系（重要，别混）
----------------------------------

* `actions/`          —— **动作层**：会改变状态（隔离、封禁、杀进程…），
                        必须过 `ActionExecutor`（R3 白名单 + PDCERF 前置 + 保护对象 + R5 确认）。
* `agent/tool_runtime` —— **查询层**：**永远只读**，不改任何状态，因此可以自由调用、
                        可以预取、可以循环多次。二者职责不重叠，不是两套并行体系。

为什么需要查询层（来自隐蔽信道评测的三类实测失败）
--------------------------------------------------

| 实测失败 | 需要的查询 |
| --- | --- |
| `block_ip` 打到受害主机自己的 IP（41.7%） | `endpoint_roles` —— 谁是本机、谁是对端 |
| 对已声明业务归属的良性流量下不可逆动作（42.5%） | `business_attribution` / `asset_lookup` |
| 称 UDP 443 为「非标准端口」 | `port_facts` |

另外提供 `intel_lookup` / `kb_search`，把原本写死在流水线里的两跳（情报富化、知识库检索）
变成**模型可主动调用**的能力 —— 这是「具备工具能力」的实质。

调用协议
--------

```tool
{"tool": "endpoint_roles", "args": {}}
```

与动作协议（```action {"action":…}）**刻意分开**，避免小模型把两者混淆：
工具进 ```tool 块、动作进 ```action 块，解析器各管各的。
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from security.asset_inventory import Inventory, default_inventory, parse_endpoint_roles  # noqa: E402
from security.sanitize import get_logger, mask_text  # noqa: E402

LOG = get_logger("agent.tool_runtime")

_TOOL_BLOCK_RE = re.compile(r"```tool\s*(.+?)\s*```", re.S | re.I)
_TOOL_LINE_RE = re.compile(r"^\s*\{\s*\"tool\"\s*:\s*\"(?P<name>[\w_]+)\"\s*,\s*"
                           r"\"args\"\s*:\s*(?P<args>\{.*?\})\s*\}\s*$", re.M | re.S)
# 零成本写法：`工具: endpoint_roles` / `TOOL: endpoint_roles` / `调用 endpoint_roles`
_NAMED_CALL_RE = re.compile(r"(?:工具|TOOL|调用|call)\s*[:：]?\s*`?([a-zA-Z_][\w]*)", re.I)


@dataclass
class ToolDef:
    name: str
    description: str
    params: Dict[str, str] = field(default_factory=dict)
    handler: Optional[Callable[..., Dict[str, Any]]] = None


@dataclass
class ToolStep:
    index: int
    calls: List[Dict[str, Any]] = field(default_factory=list)
    results: List[Dict[str, Any]] = field(default_factory=list)
    rejected: List[str] = field(default_factory=list)
    model_output_head: str = ""


def _render(defs: Sequence[ToolDef]) -> str:
    lines = ["【可用查询工具（只读，不改变任何状态）】"]
    for d in defs:
        params = ", ".join(f"{k}: {v}" for k, v in d.params.items()) or "无参数"
        lines.append(f"* `{d.name}` —— {d.description}；参数：{params}")
    lines.append("")
    lines.append("【怎么调用】两种写法都可以，一行一个：")
    lines.append("① 只写工具名（无参数时最省事）：")
    lines.append("    endpoint_roles")
    lines.append("② 带参数时用 JSON，放在 ```tool 代码块或单独一行：")
    lines.append("```tool")
    lines.append('{"tool": "asset_lookup", "args": {"asset": "chrome.exe"}}')
    lines.append("```")
    lines.append("⚠ 查询工具只能看，不能改。需要处置时用 ```action 块，不要混用。")
    lines.append("不要臆造查询结果；没查到的信息写「未获取到该项信息」。")
    return "\n".join(lines)


def _parse_json_calls(text: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    calls: List[Dict[str, Any]] = []
    rejected: List[str] = []
    blocks = _TOOL_BLOCK_RE.findall(text or "")
    if not blocks:
        # 容错：模型可能漏掉代码块围栏，只写了裸 JSON 行
        blocks = [m.group(0) for m in _TOOL_LINE_RE.finditer(text or "")]
    for block in blocks:
        block = block.strip()
        try:
            payload = json.loads(block)
        except json.JSONDecodeError as exc:
            rejected.append(f"```tool 不是合法 JSON: {mask_text(str(exc))}")
            continue
        items = payload if isinstance(payload, list) else [payload]
        for item in items:
            if not isinstance(item, dict) or "tool" not in item:
                rejected.append(f"缺少 tool 字段: {str(item)[:60]}")
                continue
            args = item.get("args") or {}
            if not isinstance(args, dict):
                rejected.append(f"{item.get('tool')}: args 必须是对象")
                continue
            calls.append({"tool": str(item["tool"]), "args": args})
    return calls, rejected


def parse_tool_calls(text: str,
                     known: Optional[Sequence[str]] = None
                     ) -> Tuple[List[Dict[str, Any]], List[str]]:
    """解析工具调用。

    小模型写不出 JSON 工具调用（实测 3B 模型 `tool_call_rate = 0`），
    所以额外支持**零成本写法**：整行就是一个工具名，或 `工具: 名字`。
    参数缺失时用空参数，由工具自己报「需要参数」。
    """
    calls, rejected = _parse_json_calls(text)
    names = set(known or ())
    if names:
        for m in _NAMED_CALL_RE.finditer(text or ""):
            name = m.group(1)
            if name in names:
                calls.append({"tool": name, "args": {}})
        for line in (text or "").splitlines():
            s = line.strip().strip("`*_ ").strip()
            if s in names:
                calls.append({"tool": s, "args": {}})

    seen, uniq = set(), []
    for c in calls:
        key = json.dumps(c, sort_keys=True, ensure_ascii=False)
        if key not in seen:
            seen.add(key)
            uniq.append(c)
    return uniq, rejected


class ToolRuntime:
    """只读查询工具的注册、执行与 ReAct 循环。"""

    def __init__(self, alert: str, *, inventory: Optional[Inventory] = None,
                 retriever: Any = None, rag_top_k: int = 5,
                 intel_enabled: bool = True,
                 intel_providers: Sequence[str] = ("mock",)) -> None:
        self.alert = alert or ""
        self.inv = inventory or default_inventory()
        self.retriever = retriever
        self.rag_top_k = int(rag_top_k)
        self.intel_enabled = bool(intel_enabled)
        self.intel_providers = list(intel_providers)
        self._roles = parse_endpoint_roles(self.alert)
        self._attribution = self.inv.business_attribution_in(self.alert)
        self.defs: Dict[str, ToolDef] = self._build_defs()

    # ------------------------------------------------------------------ #
    def _build_defs(self) -> Dict[str, ToolDef]:
        defs = [
            ToolDef("endpoint_roles", "判定本案中哪个地址是本机（受害主机）、哪个是对端；封禁必须指向对端",
                    {}),
            ToolDef("business_attribution", "列出遥测中**已声明的业务归属**（白名单域名/已登记网关/标准进程）；"
                                            "存在归属时，不可逆动作必须显式反驳它",
                    {}),
            ToolDef("asset_lookup", "查资产台账：主机/IP/进程名/端口号的经济归属、责任人与关键性",
                    {"asset": "要查的主机名、IP、进程名或端口号（字符串）"}),
            ToolDef("port_facts", "查某端口是否为标准端口及其服务名（防止把 443 说成非标准端口）",
                    {"port": "端口号（整数）"}),
        ]
        if self.retriever is not None:
            defs.append(ToolDef("kb_search", "在策展蓝队知识库中检索判据/处置流程，返回带出处的片段",
                                {"query": "检索语句（字符串）"}))
        if self.intel_enabled:
            defs.append(ToolDef("intel_lookup", "对 IOC（IP/域名/哈希）做威胁情报富化，返回来源与置信度",
                                {"indicator": "IOC 字符串"}))
        for d in defs:
            d.handler = getattr(self, f"_t_{d.name}", None)
        return {d.name: d for d in defs}

    def catalog_text(self) -> str:
        return _render(list(self.defs.values()))

    # ------------------------------------------------------------------ #
    #  工具实现（全部只读）
    # ------------------------------------------------------------------ #
    def _t_endpoint_roles(self) -> Dict[str, Any]:
        r = self._roles
        if not r.host_ip and not r.peer_ip:
            return {"ok": False, "reason": "告警文本中未给出明确的主机/对端句式，未能判定角色"}
        return {"ok": True, "host": r.host, "host_ip": r.host_ip,
                "peer_ip": r.peer_ip, "peer_port": r.peer_port,
                "guidance": "block_ip 必须指向 peer_ip；对 host_ip 的封禁是自伤"}

    def _t_business_attribution(self) -> Dict[str, Any]:
        if not self._attribution:
            return {"ok": True, "attribution": [],
                    "guidance": "遥测未声明业务归属；仍需结合形状判据，但无归属需要反驳"}
        return {"ok": True, "attribution": self._attribution,
                "guidance": "存在业务归属：下不可逆动作前必须在结论里显式反驳它，否则不予准入"}

    def _t_asset_lookup(self, asset: str) -> Dict[str, Any]:
        return {"ok": True, **self.inv.lookup(str(asset))}

    def _t_port_facts(self, port: Any) -> Dict[str, Any]:
        try:
            p = int(port)
        except (TypeError, ValueError):
            return {"ok": False, "reason": f"端口不是整数: {port!r}"}
        note = self.inv.port_note(p)
        return {"ok": True, "port": p, "note": note,
                "well_known": str(p) in self.inv.well_known_ports}

    def _t_kb_search(self, query: str) -> Dict[str, Any]:
        try:
            ctx = self.retriever.build_context(str(query), self.rag_top_k)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "reason": f"检索失败: {mask_text(str(exc))}"}
        return {"ok": True, "citations": list(ctx.citations()),
                "text": (ctx.text or "")[:1500]}

    def _t_intel_lookup(self, indicator: str) -> Dict[str, Any]:
        try:
            from intel.enrich import enrich  # noqa: PLC0415
            ictx = enrich([str(indicator)], self.intel_providers, max_iocs=1)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "reason": f"情报检索失败: {mask_text(str(exc))}"}
        recs = [r.to_dict() for r in ictx.records]
        return {"ok": True, "records": recs, "text": (ictx.text or "")[:800]}

    # ------------------------------------------------------------------ #
    def dispatch(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        d = self.defs.get(name)
        if d is None or d.handler is None:
            return {"ok": False, "reason": f"未知工具 {name}；可用：{sorted(self.defs)}"}
        try:
            return d.handler(**args)
        except TypeError as exc:
            return {"ok": False, "reason": f"{name} 参数不匹配: {mask_text(str(exc))}"}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "reason": f"{name} 执行异常: {mask_text(str(exc))}"}

    # ------------------------------------------------------------------ #
    def prefetch(self) -> List[Dict[str, Any]]:
        """确定性预取：不依赖模型主动调用，保证关键事实一定进入上下文。

        理由：3B 模型的工具调用率不稳定。把「端点角色 / 业务归属」这类**必查项**
        预取，可以让准入闸门拿到事实；同时模型仍可自行调用其它工具补充。
        """
        out: List[Dict[str, Any]] = []
        for name, args in (("endpoint_roles", {}), ("business_attribution", {})):
            res = self.dispatch(name, args)
            out.append({"tool": name, "args": args, "result": res})

        # 对端端口/进程名顺手查一下，成本为零、收益明确
        if self._roles.peer_port:
            res = self.dispatch("port_facts", {"port": self._roles.peer_port})
            out.append({"tool": "port_facts", "args": {"port": self._roles.peer_port},
                        "result": res})
        for proc in re.findall(r"进程\s+([\w.\-]+)", self.alert):
            res = self.dispatch("asset_lookup", {"asset": proc})
            out.append({"tool": "asset_lookup", "args": {"asset": proc}, "result": res})
        return out

    @staticmethod
    def format_observations(items: Sequence[Dict[str, Any]]) -> str:
        if not items:
            return ""
        lines = ["【工具查询结果（只读、真实返回）】"]
        for it in items:
            payload = json.dumps(it["result"], ensure_ascii=False)
            lines.append(f"* {it['tool']}({json.dumps(it.get('args', {}), ensure_ascii=False)}) → "
                         f"{payload[:900]}")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    def run(self, backend: Any, system_prompt: str, base_user: str, *,
            max_rounds: int = 3, max_tokens: int = 512,
            do_prefetch: bool = True) -> Tuple[str, List[ToolStep], List[Dict[str, Any]]]:
        """ReAct 式只读查询循环：模型可多轮调用工具，直到直接给出最终研判。"""
        pre: List[Dict[str, Any]] = self.prefetch() if do_prefetch else []
        transcript: List[str] = []
        if pre:
            transcript.append(self.format_observations(pre))
        steps: List[ToolStep] = []
        answer = ""

        for idx in range(max(1, max_rounds)):
            user = "\n\n".join(x for x in (base_user, *transcript,
                                           f"（第 {idx + 1}/{max_rounds} 轮）需要更多信息就输出"
                                           f"一个 ```tool 块；否则直接给出最终研判。") if x)
            try:
                output = backend.generate(system_prompt, user, max_tokens)
            except Exception as exc:  # noqa: BLE001
                LOG.error("查询循环调用后端失败: %s", mask_text(str(exc)))
                raise
            calls, rejected = parse_tool_calls(output, known=list(self.defs))
            step = ToolStep(index=idx + 1, calls=calls, rejected=rejected,
                            model_output_head=output[:200])
            if not calls:
                answer = output
                steps.append(step)
                break

            results = []
            for c in calls:
                res = self.dispatch(c["tool"], c["args"])
                results.append({"tool": c["tool"], "args": c["args"], "result": res})
            step.results = results
            steps.append(step)
            transcript.append("【你上一步的输出】\n" + output.strip()[:800])
            transcript.append(self.format_observations(results))

        if not answer:
            # 工具轮次用尽后仍在调工具：补一轮**禁止调用工具**的收敛轮。
            # 不能拿「最后一次输出」当答复 —— 那是 200 字的工具调用，不是研判。
            LOG.warning("查询循环达到 max_rounds=%d 仍在调用工具，转为强制收敛轮", max_rounds)
            user = "\n\n".join(x for x in (
                base_user, *transcript,
                "查询额度已用完。请**不要再输出 ```tool 块**，直接给出最终研判。") if x)
            answer = backend.generate(system_prompt, user, max_tokens)

        return answer, steps, pre


def selftest() -> int:
    """解析协议 + 工具实现的自检（工具层出问题会让 Agent 静默瞎判，必须可自证）。"""
    ok = 0
    total = 0

    def check(name: str, cond: bool) -> None:
        nonlocal ok, total
        total += 1
        if cond:
            ok += 1
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}")

    known = ["endpoint_roles", "port_facts", "asset_lookup"]
    check("解析：整行工具名",
          parse_tool_calls("endpoint_roles", known=known)[0]
          == [{"tool": "endpoint_roles", "args": {}}])
    check("解析：`工具: 名字`",
          parse_tool_calls("工具: port_facts", known=known)[0]
          == [{"tool": "port_facts", "args": {}}])
    check("解析：```tool JSON",
          parse_tool_calls('```tool\n{"tool": "asset_lookup", "args": {"asset": "x"}}\n```',
                           known=known)[0]
          == [{"tool": "asset_lookup", "args": {"asset": "x"}}])
    check("未知工具名不被当调用",
          parse_tool_calls("nonexistent_tool", known=known)[0] == [])
    check("行文中提到工具名不算调用",
          parse_tool_calls("需要先查 endpoint_roles 确认角色", known=known)[0] == [])

    rt = ToolRuntime(
        "[NDR] 主机 ws-108（192.0.2.86）与 198.51.100.13:443 之间存在持续 UDP 会话。\n"
        "主机侧：进程 chrome.exe，域名命中企业白名单", intel_enabled=False)
    check("endpoint_roles 返回对端",
          rt.dispatch("endpoint_roles", {}).get("peer_ip") == "198.51.100.13")
    check("business_attribution 命中白名单",
          bool(rt.dispatch("business_attribution", {}).get("attribution")))
    check("port_facts 认出 443 是标准端口",
          rt.dispatch("port_facts", {"port": 443}).get("well_known") is True)
    check("asset_lookup 认 chrome.exe",
          rt.dispatch("asset_lookup", {"asset": "chrome.exe"}).get("approved") is True)
    check("预取覆盖必查项",
          {"endpoint_roles", "business_attribution"}
          <= {i["tool"] for i in rt.prefetch()})
    print(f"  {ok}/{total} 通过")
    return 0 if ok == total else 1


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="只读查询工具")
    ap.add_argument("--alert", default=None, help="一段告警文本")
    ap.add_argument("--catalog", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        raise SystemExit(selftest())

    alert = args.alert or (
        "[NDR] 主机 ws-108（192.0.2.86）与 198.51.100.13:443 之间存在持续 UDP 会话。\n"
        "主机侧：进程 chrome.exe，浏览器正常网络行为；域名命中企业白名单")
    rt = ToolRuntime(alert, intel_enabled=True)
    if args.catalog:
        print(rt.catalog_text())
    for item in rt.prefetch():
        print(f"{item['tool']} → {json.dumps(item['result'], ensure_ascii=False)[:200]}")
