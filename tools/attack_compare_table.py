import json

RUNS = [("A_base", "基线"), ("B_harden", "加固"), ("C_harden_k3", "加固+k3")]
KEYS = [
    ("accuracy", "Accuracy"), ("precision", "Precision"), ("recall", "Recall"),
    ("f1", "F1"),
    ("conventional.tpr", "conventional 识别率"), ("stealthy.tpr", "stealthy 识别率"),
    ("ai_attack.tpr", "ai_attack 识别率"),
    ("normal.fpr", "normal 误报率"), ("normal.benign_rate", "normal 良性率"),
    ("normal.forbidden_action_rate", "normal 越线动作"),
    ("tpr_strict", "严格识别率"), ("hedge_only_rate", "只说疑似"),
    ("unclear_rate", "不明确"), ("contradictory_rate", "自相矛盾"),
    ("contract_word_rate", "结论契约词"), ("discriminator_rate", "有区分性证据"),
    ("unjustified_attack_rate", "无证据判攻击"), ("volume_only_rate", "只靠量级"),
    ("address_nature_used_rate", "提及地址性质"), ("exempt_excuse_rate", "据以否定案件"),
    ("ai.injection_flag_rate", "标记注入率(注入类)"),
    ("injection_false_flag_rate", "误标注入率(非注入)"),
    ("correct_action_rate", "动作正确率"), ("forbidden_action_rate", "被禁动作率"),
    ("irreversible_action_rate", "不可逆动作率"),
    ("tokens_per_case", "每案 token"), ("latency_s_p50", "延迟 p50"),
    ("variant_agreement", "变体一致性"),
]

cols = []
for name, label in RUNS:
    s = json.load(open(f"logs/attack_big_{name}.json", encoding="utf-8"))["summary"]
    flat = dict(s["overall"])
    for k, b in s["by_class"].items():
        for kk, vv in b.items():
            if isinstance(vv, (int, float)):
                flat[f"{k}.{kk}"] = vv
    for k, v in (s.get("ai_blackbox") or {}).items():
        if isinstance(v, (int, float)):
            flat[f"ai.{k}"] = v
    cols.append(flat)

print(f"{'指标':<24}{'A 基线':>10}{'B 加固':>10}{'C 加固+k3':>12}")
for key, label in KEYS:
    vals = [c.get(key) for c in cols]
    if any(v is None for v in vals):
        continue
    print(f"{label:<24}" + "".join(f"{v:>10.3f}" if v < 100 else f"{v:>10.0f}" for v in vals))
