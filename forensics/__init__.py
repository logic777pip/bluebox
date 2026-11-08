"""forensics —— 「发现可疑目标 → 取证 → （占位）遏制」的取证联动包。

分层（与 actions/PDCERF.md 的分层原则一致：安全基线不放进业务编排文件里）：

    forensics/kape.py          KAPE 命令构造 + 执行 + 产物清点（**默认只演练**）
    forensics/containment.py   遏制动作的**占位实现**（永不执行真实变更）
    forensics/collect.py       编排：读检测结果 → 过闸门 → 取证 → 占位遏制 → 落审计

与 actions/ 的关系（同一条链，不是两套）：
    actions/adapters/kape.py                 把 `collect_forensics` 动作路由到这里
    actions/adapters/containment_placeholder.py  把遏制类动作路由到占位实现
    ActionExecutor（security/action_schema + actions/pdcerf）仍然是**唯一放行点**：
    本包不绕过它，也不自己再实现一遍校验。

为什么遏制只做占位（用户明确要求，也是稳妥的默认）：
    遏制是**不可逆**动作（隔离主机、封 IP、禁用账号）。在没有真实 EDR/防火墙
    可控面、也没有经过演练的预案之前，自动执行不可逆动作的风险远大于收益
    （打错目标 = 自己制造一次事故）。占位实现把"该做什么"完整记下来，
    把"要不要做"留给人。
"""
