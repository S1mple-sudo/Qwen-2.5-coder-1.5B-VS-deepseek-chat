# -*- coding: utf-8 -*-
"""校验：题目集里 semgrep 轨的**参考修复**是否满足「安全替代」要求。

不满足说明模式写得太窄（或该题的修复方式特殊），需要调正则，
否则 qa.py 会把题目降级、自检 SFR 会掉。
"""
import collections
import json
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, ".")
from src.remediation import has_remediation, requirements_for  # noqa: E402

qs = [json.loads(l) for l in open("questions.jsonl", encoding="utf-8") if l.strip()]
semi = [q for q in qs if q["eval_method"] == "semgrep"]

bad = []
for q in semi:
    if not has_remediation(q["semgrep_rule_id"], q["fixed_code"]):
        bad.append(q)

print(f"semgrep 题 {len(semi)} 道，参考修复不满足替代要求的：{len(bad)}")
by_rule = collections.Counter(q["semgrep_rule_id"] for q in bad)
for rule, n in by_rule.most_common():
    print(f"\n  {rule}  失败 {n} 道  (要求: {requirements_for(rule)[:3]} ...)")
    for q in [x for x in bad if x["semgrep_rule_id"] == rule][:3]:
        print(f"    {q['id']} 修复代码片段：")
        print("      " + "\n      ".join(q["fixed_code"].splitlines()[:8]))
