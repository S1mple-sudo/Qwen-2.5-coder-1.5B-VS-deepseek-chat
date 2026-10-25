# -*- coding: utf-8 -*-
"""诊断：为什么「删行作弊」还有 15 道能过？看是不是漏洞代码本身就满足了替代要求。"""
import collections
import json
import re
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, ".")
from src.remediation import requirements_for

qs = {q["id"]: q for q in map(json.loads, open("questions.jsonl", encoding="utf-8"))}
rep = json.load(open("data/processed/eval_report.json", encoding="utf-8"))
ids = rep["scorer_selfcheck"]["deletion_cheat"]["ids"]

print("删行作弊仍通过的题：", len(ids))
by_rule = collections.Counter(qs[i]["semgrep_rule_id"] for i in ids)
for r, n in by_rule.most_common():
    print(f"  {r}  {n}")

print("\n这些题的「漏洞代码」是否本来就满足替代要求（说明规则漏检）：")
for qid in ids:
    q = qs[qid]
    pats = [p for p in requirements_for(q["semgrep_rule_id"]) if re.search(p, q["vulnerable_code"], re.I)]
    print(f"  {qid} {q['semgrep_rule_id']}: 命中 {pats}")

print("\n全量：漏洞代码本身满足替代要求的题（应为 0，否则该要求无法区分）")
bad = [(q["id"], q["semgrep_rule_id"],
        [p for p in requirements_for(q["semgrep_rule_id"]) if re.search(p, q["vulnerable_code"], re.I)])
       for q in qs.values() if q["eval_method"] == "semgrep"
       and any(re.search(p, q["vulnerable_code"], re.I) for p in requirements_for(q["semgrep_rule_id"]))]
print(f"  {len(bad)} 道")
for b in bad[:15]:
    print("   ", b)
