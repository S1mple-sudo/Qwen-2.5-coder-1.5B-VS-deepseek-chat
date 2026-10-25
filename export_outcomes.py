# -*- coding: utf-8 -*-
"""把一份模型输出（JSONL）导出成逐题判定，供对比图 / 失败分析使用。

输出字段：id / cwe / track / rule / elim / applic / pres / verdict / shrink
    elim    —— 该题漏洞是否消除（semgrep：规则不再命中且有安全替代；functional：断言通过）
    applic  —— 功能轴是否适用（参考修复不是「重写型」）
    pres    —— 功能是否未被破坏（结构保真度代理）
    verdict —— secure_fix / fixed_behavior_na / vuln_not_fixed / behavior_broken / both_failed

用法：
    python src/export_outcomes.py --model-output data/processed/qwen1.5b_out.jsonl \
        --out data/processed/qwen1.5b_outcomes.jsonl
"""
import argparse
import collections
import json
import os
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.preservation import behavior_applicable, behavior_preserved  # noqa: E402
from src.remediation import elimination_ok  # noqa: E402
from src.report import RULES_DIR, run_functional_test  # noqa: E402
from src.semgrep_runner import run_semgrep_batch  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def export(questions_path, model_output_path, out_path):
    qs = [json.loads(l) for l in open(questions_path, encoding="utf-8") if l.strip()]
    ev = [q for q in qs if q["eval_method"] in ("semgrep", "functional")]
    codes = {}
    for line in open(model_output_path, encoding="utf-8"):
        line = line.strip()
        if line:
            d = json.loads(line)
            codes[d["id"]] = d.get("code") or d.get("fixed_code") or ""

    semi = [q for q in ev if q["eval_method"] == "semgrep"]
    findings = run_semgrep_batch({q["id"]: codes.get(q["id"], "") for q in semi}, RULES_DIR)

    rows = []
    for q in ev:
        cand = codes.get(q["id"], "")
        if q["eval_method"] == "semgrep":
            elim = elimination_ok(q.get("semgrep_rule_id", ""), findings.get(q["id"], set()),
                                  cand, q.get("fix_required"))
        else:
            elim = run_functional_test(q, cand)
        applic = behavior_applicable(q["vulnerable_code"], q["fixed_code"])
        pres = behavior_preserved(q["vulnerable_code"], cand, q["fixed_code"]) if applic else None
        if not elim and applic and pres is False:
            verdict = "both_failed"
        elif not elim:
            verdict = "vuln_not_fixed"
        elif applic and not pres:
            verdict = "behavior_broken"
        elif applic:
            verdict = "secure_fix"
        else:
            verdict = "fixed_behavior_na"
        rows.append({"id": q["id"], "cwe": q["cwe"], "track": q["eval_method"],
                     "rule": q.get("semgrep_rule_id", ""),
                     "elim": elim, "applic": applic, "pres": pres, "verdict": verdict,
                     "shrink": round(len(cand) / max(1, len(q["fixed_code"])), 2)})

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--questions", default=os.path.join(ROOT, "questions.jsonl"))
    ap.add_argument("--model-output", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    rows = export(args.questions, args.model_output, args.out)
    c = collections.Counter(r["verdict"] for r in rows)
    print(f"{len(rows)} 题 -> {args.out}")
    for k, v in c.most_common():
        print(f"  {k:20s} {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
