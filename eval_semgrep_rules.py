# -*- coding: utf-8 -*-
"""实测 Semgrep 规则对题目的命中率（一次性批量扫描，供规则校准）。

对 semgrep 轨的每题，把漏洞代码与修复代码各落一个文件，一次 semgrep scan 扫完，
按文件名映射回题目，统计：漏洞代码命中率、修复代码命中率、按规则分组的命中情况。

用法：
    python src/eval_semgrep_rules.py
输出：
    data/processed/semgrep_qa_report.json
"""
import json
import os
import subprocess
import sys
import tempfile
from collections import defaultdict

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.semgrep_runner import find_semgrep, normalize_check_id  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUESTIONS_PATH = os.path.join(ROOT, "questions.jsonl")
RULES_DIR = os.path.join(ROOT, "semgrep", "rules")
OUT_PATH = os.path.join(ROOT, "data", "processed", "semgrep_qa_report.json")


def load_questions(path=QUESTIONS_PATH):
    qs = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                qs.append(json.loads(line))
    return qs


def main():
    semgrep_bin = find_semgrep()
    if semgrep_bin is None:
        print("[ERROR] 未找到 semgrep")
        return 1

    qs = load_questions()
    sg = [q for q in qs if q.get("eval_method") == "semgrep"]
    print(f"semgrep 轨题目数: {len(sg)}")

    # 落盘
    with tempfile.TemporaryDirectory() as td:
        idx = {}
        for i, q in enumerate(sg):
            vf = os.path.join(td, f"{i:04d}_vuln.py")
            ff = os.path.join(td, f"{i:04d}_fixed.py")
            with open(vf, "w", encoding="utf-8") as f:
                f.write(q["vulnerable_code"])
            with open(ff, "w", encoding="utf-8") as f:
                f.write(q["fixed_code"])
            idx[os.path.basename(vf)] = (q, "vuln")
            idx[os.path.basename(ff)] = (q, "fixed")

        cmd = [semgrep_bin, "scan", "--config", RULES_DIR, "--json",
               "--no-git-ignore", td]
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", timeout=600)
        if proc.returncode == 2:
            print("[ERROR] semgrep 运行失败:")
            print(proc.stderr[:3000])
            return 1
        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as e:
            print("[ERROR] 无法解析 semgrep 输出:", e)
            return 1

    # 按文件名聚合命中
    hits = defaultdict(set)  # basename -> set(check_id)
    for r in data.get("results", []):
        base = os.path.basename(r.get("path", ""))
        cid = r.get("check_id")
        if base in idx and cid:
            hits[base].add(normalize_check_id(cid))

    # 统计
    per_rule = defaultdict(lambda: {"total": 0, "vuln_hit": 0, "fixed_hit": 0})
    vuln_hit = 0
    fixed_hit = 0
    missed_vuln = []
    wrong_fixed = []

    for q in sg:
        # 找到该题的两个文件（倒序不友好，直接重建映射）
        pass

    # 用 idx 里存的关系重算
    # 上面 idx 是按 basename 存的，这里遍历 idx
    per_rule2 = defaultdict(lambda: {"total": 0, "vuln_hit": 0, "fixed_hit": 0})
    seen = {}
    for base, (q, kind) in idx.items():
        rule = q.get("semgrep_rule_id")
        got = hits.get(base, set())
        key = q["id"]
        seen.setdefault(key, {"vuln": set(), "fixed": set()})
        seen[key][kind] = got

    vuln_hit = 0
    fixed_clean = 0
    total = 0
    for q in sg:
        total += 1
        rule = q.get("semgrep_rule_id")
        v = seen.get(q["id"], {}).get("vuln", set())
        f = seen.get(q["id"], {}).get("fixed", set())
        v_ok = (rule in v) if rule else bool(v)
        f_ok = (rule not in f) if rule else (not f)
        if v_ok:
            vuln_hit += 1
        else:
            missed_vuln.append({"id": q["id"], "cwe": q["cwe"],
                                "rule": rule, "actual_hit": sorted(v)})
        if f_ok:
            fixed_clean += 1
        else:
            wrong_fixed.append({"id": q["id"], "cwe": q["cwe"],
                                "rule": rule, "actual_hit": sorted(f)})
        if rule:
            per_rule2[rule]["total"] += 1
            if v_ok:
                per_rule2[rule]["vuln_hit"] += 1
            if f_ok:
                per_rule2[rule]["fixed_hit"] += 1

    report = {
        "total": total,
        "vuln_hit": vuln_hit,
        "vuln_hit_rate": round(vuln_hit / total, 4) if total else 0,
        "fixed_clean": fixed_clean,
        "fixed_clean_rate": round(fixed_clean / total, 4) if total else 0,
        "per_rule": {k: v for k, v in sorted(per_rule2.items())},
        "missed_vuln": missed_vuln,
        "wrong_fixed": wrong_fixed,
    }

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print("=" * 60)
    print(f"漏洞代码命中率: {vuln_hit}/{total} = {vuln_hit/total:.1%}" if total else "N/A")
    print(f"修复代码不命中率: {fixed_clean}/{total} = {fixed_clean/total:.1%}" if total else "N/A")
    print("-" * 60)
    print("按规则分组（total / vuln_hit / fixed_clean）:")
    for k, v in sorted(per_rule2.items()):
        print(f"  {k}: {v['vuln_hit']}/{v['total']}  (fixed_clean {v['fixed_hit']}/{v['total']})")
    print("=" * 60)
    print(f"报告已写入: {OUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
