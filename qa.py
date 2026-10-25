"""质检（semgrep 轨）：验证 semgrep 类题目的规则可命中性与修复有效性。

三轨质检的分工：
  - functional 轨由 functional_qa.py 负责（不依赖 semgrep）
  - 本脚本负责 semgrep 轨（eval_method == "semgrep" 的题目）
  - manual 轨（两者都无法自动判定的）保留题目，仅标注

对每道 semgrep 题：
  1. 对 vulnerable_code 跑 semgrep，记录命中规则 vuln_findings
  2. 对 fixed_code 跑 semgrep，记录命中规则 fixed_findings
  3. "合格规则" = 命中漏洞代码 且 不命中修复代码 的规则
  4. 优先保留题目自带的 semgrep_rule_id（若合格），否则从候选规则里挑，
     仍无则标记 eval_method="manual"（保留题目，供人工复核）

与旧版不同：**不丢弃任何题目**，全部写回 questions.jsonl。

用法：
    python src/qa.py --in questions.jsonl --out questions.jsonl
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.mapping import cwe_to_rule_candidates  # noqa: E402
from src.remediation import required_for  # noqa: E402
from src.semgrep_runner import find_semgrep, normalize_check_id  # noqa: E402

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "semgrep", "rules")


def _write_files(questions, suffix, tmpdir):
    """把每题代码写到 tmpdir/<id>.py，返回 {id: filename}。"""
    mapping = {}
    for q in questions:
        fname = f"{q['id']}.py"
        with open(os.path.join(tmpdir, fname), "w", encoding="utf-8") as f:
            f.write(q[suffix])
        mapping[q["id"]] = fname
    return mapping


def run_semgrep_dir(dirpath):
    """对目录批量跑 semgrep，返回 {basename: set(check_id)}（已规范化）。"""
    semgrep_bin = find_semgrep()
    if semgrep_bin is None:
        raise RuntimeError("未找到 semgrep")
    cmd = [semgrep_bin, "scan", "--config", RULES_DIR, "--json", "--no-git-ignore", dirpath]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=900)
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"semgrep 运行失败 (rc={proc.returncode}): {proc.stderr[:2000]}")
    data = json.loads(proc.stdout or "{}")
    mapping = {}
    for r in data.get("results", []):
        base = os.path.basename(r.get("path", ""))
        cid = r.get("check_id")
        if base and cid:
            mapping.setdefault(base, set()).add(normalize_check_id(cid))
    return mapping


def qa(in_path, out_path, report_path):
    with open(in_path, "r", encoding="utf-8") as f:
        questions = [json.loads(l) for l in f if l.strip()]

    semgrep_qs = [q for q in questions if q.get("eval_method") == "semgrep"]

    stats = {"total": len(questions), "semgrep_total": len(semgrep_qs),
             "semgrep_verified": 0, "semgrep_reassigned": 0, "semgrep_to_manual": 0,
             "semgrep_no_requirement": 0, "pending": 0}

    if semgrep_qs and find_semgrep() is None:
        print("[warn] 未安装 semgrep，semgrep 轨跳过，题目保留为未验证状态。")
        stats["pending"] = len(semgrep_qs)
    elif semgrep_qs:
        with tempfile.TemporaryDirectory() as vdir, tempfile.TemporaryDirectory() as fdir:
            _write_files(semgrep_qs, "vulnerable_code", vdir)
            _write_files(semgrep_qs, "fixed_code", fdir)
            vuln_map = run_semgrep_dir(vdir)
            fixed_map = run_semgrep_dir(fdir)

        for q in semgrep_qs:
            qid = q["id"]
            vuln_findings = vuln_map.get(f"{qid}.py", set())
            fixed_findings = fixed_map.get(f"{qid}.py", set())
            good = vuln_findings - fixed_findings

            assigned = q.get("semgrep_rule_id", "")
            final_rule = ""
            # 规则「合格」= 命中漏洞代码 且 不命中修复代码
            if assigned in good:
                final_rule = assigned
            else:
                for cand in cwe_to_rule_candidates(q.get("cwe", "")):
                    if cand in good:
                        final_rule = cand
                        break
                if final_rule and final_rule != assigned:
                    stats["semgrep_reassigned"] += 1

            if final_rule:
                q["semgrep_rule_id"] = final_rule
                # 按题校准「安全替代」：只留参考修复新增、漏洞代码里没有的记号。
                # 评测时缺这些记号 = 只是把危险行删掉，不算修好。
                q["fix_required"] = required_for(final_rule, q["vulnerable_code"], q["fixed_code"])
                if not q["fix_required"]:
                    stats["semgrep_no_requirement"] += 1
                q["verified"] = True
                stats["semgrep_verified"] += 1
            else:
                q["semgrep_rule_id"] = ""
                q["fix_required"] = []
                q["verified"] = False
                q["eval_method"] = "manual"
                stats["semgrep_to_manual"] += 1

    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for q in questions:
            f.write(json.dumps(q, ensure_ascii=False) + "\n")

    rep_dir = os.path.dirname(report_path)
    if rep_dir:
        os.makedirs(rep_dir, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    return stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True)
    ap.add_argument("--out", default="questions.jsonl")
    ap.add_argument("--report", default="data/processed/qa_report.json")
    args = ap.parse_args()

    stats = qa(args.in_path, args.out, args.report)
    print(f"[done] semgrep 验证 {stats['semgrep_verified']}/{stats['semgrep_total']} 题"
          f"（转人工 {stats['semgrep_to_manual']}，待验证 {stats['pending']}）")
    print(json.dumps(stats, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
