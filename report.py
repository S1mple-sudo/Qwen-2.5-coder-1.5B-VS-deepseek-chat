# -*- coding: utf-8 -*-
"""评测汇总报告：输出两个指标。

指标定义（一个修复「做对」= 同时满足两条件）：
  1. 漏洞已消除：semgrep 轨规则不再命中 / functional 轨功能断言通过
  2. 功能未破坏：结构保真度不低于参考修复基线（仅功能轴适用的题）

分两个子集上报：
  - 全量漏洞消除率 = 漏洞消除题数 / 可评测题数（236）
  - SFR（安全修复率）= (漏洞消除 且 功能未破坏) 题数 / 功能轴适用题数（172）

用法：
  python src/report.py                            # 用参考修复自检（SFR 应为 1.0）
  python src/report.py --model-output out.jsonl   # 读模型输出（每行 {"id":..., "code":...}）
  python src/report.py --report data/processed/eval_report.json
"""
import argparse
import json
import os
import sys

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.preservation import behavior_applicable, behavior_preserved  # noqa: E402
from src.remediation import elimination_ok  # noqa: E402
from src.semgrep_runner import find_semgrep, run_semgrep_batch  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUESTIONS_PATH = os.path.join(ROOT, "questions.jsonl")
RULES_DIR = os.path.join(ROOT, "semgrep", "rules")


def load_questions(path=QUESTIONS_PATH):
    if not os.path.exists(path):
        return []
    qs = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                qs.append(json.loads(line))
    return qs


def run_functional_test(q, candidate_code):
    test_code = q.get("functional_test")
    if not test_code:
        return False
    ns = {"candidate_code": candidate_code, "__builtins__": __builtins__}
    try:
        exec(test_code, ns)
        return True
    except AssertionError:
        return False
    except Exception:
        return False


def load_model_output(path):
    """读模型输出 JSONL -> {id: code}。缺省返回 None（用参考修复自检）。"""
    if not path:
        return None
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            out[d["id"]] = d.get("code") or d.get("fixed_code") or ""
    return out


def run_semgrep_batch(codes, rules_dir):  # noqa: F811  —— 保留旧名，逻辑已移到 semgrep_runner
    """批量扫描多段代码（委托给 semgrep_runner，供外部脚本沿用旧调用名）。"""
    from src.semgrep_runner import run_semgrep_batch as _batch
    return _batch(codes, rules_dir)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", default=QUESTIONS_PATH)
    ap.add_argument("--model-output", default=None,
                    help="模型输出 JSONL（每行 {\"id\":..., \"code\":...}），缺省用参考修复自检")
    ap.add_argument("--report", default="data/processed/eval_report.json")
    ap.add_argument("--selfcheck", action="store_true",
                    help="额外跑评分器自检：用「删行 / pass」两种作弊答案验证不给分（多一次 semgrep 扫描）")
    args = ap.parse_args()

    questions = load_questions(args.in_path)
    model_out = load_model_output(args.model_output)
    has_semgrep = find_semgrep() is not None

    evaluable = [q for q in questions if q.get("eval_method") in ("semgrep", "functional")]

    sg_total = sum(1 for q in evaluable if q["eval_method"] == "semgrep")
    if not has_semgrep and sg_total:
        print(f"[warn] 未找到 semgrep：semgrep 轨 {sg_total} 题无法判定（记为 pending），"
              f"下面的指标只在剩下的 {len(evaluable) - sg_total} 道 functional 题上计算，不能与完整基线直接比较。",
              file=sys.stderr)
        print("       安装：pip install semgrep  或设置环境变量 SEMGREP_BIN 指向 semgrep 可执行文件",
              file=sys.stderr)

    # 批量扫描 semgrep 轨（一次 semgrep 进程，避免逐题起进程）
    semgrep_findings = {}
    if has_semgrep:
        sg_codes = {}
        for q in evaluable:
            if q["eval_method"] == "semgrep":
                candidate = (model_out or {}).get(q["id"]) if model_out is not None else q["fixed_code"]
                sg_codes[q["id"]] = candidate or ""
        semgrep_findings = run_semgrep_batch(sg_codes, RULES_DIR)

    # 计数
    eliminated = 0        # 漏洞消除题数（可判定的）
    elim_judged = 0       # 实际判定了漏洞消除的题数
    semgrep_pending = 0   # 因未装 semgrep 而未判定的 semgrep 题数
    applicable = 0        # 功能轴适用题数
    behavior_ok = 0       # 功能未破坏题数（适用集内）
    applicable_judged = 0  # 功能轴适用 且 漏洞消除可判定的题数（SFR 分母）
    secure_fix = 0        # 漏洞消除 且 功能未破坏（适用且可判定集内）

    for q in evaluable:
        candidate = (model_out or {}).get(q["id"]) if model_out is not None else q["fixed_code"]
        candidate = candidate or ""

        # 1) 漏洞消除
        elim = None
        if q["eval_method"] == "functional":
            elim = run_functional_test(q, candidate)
        else:  # semgrep
            if not has_semgrep:
                semgrep_pending += 1
            else:
                findings = semgrep_findings.get(q["id"], set())
                rule = q.get("semgrep_rule_id") or ""
                # 漏洞消除 = 规则不再命中 且 出现该题要求的安全替代（防止「删掉危险行」刷分）
                elim = elimination_ok(rule, findings, candidate, q.get("fix_required"))

        if elim is not None:
            elim_judged += 1
            if elim:
                eliminated += 1

        # 2) 功能未破坏（仅功能轴适用的题）
        if behavior_applicable(q["vulnerable_code"], q["fixed_code"]):
            applicable += 1
            pres = behavior_preserved(q["vulnerable_code"], candidate, q["fixed_code"])
            if pres:
                behavior_ok += 1
            if elim is not None:
                applicable_judged += 1
                if elim and pres:
                    secure_fix += 1

    # 汇总
    elim_rate = eliminated / elim_judged if elim_judged else 0.0
    behavior_rate = behavior_ok / applicable if applicable else 0.0
    sfr = secure_fix / applicable_judged if applicable_judged else 0.0
    # 统一分母：同一个 172 题基座上的联合通过率（功能轴不适用的题计入分母、不计入分子）
    unified_rate = secure_fix / len(evaluable) if evaluable else 0.0

    report = {
        "total_questions": len(questions),
        "evaluable": len(evaluable),
        "vulnerability_elimination": {
            "eliminated": eliminated,
            "judged": elim_judged,
            "rate": round(elim_rate, 4),
            "semgrep_pending": semgrep_pending,
        },
        "behavior_preservation": {
            "applicable": applicable,
            "preserved": behavior_ok,
            "rate": round(behavior_rate, 4),
        },
        "SFR": {
            "secure_fix": secure_fix,
            "denominator": applicable_judged,
            "rate": round(sfr, 4),
        },
        # 统一分母口径：secure_fix / 全部可评测题（172）
        "unified": {
            "joint": secure_fix,
            "denominator": len(evaluable),
            "rate": round(unified_rate, 4),
            "note": "功能轴不适用的题计入分母、不计入分子",
        },
        "notes": {
            "semgrep_installed": has_semgrep,
            "mode": "self-check (reference fix)" if model_out is None else "model output",
            "semgrep_rule": "规则不再命中 + 必须有安全替代（src/remediation.py）",
        },
    }

    # 评分器自检（可选）：用「删行 / pass」两种作弊答案跑同一套判定
    selfcheck = None
    if args.selfcheck and has_semgrep:
        from src import cheat_check
        semi = [q for q in evaluable if q["eval_method"] == "semgrep"]
        func = [q for q in evaluable if q["eval_method"] == "functional"]
        selfcheck = cheat_check.run(semi, func, RULES_DIR)
        report["scorer_selfcheck"] = selfcheck

    rep_dir = os.path.dirname(args.report)
    if rep_dir:  # --report 只给文件名（无目录部分）时 makedirs('') 会报错
        os.makedirs(rep_dir, exist_ok=True)
    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    # 人类可读打印
    print("=" * 64)
    print("评测指标汇总")
    print("=" * 64)
    print(f"总题数: {report['total_questions']}  |  可评测题: {report['evaluable']}")
    print(f"模式: {report['notes']['mode']}  |  semgrep 已装: {has_semgrep}")
    print("-" * 64)
    v = report["vulnerability_elimination"]
    print(f"[1] 安全通过率（漏洞消除）: {v['eliminated']}/{v['judged']} = {v['rate']:.2%}"
          + (f"  (semgrep 轨 {v['semgrep_pending']} 题待验证)" if v["semgrep_pending"] else ""))
    b = report["behavior_preservation"]
    print(f"[2] 功能通过率（功能轴适用）: {b['preserved']}/{b['applicable']} = {b['rate']:.2%}")
    s = report["SFR"]
    print(f"[3] 联合通过率 SFR（安全∧功能）: {s['secure_fix']}/{s['denominator']} = {s['rate']:.2%}")
    u = report["unified"]
    print(f"[4] 全题集联合（分母 {u['denominator']}）: {u['joint']}/{u['denominator']} = {u['rate']:.2%}")
    if selfcheck:
        d, ss, sf = selfcheck["deletion_cheat"], selfcheck["stub_semgrep"], selfcheck["stub_functional"]
        print("-" * 64)
        print(f"[自检] 作弊答案通过数（应为 0）: 删行 {d['passed']}/{d['total']} · "
              f"pass(semgrep) {ss['passed']}/{ss['total']} · "
              f"pass(functional) {sf['passed']}/{sf['total']}")
        if d["excluded"]:
            print(f"       （另有 {d['excluded']} 道属移除型修复，未纳入删行自检："
                  f"{', '.join(d['excluded_rules'])}）")
    print("=" * 64)
    print(f"报告已写入: {args.report}")


if __name__ == "__main__":
    main()
