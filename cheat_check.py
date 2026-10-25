# -*- coding: utf-8 -*-
"""评分器自检：构造「作弊答案」，确认评分器不会给分。

为什么需要
----------
只判「规则不再命中」时，把危险行删掉就能拿满分——这不是能力，是评分器的漏洞。
本模块提供两类作弊答案，用于**验收评分器本身**：

    A. 删行作弊：把 semgrep 命中的行整行删掉，其余一字不改（最省力的作弊）
    B. pass 作弊：整份答案只写 `pass`

健康的标准：两类作弊在「安全通过」上的通过数应接近 0。
CI 里由 tests/test_scorer_robustness.py 守着；report.py --selfcheck 也会打印这份体检。
"""
from src.functional_checks import check_code
from src.remediation import elimination_ok
from src.semgrep_runner import run_semgrep_batch, run_semgrep_batch_detail


def deletion_cheats(semgrep_questions: list, rules_dir: str) -> dict:
    """构造「只删命中行」的作弊答案：{qid: code}。"""
    codes = {q["id"]: q["vulnerable_code"] for q in semgrep_questions}
    detail = run_semgrep_batch_detail(codes, rules_dir)
    cheats = {}
    for q in semgrep_questions:
        lines = q["vulnerable_code"].splitlines()
        drop = set()
        for _rule, start, end in detail.get(q["id"], []):
            drop.update(range(start - 1, end))
        kept = [ln for i, ln in enumerate(lines) if i not in drop]
        cheats[q["id"]] = "\n".join(kept) if kept else "pass\n"
    return cheats


def stub_cheats(questions: list) -> dict:
    """构造「整份只写 pass」的作弊答案：{qid: code}。"""
    return {q["id"]: "pass\n" for q in questions}


def score_semgrep(semgrep_questions: list, codes: dict, rules_dir: str) -> dict:
    """按 semgrep 轨口径给答案打分，返回 {qid: 是否判为已消除}。"""
    findings = run_semgrep_batch({q["id"]: codes.get(q["id"], "") for q in semgrep_questions}, rules_dir)
    return {q["id"]: elimination_ok(q.get("semgrep_rule_id", ""),
                                    findings.get(q["id"], set()),
                                    codes.get(q["id"], ""),
                                    q.get("fix_required"))
            for q in semgrep_questions}


def score_functional(functional_questions: list, codes: dict) -> dict:
    """按 functional 轨口径给答案打分，返回 {qid: 是否判为已修复}。"""
    return {q["id"]: check_code(q["cwe"], codes.get(q["id"], ""))
            for q in functional_questions}


def run(semgrep_questions: list, functional_questions: list, rules_dir: str) -> dict:
    """跑完整自检，返回统计（作弊通过数应全为 0）。

    说明：只对「有安全替代要求」的题做删行作弊——像 mark_safe 这种
    「移除即修复」的题没有正面记号可验，删掉危险调用本身就是正确做法，
    会计入 `deletion_cheat.excluded` 单独说明。
    """
    covered = [q for q in semgrep_questions if q.get("fix_required")]
    uncovered = [q for q in semgrep_questions if not q.get("fix_required")]

    del_cheat = deletion_cheats(covered, rules_dir)
    stub = stub_cheats(semgrep_questions + functional_questions)

    del_pass = [qid for qid, ok in score_semgrep(covered, del_cheat, rules_dir).items() if ok]
    stub_semi = [qid for qid, ok in score_semgrep(semgrep_questions, stub, rules_dir).items() if ok]
    stub_func = [qid for qid, ok in score_functional(functional_questions, stub).items() if ok]

    return {
        "deletion_cheat": {"total": len(covered), "passed": len(del_pass), "ids": del_pass,
                           "excluded": len(uncovered),
                           "excluded_rules": sorted({q.get("semgrep_rule_id", "") for q in uncovered})},
        "stub_semgrep": {"total": len(semgrep_questions), "passed": len(stub_semi), "ids": stub_semi},
        "stub_functional": {"total": len(functional_questions), "passed": len(stub_func), "ids": stub_func},
    }
