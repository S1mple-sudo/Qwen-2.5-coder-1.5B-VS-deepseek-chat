"""数据集黄金校验（golden test）——三轨评测的「质检闸门」。

对每道题，按其 eval_method 校验 ground-truth 的正确性：

  semgrep    —— 漏洞代码被规则命中，修复代码不再命中
  functional —— 漏洞代码不通过功能断言，修复代码通过功能断言
  manual     —— 仅校验字段完整（无法自动判定，需人工评审）

只有全部通过，题目集才可用于评测。
依赖 semgrep（仅 semgrep 轨），未安装时该轨自动跳过。

用法：
    pytest tests/test_golden.py -v
    pytest tests/test_golden.py -v -m "not semgrep"   # 跳过 semgrep 轨
"""
import pytest

from conftest import load_questions, question_ids, RULES_DIR, run_functional_test
from src.semgrep_runner import run_semgrep, find_semgrep

QUESTIONS = load_questions()
IDS = question_ids(QUESTIONS)

SEMGREP = [q for q in QUESTIONS if q.get("eval_method") == "semgrep"]
FUNCTIONAL = [q for q in QUESTIONS if q.get("eval_method") == "functional"]

semgrep_skip = pytest.mark.skipif(
    find_semgrep() is None,
    reason="未安装 semgrep，跳过 semgrep 轨。安装：pip install semgrep",
)


# ---------------------------------------------------------------------------
# semgrep 轨
# ---------------------------------------------------------------------------
@pytest.mark.semgrep
@semgrep_skip
@pytest.mark.parametrize("q", SEMGREP, ids=question_ids(SEMGREP))
def test_vulnerable_code_is_flagged(q):
    """漏洞代码必须能被规则命中（保证题目可被检测）。"""
    findings = run_semgrep(q["vulnerable_code"], RULES_DIR)
    rule = q.get("semgrep_rule_id")
    assert rule and rule in findings, f"漏洞代码未被规则 {rule} 命中（实际命中: {findings}）"


@pytest.mark.semgrep
@semgrep_skip
@pytest.mark.parametrize("q", SEMGREP, ids=question_ids(SEMGREP))
def test_fixed_code_clears_rule(q):
    """修复代码必须不再被该规则命中（保证 ground-truth 修复有效）。"""
    findings = run_semgrep(q["fixed_code"], RULES_DIR)
    rule = q.get("semgrep_rule_id")
    assert rule and rule not in findings, f"修复代码仍被规则 {rule} 命中（实际命中: {findings}）"


# ---------------------------------------------------------------------------
# functional 轨
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("q", FUNCTIONAL, ids=question_ids(FUNCTIONAL))
def test_vulnerable_code_fails_functional(q):
    """漏洞代码必须不通过功能断言（保证题目确实是漏洞）。"""
    assert not run_functional_test(q, q["vulnerable_code"]), \
        f"漏洞代码意外通过了功能断言，题目 {q['id']}（{q['cwe']}）的漏洞无法被识别"


@pytest.mark.parametrize("q", FUNCTIONAL, ids=question_ids(FUNCTIONAL))
def test_fixed_code_passes_functional(q):
    """修复代码必须通过功能断言（保证 ground-truth 修复有效）。"""
    assert run_functional_test(q, q["fixed_code"]), \
        f"修复代码未通过功能断言，题目 {q['id']}（{q['cwe']}）的修复未被认可"


# ---------------------------------------------------------------------------
# 通用：字段完整
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("q", QUESTIONS, ids=IDS)
def test_required_fields(q):
    """每道题必须包含评测所需的全部字段。"""
    for field in ("id", "cwe", "owasp", "vulnerable_code", "fixed_code", "eval_method"):
        assert q.get(field), f"题目 {q.get('id')} 缺少字段 {field}"
    assert "semgrep_rule_id" in q and "functional_test" in q and "verified" in q, \
        f"题目 {q.get('id')} 缺少 semgrep_rule_id/functional_test/verified 字段"
