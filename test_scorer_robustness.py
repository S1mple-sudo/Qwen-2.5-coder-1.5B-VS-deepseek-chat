# -*- coding: utf-8 -*-
"""评分器自检：作弊答案必须拿不到分（防「删掉危险行 / 只写 pass」刷分）。

这是针对评分器本身的测试，不是针对题目的测试——它回答的问题是
「一个什么都没做的答案，能不能通过？」答案必须是「不能」。

需要 semgrep（跑 3 次批量扫描，约 2 分钟），因此打 semgrep 标记：
    pytest tests/test_scorer_robustness.py -m semgrep -q
    pytest -m "not semgrep"        # 快速测试里会跳过它
"""
import pytest

from conftest import load_questions, RULES_DIR
from src import cheat_check

QUESTIONS = load_questions()
SEMI = [q for q in QUESTIONS if q.get("eval_method") == "semgrep"]
FUNC = [q for q in QUESTIONS if q.get("eval_method") == "functional"]


@pytest.fixture(scope="module")
def selfcheck():
    return cheat_check.run(SEMI, FUNC, RULES_DIR)


@pytest.mark.semgrep
def test_deletion_cheat_scores_zero(selfcheck):
    """把 semgrep 命中的行整行删掉，不应被判为「漏洞已消除」。"""
    d = selfcheck["deletion_cheat"]
    assert d["total"] > 0, "没有可检验的题目"
    assert d["passed"] == 0, f"删行作弊拿到了分：{d['ids']}"


@pytest.mark.semgrep
def test_stub_cheat_scores_zero(selfcheck):
    """整份答案只写 pass，不应被判为已修复。"""
    assert selfcheck["stub_semgrep"]["passed"] == 0, selfcheck["stub_semgrep"]["ids"]
    assert selfcheck["stub_functional"]["passed"] == 0, selfcheck["stub_functional"]["ids"]
