"""模型修复评测模板（三轨，双指标）。

评测指标：一个修复「做对」= 同时满足两个条件
    1. 漏洞已消除（vulnerability eliminated）
       - semgrep 轨：对应规则不再命中
       - functional 轨：功能断言通过
    2. 功能未破坏（behavior preserved）
       - 结构保真度不低于参考修复基线（仅功能轴适用的题，见 src/preservation.py）

最终分两个子集上报（见 src/report.py）：
    - 全量漏洞消除率 = 漏洞消除题数 / 可评测题数（236）
    - SFR = (漏洞消除 且 功能未破坏) 题数 / 功能轴适用题数（172）

manual 轨无自动判定，此模板跳过。

如何接入你的模型：
  修改下方 `model_fix()`，把 `question["vulnerable_code"]` 和 `question["description"]`
  喂给你的模型，返回其生成的修复代码即可。默认返回参考修复，保证开箱可跑通。

用法：
    pytest tests/test_evaluate.py -v
"""
import pytest

from conftest import load_questions, question_ids, RULES_DIR, run_functional_test
from src.semgrep_runner import run_semgrep, find_semgrep
from src.preservation import behavior_applicable, behavior_preserved

QUESTIONS = load_questions()
SEMGREP = [q for q in QUESTIONS if q.get("eval_method") == "semgrep"]
FUNCTIONAL = [q for q in QUESTIONS if q.get("eval_method") == "functional"]
# 功能轴适用的题（结构可比的题，跨 semgrep/functional 两轨）
BEHAVIOR = [
    q for q in QUESTIONS
    if q.get("eval_method") in ("semgrep", "functional")
    and behavior_applicable(q["vulnerable_code"], q["fixed_code"])
]


# ---------------------------------------------------------------------------
# TODO: 在此接入你的模型
# ---------------------------------------------------------------------------
def model_fix(question: dict) -> str:
    """把题目喂给模型并返回修复代码。

    示例（接入 OpenAI 兼容接口）：
        resp = client.chat.completions.create(
            model="your-model",
            messages=[
                {"role": "system", "content": "你是安全代码修复专家。"},
                {"role": "user", "content": question["description"] + "\n\n```python\n" + question["vulnerable_code"] + "\n```"},
            ],
        )
        return extract_code(resp.choices[0].message.content)
    """
    # 默认返回参考修复，用于验证评测框架本身可跑通
    return question["fixed_code"]


# ---------------------------------------------------------------------------
# semgrep 轨
# ---------------------------------------------------------------------------
semgrep_skip = pytest.mark.skipif(
    find_semgrep() is None,
    reason="未安装 semgrep，跳过 semgrep 轨。安装：pip install semgrep",
)


@pytest.mark.semgrep
@semgrep_skip
@pytest.mark.parametrize("q", SEMGREP, ids=question_ids(SEMGREP))
def test_model_fix_resolves_vulnerability(q):
    """模型修复后，对应漏洞规则应不再命中。"""
    candidate = model_fix(q)
    assert candidate and candidate.strip(), "模型未输出有效代码"

    findings = run_semgrep(candidate, RULES_DIR)
    rule = q.get("semgrep_rule_id")
    if rule:
        assert rule not in findings, (
            f"模型修复后仍被规则 {rule} 命中，漏洞未消除。（实际命中: {findings}）"
        )
    else:
        assert not findings, f"模型修复后仍存在安全发现: {findings}"


# ---------------------------------------------------------------------------
# functional 轨
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("q", FUNCTIONAL, ids=question_ids(FUNCTIONAL))
def test_model_fix_passes_functional(q):
    """模型修复后，应通过题目的功能断言（安全控制已引入）。"""
    candidate = model_fix(q)
    assert candidate and candidate.strip(), "模型未输出有效代码"
    assert run_functional_test(q, candidate), (
        f"模型修复未通过功能断言，漏洞 {q['cwe']} 仍未消除。"
    )


# ---------------------------------------------------------------------------
# 功能未破坏（跨轨，仅功能轴适用的题）
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("q", BEHAVIOR, ids=question_ids(BEHAVIOR))
def test_model_fix_preserves_behavior(q):
    """模型修复后，功能不应被破坏（结构保真度不低于参考修复基线）。"""
    candidate = model_fix(q)
    assert candidate and candidate.strip(), "模型未输出有效代码"
    assert behavior_preserved(q["vulnerable_code"], candidate, q["fixed_code"]), (
        f"模型修复破坏了功能：结构保真度显著低于参考修复基线（可能删代码/推倒重写）。"
    )
