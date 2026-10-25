"""pytest 共享夹具与工具函数。"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

QUESTIONS_PATH = os.path.join(ROOT, "questions.jsonl")
RULES_DIR = os.path.join(ROOT, "semgrep", "rules")


def load_questions(path: str = None) -> list:
    """从 questions.jsonl 加载题目列表。"""
    path = path or QUESTIONS_PATH
    if not os.path.exists(path):
        return []
    questions = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                questions.append(json.loads(line))
    return questions


def question_ids(questions: list) -> list:
    return [q.get("id", str(i)) for i, q in enumerate(questions)]


def run_functional_test(q: dict, candidate_code: str) -> bool:
    """运行一道 functional 题的功能断言，判断候选代码是否已修复。

    返回 True = 通过断言（已修复）；False = 断言失败（漏洞仍在）。
    依赖题目自带的 functional_test 字段（一段 import check_code 并 assert 的代码）。
    """
    test_code = q.get("functional_test")
    if not test_code:
        return False
    ns = {"candidate_code": candidate_code, "__builtins__": __builtins__}
    try:
        exec(test_code, ns)
        return True
    except AssertionError:
        return False
