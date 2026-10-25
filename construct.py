"""归一化 + 去重 + 反向构造评测题目。

输入：各源的中间产物 JSONL（data/processed/*_pairs.jsonl）
输出：questions.jsonl（最终题目集）

反向构造逻辑：
  - 漏洞代码(vulnerable_code) = 题干
  - 修复代码(fixed_code)     = ground-truth 答案
  - 附 CWE / OWASP / severity / framework / 难度 / 对应 semgrep 规则 id

用法：
  python src/construct.py --pairs data/processed/securecode_pairs.jsonl data/processed/cvefixes_pairs.jsonl \
      --out questions.jsonl --max 500
"""
import argparse
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.mapping import cwe_to_owasp, cwe_to_rule  # noqa: E402
from src.functional_checks import eval_method_for  # noqa: E402

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "": 0}


def norm_owasp(owasp: str) -> str:
    """统一 OWASP 字符串格式，如 'A07:2021-Identification...' -> 'A07:2021 - Identification...'。"""
    if not owasp:
        return ""
    m = re.match(r"(A\d{2}):(\d{4})-?\s*(.+)", owasp.strip())
    if m:
        return f"{m.group(1)}:{m.group(2)} - {m.group(3).strip()}"
    return owasp.strip()


def norm_code(code: str) -> str:
    """归一化代码用于去重哈希。"""
    return re.sub(r"\s+", " ", (code or "").strip()).lower()


def code_hash(code: str) -> str:
    return hashlib.md5(norm_code(code).encode("utf-8")).hexdigest()


def map_difficulty(meta_complexity: str, code: str) -> str:
    """映射难度：优先用源数据复杂度，否则按代码长度启发式。"""
    c = (meta_complexity or "").strip().lower()
    if c in ("easy", "low", "basic", "beginner", "simple"):
        return "easy"
    if c in ("moderate", "medium", "intermediate"):
        return "medium"
    if c in ("hard", "complex", "advanced", "difficult"):
        return "hard"
    n = len((code or "").splitlines())
    if n <= 20:
        return "easy"
    if n <= 60:
        return "medium"
    return "hard"


def map_severity(sev: str, cwe: str) -> str:
    s = (sev or "").strip().upper()
    if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return s
    # CVEfixes 无 severity 时给个默认值
    return "MEDIUM"


def load_pairs(paths):
    """加载并合并多个中间产物 JSONL。"""
    pairs = []
    for p in paths:
        if not p or not os.path.exists(p):
            continue
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    pairs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return pairs


def build_title(cwe: str, owasp: str, category: str) -> str:
    cat = (category or "").replace("_", " ").strip()
    base = cwe or "安全漏洞"
    if cat:
        return f"{base}：{cat}"
    return f"{base} 漏洞修复"


def construct(pair_paths, out_path, max_questions=500, seed=None):
    pairs = load_pairs(pair_paths)
    seen = set()
    questions = []

    for p in pairs:
        vuln = (p.get("vulnerable_code") or "").strip()
        fixed = (p.get("fixed_code") or "").strip()
        if not vuln or not fixed:
            continue

        h = code_hash(vuln)
        if h in seen:
            continue
        seen.add(h)

        cwe = (p.get("cwe") or "").strip()
        owasp = norm_owasp(p.get("owasp") or "") or cwe_to_owasp(cwe)
        qid = f"Q{len(questions) + 1:04d}"

        method = eval_method_for(cwe)
        questions.append({
            "id": qid,
            "source": p.get("source", ""),
            "source_id": p.get("source_id", ""),
            "cwe": cwe,
            "owasp": owasp,
            "category": p.get("category", ""),
            "severity": map_severity(p.get("severity"), cwe),
            "difficulty": map_difficulty((p.get("extra") or {}).get("complexity"), vuln),
            "language": "python",
            "framework": p.get("framework"),
            "title": build_title(cwe, owasp, p.get("category")),
            "description": p.get("description") or "以下代码存在安全漏洞，请修复。",
            "vulnerable_code": vuln,
            "fixed_code": fixed,
            # 双轨评测：semgrep 题用静态规则，functional 题用功能断言
            "eval_method": method,
            "semgrep_rule_id": cwe_to_rule(cwe) if method == "semgrep" else "",
            "functional_test": None,
            "verified": False,
        })

    if max_questions and len(questions) > max_questions:
        questions = questions[:max_questions]

    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for q in questions:
            f.write(json.dumps(q, ensure_ascii=False) + "\n")

    return questions


def summarize(questions):
    from collections import Counter
    owasp = Counter(q["owasp"] for q in questions)
    diff = Counter(q["difficulty"] for q in questions)
    sev = Counter(q["severity"] for q in questions)
    src = Counter(q["source"] for q in questions)
    return {"total": len(questions), "owasp": dict(owasp), "difficulty": dict(diff),
            "severity": dict(sev), "source": dict(src)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pairs", nargs="+", required=True, help="中间产物 JSONL 列表")
    ap.add_argument("--out", default="questions.jsonl")
    ap.add_argument("--max", type=int, default=500)
    ap.add_argument("--summary", default="data/processed/construct_summary.json")
    args = ap.parse_args()

    qs = construct(args.pairs, args.out, args.max)
    summary = summarize(qs)
    with open(args.summary, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"[done] 构造 {len(qs)} 道题 -> {args.out}")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
