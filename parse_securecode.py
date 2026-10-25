"""SecureCode 解析：从 conversations 中抽取 Python 的 vulnerable/secure 代码对。

数据来源：scthornton/securecode 的 web 配置 parquet。
结构：每行 metadata.lang=python，conversations 为 {role, content} 对话列表（字符串形式存储），
assistant 轮次中通过 "**Vulnerable Code ...**" 与 "**Secure Code ...**" 标题标注代码块。

用法：
  python src/parse_securecode.py --parquet data/raw/securecode_web_train.parquet \
      --out data/processed/securecode_pairs.jsonl --stats data/processed/securecode_stats.txt
"""
import argparse
import ast
import json
import os
import re

# 只匹配 ```python / ```py 代码块，避免把 ```bash 等其它语言块的结束反引号
# 误当成 python 块的开头。
FENCE_RE = re.compile(r"```(?:python|py)[ \t]*\n(.*?)```", re.DOTALL)

VULN_KW = [
    "vulnerable", "insecure", "unsafe", "dangerous", "attack", "before",
    "buggy", "flawed", "weak", "bad", "vulnerability",
]
SECURE_KW = [
    "secure", "safe", "fixed", "good", "defense", "mitigat", "after",
    "patched", "correct", "hardened", "recommended", "production",
    "pattern", "best practice", "proper", "robust", "solution",
]


def parse_conversations(val):
    """把 conversations 列（numpy 数组 / 列表 / 字符串）解析成 [{role, content}]。"""
    if isinstance(val, str):
        try:
            return ast.literal_eval(val)
        except Exception:
            return []
    try:
        import numpy as np
        if isinstance(val, np.ndarray):
            val = val.tolist()
    except ImportError:
        pass
    if isinstance(val, (list, tuple)):
        return list(val)
    return []


def label_block(header: str) -> str:
    """根据代码块前的标题文本判断是漏洞代码还是修复代码。"""
    h = header.lower()
    lines = [ln for ln in h.split("\n") if ln.strip()]
    last = lines[-1] if lines else h
    has_vuln = any(k in last for k in VULN_KW)
    has_secure = any(k in last for k in SECURE_KW)
    if has_vuln and not has_secure:
        return "vuln"
    if has_secure and not has_vuln:
        return "secure"
    # 兜底：看整段 header
    if any(k in h for k in VULN_KW) and not any(k in h for k in SECURE_KW):
        return "vuln"
    if any(k in h for k in SECURE_KW):
        return "secure"
    return "unknown"


def extract_pair(conversations):
    """从对话中抽取 (vulnerable_code, fixed_code)。找不到返回 (None, None)。"""
    vuln = None
    secure = None
    for turn in conversations:
        if not isinstance(turn, dict) or turn.get("role") != "assistant":
            continue
        text = turn.get("content", "")
        for m in FENCE_RE.finditer(text):
            code = m.group(1).strip()
            if not code:
                continue
            start = max(0, m.start() - 180)
            header = text[start:m.start()]
            lab = label_block(header)
            if lab == "vuln" and vuln is None:
                vuln = code
            elif lab == "secure" and secure is None:
                secure = code
        if vuln and secure:
            break
    return vuln, secure


def build_description(row_meta: dict, row_ctx: dict) -> str:
    """合成题目描述文本。"""
    owasp = row_meta.get("owasp_2021") or ""
    cwe = row_meta.get("cwe") or ""
    impact = (row_ctx or {}).get("impact")
    category = row_meta.get("category") or row_meta.get("subcategory") or ""
    parts = []
    if owasp:
        parts.append(f"【{owasp}】")
    if cwe:
        parts.append(f"漏洞类型 {cwe}")
    if impact:
        parts.append(f"影响：{impact}")
    if parts:
        return " ".join(parts)
    return f"以下代码存在安全漏洞（{category or '未知类别'}），请修复。"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--parquet", default="data/raw/securecode_web_train.parquet")
    ap.add_argument("--out", default="data/processed/securecode_pairs.jsonl")
    ap.add_argument("--stats", default="data/processed/securecode_stats.txt")
    args = ap.parse_args()

    import pandas as pd

    df = pd.read_parquet(args.parquet)

    stats = {"total": int(len(df)), "python": 0, "paired": 0, "only_vuln": 0,
             "only_secure": 0, "none": 0, "labels_unknown": 0}

    def is_python(m):
        return isinstance(m, dict) and str((m or {}).get("lang", "")).lower() == "python"

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    n_out = 0
    with open(args.out, "w", encoding="utf-8") as fout:
        for _, row in df.iterrows():
            meta = row["metadata"] if isinstance(row["metadata"], dict) else {}
            if not is_python(meta):
                continue
            stats["python"] += 1

            convs = parse_conversations(row["conversations"])
            vuln, secure = extract_pair(convs)

            if vuln and secure:
                stats["paired"] += 1
            elif vuln:
                stats["only_vuln"] += 1
            elif secure:
                stats["only_secure"] += 1
            else:
                stats["none"] += 1

            if not (vuln and secure):
                continue

            ctx = row["context"] if isinstance(row["context"], dict) else {}
            framework = meta.get("framework") or meta.get("framework_native") or None
            if not framework:
                # 从代码头部 import 粗略推断框架
                head = (vuln[:800] + " " + secure[:200]).lower()
                for fw in ("flask", "django", "fastapi", "sqlalchemy", "aiohttp", "starlette"):
                    if fw in head:
                        framework = fw
                        break

            record = {
                "source": "securecode",
                "source_id": str(row.get("uid") or row.get("id") or ""),
                "cwe": meta.get("cwe") or "",
                "owasp": meta.get("owasp_2021") or "",
                "category": meta.get("category") or "",
                "severity": meta.get("severity") or "",
                "language": "python",
                "framework": framework,
                "description": build_description(meta, ctx),
                "vulnerable_code": vuln,
                "fixed_code": secure,
                "extra": {
                    "complexity": meta.get("complexity"),
                    "subcategory": meta.get("subcategory"),
                    "template_engine": meta.get("template_engine"),
                },
            }
            fout.write(json.dumps(record, ensure_ascii=False) + "\n")
            n_out += 1

    with open(args.stats, "w", encoding="utf-8") as f:
        f.write(json.dumps(stats, ensure_ascii=False, indent=2))

    print(f"[done] 写入 {n_out} 条 Python 修复对 -> {args.out}")
    print(json.dumps(stats, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
