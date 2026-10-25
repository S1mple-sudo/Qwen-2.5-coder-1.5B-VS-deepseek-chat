"""CVEfixes 摄入：从 SQLite 数据库抽取 Python 漏洞修复对（before -> after）。

依赖：无第三方库，仅 Python 内置 sqlite3。

数据获取（详见 README）：
  1. 从 Zenodo 下载 SQL dump（DOI: 10.5281/zenodo.4476563）
  2. 转成 SQLite：gzcat CVEfixes.sql.gz | sqlite3 CVEfixes.db
     或 Windows：gzip -d CVEfixes.sql.gz 后 sqlite3 CVEfixes.db < CVEfixes.sql

用法：
  python src/parse_cvefixes.py --db path/to/CVEfixes.db --out data/processed/cvefixes_pairs.jsonl
"""
import argparse
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.mapping import cwe_to_owasp  # noqa: E402

# 官方给出的跨表连接关系（见 CVEfixes INSTALL.md）：
#   file_change.hash -> commits.hash -> fixes.hash -> fixes.cve_id -> cve.cve_id
#   cve.cve_id -> cwe_classification.cve_id -> cwe_classification.cwe_id -> cwe.cwe_id
SQL_FILE_LEVEL = """
SELECT
    cv.cve_id,
    f.file_change_id,
    f.filename,
    f.num_lines_added,
    f.num_lines_deleted,
    f.code_before,
    f.code_after,
    GROUP_CONCAT(cw.name, ';') AS cwe_names
FROM file_change f
JOIN commits c ON f.hash = c.hash
JOIN fixes fx ON c.hash = fx.hash
JOIN cve cv ON fx.cve_id = cv.cve_id
LEFT JOIN cwe_classification cc ON cv.cve_id = cc.cve_id
LEFT JOIN cwe cw ON cc.cwe_id = cw.cwe_id
WHERE f.programming_language = 'Python'
  AND f.code_before IS NOT NULL
  AND f.code_after IS NOT NULL
  AND TRIM(f.code_before) <> ''
  AND TRIM(f.code_after) <> ''
GROUP BY f.file_change_id
"""


def normalize_cwe(cwe_name: str) -> str:
    """把 CWE 名称（如 'CWE-89' 或 '89'）规范化为 'CWE-89'。"""
    if not cwe_name:
        return ""
    cwe_name = cwe_name.strip()
    if cwe_name.upper().startswith("CWE-"):
        return cwe_name.upper()
    return f"CWE-{cwe_name}"


def extract(db_path: str, out_path: str, limit: int = 0) -> int:
    """抽取 Python 修复对并写入 JSONL，返回抽取条数。"""
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"数据库不存在: {db_path}")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # 校验关键表是否存在，给出可读的报错
    tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    required = {"file_change", "commits", "fixes", "cve", "cwe_classification", "cwe"}
    missing = required - tables
    if missing:
        raise RuntimeError(f"CVEfixes 数据库缺少表: {missing}。实际表: {sorted(tables)}")

    sql = SQL_FILE_LEVEL
    if limit:
        sql += f" LIMIT {limit}"

    n = 0
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fout:
        for row in cur.execute(sql):
            cwe_names = (row["cwe_names"] or "").split(";")
            # 取第一个可识别的 CWE
            cwe = ""
            for name in cwe_names:
                cwe = normalize_cwe(name)
                if cwe:
                    break

            record = {
                "source": "cvefixes",
                "source_id": f"cve-{row['cve_id']}-fc-{row['file_change_id']}",
                "cwe": cwe,
                "owasp": cwe_to_owasp(cwe) if cwe else "",
                "category": "",
                "severity": "",
                "language": "python",
                "framework": None,
                "description": "",
                "vulnerable_code": (row["code_before"] or "").strip(),
                "fixed_code": (row["code_after"] or "").strip(),
                "extra": {
                    "filename": row["filename"],
                    "num_lines_added": row["num_lines_added"],
                    "num_lines_deleted": row["num_lines_deleted"],
                },
            }
            fout.write(json.dumps(record, ensure_ascii=False) + "\n")
            n += 1

    conn.close()
    return n


def main():
    ap = argparse.ArgumentParser(description="从 CVEfixes SQLite 库抽取 Python 修复对")
    ap.add_argument("--db", required=True, help="CVEfixes.db 路径")
    ap.add_argument("--out", default="data/processed/cvefixes_pairs.jsonl")
    ap.add_argument("--limit", type=int, default=0, help="限制抽取条数（0=全部）")
    args = ap.parse_args()

    n = extract(args.db, args.out, args.limit)
    print(f"[done] 抽取 {n} 条 Python 修复对 -> {args.out}")


if __name__ == "__main__":
    main()
