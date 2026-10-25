"""探查 SecureCode parquet 的 schema 与样例行，辅助确认解析逻辑。"""
import argparse
import json
import sys


def inspect(parquet_path: str, out_path: str, n_samples: int = 2):
    import pandas as pd

    df = pd.read_parquet(parquet_path)
    info = {
        "num_rows": int(len(df)),
        "columns": list(df.columns),
        "dtypes": {c: str(t) for c, t in df.dtypes.items()},
    }

    # 语言分布
    lang_counts = {}
    if "metadata" in df.columns:
        def get_lang(m):
            return (m or {}).get("lang") if isinstance(m, dict) else None
        langs = df["metadata"].map(get_lang)
        lang_counts = langs.value_counts(dropna=False).to_dict()
    info["lang_counts"] = lang_counts

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("=== SCHEMA INFO ===\n")
        f.write(json.dumps(info, ensure_ascii=False, indent=2, default=str) + "\n")

        f.write("\n=== SAMPLE ROWS (python) ===\n")
        sample = df
        if "metadata" in df.columns:
            sample = df[df["metadata"].map(
                lambda m: isinstance(m, dict) and str((m or {}).get("lang", "")).lower() == "python"
            )]
        for i, row in sample.head(n_samples).iterrows():
            f.write(f"\n----- row {i} -----\n")
            for col in df.columns:
                f.write(f"[{col}] => {json.dumps(row[col], ensure_ascii=False, indent=2, default=str)[:4000]}\n")

    print(f"[done] 已写入探查结果 -> {out_path}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--parquet", default="data/raw/securecode_web_train.parquet")
    ap.add_argument("--out", default="data/processed/inspect_securecode.txt")
    ap.add_argument("--n", type=int, default=2)
    args = ap.parse_args()
    inspect(args.parquet, args.out, args.n)
