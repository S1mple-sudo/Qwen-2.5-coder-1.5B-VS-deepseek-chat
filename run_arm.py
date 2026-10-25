# -*- coding: utf-8 -*-
"""一条命令跑完「一臂」：baseline → report → 逐题判定。

`.bat` 的 Python 版：不依赖 cmd，PyCharm / macOS / Linux 都能直接跑，
PyCharm 里只需建一个 Run Configuration，改 `Parameters` 就能切换模型与提示词。

用法（等价于 run_arm.bat）：
    python src/run_arm.py --tag qwen_default \
        --base-url http://127.0.0.1:11434/v1 --model qwen2.5-coder:1.5b
    python src/run_arm.py --tag qwen_hardened \
        --base-url http://127.0.0.1:11434/v1 --model qwen2.5-coder:1.5b \
        --prompt-file prompts/hardened_generic.md
    python src/run_arm.py --tag qwen_pilot \
        --base-url http://127.0.0.1:11434/v1 --model qwen2.5-coder:1.5b --limit 20
"""
import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(encoding="utf-8")


def _run(step, cmd):
    print(f"\n=== {step} ===", flush=True)
    print("$ " + " ".join(cmd), flush=True)
    proc = subprocess.run(cmd, cwd=ROOT)
    if proc.returncode != 0:
        print(f"\n[error] {step} 失败（exit {proc.returncode}）", file=sys.stderr)
        raise SystemExit(proc.returncode)


def main():
    ap = argparse.ArgumentParser(description="跑一臂：baseline → report → outcomes")
    ap.add_argument("--tag", required=True, help="结果文件名前缀，如 qwen_hardened")
    ap.add_argument("--base-url", required=True, help="OpenAI 兼容端点；本机端点免 key")
    ap.add_argument("--model", required=True)
    ap.add_argument("--prompt-file", default=None, help="prompts/hardened_generic.md 之类；缺省用内置提示词")
    ap.add_argument("--limit", type=int, default=0, help="只跑前 N 题（小样，不出报告）")
    ap.add_argument("--max-tokens", type=int, default=0, help="缺省：本地端点 1024，云端 2048")
    ap.add_argument("--timeout", type=float, default=0, help="缺省：本地端点 900s，云端 180s")
    ap.add_argument("--sleep", type=float, default=0.0)
    ap.add_argument("--api-key", default=None)
    args = ap.parse_args()

    local = any(h in args.base_url for h in ("127.0.0.1", "localhost", "::1"))
    out = os.path.join("data", "processed", f"{args.tag}.jsonl")
    rep = os.path.join("data", "processed", f"{args.tag}_report.json")
    outc = os.path.join("data", "processed", f"{args.tag}_outcomes.jsonl")

    base_cmd = [sys.executable, os.path.join("src", "run_baseline.py"),
                "--base-url", args.base_url, "--model", args.model, "--out", out]
    if args.prompt_file:
        base_cmd += ["--prompt-file", args.prompt_file]
    if args.api_key:
        base_cmd += ["--api-key", args.api_key]
    if args.limit:
        base_cmd += ["--limit", str(args.limit)]
    base_cmd += ["--max-tokens", str(args.max_tokens or (1024 if local else 2048))]
    base_cmd += ["--timeout", str(args.timeout or (900 if local else 180))]
    if args.sleep:
        base_cmd += ["--sleep", str(args.sleep)]

    _run("1/3 baseline", base_cmd)

    if args.limit:
        print("\n[pilot] 小样跑：跳过 report / outcomes（只看有没有空代码或截断）")
        return 0

    _run("2/3 report", [sys.executable, os.path.join("src", "report.py"),
                        "--model-output", out, "--report", rep])
    _run("3/3 outcomes", [sys.executable, os.path.join("src", "export_outcomes.py"),
                          "--model-output", out, "--out", outc])

    print("\n完成。产物：")
    for p in (out, rep, outc):
        print("  " + p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
