# -*- coding: utf-8 -*-
"""baseline 跑分：让模型做题，产出可直接喂给 src/report.py 的模型输出。

流程：
    questions.jsonl  ->  逐题调用 OpenAI 兼容的 /chat/completions  ->  data/processed/baseline_out.jsonl
    ->  python src/report.py --model-output data/processed/baseline_out.jsonl

只处理 eval_method ∈ {semgrep, functional} 的可评测题（manual 轨跳过）。
零第三方依赖：用标准库 urllib 发请求，不需要装 openai SDK。

用法：
    # 0) 只看提示词，不发请求（不花钱）
    python src/run_baseline.py --dry-run --limit 3

    # 1) 小样试跑（先花几厘钱验证通路与格式）
    set DEEPSEEK_API_KEY=sk-xxx        # PowerShell: $env:DEEPSEEK_API_KEY="sk-xxx"
    python src/run_baseline.py --limit 10

    # 2) 全量（可断点续跑，已跑过的 id 自动跳过）
    python src/run_baseline.py

    # 3) 出指标
    python src/report.py --model-output data/processed/baseline_out.jsonl \
        --report data/processed/baseline_report.json

    # 换供应商（OpenAI 兼容端点都行）
    python src/run_baseline.py --base-url https://api.deepseek.com --model deepseek-chat
    python src/run_baseline.py --base-url https://open.bigmodel.cn/api/paas/v4 --model glm-4-plus
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.stdout.reconfigure(encoding="utf-8")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUESTIONS = os.path.join(ROOT, "questions.jsonl")
OUT_DEFAULT = os.path.join(ROOT, "data", "processed", "baseline_out.jsonl")

SYSTEM_PROMPT = "你是安全代码修复专家，只输出修复后的完整 Python 代码，不要任何解释。"


# ---------------------------------------------------------------------------
# 提示词与解析
# ---------------------------------------------------------------------------
def load_questions(path=QUESTIONS):
    qs = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                qs.append(json.loads(line))
    return qs


def load_system_prompt(prompt_file=None, inline=None):
    """返回 (system 提示词, prompt_id)。

    prompt_id 会写进输出 JSONL，便于同一模型多套提示词横向对比（如 "default" / "hardened_generic"）。
    """
    if inline:
        return inline, "inline"
    if prompt_file:
        with open(prompt_file, encoding="utf-8") as f:
            return f.read().strip(), os.path.splitext(os.path.basename(prompt_file))[0]
    return SYSTEM_PROMPT, "default"


def build_messages(q, system_prompt=SYSTEM_PROMPT):
    """题干 = description + 漏洞代码块（与 tests/test_evaluate.py 的接入示例一致）。"""
    user = (q.get("description") or "") + "\n```python\n" + (q.get("vulnerable_code") or "") + "\n```"
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user},
    ]


_FENCE = re.compile(r"```(?:[A-Za-z0-9_+-]*)\s*\n(.*?)```", re.S)


def extract_code(text):
    """从回复里取代码块；优先 ```python 块，其次任意块，最后回退纯文本。"""
    if not text:
        return ""
    py = re.search(r"```python\s*\n(.*?)```", text, re.S)
    if py:
        return py.group(1).strip("\n")
    blocks = _FENCE.findall(text)
    if blocks:
        return blocks[0].strip("\n")
    return text.strip()


# ---------------------------------------------------------------------------
# 模型调用（OpenAI 兼容 /chat/completions）
# ---------------------------------------------------------------------------
def _is_local_url(url: str) -> bool:
    """是否本机端点（Ollama / LM Studio / llama.cpp / serve_local.py 等，通常不校验 key）。"""
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    return host in ("127.0.0.1", "localhost", "::1", "0.0.0.0")


def call_model(base_url, model, api_key, messages, timeout=180, retries=3, temperature=0.0,
               max_tokens=0):
    """返回 (content, usage, finish_reason)。对 429/5xx/网络错误做指数退避重试。"""
    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "stream": False,
    }
    if max_tokens and max_tokens > 0:
        payload["max_tokens"] = max_tokens
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:  # 本地服务通常不校验，但有些实现要求非空占位
        headers["Authorization"] = f"Bearer {api_key}"
    last_err = None
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(url, data=body, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            choice = (data.get("choices") or [{}])[0]
            return (choice.get("message", {}).get("content") or "",
                    data.get("usage") or {},
                    choice.get("finish_reason") or "")
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode("utf-8", "replace")[:500]
            except Exception:
                pass
            last_err = f"HTTP {e.code}: {detail}"
            if e.code in (429, 500, 502, 503, 504) and attempt < retries:
                wait = 2 ** attempt
                print(f"    [retry {attempt}/{retries}] {last_err} -> {wait}s", flush=True)
                time.sleep(wait)
                continue
            raise RuntimeError(last_err)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last_err = f"{type(e).__name__}: {e}"
            if attempt < retries:
                time.sleep(2 ** attempt)
                continue
            raise RuntimeError(last_err)
    raise RuntimeError(last_err or "unknown error")


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def load_done(path):
    """读已有输出，返回 ({id: code}, 该文件里出现过的 prompt 标识集合)。

    断点续跑靠它；prompt 集合用于识别「同一个输出文件被拿去跑另一套提示词」的误用。
    """
    done = {}
    prompts = set()
    if not os.path.exists(path):
        return done, prompts
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue  # 上次中断留下的半行，忽略
            if d.get("id") and d.get("code"):
                done[d["id"]] = d["code"]
                prompts.add(d.get("prompt") or "default")
    return done, prompts


def main():
    ap = argparse.ArgumentParser(description="用模型跑 baseline，输出 report.py 可读的 JSONL")
    ap.add_argument("--in", dest="in_path", default=QUESTIONS)
    ap.add_argument("--out", dest="out_path", default=OUT_DEFAULT)
    ap.add_argument("--base-url", default=os.environ.get("MODEL_BASE_URL") or "https://api.deepseek.com",
                    help="OpenAI 兼容端点根地址（默认 DeepSeek）")
    ap.add_argument("--model", default=os.environ.get("MODEL_NAME") or "deepseek-chat")
    ap.add_argument("--api-key", default=os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("OPENAI_API_KEY") or "",
                    help="默认读环境变量 DEEPSEEK_API_KEY / OPENAI_API_KEY")
    ap.add_argument("--limit", type=int, default=0, help="只跑前 N 题（小样试跑用）")
    ap.add_argument("--sleep", type=float, default=0.3, help="每次请求后的间隔秒数")
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=180)
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--max-tokens", type=int, default=2048,
                    help="单次生成上限（本地小模型建议 1024~2048，避免跑飞）")
    ap.add_argument("--dry-run", action="store_true", help="只打印提示词与题量，不发请求、不写文件")
    ap.add_argument("--prompt-file", default=None,
                    help="强化提示词文件（如 prompts/hardened_generic.md）；缺省用内置精简 system 提示词")
    ap.add_argument("--system", default=None, help="直接给 system 提示词（优先级高于 --prompt-file）")
    args = ap.parse_args()

    system_prompt, prompt_id = load_system_prompt(args.prompt_file, args.system)

    if _is_local_url(args.base_url) and not args.api_key:
        args.api_key = "local"  # 本地 OpenAI 兼容服务一般不校验 key

    questions = [q for q in load_questions(args.in_path)
                 if q.get("eval_method") in ("semgrep", "functional")]
    if args.limit:
        questions = questions[:args.limit]

    done, seen_prompts = ({}, set()) if args.dry_run else load_done(args.out_path)
    if seen_prompts and prompt_id not in seen_prompts:
        print(f"[error] {args.out_path} 里已有另一套提示词的结果（{', '.join(sorted(seen_prompts))}），"
              f"本次是 {prompt_id}。", file=sys.stderr)
        print("        继续写会把两种提示词的答案混在同一个文件里；换 --out，或先删掉该文件。",
              file=sys.stderr)
        return 2
    todo = [q for q in questions if q["id"] not in done]

    print("=" * 60)
    print(f"可评测题: {len(questions)}   已完成: {len(done)}   本次待跑: {len(todo)}")
    print(f"端点: {args.base_url.rstrip('/')}/chat/completions   模型: {args.model}")
    print(f"提示词: {prompt_id}（{len(system_prompt)} 字符）")
    print("=" * 60)

    if args.dry_run:
        for q in questions[:3]:
            msgs = build_messages(q, system_prompt)
            print(f"\n--- {q['id']}  {q['cwe']}  {q['eval_method']} ---")
            print(f"[system] {msgs[0]['content']}")
            print(f"[user] {msgs[1]['content'][:600]}...")
        print(f"\n[dry-run] 未发送任何请求。去掉 --dry-run 即可开跑（{len(questions)} 题）。")
        return 0

    if todo and not args.api_key:
        print("[error] 没有 API key：请设置环境变量 DEEPSEEK_API_KEY，或加 --api-key。", file=sys.stderr)
        print("        PowerShell: $env:DEEPSEEK_API_KEY=\"sk-xxx\"", file=sys.stderr)
        print("        CMD:        set DEEPSEEK_API_KEY=sk-xxx", file=sys.stderr)
        print("        本地模型：--base-url http://127.0.0.1:11434/v1（本机端点不需要 key）", file=sys.stderr)
        return 2

    out_dir = os.path.dirname(args.out_path)
    if out_dir:  # --out 只给文件名（无目录部分）时 makedirs('') 会报错
        os.makedirs(out_dir, exist_ok=True)
    ok = fail = 0
    t0 = time.time()
    with open(args.out_path, "a", encoding="utf-8") as fout:
        for i, q in enumerate(todo, 1):
            try:
                content, usage, finish = call_model(
                    args.base_url, args.model, args.api_key, build_messages(q, system_prompt),
                    timeout=args.timeout, retries=args.retries, temperature=args.temperature,
                    max_tokens=args.max_tokens,
                )
            except RuntimeError as e:
                fail += 1
                print(f"[{i}/{len(todo)}] {q['id']} FAIL: {e}", flush=True)
                time.sleep(args.sleep)
                continue

            code = extract_code(content)
            fout.write(json.dumps({
                "id": q["id"],
                "code": code,
                "model": args.model,
                "prompt": prompt_id,
                "finish_reason": finish,
                "usage": usage,
            }, ensure_ascii=False) + "\n")
            fout.flush()
            ok += 1
            flag = "" if code.strip() else "  [warn] 空代码"
            if finish == "length":
                flag += "  [warn] 被截断"
            print(f"[{i}/{len(todo)}] {q['id']} {q['cwe']:8s} {len(code):5d} 字符{flag}", flush=True)
            time.sleep(args.sleep)

    elapsed = time.time() - t0
    print("=" * 60)
    print(f"完成 {ok} 题，失败 {fail} 题，用时 {elapsed:.1f}s -> {args.out_path}")
    print("下一步：python src/report.py --model-output "
          f"{os.path.relpath(args.out_path, ROOT)} --report data/processed/baseline_report.json")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
