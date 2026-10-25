# -*- coding: utf-8 -*-
"""把本地 HuggingFace 模型包装成 OpenAI 兼容端点，供 src/run_baseline.py 直接调用。

适用于下载了 safetensors 权重（如 Qwen2.5-Coder-1.5B-Instruct 原始目录）的场景。
如果你用的是 Ollama / LM Studio / llama.cpp，它们自带 OpenAI 兼容端点，不需要本脚本。

依赖：torch + transformers（本脚本之外的部分都是标准库）

用法：
    python src/serve_local.py --model-path D:\\models\\Qwen2.5-Coder-1.5B-Instruct --port 8000
    # 另开一个窗口：
    python src/run_baseline.py --base-url http://127.0.0.1:8000/v1 \
        --model Qwen2.5-Coder-1.5B-Instruct --limit 5

接口：
    GET  /v1/models
    POST /v1/chat/completions   {"model":..., "messages":[...], "max_tokens":...}
"""
import argparse
import json
import os
import sys
import threading
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.stdout.reconfigure(encoding="utf-8")

_LOCK = threading.Lock()   # 单卡/单模型串行生成


# ---------------------------------------------------------------------------
# 模型
# ---------------------------------------------------------------------------
def load_model(model_path, device="auto", dtype="auto"):
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    if device == "auto":
        device = "cuda" if torch.cuda.is_available() else "cpu"
    if dtype == "auto":
        dtype = torch.float16 if device == "cuda" else torch.float32
    print(f"[serve] loading {model_path} (device={device}, dtype={dtype}) ...", flush=True)
    tok = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        model_path, torch_dtype=dtype, trust_remote_code=True
    ).to(device)
    model.eval()
    print("[serve] model ready", flush=True)
    return model, tok, device


def generate(model, tok, device, messages, max_tokens=1024, temperature=0.0):
    import torch

    text = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tok([text], return_tensors="pt").to(device)
    kwargs = dict(max_new_tokens=int(max_tokens), pad_token_id=tok.eos_token_id or 0)
    if temperature and temperature > 0:
        kwargs.update(do_sample=True, temperature=float(temperature))
    else:
        kwargs.update(do_sample=False)
    with _LOCK, torch.no_grad():
        out = model.generate(**inputs, **kwargs)
    new_tokens = out[0][inputs["input_ids"].shape[-1]:]
    reply = tok.decode(new_tokens, skip_special_tokens=True)
    usage = {
        "prompt_tokens": int(inputs["input_ids"].shape[-1]),
        "completion_tokens": int(new_tokens.shape[-1]),
        "total_tokens": int(inputs["input_ids"].shape[-1] + new_tokens.shape[-1]),
    }
    finish = "length" if new_tokens.shape[-1] >= int(max_tokens) else "stop"
    return reply, usage, finish


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    model = None
    tok = None
    device = "cpu"
    model_id = "local-model"

    def log_message(self, fmt, *a):  # 安静一点
        pass

    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.rstrip("/") in ("/v1/models", "/models"):
            self._send(200, {"object": "list", "data": [
                {"id": self.model_id, "object": "model", "owned_by": "local"}]})
        else:
            self._send(404, {"error": {"message": f"unknown path {self.path}"}})

    def do_POST(self):
        if not self.path.rstrip("/").endswith("/chat/completions"):
            self._send(404, {"error": {"message": f"unknown path {self.path}"}})
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            req = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        except Exception as e:
            self._send(400, {"error": {"message": f"bad request: {e}"}})
            return

        messages = req.get("messages") or []
        max_tokens = int(req.get("max_tokens") or req.get("max_new_tokens") or 1024)
        temperature = float(req.get("temperature") or 0.0)
        t0 = time.time()
        try:
            reply, usage, finish = generate(self.model, self.tok, self.device,
                                            messages, max_tokens, temperature)
        except Exception as e:
            traceback.print_exc()
            self._send(500, {"error": {"message": f"generation failed: {e}"}})
            return

        self._send(200, {
            "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": req.get("model") or self.model_id,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": reply},
                "finish_reason": finish,
            }],
            "usage": usage,
        })
        print(f"[serve] {len(messages)} msgs -> {len(reply)} chars, {usage['completion_tokens']} tok, "
              f"{time.time() - t0:.1f}s", flush=True)


def main():
    ap = argparse.ArgumentParser(description="本地 HF 模型的 OpenAI 兼容服务")
    ap.add_argument("--model-path", required=True, help="模型目录（含 config.json / tokenizer）")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--device", default="auto", choices=["auto", "cpu", "cuda", "mps"])
    ap.add_argument("--dtype", default="auto", choices=["auto", "float32", "float16", "bfloat16"])
    args = ap.parse_args()

    if not os.path.isdir(args.model_path):
        print(f"[error] 模型目录不存在: {args.model_path}", file=sys.stderr)
        return 2

    Handler.model, Handler.tok, Handler.device = load_model(args.model_path, args.device, args.dtype)
    Handler.model_id = os.path.basename(os.path.normpath(args.model_path))

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[serve] listening on http://{args.host}:{args.port}/v1  (model id: {Handler.model_id})")
    print(f"[serve] 另开窗口跑：python src/run_baseline.py --base-url "
          f"http://{args.host}:{args.port}/v1 --model {Handler.model_id}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[serve] bye")
    return 0


if __name__ == "__main__":
    sys.exit(main())
