# -*- coding: utf-8 -*-
"""Semgrep 轨的「安全替代」约束（正面要求，按题校准）。

为什么需要
----------
只判「规则不再命中」可以被刷分：把危险的那一行删掉，规则自然不命中，
但功能也一起没了。本模块为每条规则列出一组「安全替代记号」（正则），
再在质检阶段**按题校准**：只保留「参考修复里有、漏洞代码里没有」的记号。

于是每道题的判定变成：

    漏洞消除 = 该题规则不再命中  且  候选代码里出现该题的任一「新记号码」

按题校准的好处：`request.json` 这种在漏洞代码里本来就有的东西不会被误当成证据，
而「删除危险行」的答案因为缺少新增的安全替代，自然拿不到分。

数据落在 `questions.jsonl` 的 `fix_required` 字段（由 `src/qa.py` 生成），
因此评测阶段不需要再猜，也不依赖规则文件解析。
"""
import re

# 每条规则可供挑选的「安全替代记号」；质检时会自动筛出「修复新增」的那几个。
SAFE_TOKENS = {
    # --- 反序列化 ---
    "python.security.deserialization.pickle": [
        r"json\.loads?\(", r"ast\.literal_eval", r"yaml\.safe_load",
        r"get_json\(", r"jsonschema\.validate", r"RestrictedUnpickler"],
    "python.security.deserialization.yaml-unsafe-load": [
        r"safe_load", r"SafeLoader", r"CSafeLoader"],
    "python.security.deserialization.eval-exec": [
        r"ast\.literal_eval", r"json\.loads?\(", r"shlex\.quote", r"ALLOWED_\w+"],
    "python.security.deserialization.marshal-shelve": [
        r"json\.loads?\(", r"yaml\.safe_load", r"RestrictedUnpickler"],

    # --- 注入 ---
    "python.security.command-injection.subprocess-shell": [
        r"shell\s*=\s*False", r"shlex\.quote", r"shlex\.split", r"ALLOWED_\w+"],
    "python.security.command-injection.os-system": [
        r"subprocess\.(run|call|check_output|Popen)", r"shlex\.quote"],
    "python.security.sql-injection.fstring-query": [
        r"text\(\s*[\"'][^\"']*:\w+", r"bindparam", r"\.params\(",
        r"execute\([^)]*,", r"\.objects\.", r"params\.append"],
    "python.security.sql-injection.concat-query": [
        r"text\(\s*[\"'][^\"']*:\w+", r"bindparam", r"\.params\(",
        r"execute\([^)]*,", r"\.objects\.", r"params\.append"],
    "python.security.sql-injection.raw-sql": [
        r"text\(\s*[\"'][^\"']*:\w+", r"bindparam", r"\.params\(",
        r"execute\([^)]*,", r"\.objects\.", r"params\.append"],
    "python.security.xss.autoescape-off": [
        r"autoescape\s*=\s*True", r"select_autoescape"],
    # mark-safe 属于「移除型」修复（删掉 mark_safe 即可），不设正面要求
    "python.security.path-traversal.open-user-input": [
        r"secure_filename", r"os\.path\.basename", r"realpath", r"commonpath",
        r"ALLOWED_\w+", r"startswith\("],
    "python.security.xxe.unsafe-xml-parse": [
        r"defusedxml", r"resolve_entities\s*=\s*False", r"forbid_dtd"],

    # --- SSRF ---
    "python.security.ssrf.urlopen-user-input": [
        r"urlparse", r"allowed_hosts", r"ALLOWED", r"ipaddress", r"is_private"],
    "python.security.ssrf.requests-user-input": [
        r"urlparse", r"allowed_hosts", r"ALLOWED", r"ipaddress", r"is_private"],

    # --- 密码学 ---
    "python.security.crypto.md5-hash": [
        r"sha256", r"sha512", r"sha3", r"bcrypt", r"argon2", r"pbkdf2", r"scrypt"],
    "python.security.crypto.sha1-hash": [
        r"sha256", r"sha512", r"sha3", r"bcrypt", r"argon2", r"pbkdf2", r"scrypt"],
    "python.security.crypto.weak-cipher": [
        r"AES", r"GCM", r"Fernet", r"ChaCha20"],
    "python.security.crypto.ecb-mode": [
        r"MODE_GCM", r"MODE_CBC", r"MODE_CTR", r"Fernet"],
    "python.security.crypto.insecure-random": [
        r"secrets\.", r"SystemRandom", r"os\.urandom", r"token_hex", r"token_bytes"],
    "python.security.crypto.hardcoded-key": [
        r"os\.environ", r"getenv", r"secrets\.", r"keyring"],

    # --- 配置 / 认证 ---
    "python.security.misconfig.hardcoded-secret": [
        r"os\.environ", r"getenv", r"secrets\.", r"keyring"],
    "python.security.misconfig.flask-debug": [
        r"debug\s*=\s*False", r"DEBUG['\"]?\]?\s*=\s*False"],
    "python.security.misconfig.django-debug": [
        r"DEBUG\s*=\s*False"],
    "python.security.auth.weak-password-hash": [
        r"check_password_hash", r"bcrypt", r"argon2", r"pbkdf2", r"scrypt"],
    "python.security.auth.plaintext-password-compare": [
        r"compare_digest", r"check_password_hash", r"bcrypt", r"hmac\."],
    "python.security.auth.hardcoded-credential": [
        r"os\.environ", r"getenv", r"secrets\.", r"keyring"],
}


def _hit(pattern: str, code: str) -> bool:
    return re.search(pattern, code or "", re.IGNORECASE) is not None


def required_for(rule_id: str, vuln_code: str, fixed_code: str) -> list:
    """该题真正能区分「修复」与「漏洞」的安全替代记号（可能为空）。"""
    pats = SAFE_TOKENS.get(rule_id, [])
    return [p for p in pats if _hit(p, fixed_code) and not _hit(p, vuln_code)]


def satisfies(required: list, code: str) -> bool:
    """候选代码是否满足（任一命中即可）。required 为空表示没有额外要求。"""
    if not required:
        return True
    return any(_hit(p, code) for p in required)


def looks_degenerate(code: str) -> bool:
    """退化答案识别：整份只写 `pass`、`return None` 这类一两行的空壳。

    这类答案无论多短都不该算「修好了」——它连一个函数体都没写出来。
    """
    lines = [ln for ln in (code or "").splitlines() if ln.strip()]
    if not lines:
        return True
    return len(lines) == 1 and len(lines[0].strip()) < 50


def elimination_ok(rule_id: str, findings: set, code: str, required=None) -> bool:
    """semgrep 轨「漏洞已消除」：规则不再命中 且 出现该题要求的安全替代 且 不是空壳答案。"""
    if looks_degenerate(code):
        return False
    if rule_id and rule_id in (findings or set()):
        return False
    return satisfies(list(required or []), code)
