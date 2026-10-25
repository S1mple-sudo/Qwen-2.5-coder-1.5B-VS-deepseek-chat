"""CWE -> OWASP Top 10 2021 与 CWE -> Semgrep 规则的映射表。

说明：OWASP Top 10 官方提供的是「代表性 CWE」列表，此处的映射是工程化的近似归类，
用于评测题的自动标注。对于 SecureCode 源，优先使用其自带 metadata.owasp_2021 字段。
"""

# CWE -> OWASP Top 10 2021 分类
CWE_TO_OWASP = {
    # A01 Broken Access Control
    "CWE-22": "A01:2021 - Broken Access Control",
    "CWE-284": "A01:2021 - Broken Access Control",
    "CWE-285": "A01:2021 - Broken Access Control",
    "CWE-639": "A01:2021 - Broken Access Control",
    "CWE-862": "A01:2021 - Broken Access Control",
    "CWE-863": "A01:2021 - Broken Access Control",
    "CWE-352": "A01:2021 - Broken Access Control",
    "CWE-200": "A01:2021 - Broken Access Control",
    # A02 Cryptographic Failures
    "CWE-326": "A02:2021 - Cryptographic Failures",
    "CWE-327": "A02:2021 - Cryptographic Failures",
    "CWE-328": "A02:2021 - Cryptographic Failures",
    "CWE-329": "A02:2021 - Cryptographic Failures",
    "CWE-330": "A02:2021 - Cryptographic Failures",
    "CWE-331": "A02:2021 - Cryptographic Failures",
    "CWE-312": "A02:2021 - Cryptographic Failures",
    "CWE-311": "A02:2021 - Cryptographic Failures",
    # A03 Injection
    "CWE-74": "A03:2021 - Injection",
    "CWE-77": "A03:2021 - Injection",
    "CWE-78": "A03:2021 - Injection",
    "CWE-79": "A03:2021 - Injection",
    "CWE-88": "A03:2021 - Injection",
    "CWE-89": "A03:2021 - Injection",
    "CWE-91": "A03:2021 - Injection",
    "CWE-94": "A03:2021 - Injection",
    "CWE-95": "A03:2021 - Injection",
    "CWE-611": "A03:2021 - Injection",
    "CWE-643": "A03:2021 - Injection",
    # A05 Security Misconfiguration
    "CWE-489": "A05:2021 - Security Misconfiguration",
    "CWE-16": "A05:2021 - Security Misconfiguration",
    "CWE-942": "A05:2021 - Security Misconfiguration",
    "CWE-1004": "A05:2021 - Security Misconfiguration",
    # A06 Vulnerable and Outdated Components
    "CWE-1104": "A06:2021 - Vulnerable and Outdated Components",
    "CWE-937": "A06:2021 - Vulnerable and Outdated Components",
    "CWE-1035": "A06:2021 - Vulnerable and Outdated Components",
    # A07 Identification and Authentication Failures
    "CWE-287": "A07:2021 - Identification and Authentication Failures",
    "CWE-306": "A07:2021 - Identification and Authentication Failures",
    "CWE-307": "A07:2021 - Identification and Authentication Failures",
    "CWE-798": "A07:2021 - Identification and Authentication Failures",
    "CWE-916": "A07:2021 - Identification and Authentication Failures",
    "CWE-640": "A07:2021 - Identification and Authentication Failures",
    # A08 Software and Data Integrity Failures
    "CWE-502": "A08:2021 - Software and Data Integrity Failures",
    "CWE-345": "A08:2021 - Software and Data Integrity Failures",
    "CWE-494": "A08:2021 - Software and Data Integrity Failures",
    "CWE-565": "A08:2021 - Software and Data Integrity Failures",
    "CWE-829": "A08:2021 - Software and Data Integrity Failures",
    # A09 Security Logging and Monitoring Failures
    "CWE-778": "A09:2021 - Security Logging and Monitoring Failures",
    "CWE-532": "A09:2021 - Security Logging and Monitoring Failures",
    "CWE-117": "A09:2021 - Security Logging and Monitoring Failures",
    # A10 SSRF
    "CWE-918": "A10:2021 - Server-Side Request Forgery (SSRF)",
}

# CWE -> 主用 Semgrep 规则 id（用于题目标注与 golden 校验）
CWE_TO_RULE = {
    "CWE-89": "python.security.sql-injection.fstring-query",
    "CWE-78": "python.security.command-injection.subprocess-shell",
    "CWE-79": "python.security.xss.mark-safe",
    "CWE-22": "python.security.path-traversal.open-user-input",
    "CWE-611": "python.security.xxe.unsafe-xml-parse",
    "CWE-328": "python.security.crypto.md5-hash",
    "CWE-327": "python.security.crypto.weak-cipher",
    "CWE-330": "python.security.crypto.insecure-random",
    "CWE-502": "python.security.deserialization.pickle",
    "CWE-95": "python.security.deserialization.eval-exec",
    "CWE-918": "python.security.ssrf.urlopen-user-input",
    "CWE-798": "python.security.misconfig.hardcoded-secret",
    "CWE-489": "python.security.misconfig.flask-debug",
    "CWE-916": "python.security.auth.weak-password-hash",
    "CWE-287": "python.security.auth.plaintext-password-compare",
}

# 某类 CWE 可命中的候选规则（用于 QA 阶段自动匹配实际命中的规则）
CWE_TO_RULE_CANDIDATES = {
    "CWE-89": [
        "python.security.sql-injection.fstring-query",
        "python.security.sql-injection.concat-query",
        "python.security.sql-injection.raw-sql",
    ],
    "CWE-78": [
        "python.security.command-injection.os-system",
        "python.security.command-injection.subprocess-shell",
    ],
    "CWE-79": ["python.security.xss.mark-safe", "python.security.xss.autoescape-off"],
    "CWE-328": ["python.security.crypto.md5-hash", "python.security.crypto.sha1-hash"],
    "CWE-327": ["python.security.crypto.weak-cipher", "python.security.crypto.ecb-mode"],
    "CWE-502": ["python.security.deserialization.pickle", "python.security.deserialization.yaml-unsafe-load"],
    "CWE-95": ["python.security.deserialization.eval-exec"],
    "CWE-798": ["python.security.misconfig.hardcoded-secret", "python.security.auth.hardcoded-credential"],
}


def cwe_to_owasp(cwe: str) -> str:
    """返回 CWE 对应的 OWASP 分类，未知时归入 A03 兜底。"""
    return CWE_TO_OWASP.get(cwe, "A03:2021 - Injection")


def cwe_to_rule(cwe: str) -> str:
    return CWE_TO_RULE.get(cwe, "")


def cwe_to_rule_candidates(cwe: str) -> list:
    return CWE_TO_RULE_CANDIDATES.get(cwe, [cwe_to_rule(cwe)] if cwe_to_rule(cwe) else [])
