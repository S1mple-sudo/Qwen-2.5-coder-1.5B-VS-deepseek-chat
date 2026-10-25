"""功能评测：逻辑类漏洞的「安全控制检查」注册表。

背景
----
Semgrep 等静态规则擅长判定「注入 / 反序列化 / 弱加密」这类有明确危险 API 的漏洞，
但对「认证 / 越权 / CSRF / 开放重定向 / 日志 / 会话 / 竞态」等**逻辑类**漏洞几乎无能为力
（它们没有单一的"坏函数"，而是缺少某个安全控制）。

本模块为这些逻辑类 CWE 定义「安全控制检查」（secure-control check）：

    check_code(cwe, code) -> bool

    code 是修复后的代码（或模型输出的代码）。
    - 返回 True  => 代码包含了该 CWE 应有的安全控制，视为"已修复"
    - 返回 False => 仍缺少安全控制，视为"漏洞仍在"

每个 check 是若干组 (must, must_not)，**任一组成立即视为已修复**（OR 关系）：
    must     —— 至少命中其一（OR），表示"必须出现的安全控制"
    must_not —— 必须全部不命中（AND），表示"不允许出现的危险模式"

黄金校验（见 functional_qa.py / test_golden.py）：
    check_code(cwe, vulnerable_code) 必须为 False（漏洞能被识别）
    check_code(cwe, fixed_code)      必须为 True （修复能被认可）
只有通过黄金校验的题目才被赋予 eval_method="functional" 并挂 functional_test。
"""
import re

# ---------------------------------------------------------------------------
# 模式工具
# ---------------------------------------------------------------------------

def _any(code: str, pats: list) -> bool:
    """code 是否命中 patterns 中的任意一个（忽略大小写）。"""
    return any(re.search(p, code, re.IGNORECASE) for p in pats)


def _none(code: str, pats: list) -> bool:
    """code 是否未命中 patterns 中的任意一个。"""
    return not _any(code, pats)


# ---------------------------------------------------------------------------
# 通用信号：SecureCode 中部分逻辑类题的「漏洞」是攻击演示脚本，
# 「修复」是一段 pytest 安全测试。用这一组信号识别。
# ---------------------------------------------------------------------------

ATK_PATTERNS = [
    r"attacker", r"credential stuffing", r"stolen_", r"forged_", r"exploit",
    r"shellcode", r"rapid_request", r"malicious_payload", r"for password in",
    r"steal.*session", r"capture.*cookie",
]

TEST_PATTERNS = [
    r"TestSecurityControls", r"TestClient", r"test_malicious", r"import pytest",
    r"@pytest", r"pytest\.fixture",
]

# 追加到每个 CWE 的通用「攻击演示 -> 安全测试」组
DEMO_CHECK = ("attack-demo-neutralized", TEST_PATTERNS, ATK_PATTERNS)


# ---------------------------------------------------------------------------
# 各逻辑类 CWE 的 check 定义
# 每条：(name, must, must_not)
#   must     —— 至少出现一个（空列表表示不要求）
#   must_not —— 全部不得出现
# ---------------------------------------------------------------------------

CHECKS = {
    # ---- 认证失败：安全密码验证 / JWT 算法指定 / 环境变量密钥 ----
    "CWE-287": [(
        "strong-authentication",
        [r"check_password_hash|generate_password_hash", r"password_verify", r"bcrypt", r"argon2", r"pbkdf2",
         r"django\.contrib\.auth|is_authenticated|authenticate\(",
         r"jwt\.decode|algorithms\s*=\s*\[", r"os\.environ|secrets\.|getenv\(",
         r"pyotp|totp|TOTP|two_factor|two-factor|2fa|otp\."],
        [r"password\s*==\s*['\"]|username\s*==\s*['\"]",
         r"SECRET_KEY\s*=\s*['\"]", r"hashlib\.md5|\.md5\("],
    )],

    # ---- 越权（IDOR）：必须做对象归属 / 权限校验 ----
    "CWE-639": [(
        "object-authorization",
        [r"current_user|require_auth|is_authenticated",
         r"\.owner|has_perm|permission_required|abort\((401|403)\)|request\.user|g\.\w*user"],
        [],
    )],

    # ---- CSRF：必须引入 CSRF 防护，且不得豁免 ----
    "CWE-352": [(
        "csrf-protection",
        [r"csrf|CSRFProtect|csrf_token|CsrfViewMiddleware|csrf_protect|SessionAuthentication"],
        [r"csrf_exempt|@csrf_exempt|csrf\.exempt|enforce_csrf.*\breturn\b"],
    )],

    # ---- 缺失认证：必须出现认证控制 ----
    "CWE-306": [("require-authentication",
                 [r"require_auth|is_authenticated|jwt\.decode|abort\(401\)|current_user|login_required"],
                 [])],

    # ---- 缺失授权 / 授权不当：必须有"角色/权限"检查（仅登录不算）----
    "CWE-862": [(
        "role-authorization",
        [r"admin_required|is_admin|has_perm|permission_required|authorize|require_admin|abort\(403\)|role\s*(==|in|\.get)"],
        [],
    )],
    "CWE-863": [(
        "enforce-authorization",
        [r"admin_required|is_admin|has_perm|permission_required|require_admin|abort\(403\)"],
        [],
    )],
    "CWE-425": [("forced-browsing-guard",
                 [r"login_required|require_auth|is_authenticated|has_perm|abort\(40[13]\)|current_user|permission_required"],
                 [])],

    # ---- 依赖用户输入做安全决定：不得信任请求里的角色/权限 ----
    "CWE-807": [(
        "server-side-authority",
        [r"session\[|current_user|has_perm|is_authenticated|require_auth|abort\(40[13]\)"],
        [r"request\.(args|form|json|values|get_json).*role|role.*request\.(args|form|json|values)"],
    )],

    # ---- 暴力破解：限速 / 锁定 ----
    "CWE-307": [("rate-limiting",
                 [r"limiter|Limiter|rate_limit|throttle|lockout|attempt|sleep\(|delay|captcha|retry"],
                 [])],

    # ---- TOCTOU / 竞态 / 资源耗尽：原子操作 / 加锁 / 限流 ----
    "CWE-367": [("atomic-operation",
                 [r"O_EXCL|flock|Lock\(|mutex|atomic|with\s+\w*lock|lockfile|os\.open"],
                 [])],
    "CWE-362": [("concurrency-control",
                 [r"Lock\(|mutex|atomic|transaction|with\s+\w*lock|flock|O_EXCL|contextmanager"],
                 [])],
    "CWE-770": [("resource-limiting",
                 [r"timeout|maxsize|max_size|Semaphore|throttle|rate_limit|limit"],
                 [])],

    # ---- 错误信息泄露：不得回显异常堆栈 ----
    "CWE-209": [(
        "generic-errors",
        [r"logging|logger|log\.(info|error|warning|debug|critical)|except"],
        [r"return\s+(str|repr)\(e\)|return\s+(str|repr)\(exc\)|traceback\.|stacktrace|print\((exception|error|e)\)"],
    )],
    "CWE-215": [("no-sensitive-disclosure",
                 [r"logging|logger|except"],
                 [r"return\s+(str|repr)\(e\)|traceback\.|stacktrace"])],

    # ---- 日志注入：日志内容须净化 ----
    "CWE-943": [("log-injection-guard",
                 [r"sanitize|strip\(|escape|logging|logger|replace\("],
                 [r"log\.\w+\([^)]*%s[^)]*input|logging\.\w+\(f['\"].*input"])],

    # ---- 日志缺失：必须有持久化 / 审计日志（仅 basicConfig 不算）----
    # must_not 只拦「敷衍留存」（backupCount 只留 1~2 个）；maxBytes 是正常轮转参数，不再视为缺陷
    "CWE-778": [(
        "security-audit-logging",
        [r"FileHandler|TimedRotatingFileHandler|SysLogHandler|SMTPHandler|HTTPHandler|QueueHandler|SecurityEvent|log_event",
         r"audit_logger|logging\.getLogger\(['\"]security|logging\.getLogger\(['\"]audit|retention|compliance"],
        [r"backupCount\s*=\s*[12]\b"],
    )],
    "CWE-532": [("no-sensitive-logging",
                 [r"logging|logger"],
                 [r"log\.\w+\([^)]*(password|token|secret|ssn|credit)"]),
    ],

    # ---- 开放重定向：URL 白名单校验 ----
    # must_not 只拦「把请求参数直接塞进 redirect」；先校验再 redirect(next_url) 是正确写法，不能误杀
    "CWE-601": [(
        "redirect-whitelist",
        [r"urlparse|urljoin|is_safe_url|netloc|allowed_hosts|validate|safe_url|url_for",
         r"url_has_allowed_host_and_scheme|DESTINATIONS|LOGOUT_TARGETS|reverse_lazy"],
        [r"redirect\(\s*request\.(args|form|values|POST|GET)\b"],
    )],

    # ---- 任意文件上传：类型/大小/内容校验 ----
    "CWE-434": [(
        "upload-validation",
        [r"ALLOWED|content_type|mimetype|secure_filename|max_content|content_length|magic|extension.*(in|\s*==)|Image\.open"],
        [r"f\.save\(|\.save\("],
    )],

    # ---- 下载/依赖代码执行与依赖混淆：完整性校验 / 版本固定 ----
    "CWE-494": [("dependency-pinning",
                 [r"==|--hash|sha256|checksum|pin"],
                 [])],
    "CWE-829": [("integrity-verification",
                 [r"hash|checksum|sha|signature|verify|https|digest"],
                 [])],
    "CWE-1395": [("pinned-dependencies",
                  [r"==|--hash|sha256|checksum|index-url|trusted"],
                  [])],

    # ---- JWT 签名验证 ----
    "CWE-347": [(
        "jwt-signature-verification",
        [r"jwt\.decode|verify_signature|parse_id_token|signature|nonce|algorithms\s*=\s*\["],
        [r"verify_signature['\"]?\s*:\s*False|options\s*=\s*\{[^}]*verify_signature[^}]*False"],
    )],

    # ---- 密码重置 / 弱密码策略 ----
    "CWE-640": [("password-reset-token",
                 [r"urljoin|PUBLIC_ORIGIN|token|verify|expire|secrets\.|random|nonce"],
                 [r"ALLOWED_HOSTS\s*=\s*\[['\"]\*['\"]\]"])],
    "CWE-521": [("strong-password-policy",
                 [r"min_length|max_length|complexity|upper|lower|digit|special|validate|length"],
                 [])],

    # ---- 会话固定 / 超时 / 敏感 cookie ----
    "CWE-384": [("session-regeneration",
                 [r"session\.clear|logout|regenerate|del\s+session|new.*session|session\.pop"],
                 [])],
    "CWE-613": [("session-timeout",
                 [r"PERMANENT_SESSION_LIFETIME|timeout|expire|max_age|lifetime|expires"],
                 [])],
    "CWE-614": [("secure-cookie-attributes",
                 [r"Secure\s*=\s*True|HttpOnly|SameSite|SESSION_COOKIE_SECURE\s*=\s*True|SECURE_SSL_REDIRECT"],
                 [r"SESSION_COOKIE_SECURE\s*=\s*False|CSRF_COOKIE_SECURE\s*=\s*False"])],

    # ---- 传输 / 证书 / 敏感数据 ----
    "CWE-295": [("certificate-verification",
                 [r"verify\s*=\s*True|ssl|SSLContext|check_hostname|certifi|ca_bundle|create_default_context"],
                 [r"verify\s*=\s*False|InsecureRequestWarning|disable_warnings"])],
    "CWE-319": [("encrypt-in-transit",
                 [r"https|ssl|tls|encrypt|Secure"],
                 [])],
    "CWE-522": [("no-plaintext-credentials",
                 [r"https|ssl|hash|bcrypt|encrypt|Fernet|check_password_hash"],
                 [r"password\s*=\s*['\"]|passwd\s*=\s*['\"]"])],
    "CWE-311": [("encrypt-sensitive-data",
                 [r"encrypt|Fernet|AES|crypto|hash|https|ssl"],
                 [])],
    "CWE-212": [("protect-sensitive-data",
                 [r"encrypt|hash|Fernet|AES|mask|redact|https"],
                 [])],

    # ---- 批量赋值 / 原型污染：字段白名单（Schema/EXCLUDE）----
    "CWE-915": [(
        "mass-assignment-guard",
        [r"marshmallow|Schema|EXCLUDE|allowlist|whitelist|serializers|ModelSerializer|Serializer|read_only"],
        [r"\*\*request|request\.json.*\*\*"],
    )],

    # ---- XSS 变体（点击劫持帧策略）----
    "CWE-1021": [("frame-protection",
                  [r"X-Frame-Options|Content-Security-Policy|XFrameOptionsMiddleware|frame-ancestors|DENY"],
                  [r"<script|top\.location|XFrameOptionsMiddleware.*not in"]),
    ],

    # ---- CORS 误配置：允许列表 vs 通配 ----
    "CWE-942": [(
        "cors-allowlist",
        [r"ALLOWED_ORIGINS|allowlist|is_origin_allowed|origin.*allowed|allowed_origins"],
        [r"origins\s*=\s*['\"]\*['\"]|Access-Control-Allow-Origin['\"]?\s*:\s*origin|Access-Control-Allow-Origin.*=.*request"],
    )],

    # ---- 工作流状态机 / 行为缺陷 ----
    "CWE-841": [("workflow-state-machine",
                 [r"WORKFLOW_STATES|OrderState|state_machine|Enum|hmac|transition|valid.*state"],
                 [])],
    "CWE-696": [("correct-behavior",
                 [r"validate|check|sanitize|isinstance|abort\(4|hmac|Enum"],
                 [])],
    "CWE-1357": [("logic-correctness",
                  [r"validate|check|sanitize|isinstance|abort\(4"],
                  [])],

    # ---- 输入验证 / 类型混淆 ----
    "CWE-20": [("input-validation",
                [r"isinstance|validate|sanitize|strip|escape|schema|pydantic|check|pattern"],
                [])],
    "CWE-704": [("type-checking",
                 [r"isinstance|type\(|pydantic|validate|schema|coerce.*no|strict"],
                 [r"coerce|\"true\"|\"false\""])],

    # ---- LDAP / SSI 注入 ----
    "CWE-90": [("ldap-escaping",
                [r"escape|filter|sanitize|ldap3|escape_filter_chars"],
                [])],
    "CWE-97": [("ssi-guard",
                [r"escape|disable|sanitize|filter|html\.escape"],
                [])],

    # ---- 通用逻辑类兜底 ----
    "CWE-650": [("trust-boundary", [r"validate|check|sanitize|isinstance|abort\(4"], [])],
    "CWE-1220": [("fine-grained-authz", [r"has_perm|permission_required|role|current_user|abort\(40[13]\)|admin_required"], [])],
    "CWE-548": [("no-directory-disclosure", [r"logging|logger|except"], [r"listdir|traceback"])],
}


def check_code(cwe: str, code: str) -> bool:
    """判断给定代码是否满足 CWE 应有的安全控制（True=已修复，False=漏洞仍在）。"""
    checks = CHECKS.get(cwe) or []
    # 每个 CWE 追加一个通用「攻击演示 -> 安全测试」组，识别攻击脚本型题目
    for _name, must, must_not in checks + [DEMO_CHECK]:
        must_ok = (not must) or _any(code, must)
        must_not_ok = _none(code, must_not)
        if must_ok and must_not_ok:
            return True
    return False


# ---------------------------------------------------------------------------
# 可静态判定（Semgrep）的 CWE 集合 —— 其余全部走 functional
# ---------------------------------------------------------------------------

SEMGREP_CWES = {
    "CWE-89",   # SQL 注入
    "CWE-78",   # 命令注入
    "CWE-79",   # XSS
    "CWE-22",   # 路径穿越
    "CWE-611",  # XXE
    "CWE-328",  # MD5
    "CWE-327",  # 弱加密
    "CWE-330",  # 弱随机数
    "CWE-502",  # pickle 反序列化
    "CWE-95",   # eval
    "CWE-94",   # 代码注入
    "CWE-918",  # SSRF
    "CWE-798",  # 硬编码密钥
    "CWE-321",  # 硬编码密码
    "CWE-489",  # Flask debug
    "CWE-916",  # 弱密码哈希
}


def eval_method_for(cwe: str) -> str:
    """返回题目的评测方式：semgrep / functional。"""
    return "semgrep" if cwe in SEMGREP_CWES else "functional"
