"""功能质检：对逻辑类（functional）题目做黄金校验。

黄金校验标准（与 Semgrep 质检完全对称）：
    - check_code(cwe, vulnerable_code) 必须为 False  —— 漏洞能被识别
    - check_code(cwe, fixed_code)      必须为 True   —— 修复能被认可

通过黄金校验的题目：
    - 赋予 functional_test（一段可 exec 的安全断言代码）
    - verified = True

未通过的题目：
    - 改标 eval_method = "manual"（保留题目，供人工评审，不丢弃）

产出：
    - 原地更新 questions.jsonl（写入 functional_test / verified / eval_method）
    - data/processed/functional_qa_report.json（统计）

用法：
    python src/functional_qa.py --in questions.jsonl --out questions.jsonl
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.functional_checks import check_code, eval_method_for  # noqa: E402

FUNC_TEMPLATE = (
    'from src.functional_checks import check_code\n'
    'assert check_code({cwe!r}, candidate_code), {msg!r}\n'
)


def _cwe_desc(cwe: str) -> str:
    desc = {
        "CWE-287": "认证失败：缺少安全凭据校验/JWT 算法校验",
        "CWE-639": "越权(IDOR)：缺少对象归属/权限校验",
        "CWE-352": "CSRF：缺少跨站请求伪造防护",
        "CWE-601": "开放重定向：缺少重定向 URL 白名单校验",
        "CWE-306": "缺失认证：敏感端点缺少身份认证",
        "CWE-862": "缺失授权：缺少权限校验",
        "CWE-863": "授权不当：权限校验不完整",
        "CWE-425": "强制浏览：缺少访问控制",
        "CWE-807": "信任用户输入的安全决策：权限应由服务端裁决",
        "CWE-307": "暴力破解：缺少速率限制/账户锁定",
        "CWE-367": "TOCTOU：缺少原子操作",
        "CWE-362": "竞态条件：缺少并发控制",
        "CWE-770": "资源耗尽：缺少资源限制",
        "CWE-209": "错误信息泄露：回显了敏感异常信息",
        "CWE-215": "信息泄露：泄露了敏感信息",
        "CWE-943": "日志注入：日志内容未净化",
        "CWE-778": "日志缺失：缺少安全事件审计日志",
        "CWE-532": "敏感信息入日志：日志泄露敏感数据",
        "CWE-434": "任意文件上传：缺少文件类型/大小校验",
        "CWE-494": "下载代码执行：依赖未固定版本/哈希",
        "CWE-829": "下载代码执行：缺少完整性校验",
        "CWE-1395": "依赖混淆：依赖未固定",
        "CWE-347": "JWT 签名验证缺失",
        "CWE-640": "密码重置缺陷：缺少 token 校验",
        "CWE-521": "弱密码策略：缺少密码强度校验",
        "CWE-384": "会话固定：未重建会话",
        "CWE-613": "会话超时缺失",
        "CWE-614": "敏感 Cookie 属性缺失：未设置 Secure/HttpOnly/SameSite",
        "CWE-295": "证书校验缺陷：未验证 SSL 证书",
        "CWE-319": "明文传输：未加密敏感数据",
        "CWE-522": "明文凭据：凭据未加密存储",
        "CWE-311": "敏感数据未加密",
        "CWE-212": "敏感数据未保护",
        "CWE-20": "输入验证缺失",
        "CWE-704": "类型混淆：缺少类型校验",
        "CWE-841": "不恰当行为：缺少校验",
        "CWE-696": "行为缺陷：缺少校验",
        "CWE-1357": "逻辑错误：缺少校验",
        "CWE-915": "原型污染/批量赋值：缺少字段白名单",
        "CWE-1021": "XSS 输出编码缺失",
        "CWE-90": "LDAP 注入：未转义",
        "CWE-97": "SSI 注入：未转义",
        "CWE-650": "信任边界缺失",
        "CWE-1220": "授权粒度不足",
        "CWE-548": "目录泄露",
    }
    return desc.get(cwe, cwe)


def run_functional_qa(in_path, out_path, report_path):
    with open(in_path, "r", encoding="utf-8") as f:
        questions = [json.loads(l) for l in f if l.strip()]

    stats = {"total": len(questions), "semgrep": 0, "functional_verified": 0,
             "manual": 0, "by_cwe": {}}

    for q in questions:
        cwe = q.get("cwe", "")
        if q.get("eval_method") != "functional":
            stats["semgrep"] += 1
            continue

        vuln_flagged = check_code(cwe, q["vulnerable_code"])   # 应 False
        fixed_ok = check_code(cwe, q["fixed_code"])            # 应 True

        cstats = stats["by_cwe"].setdefault(cwe, {"total": 0, "verified": 0, "manual": 0})
        cstats["total"] += 1

        if (not vuln_flagged) and fixed_ok:
            q["functional_test"] = FUNC_TEMPLATE.format(cwe=cwe, msg=_cwe_desc(cwe))
            q["verified"] = True
            stats["functional_verified"] += 1
            cstats["verified"] += 1
        else:
            # 黄金校验不通过 -> 保留题目，转人工评审
            q["eval_method"] = "manual"
            q["functional_test"] = None
            q["verified"] = False
            stats["manual"] += 1
            cstats["manual"] += 1

    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for q in questions:
            f.write(json.dumps(q, ensure_ascii=False) + "\n")

    rep_dir = os.path.dirname(report_path)
    if rep_dir:
        os.makedirs(rep_dir, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    return stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True)
    ap.add_argument("--out", default="questions.jsonl")
    ap.add_argument("--report", default="data/processed/functional_qa_report.json")
    args = ap.parse_args()

    stats = run_functional_qa(args.in_path, args.out, args.report)
    print(f"[done] functional 验证 {stats['functional_verified']} 题，转人工 {stats['manual']} 题，semgrep {stats['semgrep']} 题")
    print(json.dumps(stats, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
