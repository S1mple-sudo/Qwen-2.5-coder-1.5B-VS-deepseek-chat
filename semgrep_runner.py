"""Semgrep 运行封装：把一段代码落盘后扫描，返回命中的规则 id 列表。

供 QA 脚本与 pytest 评测模板共用。
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

SEMGREP_BIN = "semgrep"


def normalize_check_id(check_id: str) -> str:
    """把 semgrep 报出的 check_id 规范化为规则文件里定义的 id。

    semgrep 用目录 --config 时会给规则 id 加上前缀（如 `semgrep.rules.`），
    这里剥离前缀，只保留以 `python.security.` 开头的规则 id。
    """
    if not check_id:
        return check_id
    marker = "python.security."
    idx = check_id.find(marker)
    if idx != -1:
        return check_id[idx:]
    return check_id

# 兜底候选：写在 .local_semgrep_paths（每行一个路径，已被 .gitignore 忽略），
# 供 semgrep 装在非常规目录时使用；正常情况用 SEMGREP_BIN 或 PATH 就够了。
_LOCAL_PATHS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".local_semgrep_paths"
)


def _local_candidates():
    try:
        with open(_LOCAL_PATHS_FILE, encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    except OSError:
        return []


def _interpreter_candidates():
    """与「当前 Python 解释器」同目录的 semgrep（venv\\Scripts、pip --user 的 Scripts）。

    换机器、换 venv 时不用改代码也不用配 PATH：谁装的 semgrep，谁来找到它。
    """
    import site

    names = ("semgrep.exe", "semgrep") if os.name == "nt" else ("semgrep",)
    roots = [os.path.dirname(sys.executable)]
    user_base = getattr(site, "USER_BASE", "") or ""
    if user_base:
        roots += [os.path.join(user_base, "Scripts"), os.path.join(user_base, "bin")]
    return [os.path.join(r, n) for r in roots for n in names]


def find_semgrep() -> str:
    """定位 semgrep 可执行文件，找不到则返回 None。

    优先级：环境变量 SEMGREP_BIN > 系统 PATH > 解释器同目录（venv / --user）> .local_semgrep_paths。
    """
    # 1. 显式环境变量
    env_bin = os.environ.get("SEMGREP_BIN")
    if env_bin and os.path.isfile(env_bin):
        return env_bin

    # 2. 系统 PATH
    found = shutil.which(SEMGREP_BIN)
    if found:
        return found

    # 3. 当前解释器旁的 semgrep（venv / --user 安装，换机器时最常用）
    for c in _interpreter_candidates():
        if os.path.isfile(c):
            return c

    # 4. 本地兜底候选路径（.local_semgrep_paths，不入库）
    for c in _local_candidates():
        if os.path.isfile(c):
            return c

    return None


def run_semgrep(code: str, config_dir: str, language: str = "python") -> list:
    """扫描一段代码，返回命中的规则 id（check_id）列表（已排序去重）。

    参数:
        code: 待扫描的源代码字符串
        config_dir: 规则目录（含 .yaml 规则文件）
        language: 目标语言，决定临时文件的扩展名

    返回:
        命中的规则 id 列表，例如 ["python.security.sql-injection.fstring-query"]
    """
    semgrep_bin = find_semgrep()
    if semgrep_bin is None:
        raise RuntimeError(
            "未找到 semgrep。请先安装：pip install semgrep  "
            "（或参考 https://semgrep.dev/docs/getting-started/）"
        )

    ext = ".py" if language == "python" else ".txt"
    with tempfile.TemporaryDirectory() as td:
        fname = "target" + ext
        target = os.path.join(td, fname)
        with open(target, "w", encoding="utf-8") as f:
            f.write(code)

        cmd = [semgrep_bin, "scan", "--config", config_dir, "--json", "--no-git-ignore", target]
        try:
            proc = subprocess.run(
                cmd,
                cwd=td,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=180,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("semgrep 扫描超时（>180s）")

        # semgrep 返回码：0 无发现，1 有发现，2 运行错误
        if proc.returncode == 2:
            raise RuntimeError(f"semgrep 运行失败: {proc.stderr[:2000]}")

        try:
            data = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return []

        rule_ids = set()
        for r in data.get("results", []):
            cid = r.get("check_id")
            if cid:
                rule_ids.add(normalize_check_id(cid))
        return sorted(rule_ids)
