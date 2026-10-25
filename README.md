# Python 安全代码评测系统

从公开漏洞数据集反向构造 Python 安全修复评测题，并配套 Semgrep 规则与 pytest 评测模板。

## 一、数据来源

| 来源 | 说明 | 许可证 | Python 样本 |
|------|------|--------|-------------|
| **SecureCode** | `scthornton/securecode`（HuggingFace），OWASP Top 10 2021，11 语言 9 框架，多轮对话格式 | CC-BY-NC-SA-4.0（非商用） | 341 条 |
| **CVEfixes** | `secureIT-project/CVEfixes`，基于 NVD 的真实 CVE 修复提交 | 宽松（NVD + 公开仓库） | 按需抽取 |

> SecureCode 代码嵌在对话的 `**Vulnerable Code**` / `**Secure Version**` 标注代码块里，
> 需要解析抽取；CVEfixes 的 `file_change` 表直接带 `code_before` / `code_after`，是干净的修复对。

## 二、题目规模与覆盖（当前）

- **题目总数：326 条**（全部来自 SecureCode 的 Python 子集）
- **OWASP 覆盖**：A01–A10 全部十类

| OWASP | 数量 | OWASP | 数量 |
|-------|------|-------|------|
| A01 Broken Access Control | 65 | A06 Vulnerable Components | 16 |
| A02 Cryptographic Failures | 22 | A07 Auth Failures | 40 |
| A03 Injection | 45 | A08 Data Integrity | 31 |
| A04 Insecure Design | 38 | A09 Logging | 22 |
| A05 Security Misconfiguration | 35 | A10 SSRF | 12 |

- **难度**：easy 62 / medium 203 / hard 61
- **严重度**：CRITICAL 218 / HIGH 102 / MEDIUM 6

### 三轨评测分布

逻辑类漏洞（认证/越权/CSRF/开放重定向/日志/会话等）没有单一的"坏函数"，Semgrep 静态规则难以判定，
因此按 `eval_method` 分三轨评测：

| eval_method | 数量 | 判定方式 | 说明 |
|-------------|------|----------|------|
| `semgrep` | 56 | 静态规则命中/消除 | 注入、反序列化、弱加密、SSRF 等有明确危险 API 的漏洞 |
| `functional` | 116 | 功能断言（`functional_test`） | 逻辑类漏洞，检查修复代码是否引入正确的安全控制 |
| `manual` | 154 | 人工评审 | 逻辑类里无法可靠自动判定者，保留题目供人工复核 |

> 自动可评测率 172/326 ≈ 52.8%；`manual` 题不丢弃，仅标记需人工评审。
> 三轨由 `construct.py` 初分、`functional_qa.py` 与 `qa.py` 两道质检闸门校正：
> qa.py 只允许「题目自带规则」或「该 CWE 的候选规则」判为 `verified`，其余一律降级 `manual`
> （早期版本曾用「随便挑一个命中的规则」兜底，导致 CWE 与规则错配，已修复）。
> 接入 CVEfixes 后（见第五节）可扩充至 500 条上限，并显著提升真实 CVE 占比。

## 三、目录结构

```
评测系统/
├── data/
│   ├── raw/                 # 原始 parquet（不入库，按第五节下载）
│   └── processed/           # 中间产物与质检报告（不入库，可重建）
├── src/
│   ├── parse_securecode.py  # 解析 SecureCode -> 修复对
│   ├── parse_cvefixes.py    # 解析 CVEfixes(SQLite) -> 修复对
│   ├── mapping.py           # CWE -> OWASP / Semgrep 规则 映射
│   ├── construct.py         # 归一化 + 去重 + 反向构造题目（标注 eval_method）
│   ├── functional_checks.py # 逻辑类漏洞的「安全控制检查」注册表
│   ├── functional_qa.py     # 功能质检（functional 轨，不依赖 semgrep）
│   ├── qa.py                # 质检（semgrep 轨）
│   ├── preservation.py      # 「功能未破坏」判定（结构保真度弱代理）
│   ├── report.py            # 评测汇总报告（安全 / 功能 / 联合 / 自检）
│   ├── remediation.py       # semgrep 轨「安全替代」约束（防删行刷分）
│   ├── cheat_check.py       # 评分器自检（删行 / pass 作弊答案）
│   ├── export_outcomes.py   # 逐题判定导出（画图 / 复盘）
│   ├── run_baseline.py      # 接大模型跑 baseline（零依赖，产出 report 可读的 JSONL）
│   ├── build_viewer.py      # 生成 questions_viewer.html 题目浏览器
│   ├── plot_compare.py      # 模型横评图（逐题胜负矩阵 + 分轨汇总）
│   └── semgrep_runner.py    # Semgrep 运行封装 + 可执行文件定位
├── semgrep/rules/           # 按 OWASP 分类的 Semgrep 规则（8 个文件）
├── docs/baseline_compare.png  # 基线对比图（README 引用）
├── tests/
│   ├── conftest.py          # 夹具与工具函数
│   ├── test_golden.py       # 黄金校验（质检闸门）
│   ├── test_scorer_robustness.py  # 评分器自检：作弊答案必须拿 0 分
│   └── test_evaluate.py     # 模型修复评测模板
├── .github/workflows/ci.yml # CI：快速测试 + 参考修复自检（断言两指标 = 1.0）
├── questions.jsonl          # 最终题目集（326 题，入库）
├── questions_viewer.html    # 题目浏览器（可直接开，或挂 GitHub Pages）
├── requirements.txt
├── LICENSE                  # 代码：MIT
├── DATA_LICENSE.md          # 题目数据：CC-BY-NC-SA-4.0
└── README.md
```

> 不入库的内容：`data/raw/`（8.6 MB 原始数据集）、`data/processed/`（可重建）、`.workbuddy/`（内部记录）、
> `dist/`（便携包构建产物）、`*.backup-*.jsonl`。规则见 `.gitignore`。

## 四、题目 Schema（questions.jsonl，每行一条 JSON）

```json
{
  "id": "Q0001",
  "source": "securecode",
  "source_id": "scw-000428",
  "cwe": "CWE-287",
  "owasp": "A07:2021 - Identification and Authentication Failures",
  "category": "auth_failures",
  "severity": "HIGH",
  "difficulty": "medium",
  "language": "python",
  "framework": "flask",
  "title": "CWE-287：auth_failures",
  "description": "【A07:2021 - ...】漏洞类型 CWE-287。影响：...",
  "vulnerable_code": "...",
  "fixed_code": "...",
  "eval_method": "semgrep | functional | manual",
  "semgrep_rule_id": "python.security.auth.hardcoded-credential",
  "functional_test": "from src.functional_checks import check_code\nassert check_code('CWE-287', candidate_code), '...'",
  "verified": true
}
```

- `vulnerable_code`：题干（待修复的漏洞代码）
- `fixed_code`：ground-truth 答案（参考修复）
- `eval_method`：评测方式（`semgrep` 静态规则 / `functional` 功能断言 / `manual` 人工评审）
- `semgrep_rule_id`：semgrep 轨用的规则 id（经质检校正）
- `functional_test`：functional 轨的功能断言代码，运行时注入 `candidate_code` 变量，
  `assert check_code(cwe, candidate_code)` 通过即视为已修复
- `verified`：`true` 表示该题已通过对应轨的黄金校验（漏洞可识别 + 修复可认可）

## 五、复现步骤

### 0. 快速验证（3 分钟，不下载原始数据集）

仓库已含 `questions.jsonl`，拿到就能复现指标：

```bash
git clone <your-repo-url> && cd <repo>
pip install -r requirements.txt          # 含 semgrep、pytest

python src/report.py                     # 参考修复自检：应为 172/172 = 100%，SFR 128/128 = 100%
python -m pytest tests/ -m "not semgrep" -q   # 802 passed
```

想接自己的模型跑分，见第七节「模型修复评测」与 `src/run_baseline.py`。

> 下面第 1~2 步是**从零重建题目集**，只有改动数据源时才需要；8.6 MB 原始 parquet 未入库。

### 1. 下载 SecureCode（约 8.6 MB）

```bash
curl -L -o data/raw/securecode_web_train.parquet \
  "https://huggingface.co/datasets/scthornton/securecode/resolve/main/data/web/train.parquet"
```

### 2. 解析 -> 构造 -> 质检（一键）

```bash
python src/parse_securecode.py                              # 抽 Python 修复对
python src/construct.py --pairs data/processed/securecode_pairs.jsonl --out questions.jsonl
python src/functional_qa.py --in questions.jsonl --out questions.jsonl  # functional 轨（无需 semgrep）
python src/qa.py --in questions.jsonl --out questions.jsonl              # semgrep 轨（需 semgrep）
```

> 两条质检脚本都**原地更新** questions.jsonl、不丢弃任何题目：
> 通过黄金校验的置 `verified=true`；不通过的置 `eval_method=manual` 保留。

### 3. （可选）接入 CVEfixes

CVEfixes 完整数据约 **12.7 GB**（`CVEfixes_v1.0.8.zip`，Zenodo DOI 10.5281/zenodo.4476563），
请在本机下载后执行：

```bash
# 解压得到 SQL dump 后转成 SQLite
gzcat CVEfixes.sql.gz | sqlite3 data/raw/CVEfixes.db      # macOS/Linux
# Windows: 解压后用 sqlite3.exe 导入

# 抽取 Python 修复对（内置 sqlite3，零额外依赖）
python src/parse_cvefixes.py --db data/raw/CVEfixes.db --out data/processed/cvefixes_pairs.jsonl

# 合并两源重新构造（--max 控制上限）
python src/construct.py \
  --pairs data/processed/securecode_pairs.jsonl data/processed/cvefixes_pairs.jsonl \
  --out questions.jsonl --max 500
python src/qa.py --in questions.jsonl --out questions.jsonl
```

## 六、Semgrep 规则

规则按 OWASP 分类放在 `semgrep/rules/`，每条含 `id`、`message`、`metadata`（CWE/OWASP/置信度）。
单独扫描某段代码：

```bash
semgrep scan --config semgrep/rules/ <target.py>
```

覆盖的 Python 高发漏洞类型：

| 类目 | 典型规则 id | 覆盖漏洞 |
|------|-------------|----------|
| A01 访问控制 | `...access-control.csrf-exempt` | CSRF 关闭、越权 |
| A02 加密 | `...crypto.md5-hash` / `weak-cipher` / `insecure-random` | 弱哈希、弱算法、弱随机 |
| A03 注入 | `...sql-injection.*` / `command-injection.*` / `xss.*` / `xxe.*` | SQLi、命令注入、XSS、XXE |
| A05 配置 | `...misconfig.flask-debug` / `hardcoded-secret` | Debug、硬编码密钥 |
| A07 认证 | `...auth.weak-password-hash` | 弱口令哈希、明文比较 |
| A08 反序列化 | `...deserialization.pickle` / `eval-exec` | pickle、yaml.load、eval |
| A09 日志 | `...logging.sensitive-data` | 敏感信息入日志 |
| A10 SSRF | `...ssrf.urlopen-user-input` | URL 用户可控 |

## 七、pytest 评测

### 黄金校验（质检闸门）

按 `eval_method` 三轨校验 ground-truth 的正确性：

```bash
pytest tests/test_golden.py -v                # 全部三轨
pytest tests/test_golden.py -v -m "not semgrep"   # 跳过 semgrep 轨（未装 semgrep 时）
```

- `semgrep` 轨：漏洞代码命中规则 + 修复代码不再命中
- `functional` 轨：漏洞代码不通过功能断言 + 修复代码通过功能断言
- `manual` 轨：仅校验字段完整

### 模型修复评测

把 `tests/test_evaluate.py` 里的 `model_fix()` 换成你的模型调用即可：

```python
def model_fix(question: dict) -> str:
    resp = client.chat.completions.create(
        model="your-model",
        messages=[
            {"role": "system", "content": "你是安全代码修复专家。"},
            {"role": "user", "content": question["description"] + "\n```python\n" + question["vulnerable_code"] + "\n```"},
        ],
    )
    return extract_code(resp.choices[0].message.content)
```

```bash
pytest tests/test_evaluate.py -v
```

评测指标（一个修复「做对」= 同时满足两个条件）：

1. **漏洞已消除**：`semgrep` 轨规则不再命中 / `functional` 轨功能断言通过
2. **功能未破坏**：结构保真度不低于参考修复基线（仅功能轴适用的题，见 `src/preservation.py`）

`manual` 轨此模板跳过，需人工评审。

### 汇总报告（两个指标）

```bash
python src/report.py                            # 用参考修复自检（SFR 应为 1.0）
python src/report.py --model-output out.jsonl   # 读模型输出（每行 {"id":..., "code":...}）
```

分两个子集上报：

- **全量漏洞消除率** = 漏洞消除题数 / 可评测题数（172）
- **SFR（安全修复率）** = (漏洞消除 且 功能未破坏) 题数 / 功能轴适用题数（128）

### 本地模型（Ollama / LM Studio / llama.cpp / 原始权重）

`run_baseline.py` 只要求「OpenAI 兼容端点」，所以本地模型一样能跑，且本机端点**不需要 API key**：

| 服务 | 启动方式 | 跑分命令 |
|---|---|---|
| Ollama | `ollama run qwen2.5-coder:1.5b` | `python src/run_baseline.py --base-url http://127.0.0.1:11434/v1 --model qwen2.5-coder:1.5b` |
| LM Studio | 载入模型 → Developer → Local Server（默认 1234） | `--base-url http://127.0.0.1:1234/v1 --model <模型名>` |
| llama.cpp | `llama-server -m model.gguf --port 8080` | `--base-url http://127.0.0.1:8080/v1` |
| 原始 HF 权重（safetensors） | `python src/serve_local.py --model-path <模型目录> --port 8000` | `--base-url http://127.0.0.1:8000/v1 --model <目录名>` |

小模型建议加 `--max-tokens 1024 --timeout 900`，并且先 `--limit 10` 看有没有「空代码 / 被截断」再全量跑。
`src/serve_local.py` 用 transformers 加载权重、只暴露 `/v1/chat/completions` 与 `/v1/models` 两个接口，
不需要额外装 FastAPI/vLLM。

## 八、评测口径说明

- **`semgrep` 轨（56 题）**：注入、反序列化、弱加密、SSRF 等有明确危险 API 的漏洞，用静态规则判定。
  **判定 = 规则不再命中 且 出现该题要求的安全替代**（`fix_required`，见 `src/remediation.py`）——
  只把危险行删掉不算修好；整份只写 `pass` 这类退化答案也直接判否。
- **`functional` 轨（116 题）**：逻辑类漏洞（认证、越权、CSRF、开放重定向、日志、会话、竞态等），
  用 `functional_checks.check_code()` 检查修复代码是否引入了正确的安全控制（白名单校验、权限检查、CSRF 防护等）。
  检查定义见 `src/functional_checks.py`，可扩展新的 CWE。
- **`manual` 轨（154 题）**：逻辑类里无法可靠自动判定者，保留题目，供人工评审或后续补充精细检查。

### 双指标：漏洞消除 + 功能未破坏

「安全修复率 SFR」要求修复**同时**满足「漏洞已消除」且「功能未破坏」，用于惩罚两类失败：

| 失败模式 | 表现 | 哪个指标抓住 |
|----------|------|--------------|
| 漏修（没修好） | 漏洞仍在 | 漏洞消除率 ↓ |
| 假修（删掉危险行） | 规则不命中但没有安全替代 / 空壳答案 | `fix_required` 与退化守卫（见第九节自检） |
| 过度修复（修坏了） | 删代码 / return None / 推倒重写 | 功能未破坏率 ↓ |

「功能未破坏」用**结构保真度弱代理**实现：候选修复相对漏洞代码的相似度，不得比参考修复基线低出
`MARGIN`（默认 0.15）。参考修复本身是"重写型"（如攻击演示→测试）的题，功能轴不适用，标 NA 不强行判定。
实现见 `src/preservation.py`，可替换为真实的功能回归测试。

## 九、基线成绩

用 `src/run_baseline.py` 跑全部 172 道可评测题（semgrep 56 + functional 116；manual 154 不参与）。
题目集：`questions.jsonl`（2026-10-25 版，含 `fix_required` 安全替代约束）。

四个数字**同时给出**，分母不同时都标明（这是本仓库的固定报表格式）：

| 跑分对象 | ① 安全（漏洞消除）/172 | ② 功能（功能轴适用）/128 | ③ 联合 SFR =①∧② /128 | ④ 全题集联合 /172 |
|---|---|---|---|---|
| 参考修复（自检） | 172/172 = 100.00% | 128/128 = 100.00% | 128/128 = 100.00% | 128/172 = 74.42% |
| **`deepseek-chat`（2026-10-24）** | **149/172 = 86.63%** | 111/128 = 86.72% | **95/128 = 74.22%** | 95/172 = 55.23% |
| `Qwen2.5-Coder-1.5B-Instruct`（2026-10-25，本地 Ollama） | 50/172 = 29.07% | 125/128 = 97.66% | 35/128 = 27.34% | 35/172 = 20.35% |

分轨：

| 轨道 | 题数 | deepseek 消除 | Qwen-1.5B 消除 | 观察 |
|---|---|---|---|---|
| semgrep | 56 | 49 = **87.5%** | 17 = 30.4% | deepseek 剩 7 题；Qwen 主要漏在 pickle 反序列化与弱加密 |
| functional | 116 | 100 = **86.2%** | 33 = 28.4% | 逻辑类漏洞（认证、越权、CSRF、日志、重定向）两边都最难 |

逐题胜负（每格一题，按 CWE 分组；绿=两边都修好，蓝=仅 deepseek，橙=仅 Qwen，灰=都没修好）：

![基线对比](docs/baseline_compare.png)

> 复现这张图：`python src/plot_compare.py --a data/processed/baseline_outcomes.jsonl`
> `--b data/processed/qwen1.5b_outcomes.jsonl --label-a deepseek-chat --label-b Qwen2.5-Coder-1.5B`
> `--out docs/baseline_compare.png`（需要 `pip install matplotlib`）。

失败构成（172 题逐题判定，明细见 `data/processed/baseline_outcomes.jsonl` 与 `data/processed/qwen1.5b_outcomes.jsonl`）：

| 判定 | deepseek-chat | Qwen-1.5B |
|---|---|---|
| 安全修复（漏洞消除 且 功能未破坏） | 95 | 35 |
| 修好了、功能轴不适用（NA） | 37 | 13 |
| 漏洞未消除 | 23 | 121 |
| 修好了、但被判功能破坏 | 17 | 2 |
| 漏洞未消除且功能被判破坏 | 0 | 1 |

> 小模型的特征很典型：**结构保真度反而更高（97.66% vs 86.72%）**，因为它基本做局部小改甚至不改，
> 但漏洞消除率只有三成。两个指标一起看才能区分「没改」与「改坏」。

### 评分器自检（防刷分）

只判「规则不再命中」会被「把危险行删掉」刷满，所以 semgrep 轨的判定改成了
**「规则不再命中 且 出现该题要求的安全替代」**（`src/remediation.py`，按题校准，落在 `questions.jsonl` 的 `fix_required`），
外加一条「退化答案」守卫（整份只写 `pass` 不给分）。用两类作弊答案验收评分器：

| 作弊答案 | deepseek 时期（旧口径） | 现在 |
|---|---|---|
| A. 只删掉 semgrep 命中的行，其余不动 | **56/56 全部被判"修好"** | **0/48** |
| B. 整份只写 `pass`（semgrep 轨） | 22/56 | **0/56** |
| B. 整份只写 `pass`（functional 轨） | 0/116 | 0/116 |

（另有 8 道属「移除型修复」，没有正面记号可验，未纳入 A 项：`mark-safe` × 3、`weak-cipher` × 2、`fstring-query` × 3。）

复现自检：

```bash
python src/report.py --selfcheck     # 末尾会打印 [自检] 行
pytest tests/test_scorer_robustness.py -m semgrep -q
```

复现：

```bash
python src/run_baseline.py --model deepseek-chat --out data/processed/baseline_out.jsonl
python src/report.py --model-output data/processed/baseline_out.jsonl --report data/processed/baseline_report.json

# 本地模型（Ollama，端点不需要 key）
python src/run_baseline.py --base-url http://127.0.0.1:11434/v1 \
    --model qwen2.5-coder:1.5b --max-tokens 1024 \
    --out data/processed/qwen1.5b_out.jsonl
python src/report.py --model-output data/processed/qwen1.5b_out.jsonl --report data/processed/qwen1.5b_report.json

# 逐题判定（画图/复盘用）
python src/export_outcomes.py --model-output data/processed/qwen1.5b_out.jsonl \
    --out data/processed/qwen1.5b_outcomes.jsonl
```

> **口径备注**
> 1. 「功能未破坏」是结构保真度弱代理：表里 deepseek-chat 那 17 题被判破坏的答案**全部是扩写**
>    （长度为参考修复的 1.19~9.50 倍，原函数一个不少、没有删代码），属于代理对"把片段改写成完整实现"的偏保守惩罚。
>    若只把「显著变短」算作破坏，deepseek-chat 的 SFR 为 114/128 = 89.06%；
>    对"基本不改代码"的模型（如 Qwen-1.5B）这个代理几乎不惩罚，所以小模型的功能未破坏率反而虚高。
> 2. 2026-10-24 收窄过两个 functional check：CWE-778 不再把 `maxBytes`（正常轮转）算缺陷，
>    CWE-601 不再误杀「先校验再 `redirect(next_url)`」的正确写法。
> 3. 2026-10-25 收紧过 semgrep 轨口径：从「规则不再命中」改为「规则不再命中 **且** 出现安全替代」
>    （`fix_required`），并加了退化答案守卫。同一份 deepseek-chat 答案因此从 153/172 降到 149/172，
>    Qwen-1.5B 从 58/172 降到 50/172——**降下去的 12 道都是「删掉了危险行但没写替代」的答案**。
> 4. 历史数字（勿引用）：82.56%/71.09%（check 修正前）→ 88.95%/75.78%（修正后）→ 现在 86.63%/74.22%（加上防刷分后）。

## 十、许可证

| 范围 | 许可证 | 文件 |
|---|---|---|
| 代码（`src/`、`tests/`、`semgrep/rules/`、CI 配置） | **MIT** | [LICENSE](LICENSE) |
| 题目数据（`questions.jsonl`、`questions_viewer.html`） | **CC-BY-NC-SA-4.0**（派生自 SecureCode） | [DATA_LICENSE.md](DATA_LICENSE.md) |

- SecureCode 为**非商用 + 相同方式共享**：题集再分发须保留署名、以同许可发布、不得商用。
- 若未来商用，需替换或剔除 SecureCode 来源，改用 CVEfixes 等宽松许可来源重新生成题目。
- GitHub 仓库的 License 字段建议选 **MIT**，并在 About 里注明「数据集许可见 DATA_LICENSE.md」。

## 十一、引用

```bibtex
@misc{python-securecode-eval,
  title  = {Python 安全代码修复评测集（326 题，三轨：semgrep / functional / manual）},
  year   = {2026},
  note   = {Derived from SecureCode (scthornton/securecode, CC-BY-NC-SA-4.0)}
}
```
