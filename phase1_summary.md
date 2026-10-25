# 第一阶段总结：Python 安全修复评测系统

> 阶段时间：2026-10-22 ～ 2026-10-25
> 状态：**评测系统已可用、可复现、可发布**；基线数字已定；提示词实验已结案。
> 本文是这一阶段的自包含交接文档：做了什​么、现在的数字、结论、踩过的坑、遗留问题、下阶段入口。

---

## 1. 这一阶段完成了什么

| 模块 | 产出 |
|---|---|
| **题目集** | 326 题（semgrep 56 / functional 116 / manual 154），`verified` 172 道；`questions.jsonl` 内含 `fix_required` 字段 |
| **评测器** | 四指标报表：①安全（漏洞消除）/172 ②功能（结构保真）/128 ③联合 SFR /128 ④全题集联合 /172 |
| **防刷分** | semgrep 轨判定改为「规则不再命中 **且** 出现该题要求的安全替代」+ 退化答案守卫（`pass` / 单行空壳） |
| **跑分工具** | `src/run_baseline.py`（零依赖调 OpenAI 兼容端点）、`src/run_arm.py`（一臂一条命令）、`src/serve_local.py`（本地 HF 权重）、`src/export_outcomes.py`（逐题判定）、`src/plot_compare.py`（对比图） |
| **实验** | 6 臂提示词实验（2 模型 × 3 档提示词），结论落在 `docs/prompt_experiment.md` |
| **工程化** | Windows 便携包（.bat）、PyCharm 支持、GitHub 包（含 CI） |
| **文档** | `README.md`（9 节）、`docs/prompt_experiment.md`、`docs/baseline_compare.png`、`DATA_LICENSE.md` |

---

## 2. 当前核心数字

| 跑分对象 | ① 安全 /172 | ② 功能 /128 | ③ SFR /128 | ④ 全题集 /172 |
|---|---|---|---|---|
| 参考修复（自检基线） | 172 = 100% | 128 = 100% | 128 = 100% | 74.42% |
| **deepseek-chat**（默认提示） | **149 = 86.63%** | 111 = 86.72% | **95 = 74.22%** | 55.23% |
| **Qwen2.5-Coder-1.5B**（默认提示） | **50 = 29.07%** | 125 = 97.66% | **35 = 27.34%** | 20.35% |
| Qwen-1.5B（v2 提示） | 52 = 30.23% | 125 = 97.66% | 36 = 28.12% | 20.93% |
| deepseek（v1 / v2 提示） | 127 / **120** | 125 / 126 | 92 / 88 | 53.49% / 51.16% |

分轨（漏洞消除）：

| 轨道 | deepseek | Qwen |
|---|---|---|
| semgrep（56） | 49 / 45 / 42（默认/v1/v2） | 17 / 18 / 15 |
| functional（116） | 100 / 82 / 78 | 33 / 25 / 37 |

**评分器自检**（`python src/report.py --selfcheck`）：

```
[1] 172/172 = 100%   [2] 128/128 = 100%   [3] 128/128 = 100%   [4] 128/172 = 74.42%
[自检] 删行 0/48 · pass(semgrep) 0/56 · pass(functional) 0/116
```

> 改造前：删行作弊 **56/56 全部被判"修好"**——这条自检是这一阶段最重要的质量改进。

---

## 3. 三条关键结论

1. **约束型提示词对弱模型无益、对强模型有害。**
   - Qwen 三档 43 / 50 / 52，全在 50 上下——**天花板没变**；
   - deepseek 149 → 127 → 120，越约束越差。它 149 个胜利里 **125 个靠「>1.5× 扩写」**，
     而「最小改动 / 保留结构」类指令把答案砍到 58%，等于禁止它使用制胜策略。
   - 推论：**不能得出"提示词越严格越好"**；在这个 benchmark 上恰恰相反。
2. **评分器口径本身就是实验变量。** functional 按关键词判定、semgrep 按安全替代记号判定，
   提示词规定的写法会直接改变分数。任何对比必须锁定评分器版本。
3. **两个指标必须一起看。** 1.5B「功能未破坏 97.66%」是虚高（它基本不改代码，结构自然最像原文），
   SFR 27% 才暴露真相；deepseek 反之（改得多、结构分低，但真修好了）。

---

## 4. 踩过并已修复的坑

| 坑 | 现象 | 现状 |
|---|---|---|
| `semgrep.exe` 被 Application Control 拦截 | `WinError 4551`，本机无法运行 semgrep | **本机已不可用**；代码给出清晰报错并 exit 3/2，不产出半张指标；复算需换机器 |
| 断点续跑 + 同名输出文件 | 换提示词重跑时"已完成 172、待跑 0"，文件一字未改 → 误判"提示词无效" | 已加 guard：输出文件里若存在另一套 prompt，直接报错退出 |
| `.bat` 含中文 / LF 换行 | cmd 解析错乱（`ECHO is off.`、把中文当命令） | 全部改 **ASCII + CRLF + 无 BOM** |
| PyCharm Working directory 默认是脚本目录 | 产物写到 `src/data/processed` | 文档写死「设为项目根」 |
| matplotlib monospace 无 CJK 字形 | 中文表头变方框 | 数字列用 ASCII，正文用雅黑 |
| semgrep 缺 UTF-8 模式 | 规则 YAML 中文按 GBK 解码失败 | 一律 `PYTHONUTF8=1` |
| 硬编码本机 semgrep 路径 | 无法公开 / 换机器失效 | 改为 `SEMGREP_BIN` > PATH > 解释器同目录 > `.local_semgrep_paths`（已 gitignore） |

---

## 5. 遗留问题（下一阶段候选）

| 遗留 | 影响 | 建议 |
|---|---|---|
| functional check 是**关键词式** | 提示词风格主导分数；「用 flask_limiter 限流」这类正确修复被判失败 | 改成「等价实现白名单」（工作量中） |
| 功能轴是**结构保真代理** | 惩罚扩写型正确解，强模型 SFR 偏低 | 挖可执行子集做真回归（30–50 题，工作量大） |
| 8 道「移除型」题 | `mark-safe`×3、`weak-cipher`×2、`fstring-query`×3 无正面记号可验，删行作弊理论上仍可过 | 暂接受，报告与文档已注明 |
| 未推 GitHub | 本机没装 git | 包已就绪，见第 6 节 |
| 数据许可 | CC-BY-NC-SA-4.0（非商用、相同方式共享） | 商用需剔除 SecureCode，改用 CVEfixes 重建 |

---

## 6. 可直接复用的资产

**跑一臂**（自动产出 答案 / 四指标 / 逐题判定）：

```bat
run_arm.bat <tag> <base-url> <model> [prompt-file|-] [extra]
run_arm.bat qwen_v2 http://127.0.0.1:11434/v1 qwen2.5-coder:1.5b prompts\hardened_v2.md
```

**先自检**（换机器 / 改代码后的第一件事）：

```bash
python src/report.py --selfcheck
```

**回归基线**：deepseek 86.63% / SFR 74.22%；Qwen 29.07% / 27.34%。

**发布包**：`dist/python-secure-fix-eval.zip`（48 文件 / 2.78 MB，含 CI 与实验文档）。

---

## 7. 一句话概括

> 评测系统本身已经可信（防刷分 + 自检 + 可复现），当前基线是 **deepseek 86.63% / SFR 74.22%、
> Qwen 29.07% / 27.34%**，提示词工程在这个 benchmark 上收益为负——
> 瓶颈已经从「评测可信度」转到「题目难度分层 / 功能判定语义化 / 模型能力提升」这三件事上。

---

## 8. 相关文档

- [README](../README.md) —— 项目说明、复现步骤、基线成绩
- [prompt_experiment.md](prompt_experiment.md) —— 六臂提示词实验（设计 / 结果 / 机制 / 结论）
- [baseline_compare.png](baseline_compare.png) —— 逐题胜负矩阵
- [DATA_LICENSE.md](../DATA_LICENSE.md) —— 数据来源与许可
