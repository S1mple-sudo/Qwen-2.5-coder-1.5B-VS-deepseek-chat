# 数据来源与许可（Data License）

本仓库的**代码**采用 MIT（见 `LICENSE`），但**题目数据**来自第三方数据集，其许可独立于代码。

## 1. 主要来源：SecureCode

| 项 | 内容 |
|---|---|
| 数据集 | `scthornton/securecode`（HuggingFace） |
| 原始文件 | `data/web/train.parquet`（约 8.6 MB） |
| 许可证 | **CC-BY-NC-SA-4.0**（署名—非商业性使用—相同方式共享 4.0 国际） |
| 用于 | 326 道题的全部 `vulnerable_code` / `fixed_code` |

因此：

- `questions.jsonl` 以及由它派生的 `questions_viewer.html` 属于**该数据集的演绎作品**，
  应以 **CC-BY-NC-SA-4.0** 分发（署名 + 非商业 + 相同方式共享）；
- **不得用于商业用途**（包括商业产品评测、付费榜单等）；商用请改用 CVEfixes 等宽松许可来源重新生成；
- 再分发时必须保留本文件与下列署名信息。

署名建议写法：

```
This dataset is derived from SecureCode (scthornton/securecode, CC-BY-NC-SA-4.0),
via https://huggingface.co/datasets/scthornton/securecode.
```

## 2. 可选来源：CVEfixes

| 项 | 内容 |
|---|---|
| 数据集 | `secureIT-project/CVEfixes`（Zenodo DOI: 10.5281/zenodo.4476563） |
| 许可证 | 数据本身来自 NVD 与公开代码仓库，按其各自许可 |
| 用于 | `src/parse_cvefixes.py` 抽取的补充题目（当前题集未包含） |

## 3. 第三方工具

Semgrep 规则为本项目自写（MIT），但 Semgrep 引擎本身遵循其自身许可（LGPL-2.1）；
pytest / pandas / pyarrow 各自遵循其开源许可。
