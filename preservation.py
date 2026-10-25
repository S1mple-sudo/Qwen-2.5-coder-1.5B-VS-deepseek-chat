# -*- coding: utf-8 -*-
"""「功能未破坏」判定 —— 结构保真度弱代理。

背景
----
理想的功能保持验证是「喂正常输入、比对输出」（行为等价）。但本数据集的题目代码
多为框架片段 / 攻击演示脚本，没有可独立执行的入口，行为等价无法自动化。

因此退而求其次，用「结构保真度」近似「功能未破坏」：

    正确的修复是"局部修改"；删代码 / return None / 空实现 是"推倒重写"。
    用 difflib 相似度量化"候选修复相对漏洞代码保留了多少结构"，
    并与「参考修复」的保留程度（基线）比较——候选不得显著低于基线。

判定函数
--------
    behavior_applicable(vuln, ref)        -> bool  该题是否适用功能轴判定
    behavior_preserved(vuln, cand, ref)   -> bool  候选修复是否"未破坏功能"
"""
from difflib import SequenceMatcher

# 参考修复相对漏洞代码的相似度低于此值，说明题目本身是"重写型"（如攻击演示→测试），
# 功能轴不适用，标记 NA，不强行判定。
NA_THRESHOLD = 0.15
# 候选修复的相似度允许比参考修复基线低多少（超过即视为破坏功能）。
MARGIN = 0.15


def similarity(a: str, b: str) -> float:
    """两段代码的相似度（0~1）。"""
    return SequenceMatcher(None, a, b).ratio()


def behavior_applicable(vuln_code: str, ref_code: str) -> bool:
    """该题是否适用「功能未破坏」轴。

    参考修复若本身就和漏洞代码几乎无关（重写型），功能轴不适用。
    """
    return similarity(vuln_code, ref_code) >= NA_THRESHOLD


def behavior_preserved(vuln_code: str, candidate_code: str, ref_code: str) -> bool:
    """候选修复是否「未破坏功能」。

    规则：候选修复相对漏洞代码的结构相似度，不得比参考修复的基线低出 MARGIN 以上。
    - 候选 == 参考修复        -> 恒为 True（框架自洽）
    - 候选删光 / return None  -> 相似度骤降 -> False（抓住作弊）
    """
    base = similarity(vuln_code, ref_code)
    cand = similarity(vuln_code, candidate_code)
    return cand >= max(base - MARGIN, 0.0)
