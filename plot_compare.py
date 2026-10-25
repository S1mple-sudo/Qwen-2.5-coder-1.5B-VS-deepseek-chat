# -*- coding: utf-8 -*-
"""模型横评图：逐题胜负矩阵（按 CWE 分组）+ 分轨汇总。

用法：
    python src/plot_compare.py --a data/processed/baseline_outcomes.jsonl \
        --b data/processed/qwen1.5b_outcomes.jsonl \
        --label-a deepseek-chat --label-b Qwen2.5-Coder-1.5B \
        --out docs/baseline_compare.png

输入是两个「逐题判定」JSONL（report 侧的产物，字段：id / cwe / track / elim）。
判定口径：只看「漏洞消除」（elim），不看功能轴——矩阵回答的是"这题谁修好了"。
"""
import argparse
import collections
import json
import os
import sys

sys.stdout.reconfigure(encoding="utf-8")

# 颜色：绿=都修好；蓝=A 修好；橙=B 修好；灰=都没修好
C_BOTH, C_A, C_B, C_NONE = "#2E7D32", "#1565C0", "#EF6C00", "#B0BEC5"

_FONT_CANDIDATES = [
    r"C:\Windows\Fonts\msyh.ttc",
    r"C:\Windows\Fonts\simhei.ttf",
    "/System/Library/Fonts/PingFang.ttc",
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
]


def _setup_font():
    """找一个含中文的字体；找不到就退回英文标签，避免出现方框。"""
    from matplotlib import font_manager as fm
    from matplotlib import rcParams

    for p in _FONT_CANDIDATES:
        if os.path.isfile(p):
            try:
                fm.fontManager.addfont(p)
                name = fm.FontProperties(fname=p).get_name()
                rcParams["font.family"] = "sans-serif"
                rcParams["font.sans-serif"] = [name]
                rcParams["axes.unicode_minus"] = False
                return True
            except Exception:
                continue
    return False


def load(path):
    rows = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                d = json.loads(line)
                rows[d["id"]] = d
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", required=True, help="模型 A 的逐题判定 JSONL")
    ap.add_argument("--b", required=True, help="模型 B 的逐题判定 JSONL")
    ap.add_argument("--label-a", default="A")
    ap.add_argument("--label-b", default="B")
    ap.add_argument("--out", default="docs/baseline_compare.png")
    ap.add_argument("--dpi", type=int, default=150)
    args = ap.parse_args()

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch, Rectangle

    zh = _setup_font()
    L = (lambda zh_text, en_text: zh_text) if zh else (lambda zh_text, en_text: en_text)

    A, B = load(args.a), load(args.b)
    ids = sorted(set(A) & set(B))
    if not ids:
        print("[error] 两个文件没有交集 id", file=sys.stderr)
        return 2

    cat = {}
    for i in ids:
        ea, eb = bool(A[i]["elim"]), bool(B[i]["elim"])
        cat[i] = "both" if (ea and eb) else ("a" if ea else ("b" if eb else "none"))

    # 按 CWE 分组，行按题量降序
    by_cwe = collections.defaultdict(list)
    for i in ids:
        by_cwe[A[i]["cwe"]].append(i)
    order = sorted(by_cwe, key=lambda c: (-len(by_cwe[c]), c))

    counts = collections.Counter(cat.values())
    print(f"共 {len(ids)} 题 | 都修好 {counts['both']} | 仅 {args.label_a} {counts['a']} | "
          f"仅 {args.label_b} {counts['b']} | 都没修好 {counts['none']}")

    fig = plt.figure(figsize=(14, max(6, 0.26 * len(order) + 2.6)), dpi=args.dpi)
    gs = fig.add_gridspec(1, 2, width_ratios=[3.3, 1.15], wspace=0.10,
                          left=0.105, right=0.985, top=0.90, bottom=0.075)
    ax = fig.add_subplot(gs[0, 0])
    ax2 = fig.add_subplot(gs[0, 1])

    # ---- 左：逐题矩阵 ----
    max_n = max(len(v) for v in by_cwe.values())
    ax.set_xlim(-max_n * 0.42, max_n + 3.2)
    ax.set_ylim(len(order) - 0.5, -0.6)
    ax.axis("off")
    for r, cwe in enumerate(order):
        qs = sorted(by_cwe[cwe])
        ax.text(-0.45, r, f"{cwe}", ha="right", va="center", fontsize=8.5, color="#263238")
        for k, i in enumerate(qs):
            color = {"both": C_BOTH, "a": C_A, "b": C_B, "none": C_NONE}[cat[i]]
            ax.add_patch(Rectangle((k + 0.06, r - 0.32), 0.88, 0.64, facecolor=color,
                                   edgecolor="white", linewidth=0.6))
        # 行末小结：题量 / 两边都修好 / A 胜 / B 胜 / 都没修好
        both_n = sum(1 for i in qs if cat[i] == "both")
        a_n = sum(1 for i in qs if cat[i] == "a")
        b_n = sum(1 for i in qs if cat[i] == "b")
        none_n = sum(1 for i in qs if cat[i] == "none")
        ax.text(max_n + 0.55, r, f"{len(qs):>3}  {both_n:>2} {a_n:>3} {b_n:>2} {none_n:>2}",
                ha="left", va="center", fontsize=6.8, color="#546E7A", family="monospace")

    # 表头
    ax.text(-0.45, -0.95, "CWE", ha="right", va="center", fontsize=8, color="#37474F")
    ax.text(max_n + 0.55, -0.95, "   n both  A  B none", ha="left", va="center",
            fontsize=6.8, color="#37474F", family="monospace")

    # ---- 右：分轨汇总 ----
    tracks = [("semgrep", L("semgrep 轨", "semgrep")), ("functional", L("functional 轨", "functional"))]
    ax2.set_xlim(0, 1)
    ax2.set_ylim(0, 1)
    ax2.axis("off")
    ax2.text(0, 0.985, L("分轨汇总", "by track"), fontsize=10, color="#263238", va="top")
    y = 0.90
    for t, name in tracks:
        sub = [i for i in ids if A[i]["track"] == t]
        c = collections.Counter(cat[i] for i in sub)
        total = len(sub)
        ax2.text(0, y, f"{name}  n={total}", fontsize=8, color="#37474F", va="bottom")
        left = 0.0
        for key, color in (("both", C_BOTH), ("a", C_A), ("b", C_B), ("none", C_NONE)):
            w = c[key] / total
            ax2.add_patch(Rectangle((left, y - 0.055), w, 0.048, facecolor=color, edgecolor="none"))
            if w > 0.10:
                ax2.text(left + w / 2, y - 0.031, str(c[key]), ha="center", va="center",
                         fontsize=7, color="white" if key != "none" else "#37474F")
            left += w
        y -= 0.135

    # 整体
    y -= 0.02
    ax2.text(0, y, L("整体（172 题）", "overall (172)"), fontsize=9, color="#263238", va="top")
    lines = [
        (L("都修好", "both fixed"), counts["both"], C_BOTH),
        (L(f"仅 {args.label_a}", f"only {args.label_a}"), counts["a"], C_A),
        (L(f"仅 {args.label_b}", f"only {args.label_b}"), counts["b"], C_B),
        (L("都没修好", "neither"), counts["none"], C_NONE),
    ]
    for label, n, color in lines:
        y -= 0.072
        ax2.add_patch(Rectangle((0.0, y - 0.020), 0.045, 0.040, facecolor=color, edgecolor="none"))
        ax2.text(0.075, y, f"{label}", fontsize=7.6, color="#37474F", va="center")
        ax2.text(0.74, y, f"{n}", fontsize=7.6, color="#263238", va="center", ha="right")
        ax2.text(0.99, y, f"{n / len(ids):.0%}", fontsize=7.6, color="#78909C", va="center", ha="right")

    # ---- 标题与图例 ----
    fig.suptitle(L(f"逐题胜负矩阵（漏洞消除）：{args.label_a} vs {args.label_b}",
                   f"Per-question outcome matrix: {args.label_a} vs {args.label_b}"),
                 fontsize=13, color="#1A237E", x=0.012, ha="left", y=0.985)
    fig.text(0.012, 0.945,
             L(f"共 {len(ids)} 道可评测题，按 CWE 分组，每格一题；判定口径＝仅「漏洞消除」（不含功能轴）",
               f"{len(ids)} evaluable questions grouped by CWE; criterion = vulnerability eliminated only"),
             fontsize=9, color="#455A64", ha="left")

    handles = [Patch(facecolor=C_BOTH, label=L("两边都修好", "both fixed")),
               Patch(facecolor=C_A, label=L(f"仅 {args.label_a}", f"only {args.label_a}")),
               Patch(facecolor=C_B, label=L(f"仅 {args.label_b}", f"only {args.label_b}")),
               Patch(facecolor=C_NONE, label=L("都没修好", "neither"))]
    fig.legend(handles=handles, loc="lower center", ncol=4, frameon=False, fontsize=9,
               bbox_to_anchor=(0.42, 0.012))

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    fig.savefig(args.out, facecolor="white")
    print("图已写入", args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
