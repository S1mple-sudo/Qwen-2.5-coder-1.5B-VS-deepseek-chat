# -*- coding: utf-8 -*-
"""把 questions.jsonl 渲染成一个自包含的 HTML 浏览器（可筛选、搜索、切换代码）。"""
import json
import sys

sys.stdout.reconfigure(encoding="utf-8")


def main():
    in_path = "questions.jsonl"
    out_path = "questions_viewer.html"

    with open(in_path, encoding="utf-8") as f:
        questions = [json.loads(l) for l in f if l.strip()]

    data_js = json.dumps(questions, ensure_ascii=False)
    # 防止代码内容里出现 </script> 提前闭合
    data_js = data_js.replace("</", "<\\/")

    html_doc = HTML_TMPL.replace("__DATA__", data_js)

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_doc)

    print(f"[done] {len(questions)} 道题 -> {out_path}")


HTML_TMPL = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>评测系统 · 题目浏览器</title>
<style>
  :root {
    --bg: #f6f7f9;
    --panel: #ffffff;
    --border: #e3e6ea;
    --text: #1f2329;
    --muted: #6b7280;
    --accent: #2f6feb;
    --code-bg: #f2f4f7;
    --tag-bg: #eef1f5;
    --red: #d93025;
    --green: #188038;
    --amber: #b45309;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Microsoft YaHei", sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
  }
  .topbar {
    position: sticky; top: 0; z-index: 10;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    padding: 16px 24px;
    box-shadow: 0 1px 4px rgba(0,0,0,.04);
  }
  .topbar h1 { margin: 0 0 10px; font-size: 20px; }
  .stats { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }
  .stat {
    background: var(--tag-bg); border: 1px solid var(--border);
    padding: 4px 12px; border-radius: 999px; font-size: 13px; color: var(--muted);
  }
  .stat b { color: var(--text); font-weight: 600; }
  .toolbar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
  .toolbar input, .toolbar select {
    padding: 8px 12px; border: 1px solid var(--border); border-radius: 8px;
    font-size: 14px; background: #fff; color: var(--text); outline: none;
  }
  .toolbar input:focus, .toolbar select:focus { border-color: var(--accent); }
  .toolbar input { flex: 1; min-width: 220px; }
  .counter { font-size: 13px; color: var(--muted); white-space: nowrap; }
  .container { max-width: 1100px; margin: 0 auto; padding: 20px 24px 80px; }
  .card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
    padding: 16px 18px; margin-bottom: 14px;
  }
  .card-head { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
  .qid { font-weight: 700; font-size: 14px; color: var(--accent); }
  .qtitle { font-weight: 600; font-size: 15px; }
  .tags { display: flex; flex-wrap: wrap; gap: 6px; margin: 10px 0 6px; }
  .tag {
    font-size: 12px; padding: 2px 9px; border-radius: 6px; background: var(--tag-bg);
    border: 1px solid var(--border); color: var(--muted);
  }
  .tag.sev-CRITICAL { background: #fdecea; color: var(--red); border-color: #f5c6c3; }
  .tag.sev-HIGH { background: #fef4e6; color: var(--amber); border-color: #f3d6a8; }
  .tag.sev-MEDIUM, .tag.sev-LOW { background: #e8f3ec; color: var(--green); border-color: #bfe0cc; }
  .tag.method-semgrep { background: #e8f0fe; color: #1a56d6; border-color: #c5d5f7; }
  .tag.method-functional { background: #fdf0f5; color: #b02a72; border-color: #f0c9dd; }
  .tag.method-manual { background: #f2f0ea; color: #6d5c2f; border-color: #ded5bd; }
  .tag.diff-easy { color: var(--green); }
  .tag.diff-medium { color: var(--amber); }
  .tag.diff-hard { color: var(--red); }
  .desc { font-size: 14px; color: var(--muted); margin: 6px 0 10px; }
  .tabs { display: flex; gap: 8px; margin: 10px 0 0; }
  .tab {
    padding: 6px 14px; border: 1px solid var(--border); border-radius: 8px 8px 0 0;
    font-size: 13px; cursor: pointer; background: #fafbfc; color: var(--muted);
  }
  .tab.active { background: var(--code-bg); color: var(--text); font-weight: 600; border-bottom: 2px solid var(--accent); }
  pre {
    margin: 0; padding: 14px 16px; background: var(--code-bg);
    border: 1px solid var(--border); border-radius: 0 8px 8px 8px;
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
    font-size: 12.5px; overflow-x: auto; max-height: 480px; overflow-y: auto;
    white-space: pre; tab-size: 4;
  }
  .meta { font-size: 12px; color: var(--muted); margin-top: 10px; border-top: 1px dashed var(--border); padding-top: 8px; }
  .meta code { background: var(--tag-bg); padding: 1px 6px; border-radius: 4px; }
  .empty { text-align: center; color: var(--muted); padding: 60px 0; }
</style>
</head>
<body>
  <div class="topbar">
    <h1>评测系统 · 题目浏览器</h1>
    <div class="stats" id="stats"></div>
    <div class="toolbar">
      <input id="search" type="text" placeholder="搜索 id / CWE / 标题 / 分类 / 代码关键字…">
      <select id="f-owasp"><option value="">全部 OWASP</option></select>
      <select id="f-diff"><option value="">全部难度</option></select>
      <select id="f-sev"><option value="">全部严重度</option></select>
      <select id="f-method"><option value="">全部评测方式</option></select>
      <span class="counter" id="counter"></span>
    </div>
  </div>
  <div class="container" id="list"></div>

<script>
const DATA = __DATA__;

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

// 构建统计
function buildStats() {
  const n = DATA.length;
  const byMethod = {};
  DATA.forEach(q => byMethod[q.eval_method] = (byMethod[q.eval_method]||0)+1);
  const byOwasp = new Set(DATA.map(q => q.owasp.split(' - ')[0])).size;
  const parts = [
    `题目总数 <b>${n}</b>`,
    `semgrep <b>${byMethod.semgrep||0}</b>`,
    `functional <b>${byMethod.functional||0}</b>`,
    `manual <b>${byMethod.manual||0}</b>`,
    `OWASP 类别 <b>${byOwasp}</b>`,
  ];
  $('stats').innerHTML = parts.map(p => `<span class="stat">${p}</span>`).join('');
}

// 填充筛选下拉
function fillSelect(id, key) {
  const vals = [...new Set(DATA.map(q => q[key]).filter(Boolean))].sort();
  const sel = $(id);
  vals.forEach(v => {
    const o = document.createElement('option');
    o.value = v; o.textContent = v; sel.appendChild(o);
  });
}
function fillOwasp() {
  const vals = [...new Set(DATA.map(q => q.owasp.split(' - ')[0]).filter(Boolean))].sort();
  const sel = $('f-owasp');
  vals.forEach(v => {
    const o = document.createElement('option');
    o.value = v; o.textContent = v; sel.appendChild(o);
  });
}

function methodLabel(m) {
  return {semgrep:'静态规则 (semgrep)', functional:'功能断言 (functional)', manual:'人工评审 (manual)'}[m] || m;
}

function card(q) {
  const sev = q.severity || '';
  const diff = q.difficulty || '';
  const method = q.eval_method || '';
  const tags = [
    `<span class="tag">${esc(q.cwe)}</span>`,
    `<span class="tag">${esc(q.owasp)}</span>`,
    sev ? `<span class="tag sev-${esc(sev)}">${esc(sev)}</span>` : '',
    diff ? `<span class="tag diff-${esc(diff)}">${esc(diff)}</span>` : '',
    method ? `<span class="tag method-${esc(method)}">${esc(methodLabel(method))}</span>` : '',
    q.framework ? `<span class="tag">${esc(q.framework)}</span>` : '',
  ].join('');

  const vuln = esc(q.vulnerable_code || '');
  const fixed = esc(q.fixed_code || '');
  const ft = q.functional_test
    ? `<div>functional_test: <code>${esc(JSON.stringify(q.functional_test)).slice(0, 300)}</code></div>`
    : '';

  return `
  <div class="card">
    <div class="card-head">
      <span class="qid">${esc(q.id)}</span>
      <span class="qtitle">${esc(q.title || '')}</span>
    </div>
    <div class="tags">${tags}</div>
    <div class="desc">${esc(q.description || '')}</div>
    <div class="tabs">
      <span class="tab active" onclick="switchTab(this, 'vuln')">漏洞代码（题干）</span>
      <span class="tab" onclick="switchTab(this, 'fix')">修复代码（参考答案）</span>
    </div>
    <pre class="code vuln">${vuln}</pre>
    <pre class="code fix" style="display:none">${fixed}</pre>
    <div class="meta">
      <div>来源: <code>${esc(q.source || '')}</code> · <code>${esc(q.source_id || '')}</code> · 规则: <code>${esc(q.semgrep_rule_id || '—')}</code> · verified: <code>${q.verified ? 'true' : 'false'}</code></div>
      ${ft}
    </div>
  </div>`;
}

function switchTab(el, which) {
  const card = el.closest('.card');
  card.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  card.querySelector('.code.vuln').style.display = which === 'vuln' ? 'block' : 'none';
  card.querySelector('.code.fix').style.display = which === 'fix' ? 'block' : 'none';
}

function filtered() {
  const kw = $('search').value.trim().toLowerCase();
  const ow = $('f-owasp').value;
  const diff = $('f-diff').value;
  const sev = $('f-sev').value;
  const method = $('f-method').value;

  return DATA.filter(q => {
    if (ow && !q.owasp.startsWith(ow)) return false;
    if (diff && q.difficulty !== diff) return false;
    if (sev && q.severity !== sev) return false;
    if (method && q.eval_method !== method) return false;
    if (kw) {
      const hay = [q.id, q.cwe, q.title, q.category, q.owasp, q.vulnerable_code, q.fixed_code, q.description]
        .join('\n').toLowerCase();
      if (!hay.includes(kw)) return false;
    }
    return true;
  });
}

function render() {
  const list = filtered();
  $('counter').textContent = `显示 ${list.length} / ${DATA.length} 题`;
  $('list').innerHTML = list.length ? list.map(card).join('') : '<div class="empty">没有匹配的题目</div>';
}

buildStats();
fillOwasp();
fillSelect('f-diff', 'difficulty');
fillSelect('f-sev', 'severity');
fillSelect('f-method', 'eval_method');

['search','f-owasp','f-diff','f-sev','f-method'].forEach(id => $(id).addEventListener('input', render));
render();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    main()
