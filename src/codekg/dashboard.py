from __future__ import annotations

import json
import os
import webbrowser
from pathlib import Path
from typing import Any, Dict, Optional

from .exporter import QUERY_EXAMPLES, load_graph_dir


def write_dashboard(
    out_dir: Path,
    graph_payload: Dict[str, Any],
    manifest: Dict[str, Any],
    query_examples: Optional[list] = None,
    initial_query: Optional[Dict[str, Any]] = None,
    logger=None,
) -> Path:
    dashboard_dir = out_dir / "dashboard"
    dashboard_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "graph": graph_payload,
        "manifest": manifest,
        "query_examples": query_examples or QUERY_EXAMPLES,
        "initial_query": initial_query or {"kind": "auto", "target_function": "count_rows", "depth": 2},
    }
    html = DASHBOARD_TEMPLATE.replace("__CODEKG_DATA__", json.dumps(payload, ensure_ascii=False))
    path = dashboard_dir / "index.html"
    path.write_text(html, encoding="utf-8")
    (dashboard_dir / "graph_data.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    if logger:
        logger.info("Dashboard written: %s", path)
    return path


def open_dashboard(path: Path) -> None:
    webbrowser.open(path.resolve().as_uri())


def rebuild_dashboard_from_graph_dir(graph_dir: Path, initial_query: Optional[Dict[str, Any]] = None, logger=None) -> Path:
    loaded = load_graph_dir(graph_dir)
    return write_dashboard(graph_dir, loaded["graph"], loaded["manifest"], loaded["query_examples"], initial_query, logger=logger)


DASHBOARD_TEMPLATE = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>CodeKG Explorer</title>
<style>
:root {
  --bg: #f7f9fc;
  --panel: #ffffff;
  --panel2: #f1f5f9;
  --text: #111827;
  --muted: #64748b;
  --line: #d6dee9;
  --accent: #2563eb;
  --good: #047857;
  --warn: #b45309;
  --bad: #b91c1c;
  --shadow: 0 18px 50px rgba(15,23,42,.12);
}
* { box-sizing: border-box; }
html, body { height: 100%; margin: 0; overflow: hidden; background: var(--bg); color: var(--text); font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
.app { display: grid; grid-template-columns: 330px minmax(420px, 1fr) 410px; height: 100vh; width: 100vw; overflow: hidden; }
.sidebar, .details { background: linear-gradient(180deg, rgba(255,255,255,.98), rgba(248,250,252,.98)); border-right: 1px solid var(--line); overflow-y: auto; padding: 18px; }
.details { border-right: none; border-left: 1px solid var(--line); }
.stage { position: relative; min-width: 0; overflow: hidden; background: radial-gradient(circle at 15% 10%, rgba(37,99,235,.08), transparent 26%), radial-gradient(circle at 85% 80%, rgba(16,185,129,.07), transparent 28%), #f8fafc; }
.header { display: flex; flex-direction: column; gap: 4px; margin-bottom: 16px; }
.header h1 { margin: 0; font-size: 19px; letter-spacing: .2px; }
.header .sub { color: var(--muted); font-size: 12px; line-height: 1.45; }
.card { background: rgba(255,255,255,.92); border: 1px solid rgba(148,163,184,.45); border-radius: 16px; padding: 13px; margin-bottom: 13px; box-shadow: 0 10px 32px rgba(15,23,42,.08); }
.card h2 { margin: 0 0 10px; font-size: 13px; letter-spacing: .35px; text-transform: uppercase; color: #475569; }
label { display: block; color: var(--muted); font-size: 12px; margin: 10px 0 6px; }
input, select, button, textarea { width: 100%; border-radius: 10px; border: 1px solid #cbd5e1; background: #ffffff; color: var(--text); padding: 9px 10px; outline: none; }
button { cursor: pointer; background: linear-gradient(180deg, #ffffff, #f1f5f9); border-color: #cbd5e1; font-weight: 650; font-size: 12px; transition: transform .1s ease, border-color .12s ease, background .12s ease; }
button:hover { transform: translateY(-1px); border-color: var(--accent); }
button.primary { background: linear-gradient(180deg, #2563eb, #1d4ed8); border-color: #1d4ed8; color: #ffffff; }
button.ghost { background: transparent; }
.row { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.row3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; }
.kpis { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.kpi { background: #f8fafc; border: 1px solid #dbe4ef; border-radius: 12px; padding: 9px; }
.kpi b { font-size: 18px; display: block; }
.kpi span { color: var(--muted); font-size: 11px; }
.legend-item, .checkline { display: flex; align-items: center; justify-content: space-between; gap: 8px; font-size: 12px; color: #475569; margin: 5px 0; }
.legend-left { display: flex; align-items: center; gap: 8px; min-width: 0; }
.swatch { width: 11px; height: 11px; border-radius: 4px; flex: 0 0 auto; }
.checkline input { width: auto; }
.pill { display: inline-flex; align-items: center; gap: 6px; padding: 4px 7px; border: 1px solid #cbd5e1; border-radius: 999px; color: #334155; font-size: 11px; background: #f8fafc; margin: 2px; }
.warn { color: var(--warn); } .bad { color: var(--bad); } .good { color: var(--good); }
#graphCanvas { position: absolute; inset: 0; width: 100%; height: 100%; }
.toolbar { position: absolute; left: 16px; top: 16px; right: 16px; display: flex; gap: 8px; align-items: center; pointer-events: none; }
.toolbar .group { pointer-events: auto; backdrop-filter: blur(10px); background: rgba(255,255,255,.90); border: 1px solid rgba(148,163,184,.55); border-radius: 14px; box-shadow: var(--shadow); padding: 8px; display: flex; gap: 7px; align-items: center; }
.toolbar button { width: auto; min-width: 72px; padding: 8px 10px; }
.statusbar { position: absolute; left: 16px; bottom: 16px; max-width: calc(100% - 32px); pointer-events: none; background: rgba(255,255,255,.92); border: 1px solid rgba(148,163,184,.55); border-radius: 14px; padding: 9px 12px; color: #475569; font-size: 12px; backdrop-filter: blur(10px); box-shadow: var(--shadow); }
.details h2 { font-size: 15px; margin: 0 0 8px; }
.meta-grid { display: grid; grid-template-columns: 120px 1fr; gap: 6px 10px; font-size: 12px; }
.meta-grid .key { color: var(--muted); }
pre { margin: 0; overflow: auto; background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 12px; padding: 12px; color: #0f172a; font-size: 12px; line-height: 1.45; max-height: 360px; }
.table { width: 100%; border-collapse: collapse; font-size: 12px; }
.table th, .table td { border-bottom: 1px solid #e2e8f0; padding: 7px 5px; text-align: left; vertical-align: top; }
.table th { color: var(--muted); font-weight: 600; }
.small { font-size: 11px; color: var(--muted); line-height: 1.45; }
hr { border: 0; border-top: 1px solid var(--line); margin: 12px 0; }
.querybox { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 11px; min-height: 54px; }
.retrievalbox { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 11px; min-height: 96px; resize: vertical; }
.query-result { background:#f8fafc; border:1px solid #d6dee9; border-radius:12px; padding:9px; margin-top:9px; }
.agent-query-actions { display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-top:8px; }
.agent-query-card-top { border-color:#93c5fd; background:linear-gradient(180deg,#eff6ff,#ffffff); box-shadow:0 12px 34px rgba(37,99,235,.13); }
.agent-query-card-top h2 { color:#1d4ed8; }
.agent-query-card-top select { background:#ffffff; border-color:#93c5fd; }
.agent-query-card-top button.primary { background:linear-gradient(180deg,#2563eb,#1d4ed8); color:#ffffff; }
.agent-query-panel { border:1px solid #bfdbfe; background:#eff6ff; border-radius:12px; padding:9px; margin-bottom:10px; }
.agent-query-panel .title { font-weight:700; color:#1e3a8a; margin-bottom:4px; }
.query-result b { color:#111827; }
.pathbox { background:#f8fafc; border:1px solid #bfdbfe; border-radius:12px; padding:9px; margin-top:9px; }
.path-step { border-left: 2px solid #2563eb; padding: 5px 0 5px 9px; margin: 4px 0; }
.path-edge { color:#b45309; font-weight:650; }
.path-node { color:#111827; font-weight:650; }
kbd { border:1px solid #cbd5e1; background:#f8fafc; border-radius:6px; padding:1px 5px; color:#334155; font-size:10px; }

.agent-query-status { color:#64748b; font-size:11px; line-height:1.35; margin-bottom:8px; }
.agent-query-evidence { max-height:260px; overflow:auto; background:#ffffff; border:1px solid #dbe4ef; border-radius:12px; padding:8px; margin-top:8px; }
.agent-query-evidence .snippet { border-top:1px solid #e2e8f0; padding-top:7px; margin-top:7px; }
.agent-query-evidence code { white-space:pre-wrap; display:block; background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:7px; color:#0f172a; }
.agent-query-metrics { display:flex; flex-wrap:wrap; gap:4px; margin-top:6px; }
.hidden { display: none !important; }
@media (max-width: 1100px) { .app { grid-template-columns: 285px 1fr 340px; } }
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="header">
      <h1>CodeKG Explorer</h1>
      <div class="sub" id="projectSub">Standalone C/C++ code knowledge graph</div>
    </div>

    <div class="card agent-query-card-top" id="agentQueryCard">
      <h2>Agent queries</h2>
      <div id="agentQueryStatus" class="agent-query-status">Waiting for LLM-generated KG queries. This list updates while the audit runs.</div>
      <label>LLM-generated KG query</label>
      <select id="agentQuerySelect"><option value="">No saved queries yet</option></select>
      <div class="row3" style="margin-top:8px">
        <button class="primary" id="agentHighlightBtn">Highlight</button>
        <button id="agentFilterBtn">Show only</button>
        <button id="agentRefreshQueriesBtn">Refresh</button>
      </div>
      <button id="agentCopyQueryBtn" style="margin-top:8px">Copy query</button>
      <div id="agentQueryPanel" class="agent-query-panel small" style="margin-top:10px">No audit query loaded.</div>
      <div id="agentQueryEvidenceText" class="agent-query-evidence small">Select a saved agent query to see its source-grounded text output.</div>
    </div>

    <div class="card">
      <h2>Search</h2>
      <input id="searchBox" placeholder="function, file, variable, call, id, line, fact, edge..." />
      <div class="row" style="margin-top:8px">
        <button class="primary" id="searchBtn">Search</button>
        <button id="clearSearchBtn">Clear</button>
      </div>
      <label>Neighborhood depth</label>
      <select id="depthSelect"><option>1</option><option selected>2</option><option>3</option><option>4</option></select>
      <label>Minimum degree</label>
      <input id="degreeThreshold" type="number" value="0" min="0" />
    </div>

    <div class="card">
      <h2>Retrieval query</h2>
      <textarea id="retrievalQuery" class="retrievalbox">security_context(target_function=count_rows, depth=3, call_depth=2, data_depth=3, include_callers=true, include_headers=true, include_globals=true, include_joern=true, joern_limit=160, max_nodes=520, risk_terms=[pointer,array,bounds,size,copy,read,write,allocation,free,null,return,guard])</textarea>
      <div class="row" style="margin-top:8px">
        <button class="primary" id="runRetrievalQueryBtn">Run retrieval</button>
        <button id="clearRetrievalQueryBtn">Clear slice</button>
      </div>
      <div id="retrievalResult" class="query-result small">Run a query to show only the retrieved evidence subgraph.</div>
    </div>

    <div class="card">
      <h2>Relationship path</h2>
      <div class="small">After retrieval, double-click a node or explain a selected/input node to highlight how it connects back to the target function. Other graph regions are dimmed.</div>
      <label>Target anchor</label>
      <input id="relationAnchor" placeholder="auto: retrieval target / selected function" />
      <label>Node id/name to explain</label>
      <input id="relationNodeInput" placeholder="e.g. raw, read, node id, line node..." />
      <div class="row" style="margin-top:8px">
        <button class="primary" id="explainInputBtn">Explain input</button>
        <button id="explainSelectedBtn">Explain selected</button>
      </div>
      <div class="row" style="margin-top:8px">
        <button id="focusPathBtn">Path only</button>
        <button id="clearPathBtn">Clear path</button>
      </div>
      <div id="relationshipResult" class="pathbox small">No relationship path selected. Tip: run retrieval, then double-click any node.</div>
    </div>

    <div class="card">
      <h2>Graph subsets</h2>
      <div class="row"><button data-view="project">Project</button><button data-view="file">Selected file</button></div>
      <div class="row" style="margin-top:8px"><button data-view="function">Function</button><button data-view="function_callees">Function + callees</button></div>
      <div class="row" style="margin-top:8px"><button data-view="function_callers">Function + callers</button><button data-view="function_variables">Function + variables</button></div>
      <div class="row" style="margin-top:8px"><button data-view="semantic">Semantic overlay</button><button data-view="risk">Risk/semantic only</button></div>
      <div class="row" style="margin-top:8px"><button data-view="callgraph">Call graph</button><button data-view="cfg">CFG</button></div>
      <div class="row" style="margin-top:8px"><button data-view="ast">AST</button><button data-view="dataflow">Data/def-use</button></div>
    </div>

    <div class="card">
      <h2>Filters</h2>
      <label>Node types</label>
      <div id="nodeTypeFilters"></div>
      <label>Edge types</label>
      <div id="edgeTypeFilters"></div>
    </div>

    <div class="card">
      <h2>Metrics</h2>
      <div class="kpis"><div class="kpi"><b id="nodeCount">0</b><span>visible nodes</span></div><div class="kpi"><b id="edgeCount">0</b><span>visible edges</span></div></div>
      <hr />
      <div id="metricsList" class="small"></div>
    </div>

    <div class="card">
      <h2>Graph quality</h2>
      <div id="qualityPanel" class="small"></div>
    </div>

    <div class="card">
      <h2>Saved query examples</h2>
      <select id="queryExamples"></select>
      <textarea id="queryText" class="querybox" readonly></textarea>
      <button id="copyQueryBtn" style="margin-top:8px">Copy CLI query</button>
    </div>
  </aside>

  <main class="stage" id="stage">
    <canvas id="graphCanvas"></canvas>
    <div class="toolbar">
      <div class="group">
        <button id="resetBtn">Reset</button>
        <button id="fitBtn">Fit</button>
        <button id="expand1Btn">+1 hop</button>
        <button id="expand2Btn">+2 hop</button>
        <button id="isolateBtn">Isolate</button>
      </div>
      <div class="group">
        <button id="pinBtn">Pin</button>
        <button id="unpinBtn">Unpin all</button>
      </div>
    </div>
    <div class="statusbar" id="statusBar">Ready</div>
  </main>

  <aside class="details">
    <div class="card">
      <h2>Selection</h2>
      <div id="selectionDetails" class="small">Click a node or edge.</div>
      <div class="row" style="margin-top:10px"><button id="copyNodeBtn">Copy node id</button><button id="copySelectionQueryBtn">Copy query</button></div>
    </div>
    <div class="card">
      <h2>Source preview</h2>
      <pre id="codePreview">No source selected.</pre>
    </div>
    <div class="card">
      <h2>Neighborhood</h2>
      <div id="neighborhoodTable" class="small"></div>
    </div>
    <div class="card">
      <h2>Top graph signals</h2>
      <div id="topSignals" class="small"></div>
    </div>
  </aside>
</div>
<script id="codekg-data" type="application/json">__CODEKG_DATA__</script>
<script>
(() => {
  'use strict';
  const DATA = JSON.parse(document.getElementById('codekg-data').textContent);
  const graph = DATA.graph || {nodes: [], edges: []};
  const manifest = DATA.manifest || {};
  const queryExamples = DATA.query_examples || [];
  const nodes = graph.nodes.map(n => ({...n, x: 0, y: 0, vx: 0, vy: 0, pinned: false}));
  const edges = graph.edges.map(e => ({...e}));
  const nodeById = new Map(nodes.map(n => [n.id, n]));
  const outEdges = new Map(), inEdges = new Map(), bothEdges = new Map();
  for (const n of nodes) { outEdges.set(n.id, []); inEdges.set(n.id, []); bothEdges.set(n.id, []); }
  for (const e of edges) {
    if (!nodeById.has(e.source) || !nodeById.has(e.target)) continue;
    outEdges.get(e.source).push(e); inEdges.get(e.target).push(e);
    bothEdges.get(e.source).push(e); bothEdges.get(e.target).push(e);
  }
  const nodeTypes = [...new Set(nodes.map(n => n.type))].sort();
  const edgeTypes = [...new Set(edges.map(e => e.type))].sort();
  const colorMap = {
    'Project': '#73d0ff', 'File': '#8b949e', 'Include': '#a5d6ff', 'Macro': '#d2a8ff',
    'Struct/Class': '#ffa657', 'Type': '#ffa657', 'Field': '#f2cc60', 'Function': '#7ee787',
    'FunctionParameter': '#79c0ff', 'LocalVariable': '#c9d1d9', 'GlobalVariable': '#ffdf7e', 'Field': '#f2cc60', 'JoernCPGNode': '#f778ba', 'Statement': '#6e7681',
    'Assignment': '#f2cc60', 'ReturnStatement': '#ffab70', 'Condition': '#ff7b72', 'Loop': '#ff7b72',
    'OperatorExpression': '#d2a8ff', 'CallExpression': '#a5d6ff', 'Literal': '#c297ff',
    'Comment': '#586069', 'SemanticFact': '#ff7b72'
  };
  const edgeColorMap = {
    'CALLS': '#7ee787', 'CALLS_INDIRECT': '#56d364', 'CFG_NEXT': '#f2cc60', 'AST_CHILD': '#6e7681', 'DEF_USE': '#d2a8ff',
    'DATA_DEPENDS_ON': '#d2a8ff', 'USES_VARIABLE': '#79c0ff', 'DEFINES_VARIABLE': '#ffa657',
    'HAS_SEMANTIC_FACT': '#ff7b72', 'SEMANTICALLY_RELATED': '#ff7b72', 'STATEMENT_CALLS': '#a5d6ff', 'USES_GLOBAL': '#ffdf7e', 'DEFINES_GLOBAL': '#ffdf7e', 'FILE_HAS_GLOBAL': '#ffdf7e', 'USES_FIELD': '#f2cc60', 'DEFINES_FIELD': '#ffa657', 'ACCESSES_FIELD': '#f2cc60', 'TYPE_HAS_FIELD': '#f2cc60', 'HAS_TYPE': '#ffa657', 'JOERN_OVERLAY': '#f778ba', 'JOERN_AST': '#8b949e', 'JOERN_CFG': '#f2cc60', 'JOERN_DDG': '#d2a8ff', 'JOERN_CDG': '#ff7b72', 'JOERN_CALL': '#7ee787', 'JOERN_REACHING_DEF': '#d2a8ff', 'JOERN_EDGE': '#f778ba'
  };
  const state = {
    selectedNode: null, selectedEdge: null, hoverNode: null, hoverEdge: null,
    search: '', activeView: 'project', selectedFile: null, selectedFunction: null,
    visibleNodeIds: new Set(), visibleEdgeIds: new Set(), nodeTypeEnabled: new Set(nodeTypes), edgeTypeEnabled: new Set(edgeTypes),
    retrievalNodeIds: new Set(), retrievalEdgeIds: new Set(), retrievalSummary: null,
    relationPathNodeIds: new Set(), relationPathEdgeIds: new Set(), relationPath: null, relationPathOnly: false,
    externalQueryView: null, externalQueryMode: 'filter', externalQueryText: '', agentQueryViews: [], agentQueryIndexUpdatedAt: 0,
    transform: {x: 0, y: 0, scale: 1}, dragging: false, dragNode: null, lastMouse: {x:0,y:0}, simulationTicks: 0
  };
  const edgeById = new Map(edges.map(e => [e.id, e]));
  const canvas = document.getElementById('graphCanvas');
  const ctx = canvas.getContext('2d');
  function $(id) { return document.getElementById(id); }
  function esc(x) { return String(x ?? '').replace(/[&<>"']/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[s])); }
  function compact(x, n=80) { x = String(x ?? ''); return x.length > n ? x.slice(0, n-1) + '…' : x; }
  function countBy(arr, keyFn) { const m = new Map(); for (const x of arr) { const k = keyFn(x); m.set(k, (m.get(k)||0)+1); } return [...m.entries()].sort((a,b)=>b[1]-a[1]); }
  function nodeColor(n) { return colorMap[n.type] || '#c9d1d9'; }
  function edgeColor(e) { return edgeColorMap[e.type] || '#42526b'; }
  function degree(n) { return (bothEdges.get(n.id)||[]).length; }
  function radius(n) { return Math.max(4, Math.min(22, 4 + Math.sqrt(degree(n)+1)*2.4 + (n.type === 'Function' ? 2 : 0) + (n.type === 'SemanticFact' ? 1 : 0))); }
  function isFunction(n) { return n && n.type === 'Function' && n.attrs && n.attrs.defined !== false; }
  function initProject() {
    $('projectSub').textContent = `${manifest.project_name || 'project'} • backend: ${manifest.backend_used || 'unknown'} • ${nodes.length} nodes / ${edges.length} edges`;
    setupFilters(); setupQueries(); setupAgentQueryHistory(); renderQuality(); renderTopSignals();
    const countRows = nodes.find(n => n.type === 'Function' && n.name === 'count_rows') || nodes.find(n => n.type === 'Function');
    if (countRows) { state.selectedNode = countRows; state.selectedFunction = countRows.name; state.activeView = 'function'; }
    const initial = DATA.initial_query || {};
    if (initial && ['security_context','vulnerability_context','evidence_slice'].includes(String(initial.kind || '').toLowerCase())) {
      $('retrievalQuery').value = queryTextFromInitial(initial);
      runRetrievalQuery(false);
    } else {
      computeView(); fitView(); updatePanels();
    }
    loadExternalQueryViewFromUrl();
    loadAgentQueryIndex(true);
    setInterval(() => loadAgentQueryIndex(true), 3000);
    animate();
  }
  function setupFilters() {
    $('nodeTypeFilters').innerHTML = nodeTypes.map(t => `<label class="checkline"><span class="legend-left"><span class="swatch" style="background:${nodeColor({type:t})}"></span>${esc(t)}</span><input type="checkbox" checked data-node-type="${esc(t)}"></label>`).join('');
    $('edgeTypeFilters').innerHTML = edgeTypes.map(t => `<label class="checkline"><span class="legend-left"><span class="swatch" style="background:${edgeColor({type:t})}"></span>${esc(t)}</span><input type="checkbox" checked data-edge-type="${esc(t)}"></label>`).join('');
    document.querySelectorAll('[data-node-type]').forEach(cb => cb.addEventListener('change', ev => { const t = ev.target.dataset.nodeType; ev.target.checked ? state.nodeTypeEnabled.add(t) : state.nodeTypeEnabled.delete(t); computeView(false); }));
    document.querySelectorAll('[data-edge-type]').forEach(cb => cb.addEventListener('change', ev => { const t = ev.target.dataset.edgeType; ev.target.checked ? state.edgeTypeEnabled.add(t) : state.edgeTypeEnabled.delete(t); computeView(false); }));
  }
  function setupQueries() {
    const sel = $('queryExamples');
    sel.innerHTML = queryExamples.map((q,i)=>`<option value="${i}">${esc(q.name || q.kind)}</option>`).join('');
    function update() { const q = queryExamples[Number(sel.value)] || {}; $('queryText').value = q.cli || JSON.stringify(q); if (q.dashboard_query) $('retrievalQuery').value = q.dashboard_query; }
    sel.addEventListener('change', update); update();
    $('copyQueryBtn').onclick = () => copyText($('queryText').value);
  }
  function renderQuality() {
    const qm = manifest.quality_metrics || {}, warnings = manifest.quality_warnings || [];
    const joern = manifest.joern_available ? '<span class="good">available</span>' : '<span class="warn">unavailable/fallback</span>';
    let html = `<div class="meta-grid"><div class="key">Joern</div><div>${joern}</div><div class="key">Parser confidence</div><div>${esc(qm.parser_confidence_level || 'unknown')}</div><div class="key">Unresolved calls</div><div>${esc(qm.unresolved_calls || 0)}</div><div class="key">Known external calls</div><div>${esc(qm.known_external_call_edges || 0)}</div><div class="key">Duplicate-looking names</div><div>${esc(qm.duplicate_looking_names || 0)}</div><div class="key">Orphan statements</div><div>${esc(qm.orphan_statements || 0)}</div><div class="key">Nodes without lines</div><div>${esc(qm.nodes_without_source_lines || 0)}</div><div class="key">Comment facts</div><div>${esc(qm.semantic_facts_generated_from_comments || 0)}</div><div class="key">Fields</div><div>${esc(qm.fields || 0)}</div><div class="key">Field accesses</div><div>${esc(qm.field_accesses || 0)}</div><div class="key">Indirect calls</div><div>${esc(qm.indirect_calls || 0)}</div><div class="key">Suppressed shadowed globals</div><div>${esc(qm.shadowed_global_name_suppressed || 0)}</div><div class="key">Joern imported</div><div>${esc(qm.joern_imported_nodes || 0)} nodes / ${esc(qm.joern_imported_edges || 0)} edges</div><div class="key">Joern overlays</div><div>${esc(qm.joern_overlay_edges || 0)}</div></div>`;
    if (warnings.length) html += '<hr />' + warnings.slice(0,8).map(w => `<div class="pill warn">${esc(w.code || 'warning')}${w.count ? ': '+esc(w.count) : ''}</div><div>${esc(w.message || '')}</div>`).join('');
    $('qualityPanel').innerHTML = html;
  }
  function renderTopSignals() {
    const funcs = nodes.filter(n => n.type === 'Function').sort((a,b)=>degree(b)-degree(a)).slice(0,8);
    const called = countBy(edges.filter(e => e.type === 'CALLS' || e.type === 'CALLS_INDIRECT').map(e => nodeById.get(e.target)).filter(Boolean), n=>n.name || n.label).slice(0,8);
    const facts = countBy(nodes.filter(n => n.type === 'SemanticFact'), n => (n.attrs && (n.attrs.fact_type || n.attrs.rule_name)) || n.label).slice(0,10);
    $('topSignals').innerHTML = `<b>Top functions by degree</b><table class="table">${funcs.map(n=>`<tr><td>${esc(n.name||n.label)}</td><td>${degree(n)}</td></tr>`).join('')}</table><hr/><b>Most called functions</b><table class="table">${called.map(([k,v])=>`<tr><td>${esc(k)}</td><td>${v}</td></tr>`).join('')}</table><hr/><b>Semantic fact summary</b><table class="table">${facts.map(([k,v])=>`<tr><td>${esc(k)}</td><td>${v}</td></tr>`).join('')}</table>`;
  }
  function baseFilter(nodeset, edgeset) {
    const minD = Number($('degreeThreshold').value || 0);
    for (const id of [...nodeset]) { const n = nodeById.get(id); if (!n || !state.nodeTypeEnabled.has(n.type) || degree(n) < minD) nodeset.delete(id); }
    for (const id of [...edgeset]) { const e = edges.find(x => x.id === id); if (!e || !state.edgeTypeEnabled.has(e.type) || !nodeset.has(e.source) || !nodeset.has(e.target)) edgeset.delete(id); }
  }
  function addNode(nodeset, n) { if (n) nodeset.add(n.id || n); }
  function addEdgeWithEndpoints(nodeset, edgeset, e) { if (!e) return; nodeset.add(e.source); nodeset.add(e.target); edgeset.add(e.id); }
  function functionNode() {
    if (state.selectedNode && state.selectedNode.type === 'Function') return state.selectedNode;
    if (state.selectedFunction) return nodes.find(n => n.type === 'Function' && n.name === state.selectedFunction);
    return nodes.find(n => n.type === 'Function' && n.name === 'count_rows') || nodes.find(n => n.type === 'Function');
  }
  function fileNode() {
    if (state.selectedNode && state.selectedNode.type === 'File') return state.selectedNode;
    if (state.selectedNode && state.selectedNode.file) return nodes.find(n => n.type === 'File' && n.name === state.selectedNode.file);
    return nodes.find(n => n.type === 'File');
  }
  function expandNeighborhood(seedIds, depth, edgeTypeAllow=null, direction='both') {
    const nodeset = new Set(seedIds), edgeset = new Set(), q = [...seedIds].map(id => [id,0]);
    while (q.length) {
      const [id,d] = q.shift(); if (d >= depth) continue;
      let incident = [];
      if (direction === 'out' || direction === 'both') incident = incident.concat(outEdges.get(id) || []);
      if (direction === 'in' || direction === 'both') incident = incident.concat(inEdges.get(id) || []);
      for (const e of incident) {
        if (edgeTypeAllow && !edgeTypeAllow.has(e.type)) continue;
        const other = e.source === id ? e.target : e.source;
        edgeset.add(e.id);
        if (!nodeset.has(other)) { nodeset.add(other); q.push([other, d+1]); }
      }
    }
    return {nodeset, edgeset};
  }

  const DATA_EDGES = new Set(['FUNCTION_HAS_PARAMETER','FUNCTION_HAS_LOCAL','FILE_HAS_GLOBAL','USES_VARIABLE','DEFINES_VARIABLE','USES_GLOBAL','DEFINES_GLOBAL','USES_FIELD','DEFINES_FIELD','ACCESSES_FIELD','HAS_TYPE','TYPE_HAS_FIELD','CALLS_INDIRECT','DEF_USE','DATA_DEPENDS_ON']);
  const CFG_EDGES = new Set(['FUNCTION_HAS_STATEMENT','CFG_NEXT','CONTROLS','RETURNS']);
  const SEMANTIC_EDGES = new Set(['HAS_SEMANTIC_FACT','SEMANTICALLY_RELATED']);
  const JOERN_EDGES = new Set(['JOERN_OVERLAY','JOERN_AST','JOERN_CFG','JOERN_CDG','JOERN_DDG','JOERN_CALL','JOERN_REACHING_DEF','JOERN_EDGE']);
  const DEFAULT_RISK_TERMS = ['pointer','array','bounds','size','copy','read','write','allocation','free','null','return','guard'];
  const GUARD_TERMS = ['bounds','null','guard','check','sanitizer','error_return','return','size'];
  function asBool(x, def=true) { if (x === undefined || x === null || x === '') return def; return ['1','true','yes','on'].includes(String(x).toLowerCase()); }
  function asInt(x, def) { const n = Number(x); return Number.isFinite(n) ? n : def; }
  function parseValue(v) { v = String(v ?? '').trim().replace(/^['"]|['"]$/g, ''); if (/^\[.*\]$/.test(v)) return v.slice(1,-1).split(',').map(x=>x.trim().replace(/^['"]|['"]$/g,'')).filter(Boolean); if (/^(true|false)$/i.test(v)) return asBool(v); if (/^\d+$/.test(v)) return Number(v); return v; }
  function splitArgs(body) { const out=[]; let cur='', depth=0; for (const ch of body) { if (ch===',' && depth===0) { if (cur.trim()) out.push(cur.trim()); cur=''; continue; } cur+=ch; if (ch==='[') depth++; else if (ch===']') depth=Math.max(0, depth-1); } if (cur.trim()) out.push(cur.trim()); return out; }
  function parseDashboardQuery(text) {
    const raw = String(text || '').trim(); let kind='security_context', args={};
    const m = raw.match(/^\s*([A-Za-z_]\w*)\s*\((.*)\)\s*$/s);
    if (m) { kind=m[1]; for (const part of splitArgs(m[2])) { const eq=part.indexOf('='); if (eq>=0) args[part.slice(0,eq).trim().replace(/-/g,'_')] = parseValue(part.slice(eq+1)); else args.target_function = parseValue(part); } return {kind, args}; }
    for (const m2 of raw.matchAll(/([A-Za-z_][\w-]*)\s*=\s*([\w.\/\\:-]+)/g)) args[m2[1].replace(/-/g,'_')] = parseValue(m2[2]);
    if (!args.target_function && !args.target && !args.function) {
      const stop = new Set(['show','retrieve','context','vulnerability','security','for','function','target','with','called','calls','call','depth']);
      const words = raw.match(/[A-Za-z_]\w*/g) || [];
      const fn = words.find(w => !stop.has(w.toLowerCase()) && nodes.some(n=>n.type==='Function' && n.name===w));
      if (fn) args.target_function = fn;
    }
    if (args.function && !args.target_function) args.target_function = args.function;
    return {kind, args};
  }
  function queryTextFromInitial(q) {
    const k = q.kind || 'security_context'; const tf = q.target_function || q.target || state.selectedFunction || 'count_rows';
    if (k === 'security_context' || k === 'vulnerability_context' || k === 'evidence_slice') {
      return `security_context(target_function=${tf}, depth=${q.depth || 3}, call_depth=${q.call_depth || q.callDepth || 2}, data_depth=${q.data_depth || q.dataDepth || 3}, include_callers=${q.include_callers !== false}, include_headers=${q.include_headers !== false}, include_globals=${q.include_globals !== false}, include_joern=${q.include_joern !== false}, joern_limit=${q.joern_limit || q.joernLimit || 160}, max_nodes=${q.max_nodes || q.maxNodes || 520}, risk_terms=[${q.risk_terms || DEFAULT_RISK_TERMS}])`;
    }
    return `${k}(target_function=${tf}, depth=${q.depth || 2})`;
  }
  function findFunctionByName(name) { return nodes.find(n => n.type==='Function' && n.name===name && (!n.attrs || n.attrs.defined !== false)) || nodes.find(n => n.type==='Function' && n.name===name); }
  function functionFile(fn) { const e=(inEdges.get(fn.id)||[]).find(e=>e.type==='FILE_HAS_FUNCTION'); return e ? nodeById.get(e.source) : (fn.file ? nodes.find(n=>n.type==='File' && n.name===fn.file) : null); }
  function includeFileContext(file, ids, eids, includeHeaders=true, includeGlobals=true) { if (!file) return; ids.add(file.id); for (const e of outEdges.get(file.id)||[]) { if (['FILE_HAS_TYPE','FILE_HAS_MACRO'].includes(e.type)) addEdgeWithEndpoints(ids,eids,e); if (includeHeaders && e.type==='FILE_INCLUDES_FILE') addEdgeWithEndpoints(ids,eids,e); if (includeGlobals && e.type==='FILE_HAS_GLOBAL') addEdgeWithEndpoints(ids,eids,e); } for (const e of inEdges.get(file.id)||[]) if (e.type==='PROJECT_HAS_FILE') addEdgeWithEndpoints(ids,eids,e); }
  function includeJoernOverlay(ids, eids, limit=160, edgeLimit=500) {
    // Joern exports can be very dense. For dashboard retrieval, import a bounded
    // evidence overlay around already selected CodeKG nodes instead of flooding
    // the force layout with the whole raw CPG.
    if (limit <= 0) return;
    const seedIds = [...ids].filter(id => (nodeById.get(id)||{}).type !== 'JoernCPGNode' && !String(id).startsWith('joern:'));
    const selectedJoern = new Set();
    const overlayEdges = [];
    for (const id of seedIds) {
      for (const e of (bothEdges.get(id)||[])) {
        if (e.type !== 'JOERN_OVERLAY') continue;
        const other = e.source === id ? e.target : e.source;
        const on = nodeById.get(other);
        if (!on || on.type !== 'JoernCPGNode') continue;
        overlayEdges.push(e);
      }
    }
    overlayEdges.sort((a,b) => {
      const pa = joernPriority(nodeById.get(a.source), nodeById.get(a.target));
      const pb = joernPriority(nodeById.get(b.source), nodeById.get(b.target));
      return pb - pa;
    });
    for (const e of overlayEdges) {
      const other = (nodeById.get(e.source)||{}).type === 'JoernCPGNode' ? e.source : e.target;
      if (!selectedJoern.has(other) && selectedJoern.size >= limit) continue;
      selectedJoern.add(other); addEdgeWithEndpoints(ids,eids,e);
    }
    let added = 0;
    for (const jid of [...selectedJoern]) {
      for (const e of (bothEdges.get(jid)||[])) {
        if (added >= edgeLimit) return;
        if (!JOERN_EDGES.has(e.type) || e.type === 'JOERN_OVERLAY') continue;
        if (selectedJoern.has(e.source) && selectedJoern.has(e.target)) { addEdgeWithEndpoints(ids,eids,e); added++; }
      }
    }
  }
  function joernPriority(a,b) {
    const n = (a && a.type === 'JoernCPGNode') ? a : b;
    const x = JSON.stringify(n || {}).toLowerCase();
    let p = 0;
    if (x.includes('method') || x.includes('function')) p += 8;
    if (x.includes('call')) p += 7;
    if (x.includes('identifier') || x.includes('local')) p += 6;
    if (x.includes('control') || x.includes('return')) p += 5;
    if (x.includes('assignment') || x.includes('operator')) p += 4;
    if (x.includes('literal')) p += 1;
    return p;
  }
  function includeSemanticEvidence(fnName, ids, eids, terms=[]) { const lows=(terms||[]).map(x=>String(x).toLowerCase()); for (const n of nodes) { if (n.type!=='SemanticFact' || n.function!==fnName) continue; const hay=JSON.stringify(n).toLowerCase(); if (lows.length && !lows.some(t=>hay.includes(t)) && !GUARD_TERMS.some(t=>hay.includes(t))) continue; ids.add(n.id); const src=n.attrs && n.attrs.source_node_id; if (src && nodeById.has(src)) ids.add(src); for (const e of (bothEdges.get(n.id)||[])) if (SEMANTIC_EDGES.has(e.type)) addEdgeWithEndpoints(ids,eids,e); } }
  function includeFunctionBody(fn, ids, eids, opts) {
    ids.add(fn.id); includeFileContext(functionFile(fn), ids, eids, opts.includeHeaders, opts.includeGlobals);
    for (const e of outEdges.get(fn.id)||[]) if (['FUNCTION_HAS_PARAMETER','FUNCTION_HAS_LOCAL','FUNCTION_HAS_STATEMENT','AST_CHILD','RETURNS','CONTROLS','SEMANTICALLY_RELATED'].includes(e.type)) addEdgeWithEndpoints(ids,eids,e);
    for (const id of [...ids]) { const n=nodeById.get(id); if (!n || n.function!==fn.name) continue; for (const e of (bothEdges.get(id)||[])) if (DATA_EDGES.has(e.type)||CFG_EDGES.has(e.type)||SEMANTIC_EDGES.has(e.type)||['AST_CHILD','STATEMENT_CALLS'].includes(e.type)) addEdgeWithEndpoints(ids,eids,e); }
    includeSemanticEvidence(fn.name, ids, eids, opts.riskTerms);
    if (opts.includeGlobals) for (const id of [...ids]) { const n=nodeById.get(id); if (!n || n.function!==fn.name) continue; for (const e of outEdges.get(id)||[]) if (['USES_GLOBAL','DEFINES_GLOBAL'].includes(e.type)) addEdgeWithEndpoints(ids,eids,e); }
    if (opts.includeJoern) includeJoernOverlay(ids,eids, opts.joernLimit, opts.joernEdgeLimit);
  }
  function trimForVisualization(ids, eids, targetId, maxNodes=520) {
    if (!maxNodes || ids.size <= maxNodes) return {nodeset:new Set(ids), edgeset:new Set(eids), trimmed:false};
    const selected = new Set([targetId]);
    const candidates = [...ids].map(id => nodeById.get(id)).filter(Boolean).sort((a,b)=>nodeScore(b,targetId)-nodeScore(a,targetId));
    for (const n of candidates) {
      if (selected.size >= maxNodes) break;
      selected.add(n.id);
    }
    // Preserve endpoints for the most useful edges. Edges that introduce too many
    // low-value nodes are dropped rather than stretching the layout off-screen.
    const keptEdges = new Set();
    const eligibleEdges = [...eids].map(id=>edges.find(e=>e.id===id)).filter(Boolean).sort((a,b)=>edgeScore(b)-edgeScore(a));
    for (const e of eligibleEdges) {
      if (selected.has(e.source) && selected.has(e.target)) keptEdges.add(e.id);
    }
    return {nodeset:selected, edgeset:keptEdges, trimmed:true};
  }
  function nodeScore(n, targetId) {
    if (!n) return 0;
    let s = 0;
    if (n.id === targetId) s += 1000;
    const t = n.type || '';
    if (t === 'Function') s += 220;
    else if (['FunctionParameter','LocalVariable','GlobalVariable'].includes(t)) s += 180;
    else if (['Condition','Loop','ReturnStatement','Assignment','CallExpression','Statement'].includes(t)) s += 150;
    else if (t === 'SemanticFact') s += 140;
    else if (['File','Include','Macro','Type','Struct/Class'].includes(t)) s += 110;
    else if (t === 'JoernCPGNode') s += 50 + joernPriority(n, null);
    else s += 20;
    if (n.function === state.selectedFunction) s += 80;
    if ((n.name || '').toLowerCase() === String(state.selectedFunction || '').toLowerCase()) s += 80;
    s += Math.min(40, degree(n));
    return s;
  }
  function edgeScore(e) {
    if (!e) return 0;
    const priority = {CALLS:220, CALLS_INDIRECT:215, STATEMENT_CALLS:210, FUNCTION_HAS_STATEMENT:200, FUNCTION_HAS_PARAMETER:190, FUNCTION_HAS_LOCAL:185, FILE_HAS_GLOBAL:180, USES_GLOBAL:175, DEFINES_GLOBAL:175, USES_VARIABLE:170, DEFINES_VARIABLE:170, DEF_USE:165, DATA_DEPENDS_ON:165, HAS_SEMANTIC_FACT:160, CFG_NEXT:150, CONTROLS:145, RETURNS:145, FILE_HAS_FUNCTION:140, FILE_INCLUDES_FILE:125, FILE_HAS_MACRO:120, FILE_HAS_TYPE:120, JOERN_OVERLAY:80, JOERN_CALL:70, JOERN_CFG:65, JOERN_DDG:65, JOERN_CDG:65, JOERN_AST:55};
    return priority[e.type] || 10;
  }

  function securitySlice(args) {
    const target = args.target_function || args.target || args.function || state.selectedFunction || 'count_rows'; const fn=findFunctionByName(target); if (!fn) return {error:`Function not found: ${target}`, nodeset:new Set(), edgeset:new Set(), summary:null};
    const opts = { includeCallers: asBool(args.include_callers, true), includeHeaders: asBool(args.include_headers, true), includeGlobals: asBool(args.include_globals, true), includeJoern: asBool(args.include_joern, true), joernLimit: asInt(args.joern_limit || args.joernLimit, 160), joernEdgeLimit: asInt(args.joern_edge_limit || args.joernEdgeLimit, 500), maxNodes: asInt(args.max_nodes || args.maxNodes, 520), riskTerms: Array.isArray(args.risk_terms) ? args.risk_terms : DEFAULT_RISK_TERMS };
    const callDepth = asInt(args.call_depth || args.callDepth, 2); const dataDepth = asInt(args.data_depth || args.dataDepth, 3);
    const ids=new Set(), eids=new Set(), callees=new Set(), callers=new Set(), external=new Set(), visited=new Set([fn.id]);
    includeFunctionBody(fn, ids, eids, opts); const q=[[fn,0]];
    while (q.length) { const [cur,d]=q.shift(); if (d>=callDepth) continue; for (const e of outEdges.get(cur.id)||[]) { if (!['CALLS','CALLS_INDIRECT'].includes(e.type)) continue; addEdgeWithEndpoints(ids,eids,e); const via=e.attrs && e.attrs.via_statement; if (via && nodeById.has(via)) ids.add(via); const t=nodeById.get(e.target); if (!t) continue; if (e.type==='CALLS_INDIRECT') { ids.add(t.id); continue; } if (t.type==='Function' && (!t.attrs || t.attrs.defined !== false)) { callees.add(t.name||t.id); includeFunctionBody(t, ids, eids, opts); if (!visited.has(t.id)) { visited.add(t.id); q.push([t,d+1]); } } else external.add(t.name||t.label||t.id); } }
    if (opts.includeCallers) for (const e of inEdges.get(fn.id)||[]) if (e.type==='CALLS') { addEdgeWithEndpoints(ids,eids,e); const src=nodeById.get(e.source); if (src && src.type==='Function') { callers.add(src.name||src.id); includeFunctionBody(src, ids, eids, opts); } }
    const seeds=[...ids].filter(id => ['FunctionParameter','LocalVariable','GlobalVariable','Field','Statement','Assignment','ReturnStatement','Condition','Loop'].includes((nodeById.get(id)||{}).type)); const sub=expandNeighborhood(seeds.slice(0,250), Math.min(Math.max(dataDepth,1),6), new Set([...DATA_EDGES,'FUNCTION_HAS_STATEMENT','CFG_NEXT','HAS_SEMANTIC_FACT']), 'both'); for (const id of sub.nodeset) ids.add(id); for (const eid of sub.edgeset) eids.add(eid); if (opts.includeJoern) includeJoernOverlay(ids,eids, opts.joernLimit, opts.joernEdgeLimit);
    let subNodes=[...ids].map(id=>nodeById.get(id)).filter(Boolean), subEdges=edges.filter(e=>eids.has(e.id) && ids.has(e.source) && ids.has(e.target));
    const fullNodeCount = subNodes.length, fullEdgeCount = subEdges.length;
    const trimmed = trimForVisualization(ids, eids, fn.id, opts.maxNodes);
    ids.clear(); for (const id of trimmed.nodeset) ids.add(id);
    eids.clear(); for (const id of trimmed.edgeset) eids.add(id);
    subNodes=[...ids].map(id=>nodeById.get(id)).filter(Boolean); subEdges=edges.filter(e=>eids.has(e.id) && ids.has(e.source) && ids.has(e.target));
    const facts=subNodes.filter(n=>n.type==='SemanticFact'), guards=facts.filter(n=>GUARD_TERMS.some(t=>JSON.stringify(n).toLowerCase().includes(t))); const vars=[...new Set(subNodes.filter(n=>['FunctionParameter','LocalVariable','GlobalVariable'].includes(n.type)).map(n=>n.name).filter(Boolean))];
    return {nodeset:ids, edgeset:new Set(subEdges.map(e=>e.id)), summary:{target_function:target, node_count:subNodes.length, edge_count:subEdges.length, full_node_count:fullNodeCount, full_edge_count:fullEdgeCount, visual_trimmed:trimmed.trimmed, max_nodes:opts.maxNodes, functions:[...new Set(subNodes.filter(n=>n.type==='Function').map(n=>n.name).filter(Boolean))], callees:[...callees], callers:[...callers], external:[...external], variables:vars, semantic_fact_count:facts.length, guard_like_fact_count:guards.length, joern_overlay_nodes:subNodes.filter(n=>n.type==='JoernCPGNode').length, note:'Retrieval evidence only; no vulnerable/safe classification is made.'}};
  }
  function dashboardQuery(kind, args) {
    kind=String(kind||'security_context').toLowerCase();
    if (['security_context','vulnerability_context','evidence_slice'].includes(kind)) return securitySlice(args);
    const target=args.target_function||args.target||args.function||state.selectedFunction||'count_rows'; const fn=findFunctionByName(target);
    if (kind==='function_context' && fn) { const sub=expandNeighborhood([fn.id], asInt(args.depth,2), null, 'both'); return {nodeset:sub.nodeset, edgeset:sub.edgeset, summary:{target_function:target, node_count:sub.nodeset.size, edge_count:sub.edgeset.size}}; }
    if (kind==='call_neighborhood' && fn) { const sub=expandNeighborhood([fn.id], asInt(args.depth,2), new Set(['CALLS','CALLS_INDIRECT','STATEMENT_CALLS']), args.direction||'both'); return {nodeset:sub.nodeset, edgeset:sub.edgeset, summary:{target_function:target, node_count:sub.nodeset.size, edge_count:sub.edgeset.size}}; }
    if (kind==='semantic_facts' && fn) { const ids=new Set([fn.id]), eids=new Set(); includeSemanticEvidence(target, ids, eids, []); return {nodeset:ids, edgeset:eids, summary:{target_function:target, node_count:ids.size, edge_count:eids.size}}; }
    if (kind==='variable_flow' && fn) { const sym=args.symbol; const seeds=nodes.filter(n=>n.name===sym && (n.function===target || n.type==='GlobalVariable') && ['LocalVariable','FunctionParameter','GlobalVariable'].includes(n.type)).map(n=>n.id); const sub=expandNeighborhood(seeds, asInt(args.depth,4), new Set([...DATA_EDGES,'FUNCTION_HAS_STATEMENT']), 'both'); return {nodeset:sub.nodeset, edgeset:sub.edgeset, summary:{target_function:target, symbol:sym, node_count:sub.nodeset.size, edge_count:sub.edgeset.size}}; }
    if (kind==='risk_slice' && fn) { return securitySlice({...args, include_joern:false}); }
    if (kind==='file_context') { const file=nodes.find(n=>n.type==='File' && (n.name===args.file || String(n.name).endsWith(String(args.file||'')))); if (file) { const sub=expandNeighborhood([file.id], asInt(args.depth,2), null, 'both'); return {nodeset:sub.nodeset, edgeset:sub.edgeset, summary:{file:file.name, node_count:sub.nodeset.size, edge_count:sub.edgeset.size}}; } }
    return {error:`Unsupported or unresolved query: ${kind}`, nodeset:new Set(), edgeset:new Set(), summary:null};
  }

  function displayName(n) { return n ? `${n.type}: ${n.name || n.label || n.id}` : ''; }
  function currentAnchorNode() {
    const raw = String(($('relationAnchor') && $('relationAnchor').value) || '').trim();
    if (raw) {
      const n = resolveNodeInput(raw);
      if (n) return n;
    }
    if (state.retrievalSummary && state.retrievalSummary.target_function) {
      const f = findFunctionByName(state.retrievalSummary.target_function);
      if (f) return f;
    }
    const f = functionNode();
    if (f) return f;
    return nodes.find(n => n.type === 'Project') || nodes[0];
  }
  function resolveNodeInput(raw) {
    raw = String(raw || '').trim();
    if (!raw) return null;
    if (nodeById.has(raw)) return nodeById.get(raw);
    const lower = raw.toLowerCase();
    const scope = state.visibleNodeIds.size ? [...state.visibleNodeIds].map(id=>nodeById.get(id)).filter(Boolean) : nodes;
    return scope.find(n => String(n.name || '').toLowerCase() === lower)
      || scope.find(n => String(n.label || '').toLowerCase() === lower)
      || scope.find(n => String(n.id || '').toLowerCase() === lower)
      || scope.find(n => String(n.name || n.label || n.id || '').toLowerCase().includes(lower))
      || nodes.find(n => String(n.name || n.label || n.id || '').toLowerCase().includes(lower));
  }
  function relationWeight(e) {
    const p = {CALLS:1.0, CALLS_INDIRECT:1.0, STATEMENT_CALLS:1.05, FUNCTION_HAS_STATEMENT:1.05, FUNCTION_HAS_PARAMETER:.9, FUNCTION_HAS_LOCAL:.9, FILE_HAS_FUNCTION:1.15, FILE_HAS_GLOBAL:1.0, USES_GLOBAL:1.0, DEFINES_GLOBAL:1.0, USES_VARIABLE:1.0, DEFINES_VARIABLE:1.0, DEF_USE:.85, DATA_DEPENDS_ON:.9, HAS_SEMANTIC_FACT:.95, SEMANTICALLY_RELATED:1.0, CFG_NEXT:1.25, CONTROLS:1.1, RETURNS:1.1, AST_CHILD:1.65, FILE_INCLUDES_FILE:1.55, FILE_HAS_MACRO:1.35, FILE_HAS_TYPE:1.35, JOERN_OVERLAY:1.75, JOERN_CALL:1.1, JOERN_CFG:1.35, JOERN_DDG:1.1, JOERN_CDG:1.15, JOERN_REACHING_DEF:1.05, JOERN_AST:1.9, JOERN_EDGE:2.0};
    return p[e.type] || 1.8;
  }
  function shortestRelationPath(anchorId, targetId, allowedNodeIds=null, allowedEdgeIds=null) {
    if (!anchorId || !targetId || !nodeById.has(anchorId) || !nodeById.has(targetId)) return null;
    if (anchorId === targetId) return {nodeIds:[anchorId], edgeIds:[], steps:[], cost:0};
    const allowedNodes = allowedNodeIds || state.visibleNodeIds;
    const allowedEdges = allowedEdgeIds || state.visibleEdgeIds;
    const dist = new Map([[anchorId, 0]]), prev = new Map(), visited = new Set();
    const q = [anchorId];
    while (q.length) {
      q.sort((a,b)=>(dist.get(a)||Infinity)-(dist.get(b)||Infinity));
      const id = q.shift();
      if (visited.has(id)) continue;
      visited.add(id);
      if (id === targetId) break;
      for (const e of (bothEdges.get(id)||[])) {
        if (allowedEdges && allowedEdges.size && !allowedEdges.has(e.id)) continue;
        const other = e.source === id ? e.target : e.source;
        if (allowedNodes && allowedNodes.size && !allowedNodes.has(other)) continue;
        const nd = (dist.get(id)||0) + relationWeight(e);
        if (nd < (dist.get(other) ?? Infinity)) {
          dist.set(other, nd); prev.set(other, {from:id, edge:e.id}); q.push(other);
        }
      }
    }
    if (!prev.has(targetId)) return null;
    const nodeIds = [targetId], edgeIds = [], steps = [];
    let cur = targetId;
    while (cur !== anchorId) {
      const p = prev.get(cur); if (!p) return null;
      edgeIds.push(p.edge); nodeIds.push(p.from);
      const e = edgeById.get(p.edge);
      steps.push({from:p.from, edge:p.edge, to:cur, edgeType:e ? e.type : '', traversedReverse:e ? e.source !== p.from : false});
      cur = p.from;
    }
    nodeIds.reverse(); edgeIds.reverse(); steps.reverse();
    return {nodeIds, edgeIds, steps, cost:dist.get(targetId) || 0};
  }
  function explainRelationToNode(nodeOrId, fit=false) {
    const dest = typeof nodeOrId === 'string' ? resolveNodeInput(nodeOrId) : nodeOrId;
    const anchor = currentAnchorNode();
    if (!dest || !anchor) { renderRelationshipResult(null, 'Could not resolve anchor or target node.'); return; }
    let path = shortestRelationPath(anchor.id, dest.id, state.visibleNodeIds, state.visibleEdgeIds);
    let scope = 'visible graph';
    if (!path && state.retrievalNodeIds.size) {
      path = shortestRelationPath(anchor.id, dest.id, state.retrievalNodeIds, state.retrievalEdgeIds);
      scope = 'retrieval graph';
    }
    if (!path) path = shortestRelationPath(anchor.id, dest.id, null, null), scope = 'full graph fallback';
    if (!path) { clearRelationPath(false); renderRelationshipResult(null, `No path found between ${displayName(anchor)} and ${displayName(dest)}.`); return; }
    state.relationPathNodeIds = new Set(path.nodeIds);
    state.relationPathEdgeIds = new Set(path.edgeIds);
    state.relationPath = {anchorId: anchor.id, destId: dest.id, scope, ...path};
    state.selectedNode = dest; state.selectedEdge = null;
    $('relationAnchor').value = anchor.name || anchor.label || anchor.id;
    $('relationNodeInput').value = dest.name || dest.label || dest.id;
    renderRelationshipResult(state.relationPath, null);
    updatePanels();
    if (fit && state.relationPathOnly) fitView();
  }
  function clearRelationPath(update=true) {
    state.relationPathNodeIds = new Set(); state.relationPathEdgeIds = new Set(); state.relationPath = null; state.relationPathOnly = false;
    $('relationshipResult').innerHTML = 'No relationship path selected. Tip: run retrieval, then double-click any node.';
    if (update) { computeView(false); updatePanels(); }
  }
  function renderRelationshipResult(path, err) {
    if (err) { $('relationshipResult').innerHTML = `<span class="bad">${esc(err)}</span>`; return; }
    if (!path) return;
    const anchor = nodeById.get(path.anchorId), dest = nodeById.get(path.destId);
    const stepsHtml = path.steps.map(st => {
      const a=nodeById.get(st.from), b=nodeById.get(st.to), e=edgeById.get(st.edge);
      const arrow = st.traversedReverse ? '←' : '→';
      return `<div class="path-step"><span class="path-node">${esc(compact(a ? (a.name||a.label||a.id) : st.from, 38))}</span> <span class="path-edge">${esc(st.edgeType)} ${arrow}</span> <span class="path-node">${esc(compact(b ? (b.name||b.label||b.id) : st.to, 38))}</span>${e && e.attrs ? `<br><span class="small">${esc(compact(JSON.stringify(e.attrs), 110))}</span>` : ''}</div>`;
    }).join('');
    $('relationshipResult').innerHTML = `<b>Path to query target</b><br><span class="pill">anchor ${esc(anchor ? (anchor.name||anchor.label||anchor.id) : path.anchorId)}</span><span class="pill">selected ${esc(dest ? (dest.name||dest.label||dest.id) : path.destId)}</span><span class="pill">${path.edgeIds.length} hops</span><span class="pill">${esc(path.scope)}</span><hr/>${stepsHtml || '<span class="good">Selected node is the anchor.</span>'}<hr/><span class="small">Double-click another node to replace this path. Use <kbd>Path only</kbd> to hide all non-path evidence.</span>`;
  }
  function agentViewFetchPath(entry) {
    if (!entry) return '';
    if (entry.relative_path) return entry.relative_path;
    if (entry.path) return entry.path;
    if (entry.filename) return `../retrieval_views/${entry.filename}`;
    return '';
  }
  function agentViewKey(entry) { return String((entry && (entry.relative_path || entry.path || entry.filename || entry.label)) || ''); }
  function agentOptionLabel(entry, i) {
    const q = entry.query || {};
    const label = entry.label || `Q${i+1}`;
    const kind = entry.kind || q.kind || 'query';
    const target = q.target_function || q.target || q.file || q.symbol || '';
    const count = `${entry.node_count ?? entry.query_view_node_count ?? 0}n/${entry.edge_count ?? entry.query_view_edge_count ?? 0}e`;
    return `${label} · ${kind}${target ? ' · ' + target : ''} · ${count}`;
  }
  function renderAgentQueryDropdown(previousKey='') {
    const sel = $('agentQuerySelect');
    if (!sel) return;
    const views = state.agentQueryViews || [];
    if (!views.length) {
      sel.disabled = true;
      sel.innerHTML = '<option value="">No saved queries yet</option>';
      $('agentQueryStatus').textContent = 'Waiting for LLM-generated KG queries. The list refreshes automatically while the audit runs.';
      return;
    }
    sel.disabled = false;
    sel.innerHTML = views.map((v,i)=>`<option value="${i}">${esc(agentOptionLabel(v,i))}</option>`).join('');
    let idx = views.findIndex(v => agentViewKey(v) === previousKey);
    if (idx < 0) idx = views.length - 1;
    sel.value = String(idx);
    const updated = state.agentQueryIndexUpdatedAt ? new Date(state.agentQueryIndexUpdatedAt * 1000).toLocaleTimeString() : 'now';
    $('agentQueryStatus').textContent = `${views.length} saved LLM KG quer${views.length === 1 ? 'y' : 'ies'} available · last update ${updated}`;
  }
  async function loadAgentQueryIndex(silent=false) {
    const sel = $('agentQuerySelect');
    const previous = sel && !sel.disabled && sel.value !== '' && state.agentQueryViews[Number(sel.value)] ? agentViewKey(state.agentQueryViews[Number(sel.value)]) : '';
    try {
      const r = await fetch(`../retrieval_views/index.json?ts=${Date.now()}`, {cache:'no-store'});
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const idx = await r.json();
      const views = Array.isArray(idx.views) ? idx.views : [];
      state.agentQueryViews = views.filter(v => agentViewFetchPath(v));
      state.agentQueryIndexUpdatedAt = Number(idx.updated_at || idx.last_updated_at || 0) || Math.floor(Date.now()/1000);
      renderAgentQueryDropdown(previous);
      if (!state.externalQueryView && state.agentQueryViews.length) await loadSelectedAgentQueryView('details');
    } catch (err) {
      if (!silent) $('agentQueryStatus').textContent = `No retrieval view index yet (${err.message || err}). Waiting for the agent to issue KG queries.`;
      if (!state.agentQueryViews.length) renderAgentQueryDropdown(previous);
    }
  }
  function renderAgentQueryEvidence(view) {
    const diag = view.diagnostics || {};
    const preview = Array.isArray(view.preview_nodes) ? view.preview_nodes : [];
    const summary = view.evidence_summary || diag.evidence_summary || null;
    const snippets = preview.slice(0,10).map((n,i) => {
      const loc = [n.file, n.function, n.line_start ? `L${n.line_start}${n.line_end && n.line_end !== n.line_start ? '-' + n.line_end : ''}` : ''].filter(Boolean).join(' · ');
      return `<div class="snippet"><b>${i+1}. ${esc(n.type || 'Node')} · ${esc(n.name || n.id || '')}</b><br><span class="small">${esc(loc)}</span><code>${esc(n.text || '')}</code></div>`;
    }).join('');
    $('agentQueryEvidenceText').innerHTML = `${summary ? `<b>Evidence summary</b><pre>${esc(JSON.stringify(summary, null, 2))}</pre>` : ''}${snippets || '<span class="small">No source preview nodes were stored for this query.</span>'}`;
  }
  async function loadSelectedAgentQueryView(mode='details') {
    const sel = $('agentQuerySelect');
    if (!sel || sel.disabled || sel.value === '') return null;
    const entry = state.agentQueryViews[Number(sel.value)];
    if (!entry) return null;
    const path = agentViewFetchPath(entry);
    try {
      const r = await fetch(`${path}?ts=${Date.now()}`, {cache:'no-store'});
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const view = await r.json();
      state.externalQueryView = view;
      state.externalQueryText = view.query_text || JSON.stringify(view.query || {}, null, 2);
      $('agentQueryPanel').innerHTML = summarizeExternalQueryView(view);
      $('retrievalQuery').value = state.externalQueryText;
      renderAgentQueryEvidence(view);
      if (mode === 'highlight' || mode === 'filter') applyExternalQueryView(mode, true);
      else updateStatus();
      return view;
    } catch (err) {
      $('agentQueryPanel').innerHTML = `<span class="bad">Could not load selected agent query:</span><br>${esc(path)}<br>${esc(err.message || err)}`;
      return null;
    }
  }
  function setupAgentQueryHistory() {
    const sel = $('agentQuerySelect');
    if (sel) sel.addEventListener('change', () => loadSelectedAgentQueryView('details'));
    const refresh = $('agentRefreshQueriesBtn');
    if (refresh) refresh.onclick = () => loadAgentQueryIndex(false);
  }

  function summarizeExternalQueryView(view) {
    const q = view.query || {};
    const diag = view.diagnostics || {};
    const label = view.label || (`Q${view.round_index || ''}.${view.query_index || ''}`);
    const nodeCount = (view.node_ids || []).length || diag.retrieved_node_count || 0;
    const edgeCount = (view.edge_ids || []).length || diag.retrieved_edge_count || 0;
    const reason = view.reason || q.reason || 'No explicit LLM reason was recorded for this query.';
    const funcs = (diag.important_functions || []).slice(0, 10).map(x=>`<span class="pill">${esc(x)}</span>`).join('');
    const vars = (diag.important_variables || []).slice(0, 12).map(x=>`<span class="pill">${esc(x)}</span>`).join('');
    const nodeDist = Object.entries(diag.node_type_counts || {}).sort((a,b)=>b[1]-a[1]).slice(0,10).map(([k,v])=>`<span class="pill">${esc(k)} ${esc(v)}</span>`).join('');
    const edgeDist = Object.entries(diag.edge_type_counts || {}).sort((a,b)=>b[1]-a[1]).slice(0,10).map(([k,v])=>`<span class="pill">${esc(k)} ${esc(v)}</span>`).join('');
    return `<div class="title">${esc(label)} · ${esc(q.kind || view.kind || 'codekg query')}</div><div><b>Why queried:</b> ${esc(reason)}</div><div style="margin-top:6px"><b>Retrieved:</b> ${esc(nodeCount)} nodes / ${esc(edgeCount)} edges</div><div style="margin-top:6px"><b>Query:</b><pre>${esc(view.query_text || JSON.stringify(q, null, 2))}</pre></div><div style="margin-top:6px"><b>Important functions</b><br>${funcs || '<span class="small">none</span>'}</div><div style="margin-top:6px"><b>Important variables</b><br>${vars || '<span class="small">none</span>'}</div><div style="margin-top:6px"><b>Node distribution</b><br><div class="agent-query-metrics">${nodeDist || '<span class="small">none</span>'}</div></div><div style="margin-top:6px"><b>Edge type distribution</b><br><div class="agent-query-metrics">${edgeDist || '<span class="small">none</span>'}</div></div>`;
  }
  function applyExternalQueryView(mode='filter', fit=true) {
    const view = state.externalQueryView; if (!view) return;
    state.externalQueryMode = mode;
    state.retrievalNodeIds = new Set((view.node_ids || []).filter(id => nodeById.has(id)));
    state.retrievalEdgeIds = new Set((view.edge_ids || []).filter(id => edgeById.has(id)));
    state.retrievalSummary = view.diagnostics || null;
    state.relationPathNodeIds = new Set(); state.relationPathEdgeIds = new Set(); state.relationPath = null; state.relationPathOnly = false;
    state.activeView = mode === 'highlight' ? 'query_highlight' : 'retrieval_query';
    $('agentQueryCard').style.display = '';
    $('agentQueryPanel').innerHTML = summarizeExternalQueryView(view);
    renderAgentQueryEvidence(view);
    $('retrievalQuery').value = state.externalQueryText || JSON.stringify(view.query || {}, null, 2);
    $('retrievalResult').innerHTML = `<b>${esc(mode === 'highlight' ? 'Highlight mode' : 'Filter mode')}</b><br>${esc(state.retrievalNodeIds.size)} retrieved nodes / ${esc(state.retrievalEdgeIds.size)} retrieved edges from ${esc(view.label || 'agent query')}.`;
    computeView(true); if (fit) fitView(); updatePanels();
  }
  async function loadExternalQueryViewFromUrl() {
    const params = new URLSearchParams(window.location.search || '');
    const viewPath = params.get('query_view') || params.get('retrieval_view');
    if (!viewPath) return;
    try {
      const r = await fetch(viewPath, {cache:'no-store'});
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const view = await r.json();
      state.externalQueryView = view;
      state.externalQueryText = view.query_text || JSON.stringify(view.query || {}, null, 2);
      const mode = (params.get('mode') || view.mode || 'filter').toLowerCase() === 'highlight' ? 'highlight' : 'filter';
      applyExternalQueryView(mode, true);
    } catch (err) {
      $('agentQueryCard').style.display = '';
      $('agentQueryPanel').innerHTML = `<span class="bad">Could not load audit query view:</span><br>${esc(viewPath)}<br>${esc(err.message || err)}`;
    }
  }
  function renderRetrievalResult(res, kind) {
    if (res.error) { $('retrievalResult').innerHTML = `<span class="bad">${esc(res.error)}</span>`; return; }
    const s=res.summary||{}; const fnList=(s.functions||[]).slice(0,8).map(x=>`<span class="pill">${esc(x)}</span>`).join(''); const ext=(s.external||[]).slice(0,8).map(x=>`<span class="pill warn">${esc(x)}</span>`).join('');
    const trimNote = s.visual_trimmed ? `<br><span class="pill warn">visual subset ${esc(s.node_count)} / ${esc(s.full_node_count)} nodes</span><span class="pill warn">${esc(s.edge_count)} / ${esc(s.full_edge_count)} edges</span>` : '';
    $('retrievalResult').innerHTML = `<b>${esc(kind)}</b><br>${esc(s.node_count ?? res.nodeset.size)} nodes / ${esc(s.edge_count ?? res.edgeset.size)} edges${trimNote}<br><span class="pill">facts ${esc(s.semantic_fact_count || 0)}</span><span class="pill">guards ${esc(s.guard_like_fact_count || 0)}</span><span class="pill">joern ${esc(s.joern_overlay_nodes || 0)}</span><hr/><b>Functions</b><br>${fnList || '<span class="small">none</span>'}<hr/><b>External/unresolved calls</b><br>${ext || '<span class="small">none</span>'}<hr/>${esc(s.note || 'Retrieval evidence only.')}`;
  }
  function runRetrievalQuery(fit=true) { const parsed=parseDashboardQuery($('retrievalQuery').value); const res=dashboardQuery(parsed.kind, parsed.args); state.externalQueryMode='filter'; state.retrievalNodeIds = res.nodeset || new Set(); state.retrievalEdgeIds = res.edgeset || new Set(); state.retrievalSummary = res.summary || null; state.relationPathNodeIds = new Set(); state.relationPathEdgeIds = new Set(); state.relationPath = null; state.relationPathOnly = false; state.activeView='retrieval_query'; if (state.retrievalSummary && state.retrievalSummary.target_function) { state.selectedFunction=state.retrievalSummary.target_function; $('relationAnchor').value = state.retrievalSummary.target_function; } $('relationshipResult').innerHTML='Retrieval ready. Double-click a node, click Explain selected, or type a node id/name to explain its path to the target.'; renderRetrievalResult(res, parsed.kind); computeView(true); if (fit) fitView(); }

  function computeView(reheat=true) {
    let nodeset = new Set(), edgeset = new Set();
    const depth = Number($('depthSelect').value || 2);
    const selected = state.selectedNode;
    const f = functionNode();
    if (state.activeView === 'retrieval_query') {
      nodeset = new Set(state.retrievalNodeIds); edgeset = new Set(state.retrievalEdgeIds);
    } else if (state.activeView === 'query_highlight') {
      const priority = nodes.filter(n => ['Project','File','Function','Struct/Class','SemanticFact'].includes(n.type)).sort((a,b)=>degree(b)-degree(a)).slice(0, Math.min(260, nodes.length));
      priority.forEach(n => nodeset.add(n.id));
      for (const id of state.retrievalNodeIds) if (nodeById.has(id)) nodeset.add(id);
      for (const e of edges) {
        if (state.retrievalEdgeIds.has(e.id)) addEdgeWithEndpoints(nodeset, edgeset, e);
        else if (nodeset.has(e.source) && nodeset.has(e.target) && ['PROJECT_HAS_FILE','FILE_HAS_FUNCTION','FILE_HAS_TYPE','TYPE_HAS_FIELD','CALLS','CALLS_INDIRECT','SEMANTICALLY_RELATED'].includes(e.type)) edgeset.add(e.id);
      }
    } else if (state.activeView === 'project') {
      const priority = nodes.filter(n => ['Project','File','Function','Struct/Class','SemanticFact'].includes(n.type)).sort((a,b)=>degree(b)-degree(a)).slice(0, Math.min(350, nodes.length));
      priority.forEach(n => nodeset.add(n.id));
      for (const e of edges) if (nodeset.has(e.source) && nodeset.has(e.target) && ['PROJECT_HAS_FILE','FILE_HAS_FUNCTION','FILE_HAS_TYPE','TYPE_HAS_FIELD','CALLS','CALLS_INDIRECT','SEMANTICALLY_RELATED'].includes(e.type)) edgeset.add(e.id);
    } else if (state.activeView === 'file') {
      const file = fileNode(); if (file) { const sub = expandNeighborhood([file.id], 2, null, 'both'); nodeset = sub.nodeset; edgeset = sub.edgeset; }
    } else if (state.activeView === 'function') {
      if (f) { const sub = expandNeighborhood([f.id], depth, null, 'both'); nodeset = sub.nodeset; edgeset = sub.edgeset; }
    } else if (state.activeView === 'function_callees') {
      if (f) { const sub = expandNeighborhood([f.id], depth, new Set(['CALLS','CALLS_INDIRECT','STATEMENT_CALLS','FUNCTION_HAS_STATEMENT','HAS_SEMANTIC_FACT']), 'out'); nodeset = sub.nodeset; edgeset = sub.edgeset; }
    } else if (state.activeView === 'function_callers') {
      if (f) { const sub = expandNeighborhood([f.id], depth, new Set(['CALLS','CALLS_INDIRECT']), 'in'); nodeset = sub.nodeset; edgeset = sub.edgeset; }
    } else if (state.activeView === 'function_variables') {
      if (f) { const sub = expandNeighborhood([f.id], depth, new Set(['FUNCTION_HAS_PARAMETER','FUNCTION_HAS_LOCAL','USES_VARIABLE','DEFINES_VARIABLE','DEF_USE','DATA_DEPENDS_ON','FUNCTION_HAS_STATEMENT']), 'both'); nodeset = sub.nodeset; edgeset = sub.edgeset; }
    } else if (state.activeView === 'semantic' || state.activeView === 'risk') {
      const facts = nodes.filter(n => n.type === 'SemanticFact' && (!f || n.function === f.name));
      facts.forEach(n => nodeset.add(n.id)); if (f) nodeset.add(f.id);
      for (const fact of facts) for (const e of bothEdges.get(fact.id) || []) addEdgeWithEndpoints(nodeset, edgeset, e);
      if (state.activeView === 'risk') for (const n of [...nodeset]) { const x = nodeById.get(n); if (x && !['Function','Statement','Assignment','ReturnStatement','Condition','Loop','CallExpression','SemanticFact'].includes(x.type)) nodeset.delete(n); }
    } else if (state.activeView === 'callgraph') {
      nodes.filter(n => n.type === 'Function').forEach(n => nodeset.add(n.id)); edges.filter(e => e.type === 'CALLS' || e.type === 'CALLS_INDIRECT').forEach(e => addEdgeWithEndpoints(nodeset, edgeset, e));
    } else if (state.activeView === 'cfg') {
      const sub = f ? expandNeighborhood([f.id], depth+1, new Set(['FUNCTION_HAS_STATEMENT','CFG_NEXT','CONTROLS','RETURNS']), 'both') : {nodeset:new Set(), edgeset:new Set()}; nodeset = sub.nodeset; edgeset = sub.edgeset;
    } else if (state.activeView === 'ast') {
      const seed = f ? [f.id] : (fileNode() ? [fileNode().id] : []); const sub = expandNeighborhood(seed, depth+1, new Set(['AST_CHILD','FILE_HAS_FUNCTION','FUNCTION_HAS_STATEMENT','FUNCTION_HAS_PARAMETER','FUNCTION_HAS_LOCAL']), 'out'); nodeset = sub.nodeset; edgeset = sub.edgeset;
    } else if (state.activeView === 'dataflow') {
      const sub = f ? expandNeighborhood([f.id], depth+2, new Set(['FUNCTION_HAS_PARAMETER','FUNCTION_HAS_LOCAL','FUNCTION_HAS_STATEMENT','USES_VARIABLE','DEFINES_VARIABLE','DEF_USE','DATA_DEPENDS_ON']), 'both') : {nodeset:new Set(), edgeset:new Set()}; nodeset = sub.nodeset; edgeset = sub.edgeset;
    }
    if (state.search) {
      const s = state.search.toLowerCase();
      const matched = nodes.filter(n => matchesSearch(n, s));
      if (matched.length) {
        const sub = expandNeighborhood(matched.slice(0, 80).map(n=>n.id), Math.max(1, Math.min(depth,2)), null, 'both');
        for (const id of sub.nodeset) nodeset.add(id); for (const id of sub.edgeset) edgeset.add(id);
      }
    }
    if (state.relationPathOnly && state.relationPathNodeIds.size) {
      nodeset = new Set(state.relationPathNodeIds);
      edgeset = new Set(state.relationPathEdgeIds);
    }
    baseFilter(nodeset, edgeset);
    // Keep endpoints for visible edges.
    for (const e of edges) if (edgeset.has(e.id)) { nodeset.add(e.source); nodeset.add(e.target); }
    state.visibleNodeIds = nodeset; state.visibleEdgeIds = edgeset;
    if (reheat) layoutVisible();
    updatePanels();
  }
  function matchesSearch(n, s) {
    if (!s) return false;
    const attrs = JSON.stringify(n.attrs || {}).toLowerCase();
    const hay = [n.id, n.type, n.label, n.name, n.file, n.function, n.line_start, n.line_end, n.code, attrs].join(' ').toLowerCase();
    if (hay.includes(s)) return true;
    return edges.some(e => (e.type || '').toLowerCase().includes(s) && (e.source === n.id || e.target === n.id));
  }
  function layoutVisible() {
    const vis = [...state.visibleNodeIds].map(id => nodeById.get(id)).filter(Boolean);
    const W = canvas.clientWidth || 900, H = canvas.clientHeight || 700;
    if (!vis.length) return;
    if (state.activeView === 'retrieval_query' || vis.length > 450) return layoutRetrievalStable(vis, W, H);
    const groups = new Map();
    for (const n of vis) { const g = n.file || n.type; if (!groups.has(g)) groups.set(g, groups.size); }
    vis.forEach((n, i) => {
      if (n.pinned && isFinite(n.x)) return;
      const gi = groups.get(n.file || n.type) || 0;
      const angle = (2*Math.PI * gi / Math.max(1, groups.size)) + (i % 7)*0.05;
      const ring = Math.min(W,H) * (0.18 + 0.25*((i%11)/11));
      n.x = Math.cos(angle)*ring + stableJitter(n.id, 80, 1);
      n.y = Math.sin(angle)*ring + stableJitter(n.id, 80, 2);
      n.vx = 0; n.vy = 0;
    });
    state.simulationTicks = 160;
  }
  function layoutRetrievalStable(vis, W, H) {
    const target = functionNode();
    const targetId = target && state.visibleNodeIds.has(target.id) ? target.id : (vis.find(n=>n.type==='Function')||vis[0]).id;
    const rings = {
      core: 0,
      variables: 155,
      statements: 280,
      semantic: 405,
      calls: 545,
      files: 660,
      joern: 760,
      other: 860
    };
    const buckets = new Map();
    for (const n of vis) {
      let b = 'other';
      if (n.id === targetId) b = 'core';
      else if (['FunctionParameter','LocalVariable','GlobalVariable'].includes(n.type)) b = 'variables';
      else if (['Statement','Assignment','ReturnStatement','Condition','Loop','CallExpression'].includes(n.type)) b = 'statements';
      else if (n.type === 'SemanticFact') b = 'semantic';
      else if (n.type === 'Function') b = 'calls';
      else if (['File','Include','Macro','Type','Struct/Class'].includes(n.type)) b = 'files';
      else if (n.type === 'JoernCPGNode') b = 'joern';
      if (!buckets.has(b)) buckets.set(b, []);
      buckets.get(b).push(n);
    }
    for (const [b, arr] of buckets.entries()) {
      arr.sort((a,b)=>nodeScore(b,targetId)-nodeScore(a,targetId));
      const R = rings[b] || rings.other;
      const start = bucketAngle(b);
      for (let i=0; i<arr.length; i++) {
        const n = arr[i]; if (n.pinned && isFinite(n.x)) continue;
        if (b === 'core') { n.x = 0; n.y = 0; }
        else {
          const layers = Math.max(1, Math.ceil(arr.length / 44));
          const layer = Math.floor(i / 44);
          const indexInLayer = i % 44;
          const countInLayer = Math.min(44, arr.length - layer*44);
          const angle = start + (2*Math.PI * indexInLayer / Math.max(1,countInLayer)) + layer*0.17;
          const rr = R + layer*78 + stableJitter(n.id, 22, 3);
          n.x = Math.cos(angle)*rr + stableJitter(n.id, 28, 1);
          n.y = Math.sin(angle)*rr + stableJitter(n.id, 28, 2);
        }
        n.vx = 0; n.vy = 0;
      }
    }
    state.simulationTicks = Math.min(70, Math.max(20, Math.floor(18000 / Math.max(80, vis.length))));
  }
  function bucketAngle(b) { return {variables:-2.75, statements:-1.8, semantic:-0.55, calls:0.65, files:1.65, joern:2.65, other:2.95}[b] || 0; }
  function stableJitter(id, amount, salt=0) { let h = 2166136261 + salt; const s=String(id||''); for (let i=0;i<s.length;i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return (((h >>> 0) / 4294967295) - .5) * amount; }
  function tickLayout() {
    if (state.simulationTicks <= 0) return;
    const vis = [...state.visibleNodeIds].map(id => nodeById.get(id)).filter(Boolean);
    const idx = new Map(vis.map((n,i)=>[n.id,i]));
    const visibleEdges = edges.filter(e => state.visibleEdgeIds.has(e.id) && idx.has(e.source) && idx.has(e.target));
    // Repulsion, O(n^2) but capped by default visible views.
    const maxN = Math.min(vis.length, 650);
    for (let i=0; i<maxN; i++) for (let j=i+1; j<maxN; j++) {
      const a=vis[i], b=vis[j]; let dx=a.x-b.x, dy=a.y-b.y; let d2=dx*dx+dy*dy+0.01;
      const min = 36 + radius(a) + radius(b); const force = Math.min(5, (min*min)/d2)*0.028;
      const d = Math.sqrt(d2); dx/=d; dy/=d;
      if (!a.pinned) { a.vx += dx*force; a.vy += dy*force; }
      if (!b.pinned) { b.vx -= dx*force; b.vy -= dy*force; }
    }
    for (const e of visibleEdges) {
      const a=nodeById.get(e.source), b=nodeById.get(e.target); if (!a || !b) continue;
      let dx=b.x-a.x, dy=b.y-a.y; const d=Math.sqrt(dx*dx+dy*dy)+0.01; const isJoern = String(e.type||'').startsWith('JOERN_'); const target=(e.type==='CALLS'||e.type==='CALLS_INDIRECT')?185:(isJoern?70:105); const k=isJoern?0.006:(e.type==='CFG_NEXT'?0.025:0.016);
      const f=Math.max(-4, Math.min(4, (d-target)*k)); dx/=d; dy/=d;
      if (!a.pinned) { a.vx += dx*f; a.vy += dy*f; }
      if (!b.pinned) { b.vx -= dx*f; b.vy -= dy*f; }
    }
    for (const n of vis) {
      if (n.pinned) continue;
      n.vx += -n.x*0.002; n.vy += -n.y*0.002;
      n.vx *= 0.74; n.vy *= 0.74; n.x += n.vx; n.y += n.vy;
      const limit = state.activeView === 'retrieval_query' ? 1800 : 2600;
      if (n.x > limit) { n.x = limit; n.vx *= -.2; } else if (n.x < -limit) { n.x = -limit; n.vx *= -.2; }
      if (n.y > limit) { n.y = limit; n.vy *= -.2; } else if (n.y < -limit) { n.y = -limit; n.vy *= -.2; }
    }
    state.simulationTicks--;
  }
  function resize() { const dpr = window.devicePixelRatio || 1; const r = canvas.getBoundingClientRect(); canvas.width = Math.max(1, Math.floor(r.width*dpr)); canvas.height = Math.max(1, Math.floor(r.height*dpr)); ctx.setTransform(dpr,0,0,dpr,0,0); }
  window.addEventListener('resize', () => { resize(); draw(); }); resize();
  function worldToScreen(p) { return {x: p.x*state.transform.scale + state.transform.x, y: p.y*state.transform.scale + state.transform.y}; }
  function screenToWorld(p) { return {x: (p.x-state.transform.x)/state.transform.scale, y: (p.y-state.transform.y)/state.transform.scale}; }

  function pathModeActive() { return state.relationPathNodeIds && state.relationPathNodeIds.size > 0; }
  function nodePathAlpha(n) {
    if (!pathModeActive()) return n.type === 'Comment' ? .42 : .95;
    if (state.relationPathNodeIds.has(n.id)) return .98;
    const nearPath = (bothEdges.get(n.id)||[]).some(e => state.relationPathNodeIds.has(e.source) || state.relationPathNodeIds.has(e.target));
    return nearPath ? .24 : .075;
  }
  function edgePathAlpha(e) {
    if (!pathModeActive()) return e.type === 'AST_CHILD' ? 0.22 : 0.52;
    if (state.relationPathEdgeIds.has(e.id)) return .98;
    if (state.relationPathNodeIds.has(e.source) && state.relationPathNodeIds.has(e.target)) return .28;
    return .045;
  }
  function queryHighlightActive() { return state.activeView === 'query_highlight' && state.retrievalNodeIds && state.retrievalNodeIds.size > 0; }
  function queryNodeAlpha(n) { if (!queryHighlightActive()) return nodePathAlpha(n); return state.retrievalNodeIds.has(n.id) ? .98 : .20; }
  function queryEdgeAlpha(e) { if (!queryHighlightActive()) return edgePathAlpha(e); return state.retrievalEdgeIds.has(e.id) ? .90 : .12; }
  function draw() {
    const W = canvas.clientWidth, H = canvas.clientHeight;
    ctx.clearRect(0,0,W,H);
    ctx.save(); ctx.translate(state.transform.x, state.transform.y); ctx.scale(state.transform.scale, state.transform.scale);
    const visibleEdges = edges.filter(e => state.visibleEdgeIds.has(e.id));
    ctx.lineCap='round'; ctx.lineJoin='round';
    for (const e of visibleEdges) {
      const a=nodeById.get(e.source), b=nodeById.get(e.target); if (!a || !b) continue;
      const selected = state.selectedEdge && state.selectedEdge.id === e.id;
      ctx.beginPath(); ctx.moveTo(a.x, a.y);
      const mx=(a.x+b.x)/2, my=(a.y+b.y)/2; const dx=b.x-a.x, dy=b.y-a.y; const norm=Math.sqrt(dx*dx+dy*dy)+0.01; const curve=((e.type==='CALLS'||e.type==='CALLS_INDIRECT')?24:8);
      ctx.quadraticCurveTo(mx - dy/norm*curve, my + dx/norm*curve, b.x, b.y);
      const pathEdge = state.relationPathEdgeIds.has(e.id);
      ctx.strokeStyle = selected ? '#111827' : pathEdge ? '#b45309' : state.retrievalEdgeIds.has(e.id) ? '#2563eb' : edgeColor(e);
      ctx.globalAlpha = selected ? 0.95 : queryEdgeAlpha(e);
      ctx.lineWidth = selected ? 3.2/state.transform.scale : pathEdge ? 4.2/state.transform.scale : state.retrievalEdgeIds.has(e.id) ? 3.0/state.transform.scale : ((e.type==='CALLS'||e.type==='CALLS_INDIRECT')?1.8:1.0)/state.transform.scale;
      if (['DEF_USE','DATA_DEPENDS_ON'].includes(e.type)) ctx.setLineDash([5/state.transform.scale,5/state.transform.scale]); else ctx.setLineDash([]);
      ctx.stroke(); ctx.setLineDash([]);
    }
    ctx.globalAlpha = 1;
    const visibleNodes = [...state.visibleNodeIds].map(id => nodeById.get(id)).filter(Boolean).sort((a,b)=>radius(a)-radius(b));
    for (const n of visibleNodes) {
      const r = radius(n); const selected = state.selectedNode && state.selectedNode.id === n.id; const hover = state.hoverNode && state.hoverNode.id === n.id; const matched = state.search && matchesSearch(n, state.search.toLowerCase()); const pathNode = state.relationPathNodeIds.has(n.id);
      ctx.beginPath(); ctx.arc(n.x, n.y, r + (selected?4:pathNode?3:0), 0, Math.PI*2);
      ctx.globalAlpha = pathModeActive() && !pathNode ? .18 : 1;
      ctx.fillStyle = selected ? 'rgba(37,99,235,.18)' : pathNode ? 'rgba(180,83,9,.16)' : state.retrievalNodeIds.has(n.id) ? 'rgba(37,99,235,.14)' : hover ? 'rgba(37,99,235,.10)' : 'rgba(15,23,42,.06)'; ctx.fill(); ctx.globalAlpha = 1;
      ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI*2); ctx.fillStyle = nodeColor(n); ctx.globalAlpha = queryNodeAlpha(n); ctx.fill(); ctx.globalAlpha = 1;
      ctx.strokeStyle = selected ? '#111827' : pathNode ? '#b45309' : state.retrievalNodeIds.has(n.id) ? '#2563eb' : matched ? '#b45309' : 'rgba(15,23,42,.30)'; ctx.lineWidth = (selected||matched||pathNode||state.retrievalNodeIds.has(n.id)?2.7:1)/state.transform.scale; ctx.stroke();
      if (n.pinned) { ctx.beginPath(); ctx.arc(n.x+r*.55, n.y-r*.55, Math.max(2, r*.25), 0, Math.PI*2); ctx.fillStyle='#111827'; ctx.fill(); }
      const showLabel = selected || hover || matched || pathNode || state.transform.scale > .85 || (n.type === 'Function' && degree(n) > 2) || n.type === 'Project';
      if (showLabel) { ctx.font = `${Math.max(10, 12/state.transform.scale)}px ui-sans-serif, system-ui`; ctx.fillStyle = 'rgba(15,23,42,.92)'; ctx.textAlign='center'; ctx.fillText(compact(n.name || n.label || n.id, 28), n.x, n.y + r + 13/state.transform.scale); }
    }
    ctx.restore();
  }
  function animate() { tickLayout(); draw(); requestAnimationFrame(animate); }
  function fitView() {
    const vis = [...state.visibleNodeIds].map(id => nodeById.get(id)).filter(Boolean); if (!vis.length) return;
    const xs = vis.map(n=>n.x), ys=vis.map(n=>n.y); const minX=Math.min(...xs), maxX=Math.max(...xs), minY=Math.min(...ys), maxY=Math.max(...ys);
    const W=canvas.clientWidth, H=canvas.clientHeight; const pad=110; const minScale = state.activeView === 'retrieval_query' ? .055 : .12; const maxScale = state.activeView === 'retrieval_query' ? 1.0 : 1.4; const scale=Math.min(maxScale, Math.max(minScale, Math.min((W-pad)/(maxX-minX+1), (H-pad)/(maxY-minY+1))));
    state.transform.scale=scale; state.transform.x=W/2 - (minX+maxX)/2*scale; state.transform.y=H/2 - (minY+maxY)/2*scale;
  }
  function nearestNode(pos) {
    const w = screenToWorld(pos); let best=null, bd=Infinity;
    for (const id of state.visibleNodeIds) { const n=nodeById.get(id); const d=Math.hypot(n.x-w.x,n.y-w.y); const rr=radius(n)+8/state.transform.scale; if (d<rr && d<bd) { best=n; bd=d; } }
    return best;
  }
  function distToSegment(px,py,x1,y1,x2,y2) { const dx=x2-x1, dy=y2-y1; const l2=dx*dx+dy*dy; if (!l2) return Math.hypot(px-x1,py-y1); let t=((px-x1)*dx+(py-y1)*dy)/l2; t=Math.max(0,Math.min(1,t)); return Math.hypot(px-(x1+t*dx), py-(y1+t*dy)); }
  function nearestEdge(pos) { const w=screenToWorld(pos); let best=null, bd=10/state.transform.scale; for (const id of state.visibleEdgeIds) { const e=edges.find(x=>x.id===id); const a=nodeById.get(e.source), b=nodeById.get(e.target); if (!a||!b) continue; const d=distToSegment(w.x,w.y,a.x,a.y,b.x,b.y); if (d<bd) { best=e; bd=d; } } return best; }
  canvas.addEventListener('mousedown', ev => { const pos=mouse(ev); state.lastMouse=pos; const n=nearestNode(pos); if (n) { state.dragNode=n; n.pinned=true; } else state.dragging=true; });
  canvas.addEventListener('mousemove', ev => { const pos=mouse(ev); const w=screenToWorld(pos); if (state.dragNode) { state.dragNode.x=w.x; state.dragNode.y=w.y; state.dragNode.vx=0; state.dragNode.vy=0; } else if (state.dragging) { state.transform.x += pos.x-state.lastMouse.x; state.transform.y += pos.y-state.lastMouse.y; } else { state.hoverNode = nearestNode(pos); state.hoverEdge = state.hoverNode ? null : nearestEdge(pos); }
    state.lastMouse=pos; updateStatus(); });
  window.addEventListener('mouseup', () => { state.dragging=false; state.dragNode=null; });
  canvas.addEventListener('click', ev => { const pos=mouse(ev); const n=nearestNode(pos); if (n) { state.selectedNode=n; state.selectedEdge=null; if (n.type==='Function') state.selectedFunction=n.name; if (n.type==='File') state.selectedFile=n.name; updatePanels(); return; } const e=nearestEdge(pos); if (e) { state.selectedEdge=e; state.selectedNode=null; updatePanels(); }});
  canvas.addEventListener('dblclick', ev => { ev.preventDefault(); const pos=mouse(ev); const n=nearestNode(pos); if (n) explainRelationToNode(n, false); });
  canvas.addEventListener('wheel', ev => { ev.preventDefault(); const pos=mouse(ev); const before=screenToWorld(pos); const factor=Math.exp(-ev.deltaY*0.001); state.transform.scale=Math.max(.05, Math.min(4, state.transform.scale*factor)); const after=screenToWorld(pos); state.transform.x += (after.x-before.x)*state.transform.scale; state.transform.y += (after.y-before.y)*state.transform.scale; }, {passive:false});
  function mouse(ev) { const r=canvas.getBoundingClientRect(); return {x: ev.clientX-r.left, y: ev.clientY-r.top}; }
  function updateStatus() { const h = state.hoverNode ? `${state.hoverNode.type}: ${state.hoverNode.name || state.hoverNode.label}` : state.hoverEdge ? `${state.hoverEdge.type}` : `${state.visibleNodeIds.size} nodes / ${state.visibleEdgeIds.size} edges`; const path = state.relationPath ? ` • path ${state.relationPath.edgeIds.length} hops` : ''; $('statusBar').textContent = `${state.activeView} • ${h}${path}`; }
  function updatePanels() {
    $('nodeCount').textContent = state.visibleNodeIds.size; $('edgeCount').textContent = state.visibleEdgeIds.size; updateStatus();
    const nodeDist = countBy([...state.visibleNodeIds].map(id=>nodeById.get(id)).filter(Boolean), n=>n.type).slice(0,8);
    const edgeDist = countBy([...state.visibleEdgeIds].map(id=>edges.find(e=>e.id===id)).filter(Boolean), e=>e.type).slice(0,8);
    $('metricsList').innerHTML = `<b>Node type distribution</b><br>${nodeDist.map(([k,v])=>`<span class="pill">${esc(k)} ${v}</span>`).join('')}<hr/><b>Edge type distribution</b><br>${edgeDist.map(([k,v])=>`<span class="pill">${esc(k)} ${v}</span>`).join('')}`;
    if (state.selectedNode) renderNodeDetails(state.selectedNode); else if (state.selectedEdge) renderEdgeDetails(state.selectedEdge); else { $('selectionDetails').innerHTML = 'Click a node or edge.'; $('codePreview').textContent = 'No source selected.'; $('neighborhoodTable').innerHTML = ''; }
  }
  function attrsHtml(attrs) { if (!attrs) return ''; return Object.entries(attrs).map(([k,v])=>`<div class="key">${esc(k)}</div><div>${esc(typeof v === 'object' ? JSON.stringify(v) : v)}</div>`).join(''); }
  function renderNodeDetails(n) {
    $('selectionDetails').innerHTML = `<div class="meta-grid"><div class="key">id</div><div>${esc(n.id)}</div><div class="key">type</div><div>${esc(n.type)}</div><div class="key">name</div><div>${esc(n.name || n.label || '')}</div><div class="key">file</div><div>${esc(n.file || '')}</div><div class="key">function</div><div>${esc(n.function || '')}</div><div class="key">lines</div><div>${esc((n.line_start || '') + (n.line_end ? '-' + n.line_end : ''))}</div><div class="key">degree</div><div>${degree(n)}</div>${attrsHtml(n.attrs)}</div>`;
    $('codePreview').textContent = n.code || 'No source snippet available.';
    const inc = (bothEdges.get(n.id)||[]).slice(0,40).map(e => { const other = nodeById.get(e.source === n.id ? e.target : e.source); const mark = state.relationPathEdgeIds.has(e.id) ? ' ★' : ''; return `<tr><td>${esc(e.type + mark)}</td><td>${esc(other ? (other.type + ': ' + (other.name || other.label || other.id)) : '')}</td></tr>`; }).join('');
    const rel = state.relationPath && state.relationPathNodeIds.has(n.id) ? `<div class="pathbox"><b>On highlighted path</b><br>${esc(state.relationPath.edgeIds.length)} hops from anchor to selected evidence node.</div>` : '';
    $('neighborhoodTable').innerHTML = `${rel}<table class="table"><tr><th>edge</th><th>neighbor</th></tr>${inc}</table>`;
  }
  function renderEdgeDetails(e) {
    const s=nodeById.get(e.source), t=nodeById.get(e.target);
    $('selectionDetails').innerHTML = `<div class="meta-grid"><div class="key">id</div><div>${esc(e.id)}</div><div class="key">type</div><div>${esc(e.type)}</div><div class="key">source</div><div>${esc(s ? s.type + ': ' + (s.name || s.label || s.id) : e.source)}</div><div class="key">target</div><div>${esc(t ? t.type + ': ' + (t.name || t.label || t.id) : e.target)}</div>${attrsHtml(e.attrs)}</div>`;
    $('codePreview').textContent = [s && s.code ? `SOURCE NODE SNIPPET:\n${s.code}` : '', t && t.code ? `\nTARGET NODE SNIPPET:\n${t.code}` : ''].filter(Boolean).join('\n') || 'No source snippet available.';
    $('neighborhoodTable').innerHTML = '';
  }
  function copyText(txt) { navigator.clipboard?.writeText(txt).then(()=>{ $('statusBar').textContent='Copied.'; }).catch(()=>{ $('statusBar').textContent='Copy failed.'; }); }
  $('agentHighlightBtn').onclick = () => loadSelectedAgentQueryView('highlight').then(v => { if (!v && state.externalQueryView) applyExternalQueryView('highlight', true); });
  $('agentFilterBtn').onclick = () => loadSelectedAgentQueryView('filter').then(v => { if (!v && state.externalQueryView) applyExternalQueryView('filter', true); });
  $('agentCopyQueryBtn').onclick = () => copyText(state.externalQueryText || $('retrievalQuery').value || '');
  $('runRetrievalQueryBtn').onclick = () => runRetrievalQuery(true);
  $('retrievalQuery').addEventListener('keydown', ev => { if ((ev.ctrlKey || ev.metaKey) && ev.key === 'Enter') runRetrievalQuery(true); });
  $('clearRetrievalQueryBtn').onclick = () => { state.retrievalNodeIds=new Set(); state.retrievalEdgeIds=new Set(); state.retrievalSummary=null; clearRelationPath(false); $('retrievalResult').innerHTML='Retrieval slice cleared.'; state.activeView='function'; computeView(true); fitView(); };
  $('searchBtn').onclick = () => { state.search = $('searchBox').value.trim(); computeView(true); };
  $('searchBox').addEventListener('keydown', ev => { if (ev.key === 'Enter') $('searchBtn').click(); });
  $('clearSearchBtn').onclick = () => { $('searchBox').value=''; state.search=''; computeView(true); };
  $('degreeThreshold').addEventListener('change', () => computeView(false)); $('depthSelect').addEventListener('change', () => computeView(true));
  document.querySelectorAll('[data-view]').forEach(b => b.onclick = () => { state.relationPathOnly=false; $('focusPathBtn').textContent='Path only'; state.activeView=b.dataset.view; computeView(true); fitView(); });
  $('resetBtn').onclick = () => { state.activeView='project'; state.search=''; $('searchBox').value=''; state.retrievalNodeIds=new Set(); state.retrievalEdgeIds=new Set(); state.retrievalSummary=null; clearRelationPath(false); computeView(true); fitView(); };
  $('fitBtn').onclick = fitView;
  $('expand1Btn').onclick = () => expandSelected(1); $('expand2Btn').onclick = () => expandSelected(2);
  $('isolateBtn').onclick = () => { if (!state.selectedNode) return; state.visibleNodeIds=new Set([state.selectedNode.id]); state.visibleEdgeIds=new Set(); layoutVisible(); fitView(); updatePanels(); };
  $('pinBtn').onclick = () => { if (state.selectedNode) state.selectedNode.pinned = !state.selectedNode.pinned; };
  $('unpinBtn').onclick = () => { nodes.forEach(n=>n.pinned=false); state.simulationTicks=120; };
  function expandSelected(depth) { if (!state.selectedNode) return; const sub=expandNeighborhood([state.selectedNode.id], depth, null, 'both'); for (const id of sub.nodeset) state.visibleNodeIds.add(id); for (const id of sub.edgeset) state.visibleEdgeIds.add(id); baseFilter(state.visibleNodeIds, state.visibleEdgeIds); state.simulationTicks=120; updatePanels(); }
  $('explainInputBtn').onclick = () => explainRelationToNode($('relationNodeInput').value, false);
  $('explainSelectedBtn').onclick = () => { if (state.selectedNode) explainRelationToNode(state.selectedNode, false); else if (state.selectedEdge) { const n = nodeById.get(state.selectedEdge.target) || nodeById.get(state.selectedEdge.source); if (n) explainRelationToNode(n, false); } };
  $('clearPathBtn').onclick = () => clearRelationPath(true);
  $('focusPathBtn').onclick = () => { if (!state.relationPathNodeIds.size) return; state.relationPathOnly = !state.relationPathOnly; $('focusPathBtn').textContent = state.relationPathOnly ? 'Evidence view' : 'Path only'; computeView(false); fitView(); };
  $('relationNodeInput').addEventListener('keydown', ev => { if (ev.key === 'Enter') explainRelationToNode($('relationNodeInput').value, false); });
  $('copyNodeBtn').onclick = () => { if (state.selectedNode) copyText(state.selectedNode.id); else if (state.selectedEdge) copyText(state.selectedEdge.id); };
  $('copySelectionQueryBtn').onclick = () => { if (state.selectedNode) { const n=state.selectedNode; let cmd=''; if (n.type==='Function') cmd=`codekg query --graph-dir outputs\\rockhopper_kg --kind function_context --target-function ${n.name} --depth 2 --write-dashboard`; else if (n.type==='File') cmd=`codekg query --graph-dir outputs\\rockhopper_kg --kind file_context --file "${n.name}" --write-dashboard`; else cmd=`codekg query --graph-dir outputs\\rockhopper_kg --kind function_context --source-node ${n.id} --depth 2 --write-dashboard`; copyText(cmd); } };
  initProject();
})();
</script>
</body>
</html>
'''
