from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from vuln_commit_kg.config import KGConfig
from vuln_commit_kg.utils.jsonl import to_jsonable

from .graph_store import ProjectGraph, load_graph
from .query_engine import LLM_QUERY_PROMPT, QUERY_CONTRACT, QUERY_EXAMPLES, KGQueryEngine


def write_kg_dashboard(
    graph: ProjectGraph | None = None,
    *,
    graph_dir: str | Path | None = None,
    out_path: str | Path | None = None,
    cfg: KGConfig | None = None,
    target_function: str | None = None,
    query_result: dict[str, Any] | None = None,
) -> Path:
    if graph is None:
        if graph_dir is None:
            raise ValueError("Either graph or graph_dir is required")
        graph = load_graph(graph_dir)
    if out_path is None:
        if graph_dir is None:
            out_path = Path("kg_dashboard.html")
        else:
            out_path = Path(graph_dir) / "kg_dashboard.html"
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    max_nodes = int(getattr(cfg, "visualization_max_nodes", 2500) if cfg else 2500)
    max_edges = int(getattr(cfg, "visualization_max_edges", 6000) if cfg else 6000)
    data = _visual_subset(graph, max_nodes=max_nodes, max_edges=max_edges, target_function=target_function)
    manifest = graph.manifest or {}
    html_text = _html(data=data, manifest=manifest, query_result=query_result)
    out.write_text(html_text, encoding="utf-8")
    return out


def _visual_subset(graph: ProjectGraph, *, max_nodes: int, max_edges: int, target_function: str | None) -> dict[str, Any]:
    engine = KGQueryEngine(graph)
    if target_function:
        result = engine.run({"kind": "function_context", "target_function": target_function, "depth": 2, "limit": max_nodes})
        nodes = result["nodes"][:max_nodes]
        ids = {n["id"] for n in nodes}
        edges = [e for e in result["edges"] if e["source"] in ids and e["target"] in ids][:max_edges]
    else:
        priority = {"Project", "Commit", "File", "Function", "Method", "Statement", "SemanticFact", "SecurityRisk", "SafetyCheck"}
        selected = []
        for n in graph.nodes:
            if n.type in priority or n.type.lower() in {"function", "method", "statement"}:
                selected.append(n)
                if len(selected) >= max_nodes:
                    break
        if len(selected) < max_nodes:
            seen = {n.id for n in selected}
            for n in graph.nodes:
                if n.id not in seen:
                    selected.append(n)
                    if len(selected) >= max_nodes:
                        break
        ids = {n.id for n in selected}
        nodes = [_node_vis(n) for n in selected]
        edges = [_edge_vis(e) for e in graph.edges if e.source in ids and e.target in ids][:max_edges]
    return {
        "nodes": nodes,
        "edges": edges,
        "counts": {"shown_nodes": len(nodes), "shown_edges": len(edges), "total_nodes": len(graph.nodes), "total_edges": len(graph.edges)},
        "query_contract": QUERY_CONTRACT,
        "query_examples": QUERY_EXAMPLES,
        "llm_query_prompt": LLM_QUERY_PROMPT,
    }


def _node_vis(n) -> dict[str, Any]:
    props = n.properties or {}
    label = props.get("name") or props.get("function") or props.get("fact_type") or props.get("relpath") or props.get("CODE") or props.get("text") or n.id
    return {"id": n.id, "label": str(label)[:80], "type": n.type, "props": to_jsonable(props)}


def _edge_vis(e) -> dict[str, Any]:
    return {"source": e.source, "target": e.target, "label": e.type, "type": e.type, "props": to_jsonable(e.properties)}


def _html(*, data: dict[str, Any], manifest: dict[str, Any], query_result: dict[str, Any] | None) -> str:
    """Return a fully self-contained offline graph dashboard.

    Earlier versions depended on the Cytoscape CDN and also embedded a JavaScript
    string containing unescaped newlines.  In local file:// usage that made the
    graph panel appear empty even though the manifest/query JSON was visible.
    This dashboard has no external dependency and renders with plain SVG.
    """
    data_json = json.dumps(data, ensure_ascii=False)
    manifest_json = json.dumps(to_jsonable(manifest), ensure_ascii=False, indent=2)
    result_json = json.dumps(to_jsonable(query_result or {}), ensure_ascii=False, indent=2)
    return f"""<!doctype html>
<html><head><meta charset='utf-8'/><title>VCKG Knowledge Graph Dashboard</title>
<style>
:root{{--bg:#0b1020;--panel:#0f172a;--card:#111827;--line:#263044;--text:#e5e7eb;--muted:#94a3b8;--accent:#3b82f6}}
*{{box-sizing:border-box}}
body{{font-family:Inter,Segoe UI,Arial,sans-serif;margin:0;background:var(--bg);color:var(--text)}}
header{{padding:14px 20px;background:#111827;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
header .badge{{background:#1e293b;border:1px solid #334155;border-radius:999px;padding:2px 8px;color:#cbd5e1;font-size:12px}}
.grid{{display:grid;grid-template-columns:390px 1fr;min-height:calc(100vh - 56px)}}
aside{{padding:14px;overflow:auto;border-right:1px solid var(--line);background:var(--panel)}}
main{{position:relative;min-width:0;background:radial-gradient(circle at 20% 20%,#111b35,#0b1020 55%)}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:10px;margin:10px 0}}
.muted{{color:var(--muted)}}
.small{{font-size:12px}}
.pill{{display:inline-block;padding:2px 7px;border-radius:99px;background:#334155;margin:2px;font-size:12px}}
input,textarea,select,button{{width:100%;box-sizing:border-box;margin:6px 0;padding:8px;border-radius:8px;border:1px solid #334155;background:#020617;color:var(--text)}}
button{{background:#1d4ed8;cursor:pointer;font-weight:600}}
button.secondary{{background:#334155}}
button:hover{{filter:brightness(1.12)}}
pre{{white-space:pre-wrap;background:#020617;border:1px solid #334155;border-radius:8px;padding:10px;max-height:280px;overflow:auto;font-size:12px}}
#toolbar{{position:absolute;z-index:5;right:12px;top:12px;display:flex;gap:8px;flex-wrap:wrap;max-width:420px}}
#toolbar button{{width:auto;padding:7px 10px;margin:0}}
#graphWrap{{position:absolute;inset:0;overflow:hidden}}
#graphSvg{{width:100%;height:100%;display:block}}
.edge{{stroke:#64748b;stroke-width:1.1;opacity:.55;marker-end:url(#arrow)}}
.edge.hit{{stroke:#facc15;opacity:1;stroke-width:2}}
.node circle,.node rect{{stroke:#e2e8f0;stroke-width:.7;cursor:pointer}}
.node text{{font-size:10px;fill:#e5e7eb;pointer-events:none;text-anchor:middle;dominant-baseline:middle}}
.node.hit circle,.node.hit rect{{stroke:#facc15;stroke-width:3}}
.node.dim,.edge.dim{{opacity:.12}}
.node.Function circle{{fill:#22c55e}}
.node.Method circle{{fill:#22c55e}}
.node.Statement rect{{fill:#f59e0b}}
.node.CallExpression circle{{fill:#38bdf8}}
.node.SemanticFact circle{{fill:#ec4899}}
.node.SecurityRisk circle{{fill:#ef4444}}
.node.SafetyCheck circle{{fill:#a3e635}}
.node.File circle{{fill:#8b5cf6}}
.node.Commit circle{{fill:#64748b}}
.node.Parameter circle,.node.LocalVariable circle{{fill:#14b8a6}}
#nodeList{{max-height:260px;overflow:auto}}
.row{{padding:6px;border-bottom:1px solid #1f2937;cursor:pointer}}
.row:hover{{background:#1e293b}}
.row b{{color:#fff}}
.warn{{background:#422006;border-color:#854d0e;color:#fed7aa}}
@media(max-width:980px){{.grid{{grid-template-columns:1fr}}aside{{border-right:0;border-bottom:1px solid var(--line)}}main{{height:70vh}}}}
</style>
</head><body>
<header><b>VCKG Knowledge Graph Dashboard</b><span class='badge'>offline SVG renderer</span><span class='muted'>Joern/CPG-ready graph inspection, query contract, navigation, and evidence search</span></header>
<div class='grid'><aside>
<div class='card'><b>Graph subset</b><div id='counts'></div><div id='health' class='small muted'></div></div>
<div class='card'><b>Search / highlight</b><input id='search' placeholder='function, variable, API, edge type, line text'/><button onclick='searchGraph()'>Search</button><button class='secondary' onclick='resetGraph()'>Reset view</button><div id='searchHits' class='small muted'></div></div>
<div class='card'><b>Layout / filters</b><select id='typeFilter' onchange='applyTypeFilter()'><option value=''>All node types</option></select><button class='secondary' onclick='focusTarget()'>Focus target function</button><button class='secondary' onclick='downloadSvg()'>Download SVG</button></div>
<div class='card'><b>Visible nodes</b><div id='nodeList'></div></div>
<div class='card'><b>LLM query contract</b><p class='muted'>Ask the LLM to return this query JSON, then run it with <code>vckg query-kg</code> or paste it into your own integration.</p><pre id='contract'></pre></div>
<div class='card'><b>Prompt to generate KG queries</b><pre id='queryPrompt'></pre></div>
<div class='card'><b>Examples</b><select id='exampleSel'></select><textarea id='queryBox' rows='8'></textarea><button onclick='showQueryInfo()'>Show selected query</button><pre id='queryInfo'></pre></div>
<div class='card'><b>Selected node / edge</b><pre id='selected'></pre></div>
<div class='card'><b>Manifest</b><pre>{html.escape(manifest_json)}</pre></div>
<div class='card'><b>Last Python query result</b><pre>{html.escape(result_json)}</pre></div>
</aside><main>
<div id='toolbar'><button onclick='zoomBy(1.2)'>Zoom +</button><button onclick='zoomBy(0.83)'>Zoom -</button><button onclick='resetView()'>Fit</button></div>
<div id='graphWrap'><svg id='graphSvg' xmlns='http://www.w3.org/2000/svg'></svg></div>
</main></div>
<script>
const DATA = {data_json};
const STATE = {{scale:1, tx:0, ty:0, nodes:[], edges:[], positions:new Map(), selected:null, typeFilter:''}};
const TYPE_ORDER = ['Commit','File','Function','Method','Statement','CallExpression','Parameter','LocalVariable','SemanticFact','SecurityRisk','SafetyCheck'];
const TYPE_COLOR = {{Function:'#22c55e',Method:'#22c55e',Statement:'#f59e0b',CallExpression:'#38bdf8',SemanticFact:'#ec4899',SecurityRisk:'#ef4444',SafetyCheck:'#a3e635',File:'#8b5cf6',Commit:'#64748b',Parameter:'#14b8a6',LocalVariable:'#14b8a6'}};
function asText(x){{try{{return JSON.stringify(x)}}catch(e){{return String(x)}}}}
function esc(s){{return String(s).replace(/[&<>"']/g, c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));}}
function init(){{
  STATE.nodes = Array.isArray(DATA.nodes) ? DATA.nodes : [];
  STATE.edges = Array.isArray(DATA.edges) ? DATA.edges : [];
  document.getElementById('counts').innerHTML = Object.entries(DATA.counts || {{}}).map(([k,v])=>`<span class='pill'>${{esc(k)}}: ${{esc(v)}}</span>`).join('');
  document.getElementById('health').textContent = `rendered nodes=${{STATE.nodes.length}}, rendered edges=${{STATE.edges.length}}`;
  document.getElementById('contract').textContent = JSON.stringify(DATA.query_contract || {{}}, null, 2);
  document.getElementById('queryPrompt').textContent = DATA.llm_query_prompt || '';
  const types = [...new Set(STATE.nodes.map(n=>n.type || 'Unknown'))].sort((a,b)=>TYPE_ORDER.indexOf(a)-TYPE_ORDER.indexOf(b));
  const typeSel = document.getElementById('typeFilter');
  for (const t of types){{ const o=document.createElement('option'); o.value=t; o.textContent=t; typeSel.appendChild(o); }}
  const exSel=document.getElementById('exampleSel');
  (DATA.query_examples || []).forEach((e,i)=>{{const o=document.createElement('option');o.value=i;o.textContent=e.name || `example ${{i+1}}`;exSel.appendChild(o);}});
  function setEx(){{ const ex=(DATA.query_examples || [])[Number(exSel.value)] || {{query:{{}}}}; document.getElementById('queryBox').value=JSON.stringify(ex.query || {{}},null,2); }}
  exSel.onchange=setEx; setEx();
  layoutGraph(); renderGraph(); renderNodeList();
}}
function layoutGraph(){{
  const nodes = STATE.nodes;
  const width = Math.max(900, window.innerWidth - 420);
  const height = Math.max(700, window.innerHeight - 80);
  const cx = width/2, cy = height/2;
  const groups = new Map();
  for (const n of nodes){{ const t=n.type || 'Unknown'; if(!groups.has(t)) groups.set(t, []); groups.get(t).push(n); }}
  const sortedGroups = [...groups.entries()].sort((a,b)=>(TYPE_ORDER.indexOf(a[0])<0?99:TYPE_ORDER.indexOf(a[0]))-(TYPE_ORDER.indexOf(b[0])<0?99:TYPE_ORDER.indexOf(b[0])));
  let ring = 0;
  for (const [type, arr] of sortedGroups){{
    const radius = 70 + ring * 105;
    const offset = ring * 0.55;
    arr.forEach((n,i)=>{{
      const angle = offset + (2*Math.PI*i/Math.max(1,arr.length));
      let r = type === 'Function' || type === 'Method' ? 80 : radius;
      if(type === 'Statement') r = Math.max(radius, 210);
      if(type === 'SemanticFact') r = Math.max(radius, 320);
      STATE.positions.set(n.id, {{x:cx + r*Math.cos(angle), y:cy + r*Math.sin(angle)}});
    }});
    ring += 1;
  }}
  const target = nodes.find(n => (n.type === 'Function' || n.type === 'Method') && String(n.label || n.props?.name || '').toLowerCase().includes('count_rows')) || nodes.find(n=>n.type==='Function'||n.type==='Method');
  if(target) STATE.positions.set(target.id, {{x:cx, y:cy}});
}}
function shapeFor(n, p){{
  const type=n.type || 'Unknown';
  if(type === 'Statement') return `<rect x='${{p.x-28}}' y='${{p.y-14}}' width='56' height='28' rx='7'></rect>`;
  const r = (type === 'Function' || type === 'Method') ? 24 : (type === 'SemanticFact' ? 17 : 15);
  return `<circle cx='${{p.x}}' cy='${{p.y}}' r='${{r}}'></circle>`;
}}
function renderGraph(){{
  const svg = document.getElementById('graphSvg');
  const nodeIds = new Set(STATE.nodes.map(n=>n.id));
  const visibleType = STATE.typeFilter;
  const visibleIds = new Set(STATE.nodes.filter(n=>!visibleType || n.type===visibleType).map(n=>n.id));
  const xs=[...STATE.positions.values()].map(p=>p.x), ys=[...STATE.positions.values()].map(p=>p.y);
  const minX=Math.min(...xs,0)-100, maxX=Math.max(...xs,100)+100, minY=Math.min(...ys,0)-100, maxY=Math.max(...ys,100)+100;
  svg.setAttribute('viewBox', `${{minX}} ${{minY}} ${{maxX-minX}} ${{maxY-minY}}`);
  let out = `<defs><marker id='arrow' viewBox='0 0 10 10' refX='9' refY='5' markerWidth='5' markerHeight='5' orient='auto-start-reverse'><path d='M 0 0 L 10 5 L 0 10 z' fill='#64748b'/></marker></defs><g id='edges'>`;
  for (const e of STATE.edges){{
    if(!nodeIds.has(e.source) || !nodeIds.has(e.target)) continue;
    if(visibleType && (!visibleIds.has(e.source) || !visibleIds.has(e.target))) continue;
    const a=STATE.positions.get(e.source), b=STATE.positions.get(e.target); if(!a||!b) continue;
    out += `<line class='edge' data-id='${{esc(e.source+'->'+e.target+'::'+(e.type||e.label||''))}}' x1='${{a.x}}' y1='${{a.y}}' x2='${{b.x}}' y2='${{b.y}}' onclick='selectEdge(${{JSON.stringify(e.source)}},${{JSON.stringify(e.target)}},${{JSON.stringify(e.type||e.label||'')}})'><title>${{esc(e.type || e.label || '')}}</title></line>`;
  }}
  out += `</g><g id='nodes'>`;
  for (const n of STATE.nodes){{
    if(visibleType && n.type!==visibleType) continue;
    const p=STATE.positions.get(n.id); if(!p) continue;
    const label = esc(n.label || n.props?.name || n.id);
    const short = label.length > 22 ? label.slice(0,21)+'…' : label;
    out += `<g class='node ${{esc(n.type||'Unknown')}}' data-node-id='${{esc(n.id)}}' onclick='selectNode(${{JSON.stringify(n.id)}})'>${{shapeFor(n,p)}}<text x='${{p.x}}' y='${{p.y}}'>${{short}}</text><title>${{label}}\n${{esc(n.type||'')}}</title></g>`;
  }}
  out += `</g>`;
  svg.innerHTML = out;
}}
function renderNodeList(filter=''){{
  const q=filter.toLowerCase();
  const list=document.getElementById('nodeList');
  const rows=STATE.nodes.filter(n=>!q || asText(n).toLowerCase().includes(q)).slice(0,160).map(n=>`<div class='row' onclick='selectNode(${{JSON.stringify(n.id)}})'><b>${{esc(n.label || n.props?.name || n.id)}}</b><br/><span class='muted small'>${{esc(n.type)}} · ${{esc(n.props?.relpath || n.props?.function || '')}}</span></div>`);
  list.innerHTML = rows.join('') || '<div class="muted small">No visible nodes.</div>';
}}
function selectNode(id){{
  const n=STATE.nodes.find(x=>x.id===id); if(!n) return;
  STATE.selected=id;
  document.getElementById('selected').textContent=JSON.stringify(n,null,2);
  document.querySelectorAll('.node,.edge').forEach(el=>el.classList.remove('hit','dim'));
  const neighbors=new Set([id]);
  for(const e of STATE.edges){{if(e.source===id)neighbors.add(e.target); if(e.target===id)neighbors.add(e.source);}}
  document.querySelectorAll('.node').forEach(el=>{{ if(neighbors.has(el.getAttribute('data-node-id'))) el.classList.add('hit'); else el.classList.add('dim'); }});
}}
function selectEdge(source,target,type){{
  const e=STATE.edges.find(x=>x.source===source&&x.target===target&&(x.type||x.label||'')===type);
  if(e) document.getElementById('selected').textContent=JSON.stringify(e,null,2);
}}
function searchGraph(){{
  const q=document.getElementById('search').value.toLowerCase().trim();
  document.querySelectorAll('.node,.edge').forEach(el=>el.classList.remove('hit','dim'));
  if(!q){{renderNodeList(''); return;}}
  let hits=0;
  for(const n of STATE.nodes){{ if(asText(n).toLowerCase().includes(q)){{ hits++; const el=document.querySelector(`[data-node-id="${{CSS.escape(n.id)}}"]`); if(el) el.classList.add('hit'); }} }}
  document.querySelectorAll('.node').forEach(el=>{{if(!el.classList.contains('hit')) el.classList.add('dim');}});
  document.getElementById('searchHits').textContent=`node hits: ${{hits}}`;
  renderNodeList(q);
}}
function resetGraph(){{document.getElementById('search').value='';document.querySelectorAll('.node,.edge').forEach(el=>el.classList.remove('hit','dim'));renderNodeList('');}}
function applyTypeFilter(){{STATE.typeFilter=document.getElementById('typeFilter').value;renderGraph();renderNodeList(document.getElementById('search').value || '');}}
function focusTarget(){{const target=STATE.nodes.find(n=>(n.type==='Function'||n.type==='Method') && String(n.label||n.props?.name||'').toLowerCase().includes(String((DATA.query_examples?.[0]?.query?.target_function)||'count_rows').toLowerCase())) || STATE.nodes.find(n=>n.type==='Function'||n.type==='Method'); if(target) selectNode(target.id);}}
function zoomBy(f){{const svg=document.getElementById('graphSvg'); const vb=svg.viewBox.baseVal; const cx=vb.x+vb.width/2, cy=vb.y+vb.height/2; const nw=vb.width/f, nh=vb.height/f; svg.setAttribute('viewBox', `${{cx-nw/2}} ${{cy-nh/2}} ${{nw}} ${{nh}}`);}}
function resetView(){{renderGraph();}}
function downloadSvg(){{const svg=document.getElementById('graphSvg').outerHTML; const blob=new Blob([svg],{{type:'image/svg+xml'}}); const url=URL.createObjectURL(blob); const a=document.createElement('a'); a.href=url; a.download='vckg_kg_dashboard.svg'; a.click(); URL.revokeObjectURL(url);}}
function showQueryInfo(){{
  const command = 'vckg query-kg --latest --kind function_context --target-function TARGET_FUNCTION --write-dashboard';
  document.getElementById('queryInfo').textContent = ['This dashboard is static. To execute the selected query over the latest graph, run:', '', command, '', 'Selected JSON:', document.getElementById('queryBox').value].join(String.fromCharCode(10));
}}
window.addEventListener('resize',()=>{{layoutGraph();renderGraph();}});
init();
</script></body></html>"""

