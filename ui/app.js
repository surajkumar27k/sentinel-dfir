/* ── SENTINEL v2.3 — app.js ───────────────────────────────────────────
   All original pages preserved. New: Display Control page.
   ──────────────────────────────────────────────────────────────────── */

const API = '';
let currentPage = 'dashboard';
let liveLogInterval = null;

// ── Display preferences (persisted in localStorage) ────────────────────
const DISPLAY_DEFAULTS = {
  theme:    'dark',
  glow:     'off',
  fontsize: 'md',
  graphType:'timing',   // 'timing' | 'heatmap' | 'network' | 'none'
  pages: ['dashboard','incidents','timeline','graph','mitre','campaigns',
          'anomalies','hunt','demos','logs','system','control','display'],
  icons: {
    dashboard:'◈', incidents:'⚠', timeline:'◫', graph:'⬡',
    mitre:'◉', campaigns:'◎', anomalies:'⊕', hunt:'⊗',
    demos:'▶', logs:'≡', system:'◇', control:'⚙', display:'✦'
  }
};
let DISPLAY = JSON.parse(localStorage.getItem('sentinel_display') || 'null') || {...DISPLAY_DEFAULTS, icons:{...DISPLAY_DEFAULTS.icons}, pages:[...DISPLAY_DEFAULTS.pages]};

function saveDisplay() { localStorage.setItem('sentinel_display', JSON.stringify(DISPLAY)); }
function applyDisplay() {
  const root = document.documentElement;
  root.setAttribute('data-theme',    DISPLAY.theme);
  root.setAttribute('data-glow',     DISPLAY.glow);
  root.setAttribute('data-fontsize', DISPLAY.fontsize);
  rebuildNav();
}

// ── Navigation ─────────────────────────────────────────────────────────
function navigate(page, btn) {
  currentPage = page;
  clearInterval(liveLogInterval);
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  (btn || document.querySelector(`[data-page="${page}"]`))?.classList.add('active');
  const titles = {
    dashboard:'Dashboard', incidents:'Incidents', timeline:'Timeline',
    graph:'Attack Graph', mitre:'MITRE ATT&CK', campaigns:'Campaigns',
    logs:'Live Logs', system:'System', anomalies:'ML Anomalies',
    demos:'Attack Demos', hunt:'Threat Hunt', control:'Control',
    display:'Display Control'
  };
  document.getElementById('page-title').textContent = titles[page] || page;
  loadPage(page);
}

function refreshPage() { loadPage(currentPage); }
function toggleSidebar() { document.getElementById('sidebar').classList.toggle('collapsed'); }

function loadPage(p) {
  const map = {
    dashboard, incidents, timeline, graph: attackGraph, mitre,
    campaigns, logs, system: systemPage, anomalies, demos, hunt,
    control, display: displayPage
  };
  map[p]?.();
}

function rebuildNav() {
  const container = document.getElementById('nav-container');
  if (!container) return;
  const allPages = [
    {id:'dashboard', label:'Dashboard'},
    {id:'incidents', label:'Incidents'},
    {id:'timeline',  label:'Timeline'},
    {id:'graph',     label:'Attack Graph'},
    {id:'mitre',     label:'MITRE ATT&CK'},
    {id:'campaigns', label:'Campaigns'},
    {id:'anomalies', label:'ML Anomalies'},
    {id:'hunt',      label:'Threat Hunt'},
    {id:'demos',     label:'Attack Demos'},
    {id:'logs',      label:'Live Logs'},
    {id:'system',    label:'System'},
    {id:'control',   label:'Control'},
    {id:'display',   label:'Display'},
  ];
  container.innerHTML = allPages
    .filter(p => DISPLAY.pages.includes(p.id))
    .map(p => {
      const icon = DISPLAY.icons[p.id] || '◦';
      const badge = p.id === 'incidents' ? '<span class="nav-badge" id="badge-incidents">0</span>' : '';
      const active = currentPage === p.id ? ' active' : '';
      return `<button class="nav-btn${active}" data-page="${p.id}" onclick="navigate('${p.id}',this)"><span class="nav-icon">${icon}</span><span>${p.label}</span>${badge}</button>`;
    }).join('');
}

// ── API helpers ────────────────────────────────────────────────────────
async function api(path) {
  try { return await (await fetch(API + path)).json(); }
  catch { return null; }
}
function setContent(html) { document.getElementById('content').innerHTML = html; }
function loading() {
  return '<div class="loading-state"><div class="loader-ring"></div><p>Loading...</p></div>';
}

function lvlBadge(lvl) {
  const m = {CRITICAL:'badge-critical',HIGH:'badge-high',MEDIUM:'badge-medium',LOW:'badge-low'};
  return `<span class="badge ${m[lvl]||'badge-low'}">${lvl||'LOW'}</span>`;
}
function rel(iso) {
  if (!iso) return '—';
  const d = (Date.now() - new Date(iso)) / 1000;
  if (d < 60)    return `${~~d}s ago`;
  if (d < 3600)  return `${~~(d/60)}m ago`;
  if (d < 86400) return `${~~(d/3600)}h ago`;
  return new Date(iso).toLocaleDateString();
}
function toast(msg, type='ok') {
  let c = document.getElementById('toast-container');
  if (!c) { c = document.createElement('div'); c.id='toast-container'; document.body.appendChild(c); }
  const t = document.createElement('div');
  t.className = `toast ${type}`; t.textContent = msg;
  c.appendChild(t); setTimeout(() => t.remove(), 3500);
}

// ── Status bar ─────────────────────────────────────────────────────────
async function updateStatus() {
  const [stats, eng] = await Promise.all([api('/api/stats'), api('/api/engine/status')]);
  if (stats) {
    const critEl = document.getElementById('chip-crit-val');
    const highEl = document.getElementById('chip-high-val');
    const badgeEl = document.getElementById('badge-incidents');
    if (critEl)  critEl.textContent  = stats.by_level?.CRITICAL || 0;
    if (highEl)  highEl.textContent  = stats.by_level?.HIGH || 0;
    if (badgeEl) badgeEl.textContent = stats.total || 0;
    const tv   = document.getElementById('threat-value');
    const crit = stats.by_level?.CRITICAL || 0, high = stats.by_level?.HIGH || 0;
    if (tv) {
      if (crit > 0)      { tv.textContent = 'CRITICAL'; tv.className = 'threat-value critical'; }
      else if (high > 5) { tv.textContent = 'ELEVATED'; tv.className = 'threat-value high'; }
      else               { tv.textContent = 'NOMINAL';  tv.className = 'threat-value'; }
    }
  }
  if (eng) {
    const pill  = document.getElementById('engine-pill');
    const label = document.getElementById('pill-label');
    if (pill)  pill.className  = eng.running ? 'engine-pill online' : 'engine-pill';
    if (label) label.textContent = eng.running ? 'ENGINE ONLINE' : 'ENGINE OFFLINE';
  }
}

// ── DASHBOARD ──────────────────────────────────────────────────────────
async function dashboard() {
  setContent(loading());
  const [stats, recent] = await Promise.all([api('/api/stats'), api('/api/incidents?limit=8')]);
  if (!stats) {
    setContent('<div class="empty-state"><div class="empty-icon">⚠</div><p>API offline — start the server</p></div>');
    return;
  }
  const maxA = Math.max(...Object.values(stats.by_attack || {}), 1);
  const atkRows = Object.entries(stats.by_attack || {}).slice(0,8).map(([k,v]) => `
    <div class="atk-row">
      <span class="atk-name">${k}</span>
      <div class="atk-bar-wrap"><div class="atk-bar" style="width:${(v/maxA*100).toFixed(0)}%;opacity:${0.3+(v/maxA*0.6)}"></div></div>
      <span class="atk-count">${v}</span>
    </div>`).join('') || '<div style="padding:16px 20px;color:var(--text-muted);font-size:12px;font-family:var(--mono)">No attacks yet — run a demo</div>';

  const maxTL = Math.max(...(stats.timeline_24h || [0]), 1);
  const tlBars = (stats.timeline_24h || []).map((v,i) =>
    `<div class="timeline-bar" style="height:${Math.max(4,v/maxTL*100).toFixed(0)}%" title="${v} at ${i}:00"></div>`
  ).join('');

  const rows = (recent || []).map(i => `
    <tr class="inc-row" onclick="navigate('incidents')">
      <td>${lvlBadge(i.risk?.level)}</td>
      <td><div class="inc-attack">${i.attack||'?'}</div><div class="inc-desc">${(i.description||'').substring(0,70)}</div></td>
      <td style="font-family:var(--mono);font-size:var(--fs-sm)">${i.attacker?.ip||'—'}</td>
      <td class="inc-time">${rel(i.time)}</td>
    </tr>`).join('') ||
    '<tr><td colspan="4" style="text-align:center;color:var(--text-muted);padding:24px;font-family:var(--mono);font-size:12px">No incidents — run a demo</td></tr>';

  setContent(`
    <div class="grid grid-4" style="margin-bottom:14px">
      <div class="stat-card total">
        <div class="stat-label">TOTAL</div>
        <div class="stat-value">${stats.total||0}</div>
        <div class="stat-sub"><span class="tag">live</span> all incidents</div>
      </div>
      <div class="stat-card critical">
        <div class="stat-label">CRITICAL</div>
        <div class="stat-value">${stats.by_level?.CRITICAL||0}</div>
        <div class="stat-sub"><span class="tag warn">urgent</span> action needed</div>
      </div>
      <div class="stat-card high">
        <div class="stat-label">HIGH</div>
        <div class="stat-value">${stats.by_level?.HIGH||0}</div>
        <div class="stat-sub">review required</div>
      </div>
      <div class="stat-card medium">
        <div class="stat-label">MED / LOW</div>
        <div class="stat-value">${(stats.by_level?.MEDIUM||0)+(stats.by_level?.LOW||0)}</div>
        <div class="stat-sub">monitoring</div>
      </div>
    </div>
    <div class="grid grid-2" style="margin-bottom:14px">
      <div class="card">
        <div class="card-header"><span class="card-title">Top Attack Types</span><span class="card-tag">${Object.keys(stats.by_attack||{}).length} types</span></div>
        <div class="atk-list">${atkRows}</div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">24-Hour Activity</span><span class="card-tag">LIVE</span></div>
        <div class="card-body">
          <div class="timeline-chart">${tlBars}</div>
          <div style="display:flex;justify-content:space-between;font-size:var(--fs-xs);color:var(--text-muted);margin-top:6px;font-family:var(--mono)"><span>24h ago</span><span>Now</span></div>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-header">
        <span class="card-title">Recent Incidents</span>
        <div style="display:flex;gap:8px">
          <button class="topbar-btn" onclick="navigate('demos')">▶ Run Demo</button>
          <button class="topbar-btn" onclick="navigate('incidents')">View All →</button>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Level</th><th>Attack</th><th>Source IP</th><th>Time</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>`);
}

// ── INCIDENTS ──────────────────────────────────────────────────────────
let _incData = [];
async function incidents() {
  setContent(loading());
  _incData = await api('/api/incidents?limit=500') || [];
  renderIncidents(_incData, '');
}

function renderIncidents(data, search) {
  const q = search.toLowerCase();
  const filtered = q ? data.filter(i =>
    [i.attack, i.attacker?.ip, i.description, i.attacker?.user, i.mitre?.technique_id, i.mitre?.tactic]
      .some(v => (v||'').toLowerCase().includes(q))
  ) : data;

  const rows = filtered.map((inc, idx) => `
    <tr class="inc-row" onclick="toggleDetail('d${idx}')">
      <td>${lvlBadge(inc.risk?.level)}</td>
      <td><div class="inc-attack">${inc.attack||'?'}</div><div class="inc-desc">${(inc.description||'').substring(0,75)}</div></td>
      <td style="font-family:var(--mono);font-size:var(--fs-sm)">${inc.attacker?.ip||'—'}</td>
      <td style="font-family:var(--mono);font-size:var(--fs-xs);color:var(--text-muted)">${inc.attacker?.user||'—'}</td>
      <td class="inc-mitre">${inc.mitre?.technique_id||'—'}</td>
      <td style="font-size:var(--fs-xs);color:var(--purple)">${inc.mitre?.tactic||'—'}</td>
      <td class="inc-time">${rel(inc.time)}</td>
    </tr>
    <tr><td colspan="7" style="padding:0;border:none">
      <div class="detail-panel" id="d${idx}">${detailPanel(inc)}</div>
    </td></tr>`).join('');

  setContent(`
    <div class="filter-bar">
      <select class="filter-select" onchange="filterByLevel(this.value)">
        <option value="">All Levels</option>
        <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
      </select>
      <input class="filter-input" placeholder="Search attack, IP, user, MITRE..." oninput="renderIncidents(_incData,this.value)">
      <button class="topbar-btn" onclick="incidents()">↻ Refresh</button>
      <button class="topbar-btn" onclick="exportPDF()">⬇ PDF Report</button>
    </div>
    <div class="card">
      <div class="section-header">
        <span class="section-title">Incidents</span>
        <div class="section-line"></div>
        <span class="section-count">${filtered.length} of ${data.length}</span>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Level</th><th>Attack</th><th>Source IP</th><th>User</th><th>MITRE ID</th><th>Tactic</th><th>Time</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--text-muted)">No incidents</td></tr>'}</tbody>
        </table>
      </div>
    </div>`);
}

function detailPanel(inc) {
  const r = (k,v) => v ? `<div class="detail-row"><span class="detail-key">${k}</span><span class="detail-val">${v}</span></div>` : '';
  const risk = inc.risk || {}, mit = inc.mitre || {}, att = inc.attacker || {};
  return [
    r('DESCRIPTION', inc.description),
    r('SOURCE IP', att.ip),
    r('USER', att.user),
    r('RISK SCORE', `<span style="color:${risk.level==='CRITICAL'?'var(--red)':risk.level==='HIGH'?'var(--orange)':'var(--green)'}">${risk.score||0}/100 — ${risk.level||'LOW'}</span>`),
    risk.factors?.length ? r('RISK FACTORS', risk.factors.join(', ')) : '',
    r('MITRE', `<span style="color:var(--purple)">${mit.technique_id||''} — ${mit.technique||''}</span>`),
    r('TACTIC', mit.tactic),
    r('TIME', (inc.time||'').replace('T',' ').substring(0,19)+' UTC'),
    inc.intel && !inc.intel.error ? r('THREAT INTEL', `Abuse: ${inc.intel.abuse_score||'?'} | Country: ${inc.intel.country||'?'} | ISP: ${inc.intel.isp||'?'}`) : '',
    inc.evidence && Object.keys(inc.evidence).length ? r('EVIDENCE', `<pre class="raw">${JSON.stringify(inc.evidence,null,2)}</pre>`) : '',
  ].join('');
}

async function filterByLevel(level) {
  _incData = await api(`/api/incidents?limit=500${level?'&level='+level:''}`) || [];
  renderIncidents(_incData, '');
}
function toggleDetail(id) { document.getElementById(id)?.classList.toggle('open'); }
function exportPDF() { toast('Generating PDF...','ok'); window.location.href='/api/report/pdf'; }

// ── TIMELINE ───────────────────────────────────────────────────────────
async function timeline() {
  setContent(loading());
  const data = (await api('/api/incidents?limit=100') || []).sort((a,b) => new Date(b.time)-new Date(a.time));
  const levelColor = {CRITICAL:'var(--red)',HIGH:'var(--orange)',MEDIUM:'var(--yellow)',LOW:'var(--green)'};
  const items = data.map(i => {
    const c = levelColor[i.risk?.level] || 'var(--green)';
    return `
    <div style="display:flex;gap:16px;margin-bottom:12px;align-items:flex-start;padding:0 20px">
      <div style="width:72px;flex-shrink:0;font-family:var(--mono);font-size:var(--fs-xs);color:var(--text-muted);padding-top:4px;text-align:right">${rel(i.time)}</div>
      <div style="width:3px;flex-shrink:0;background:${c};border-radius:2px;min-height:44px;margin-top:2px"></div>
      <div style="flex:1;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius-s);padding:10px 14px">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
          ${lvlBadge(i.risk?.level)}
          <span style="font-family:var(--mono);font-size:var(--fs-sm);font-weight:700">${i.attack}</span>
          <span style="margin-left:auto;font-size:var(--fs-xs);color:var(--purple)">${i.mitre?.technique_id||''}</span>
        </div>
        <div style="font-size:var(--fs-xs);color:var(--text-muted)">${i.description||''}</div>
        <div style="font-size:var(--fs-xs);color:var(--text-muted);margin-top:6px;display:flex;gap:16px;flex-wrap:wrap;font-family:var(--mono)">
          <span>IP: <b style="color:var(--text)">${i.attacker?.ip||'—'}</b></span>
          <span>User: <b style="color:var(--text)">${i.attacker?.user||'—'}</b></span>
          <span style="color:var(--purple)">${i.mitre?.tactic||''}</span>
        </div>
      </div>
    </div>`;
  }).join('');

  setContent(`
    <div class="card">
      <div class="card-header">
        <span class="card-title">Forensic Timeline</span>
        <span class="card-tag">${data.length} events</span>
      </div>
      <div style="padding-top:16px;padding-bottom:16px">
        ${items || '<div class="empty-state"><div class="empty-icon">◫</div><p>No events yet — run a demo</p></div>'}
      </div>
    </div>`);
}

// ── ATTACK GRAPH ───────────────────────────────────────────────────────
async function attackGraph() {
  const gt = DISPLAY.graphType;

  if (gt === 'none') {
    setContent(`<div class="empty-state"><div class="empty-icon">⬡</div><p>Graph disabled — enable it in <b>Display Control</b></p></div>`);
    return;
  }

  if (gt === 'timing' || gt === 'heatmap') {
    await graphTimingView(gt);
    return;
  }

  // ── Network graph (d3 force) ──────────────────────────────────────────
  setContent(`
    <div id="graph-wrap" style="height:580px">
      <div style="position:absolute;top:14px;left:14px;z-index:10;display:flex;gap:8px;align-items:center">
        <span style="font-family:var(--mono);font-size:var(--fs-xs);letter-spacing:2px;color:var(--text-muted)">ATTACK GRAPH</span>
        <div style="width:1px;height:14px;background:var(--border)"></div>
        <span class="graph-legend-dot" style="color:var(--red);background:rgba(255,64,96,.08);border:1px solid rgba(255,64,96,.2)">IP</span>
        <span class="graph-legend-dot" style="color:var(--cyan);background:rgba(0,200,232,.08);border:1px solid rgba(0,200,232,.2)">USER</span>
        <span class="graph-legend-dot" style="color:var(--orange);background:rgba(255,140,0,.08);border:1px solid rgba(255,140,0,.2)">ATTACK</span>
        <span class="graph-legend-dot" style="color:var(--purple);background:rgba(176,106,240,.08);border:1px solid rgba(176,106,240,.2)">TACTIC</span>
      </div>
      <div style="position:absolute;top:14px;right:14px;z-index:10;display:flex;gap:6px">
        <button onclick="graphZoom(1.3)" style="width:28px;height:28px;background:var(--bg2);border:1px solid var(--border);border-radius:3px;color:var(--text-muted);font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center">+</button>
        <button onclick="graphZoom(0.77)" style="width:28px;height:28px;background:var(--bg2);border:1px solid var(--border);border-radius:3px;color:var(--text-muted);font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center">−</button>
        <button onclick="graphReset()" style="height:28px;padding:0 10px;background:var(--bg2);border:1px solid var(--border);border-radius:3px;color:var(--text-muted);font-size:var(--fs-xs);cursor:pointer;font-family:var(--mono)">RESET</button>
      </div>
      <svg id="graph-svg" width="100%" height="100%"></svg>
      <div id="graph-tooltip" style="display:none;position:absolute;background:var(--bg2);border:1px solid var(--border2);border-radius:var(--radius-s);padding:10px 14px;font-family:var(--mono);font-size:var(--fs-xs);pointer-events:none;z-index:20;min-width:160px"></div>
    </div>`);

  const raw = await api('/api/graph');
  const svg  = d3.select('#graph-svg');
  const wrap = document.getElementById('graph-wrap');
  if (!raw?.nodes?.length) {
    svg.append('text').attr('x','50%').attr('y','50%').attr('text-anchor','middle').attr('dominant-baseline','middle')
      .attr('fill','var(--text-muted)').attr('font-family','JetBrains Mono').attr('font-size',13).text('No graph data — run a demo first');
    return;
  }
  const W = wrap.clientWidth, H = wrap.clientHeight;
  svg.attr('viewBox',`0 0 ${W} ${H}`);
  const defs = svg.append('defs');
  const glowColors = {ip:'var(--red)', user:'var(--cyan)', attack:'var(--orange)', tactic:'var(--purple)'};
  const glowHex    = {ip:'#ff4060',    user:'#00c8e8',    attack:'#ff8c00',        tactic:'#b06af0'};

  Object.entries(glowHex).forEach(([group,col]) => {
    const f = defs.append('filter').attr('id',`glow-${group}`).attr('x','-50%').attr('y','-50%').attr('width','200%').attr('height','200%');
    f.append('feGaussianBlur').attr('stdDeviation','3').attr('result','blur');
    const merge = f.append('feMerge');
    merge.append('feMergeNode').attr('in','blur');
    merge.append('feMergeNode').attr('in','SourceGraphic');
  });
  defs.append('marker').attr('id','arrow').attr('viewBox','0 -4 8 8').attr('refX',18).attr('refY',0).attr('markerWidth',6).attr('markerHeight',6).attr('orient','auto')
    .append('path').attr('d','M0,-4L8,0L0,4').attr('fill','var(--border2)');
  defs.append('marker').attr('id','arrow-hi').attr('viewBox','0 -4 8 8').attr('refX',18).attr('refY',0).attr('markerWidth',6).attr('markerHeight',6).attr('orient','auto')
    .append('path').attr('d','M0,-4L8,0L0,4').attr('fill','var(--cyan)');

  // Grid
  const grid = svg.append('g');
  for (let x=0;x<W;x+=44) grid.append('line').attr('x1',x).attr('y1',0).attr('x2',x).attr('y2',H).attr('stroke','rgba(255,255,255,.02)').attr('stroke-width',1);
  for (let y=0;y<H;y+=44) grid.append('line').attr('x1',0).attr('y1',y).attr('x2',W).attr('y2',y).attr('stroke','rgba(255,255,255,.02)').attr('stroke-width',1);

  const edgeKeys = new Set();
  const edges = raw.edges.filter(e => { const k=[e.from,e.to].sort().join('|'); if(edgeKeys.has(k)) return false; edgeKeys.add(k); return true; });
  const nodes = raw.nodes.map(n => ({...n}));
  const nodeById = Object.fromEntries(nodes.map(n=>[n.id,n]));

  function nodeR(d) { return Math.min(6+(d.weight||1)*4, 26); }

  const sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(edges).id(d=>d.id).distance(120).strength(0.4))
    .force('charge', d3.forceManyBody().strength(-300))
    .force('center', d3.forceCenter(W/2, H/2))
    .force('collision', d3.forceCollide().radius(d=>nodeR(d)+12));

  const zoomG = svg.append('g');
  const zoom  = d3.zoom().scaleExtent([0.2,4]).on('zoom', e => zoomG.attr('transform',e.transform));
  svg.call(zoom);
  window._graphZoom = zoom; window._graphSvg = svg;

  const link = zoomG.append('g').selectAll('line').data(edges).join('line')
    .attr('stroke','rgba(255,255,255,.08)').attr('stroke-width',1.2).attr('marker-end','url(#arrow)');

  const node = zoomG.append('g').selectAll('g').data(nodes).join('g').attr('cursor','pointer')
    .call(d3.drag()
      .on('start',(e,d)=>{if(!e.active)sim.alphaTarget(0.3).restart();d.fx=d.x;d.fy=d.y;})
      .on('drag', (e,d)=>{d.fx=e.x;d.fy=e.y;})
      .on('end',  (e,d)=>{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}));

  node.append('circle').attr('r',d=>nodeR(d)+5).attr('fill','none').attr('stroke',d=>glowHex[d.group]||'#555').attr('stroke-width',0.5).attr('stroke-opacity',0.25);
  node.append('circle').attr('r',d=>nodeR(d)).attr('fill',d=>glowHex[d.group]+'18'||'#55555518').attr('stroke',d=>glowHex[d.group]||'#555').attr('stroke-width',1.5).attr('filter',d=>`url(#glow-${d.group})`);
  node.append('text').attr('text-anchor','middle').attr('dominant-baseline','central').attr('font-family','JetBrains Mono').attr('font-size',d=>Math.max(9,nodeR(d)*0.6)).attr('fill',d=>glowHex[d.group]||'#aaa').attr('pointer-events','none').text(d=>({ip:'⬡',user:'◉',attack:'⚡',tactic:'◈'})[d.group]||'●');
  node.append('text').attr('text-anchor','middle').attr('dy',d=>nodeR(d)+13).attr('font-family','JetBrains Mono').attr('font-size',9).attr('fill','var(--text-muted)').attr('pointer-events','none').text(d=>(d.label||'').substring(0,18));

  const tooltip = document.getElementById('graph-tooltip');
  node.on('mouseenter',function(e,d){
    tooltip.style.display='block';
    tooltip.innerHTML=`<div style="color:${glowHex[d.group]};font-size:9px;letter-spacing:1.5px;margin-bottom:6px">${(d.group||'').toUpperCase()}</div><div style="color:var(--text);font-size:13px;margin-bottom:4px">${d.label}</div>`;
    link.attr('stroke',l=>(l.source.id===d.id||l.target.id===d.id)?'var(--cyan)':'rgba(255,255,255,.05)').attr('marker-end',l=>(l.source.id===d.id||l.target.id===d.id)?'url(#arrow-hi)':'url(#arrow)');
  }).on('mousemove',e=>{
    const rect=wrap.getBoundingClientRect();
    let tx=e.clientX-rect.left+16, ty=e.clientY-rect.top-10;
    if(tx+180>W)tx-=196;
    tooltip.style.left=tx+'px';tooltip.style.top=ty+'px';
  }).on('mouseleave',()=>{
    tooltip.style.display='none';
    link.attr('stroke','rgba(255,255,255,.08)').attr('marker-end','url(#arrow)');
  });

  sim.on('tick',()=>{
    link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y).attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
    node.attr('transform',d=>`translate(${d.x},${d.y})`);
  });
  zoomG.attr('opacity',0);
  setTimeout(()=>zoomG.transition().duration(600).attr('opacity',1),300);
}

// ── ATTACK TIMING / HEATMAP views ──────────────────────────────────────
async function graphTimingView(type) {
  const raw = await api('/api/incidents?limit=500');
  if (!raw?.length) {
    setContent('<div class="empty-state"><div class="empty-icon">⬡</div><p>No incident data</p></div>');
    return;
  }

  // ── Stats strip ───────────────────────────────────────────────────────
  const uniqueIPs  = new Set(raw.map(i=>i.attacker?.ip)).size;
  const atkTypes   = new Set(raw.map(i=>i.attack)).size;
  const hourCounts = {};
  raw.forEach(i=>{const h=new Date(i.time).getHours();hourCounts[h]=(hourCounts[h]||0)+1;});
  const peakHour   = Object.entries(hourCounts).sort((a,b)=>b[1]-a[1])[0]?.[0];
  const times      = raw.map(i=>new Date(i.time).getTime()).sort((a,b)=>a-b);
  const avgMin     = raw.length>1 ? Math.round((times[times.length-1]-times[0])/(raw.length-1)/60000) : 0;

  const statsStrip = `
    <div class="grid grid-4" style="margin-bottom:14px">
      <div class="stat-card total"><div class="stat-label">Unique Attackers</div><div class="stat-value" style="font-size:var(--fs-stat)">${uniqueIPs}</div></div>
      <div class="stat-card high"><div class="stat-label">Attack Types</div><div class="stat-value" style="font-size:var(--fs-stat)">${atkTypes}</div></div>
      <div class="stat-card medium"><div class="stat-label">Avg. Interval</div><div class="stat-value" style="font-size:var(--fs-stat)">${avgMin<60?avgMin+'m':Math.round(avgMin/60)+'h'}</div></div>
      <div class="stat-card critical"><div class="stat-label">Peak Hour</div><div class="stat-value" style="font-size:var(--fs-stat)">${peakHour||'—'}:00</div></div>
    </div>`;

  if (type === 'timing') {
    // ── Attack timing scatter + hourly bar ────────────────────────────
    const W = 900, H = 260, ML = 60, MB = 36;
    const cw = W-ML, ch = H-MB;
    const hours = Array.from({length:24},(_,i)=>({h:i,n:hourCounts[i]||0}));
    const maxH  = Math.max(...hours.map(d=>d.n),1);

    const bars = hours.map((d,i) => {
      const bw = (cw/24)-2;
      const bh = (d.n/maxH)*ch;
      const x  = ML+(cw/24)*i+1;
      const y  = ch-bh;
      const op = d.n===0?0.06:d.n>maxH*.7?0.85:d.n>maxH*.4?0.5:0.28;
      return `<rect x="${x}" y="${y}" width="${bw}" height="${bh||2}" fill="white" opacity="${op}" rx="1"><title>${d.h}:00 — ${d.n} incidents</title></rect>
        ${i%4===0?`<text x="${x+bw/2}" y="${ch+22}" text-anchor="middle" fill="var(--text-muted)" font-size="9" font-family="JetBrains Mono">${d.h}h</text>`:''}`;
    }).join('');

    const gridLines = Array.from({length:5},(_,i)=>{
      const y=(ch/4)*i;
      return `<line x1="${ML}" y1="${y}" x2="${W}" y2="${y}" stroke="rgba(255,255,255,.04)" stroke-width="1"/>
              <text x="${ML-6}" y="${y+4}" fill="var(--text-muted)" font-size="9" font-family="JetBrains Mono" text-anchor="end">${Math.round(maxH*(4-i)/4)}</text>`;
    }).join('');

    // Attack type breakdown bars
    const atkBreak = Object.entries(
      raw.reduce((acc,i)=>{acc[i.attack]=(acc[i.attack]||0)+1;return acc;},{}))
      .sort((a,b)=>b[1]-a[1]).slice(0,8);
    const maxA = atkBreak[0]?.[1]||1;
    const atkSvg = atkBreak.map(([name,cnt],i)=>{
      const bw = (cnt/maxA)*(W-200);
      return `<g transform="translate(0,${i*28})">
        <text x="0" y="14" fill="var(--text-muted)" font-size="10" font-family="JetBrains Mono">${name.substring(0,24)}</text>
        <rect x="200" y="5" width="${bw}" height="12" fill="white" opacity="${0.2+(cnt/maxA)*0.5}" rx="2"/>
        <text x="${200+bw+6}" y="14" fill="var(--text-muted)" font-size="10" font-family="JetBrains Mono">${cnt}</text>
      </g>`;
    }).join('');

    setContent(`
      ${statsStrip}
      <div class="grid grid-2" style="margin-bottom:14px">
        <div class="card">
          <div class="card-header"><span class="card-title">Attack Timing — Hourly Distribution</span><span class="card-tag">SVG</span></div>
          <div style="padding:20px;overflow-x:auto">
            <svg width="${W}" height="${H}" style="max-width:100%">
              ${gridLines}
              ${bars}
              <line x1="${ML}" y1="0" x2="${ML}" y2="${ch}" stroke="rgba(255,255,255,.1)" stroke-width="1"/>
              <line x1="${ML}" y1="${ch}" x2="${W}" y2="${ch}" stroke="rgba(255,255,255,.1)" stroke-width="1"/>
              <text x="${W/2+ML/2}" y="${H}" text-anchor="middle" fill="var(--text-muted)" font-size="10" font-family="JetBrains Mono">Hour of Day</text>
            </svg>
          </div>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-title">Top Attack Types</span><span class="card-tag">Frequency</span></div>
          <div style="padding:20px;overflow-x:auto">
            <svg width="${W-20}" height="${atkBreak.length*28+10}" style="max-width:100%">
              ${atkSvg}
            </svg>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">Incident Timeline — Chronological</span><span class="card-tag">${raw.length} events</span></div>
        ${renderTimelineStrip(raw)}
      </div>`);
  } else {
    // ── Heatmap: day × hour ──────────────────────────────────────────
    const heatmap = {}; // key: "dow-hour"
    const days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
    raw.forEach(i=>{
      const d=new Date(i.time);
      const k=`${d.getDay()}-${d.getHours()}`;
      heatmap[k]=(heatmap[k]||0)+1;
    });
    const maxV = Math.max(...Object.values(heatmap),1);
    const cellW=38, cellH=28, padL=40, padT=28;
    const svgW=padL+24*cellW+20, svgH=padT+7*cellH+20;
    const cells = days.map((day,di)=>
      Array.from({length:24},(_,h)=>{
        const v=heatmap[`${di}-${h}`]||0;
        const op=v===0?0.04:(0.1+(v/maxV)*0.75);
        const x=padL+h*cellW, y=padT+di*cellH;
        return `<rect x="${x}" y="${y}" width="${cellW-2}" height="${cellH-2}" fill="white" opacity="${op}" rx="2">
          <title>${day} ${h}:00 — ${v} incidents</title></rect>
          ${v>0?`<text x="${x+(cellW-2)/2}" y="${y+(cellH-2)/2+4}" text-anchor="middle" fill="rgba(255,255,255,.7)" font-size="8" font-family="JetBrains Mono">${v}</text>`:''}`;
      }).join('')
    ).join('');
    const dayLabels  = days.map((d,i)=>`<text x="${padL-6}" y="${padT+i*cellH+(cellH-2)/2+4}" text-anchor="end" fill="var(--text-muted)" font-size="9" font-family="JetBrains Mono">${d}</text>`).join('');
    const hourLabels = Array.from({length:24},(_,h)=>h%4===0?`<text x="${padL+h*cellW+(cellW-2)/2}" y="${padT-8}" text-anchor="middle" fill="var(--text-muted)" font-size="9" font-family="JetBrains Mono">${h}h</text>`:'').join('');

    setContent(`
      ${statsStrip}
      <div class="card">
        <div class="card-header"><span class="card-title">Attack Heatmap — Day × Hour</span><span class="card-tag">7 × 24</span></div>
        <div style="padding:20px;overflow-x:auto">
          <svg width="${svgW}" height="${svgH}" style="max-width:100%">
            ${dayLabels}${hourLabels}${cells}
          </svg>
        </div>
      </div>
      <div class="card" style="margin-top:14px">
        <div class="card-header"><span class="card-title">Incident Timeline</span><span class="card-tag">${raw.length} events</span></div>
        ${renderTimelineStrip(raw)}
      </div>`);
  }
}

function renderTimelineStrip(raw) {
  if (!raw.length) return '<div class="empty-state"><p>No data</p></div>';
  const sorted = [...raw].sort((a,b)=>new Date(b.time)-new Date(a.time)).slice(0,30);
  const rows = sorted.map((i,idx) => `
    <tr class="inc-row" onclick="toggleDetail('gd${idx}')">
      <td>${lvlBadge(i.risk?.level)}</td>
      <td style="font-family:var(--mono);font-size:var(--fs-sm);font-weight:600">${i.attack}</td>
      <td style="font-family:var(--mono);font-size:var(--fs-sm)">${i.attacker?.ip||'—'}</td>
      <td class="inc-mitre">${i.mitre?.technique_id||'—'}</td>
      <td class="inc-time">${rel(i.time)}</td>
    </tr>
    <tr><td colspan="5" style="padding:0;border:none"><div class="detail-panel" id="gd${idx}">${detailPanel(i)}</div></td></tr>
  `).join('');
  return `<div class="table-wrap"><table>
    <thead><tr><th>Level</th><th>Attack</th><th>Source IP</th><th>MITRE</th><th>Time</th></tr></thead>
    <tbody>${rows}</tbody>
  </table></div>`;
}

function graphZoom(f) { window._graphSvg?.transition().duration(300).call(window._graphZoom.scaleBy,f); }
function graphReset() { window._graphSvg?.transition().duration(400).call(window._graphZoom.transform,d3.zoomIdentity); }

// ── MITRE ATT&CK ──────────────────────────────────────────────────────
async function mitre() {
  setContent(loading());
  const data = await api('/api/mitre');
  if (!data) return;
  const detected = new Set(data.detected || []);
  const tacMap = {};
  Object.entries(data.techniques || {}).forEach(([k,v]) => {
    const t = v.tactic || 'Other';
    if (!tacMap[t]) tacMap[t] = [];
    tacMap[t].push({key:k,...v});
  });
  const order = ['Initial Access','Execution','Persistence','Privilege Escalation',
    'Defense Evasion','Credential Access','Discovery','Lateral Movement',
    'Collection','Command and Control','Exfiltration','Impact'];
  const cols = order.filter(t=>tacMap[t]).map(tac => {
    const detCount = tacMap[tac].filter(t=>detected.has(t.key)).length;
    const cells = tacMap[tac].map(t => `
      <div class="technique-cell ${detected.has(t.key)?'detected':''}">
        <span class="technique-id">${t.technique_id}</span>${t.key.replace(/_/g,' ')}
      </div>`).join('');
    return `
      <div class="mitre-tactic">
        <div class="tactic-header">${tac}${detCount?` <span style="float:right;color:var(--red);font-size:9px">${detCount}</span>`:''}
        </div>${cells}
      </div>`;
  }).join('');
  const pct = data.total ? Math.round(data.covered/data.total*100) : 0;
  setContent(`
    <div class="card" style="margin-bottom:14px">
      <div class="card-header">
        <span class="card-title">MITRE ATT&CK Matrix Coverage</span>
        <span style="font-family:var(--mono);color:var(--cyan);font-size:var(--fs-xs)">${data.covered} / ${data.total} (${pct}%)</span>
      </div>
      <div class="card-body">
        <div style="height:5px;background:var(--bg4);border-radius:3px">
          <div style="height:100%;width:${pct}%;background:var(--cyan);border-radius:3px;transition:width .5s"></div>
        </div>
        <div style="font-size:var(--fs-xs);color:var(--text-muted);margin-top:8px;font-family:var(--mono)">🔴 = triggered · Grey = rules exist</div>
      </div>
    </div>
    <div class="card"><div class="mitre-grid">${cols}</div></div>`);
}

// ── CAMPAIGNS ──────────────────────────────────────────────────────────
async function campaigns() {
  setContent(loading());
  const data = await api('/api/campaigns');
  if (!data?.length) {
    setContent('<div class="empty-state"><div class="empty-icon">◎</div><p>No campaigns yet — run demos</p></div>');
    return;
  }
  const cards = data.sort((a,b)=>b.incident_count-a.incident_count).map(c => `
    <div class="camp-card">
      <div class="camp-id">${c.campaign_id}</div>
      <div class="camp-ip">${c.attacker_id}</div>
      <div class="camp-meta">
        <span>📍 ${c.incident_count} incidents</span>
        <span>First: ${rel(c.first_seen)}</span>
        <span>Last: ${rel(c.last_seen)}</span>
      </div>
    </div>`).join('');
  setContent(`
    <div class="card">
      <div class="card-header"><span class="card-title">Attack Campaigns</span><span class="card-tag">${data.length} campaigns</span></div>
      <div class="card-body">${cards}</div>
    </div>`);
}

// ── LIVE LOGS ──────────────────────────────────────────────────────────
let _logSeen = new Set();
async function logs() {
  setContent(`
    <div class="card">
      <div class="card-header">
        <span class="card-title">Live Incident Stream</span>
        <button class="topbar-btn" onclick="_logSeen=new Set();document.getElementById('log-stream').innerHTML=''">Clear</button>
      </div>
      <div class="log-stream" id="log-stream">
        <div style="color:var(--text-muted);font-family:var(--mono)">[SENTINEL] Watching for incidents...</div>
      </div>
    </div>`);

  async function poll() {
    if (currentPage !== 'logs') return;
    const data = await api('/api/incidents?limit=50');
    const stream = document.getElementById('log-stream');
    if (!stream || !data) return;
    const newOnes = data.filter(i => !_logSeen.has(i.id||i.time));
    if (newOnes.length && stream.children[0]?.style?.color === '') stream.innerHTML = '';
    newOnes.forEach(i => {
      _logSeen.add(i.id||i.time);
      const cls = {CRITICAL:'crit',HIGH:'high',MEDIUM:'med',LOW:'low'}[i.risk?.level]||'low';
      stream.innerHTML += `<div class="log-line ${cls}">[${(i.time||'').substring(0,19).replace('T',' ')}] [${i.risk?.level||'?'}] ${i.attack} | ${i.attacker?.ip||'?'} | ${(i.description||'').substring(0,80)}</div>`;
      stream.scrollTop = stream.scrollHeight;
    });
  }
  await poll();
  liveLogInterval = setInterval(poll, 3000);
}

// ── SYSTEM ─────────────────────────────────────────────────────────────
async function systemPage() {
  setContent(loading());
  const [sys, ml] = await Promise.all([api('/api/system'), api('/api/ml/status')]);
  if (!sys) return;
  function gauge(lbl,pct,val) {
    const cls = pct>85?'crit':pct>65?'warn':'ok';
    return `<div class="gauge-row"><span class="gauge-label">${lbl}</span><div class="gauge-track"><div class="gauge-fill ${cls}" style="width:${pct}%"></div></div><span class="gauge-val">${val}</span></div>`;
  }
  const up = sys.uptime_seconds||0;
  const ni = ((sys.network?.bytes_recv||0)/1024/1024).toFixed(1);
  const no = ((sys.network?.bytes_sent||0)/1024/1024).toFixed(1);
  setContent(`
    <div class="grid grid-2">
      <div class="card">
        <div class="card-header"><span class="card-title">Resources</span><span class="card-tag">Live</span></div>
        <div class="gauge-wrap">
          ${gauge('CPU',  sys.cpu_percent||0,    `${sys.cpu_percent||0}%`)}
          ${gauge('MEM',  sys.memory?.percent||0, `${sys.memory?.percent||0}%`)}
          ${gauge('DISK', sys.disk?.percent||0,   `${sys.disk?.percent||0}%`)}
        </div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">System Info</span></div>
        <div class="card-body">
          <table>
            ${[
              ['HOSTNAME', sys.hostname],
              ['PLATFORM', sys.platform],
              ['UPTIME',   `${~~(up/3600)}h ${~~((up%3600)/60)}m`],
              ['NET IN/OUT', `${ni} MB / ${no} MB`],
              ['ENGINE', `<span style="color:${sys.engine_running?'var(--green)':'var(--red)'}">${sys.engine_running?'ONLINE':'OFFLINE'}</span>`],
              ['ML MODEL', ml?`${ml.entities_tracked} tracked, ${ml.models_trained} models`:'unavailable'],
              ['INCIDENTS', sys.incident_count],
            ].map(([k,v])=>`<tr><td style="color:var(--text-muted);font-size:var(--fs-xs);font-family:var(--mono);padding:6px 0;width:120px;letter-spacing:1px">${k}</td><td style="font-family:var(--mono);font-size:var(--fs-sm)">${v||'—'}</td></tr>`).join('')}
          </table>
        </div>
      </div>
    </div>`);
}

// ── ML ANOMALY ─────────────────────────────────────────────────────────
async function anomalies() {
  setContent(loading());
  const [data, ml] = await Promise.all([api('/api/anomalies'), api('/api/ml/status')]);
  const rows = (data||[]).map(a => {
    let ctx = '';
    try { const f=JSON.parse(a.features_json||'{}'); ctx=`${f.event_type||''} ${f.command||''}`.substring(0,55); } catch {}
    return `
      <tr>
        <td style="font-family:var(--mono);font-size:var(--fs-xs)">${(a.time||'').substring(0,19).replace('T',' ')}</td>
        <td style="font-family:var(--mono);font-size:var(--fs-sm)">${a.entity||'—'}</td>
        <td>
          <div style="display:flex;align-items:center;gap:8px">
            <div style="flex:1;max-width:80px;background:var(--bg4);border-radius:2px;height:4px">
              <div style="height:100%;width:${a.score||0}%;background:${(a.score||0)>75?'var(--red)':'var(--orange)'};border-radius:2px"></div>
            </div>
            <span style="font-family:var(--mono);font-size:var(--fs-sm)">${a.score||0}</span>
          </div>
        </td>
        <td>${a.flagged?lvlBadge('CRITICAL'):'<span style="color:var(--text-muted);font-size:var(--fs-xs);font-family:var(--mono)">watching</span>'}</td>
        <td style="font-size:var(--fs-xs);color:var(--text-muted)">${ctx}</td>
      </tr>`;
  }).join('');

  setContent(`
    <div class="card" style="margin-bottom:14px">
      <div class="card-header"><span class="card-title">ML Engine</span><span class="card-tag">UEBA + Isolation Forest</span></div>
      <div class="card-body" style="display:flex;gap:28px;flex-wrap:wrap">
        <div style="text-align:center"><div style="font-size:var(--fs-stat);font-family:var(--mono);font-weight:800;color:var(--cyan)">${ml?.entities_tracked||0}</div><div style="font-size:var(--fs-xs);color:var(--text-muted);letter-spacing:1px;font-family:var(--mono)">ENTITIES</div></div>
        <div style="text-align:center"><div style="font-size:var(--fs-stat);font-family:var(--mono);font-weight:800;color:var(--green)">${ml?.models_trained||0}</div><div style="font-size:var(--fs-xs);color:var(--text-muted);letter-spacing:1px;font-family:var(--mono)">MODELS</div></div>
        <div style="text-align:center"><div style="font-size:var(--fs-stat);font-family:var(--mono);font-weight:800;color:${ml?.ml_available?'var(--green)':'var(--orange)'}">${ml?.ml_available?'ON':'BASIC'}</div><div style="font-size:var(--fs-xs);color:var(--text-muted);letter-spacing:1px;font-family:var(--mono)">MODE</div></div>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><span class="card-title">Anomaly Scores</span></div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Time</th><th>Entity</th><th>Score</th><th>Status</th><th>Context</th></tr></thead>
          <tbody>${rows||'<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--text-muted);font-family:var(--mono)">Collecting baselines — anomalies appear after 30+ events per entity</td></tr>'}</tbody>
        </table>
      </div>
    </div>`);
}

// ── ATTACK DEMOS ───────────────────────────────────────────────────────
async function demos() {
  const demoList = await api('/api/demo/list') || [];
  const cards = demoList.map(d => `
    <div class="demo-card" id="card-${d.id}">
      <div class="demo-header">
        <div>
          <div class="demo-name">${d.name}</div>
          <div class="demo-mitre">${d.mitre} · ${d.tactic}</div>
        </div>
        ${lvlBadge(d.risk)}
      </div>
      <div class="demo-desc">${d.desc}</div>
      <div class="demo-terminal" id="term-${d.id}"></div>
      <div class="demo-actions">
        <button class="demo-btn" id="btn-${d.id}" onclick="runDemo('${d.id}')">▶ Run Attack</button>
        <button class="demo-btn outline" onclick="toggleTerm('${d.id}')">≡ Terminal</button>
      </div>
    </div>`).join('');

  setContent(`
    <style>
    .demo-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:14px}
    .demo-card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:18px;transition:border-color .2s}
    .demo-card.running{border-color:var(--orange)}
    .demo-header{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:8px}
    .demo-name{font-size:var(--fs-base);font-weight:700;letter-spacing:-.2px}
    .demo-mitre{font-family:var(--mono);font-size:var(--fs-xs);color:var(--purple);margin-top:3px}
    .demo-desc{font-size:var(--fs-xs);color:var(--text-muted);line-height:1.6;margin-bottom:12px}
    .demo-terminal{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-s);max-height:200px;overflow-y:auto;font-family:var(--mono);font-size:var(--fs-xs);padding:10px;color:var(--text-muted);white-space:pre-wrap;word-break:break-all;line-height:1.7;display:none}
    .demo-actions{display:flex;gap:8px;margin-top:12px}
    .demo-btn{padding:7px 16px;background:var(--white);color:var(--bg);border:none;border-radius:var(--radius-s);font-size:var(--fs-sm);font-weight:700;cursor:pointer;font-family:var(--sans);transition:opacity .15s}
    .demo-btn:hover{opacity:.85}
    .demo-btn:disabled{opacity:.4;cursor:not-allowed}
    .demo-btn.outline{background:transparent;border:1px solid var(--border2);color:var(--text-muted)}
    .demo-btn.outline:hover{border-color:var(--cyan);color:var(--cyan)}
    </style>
    <div style="margin-bottom:14px;padding:12px 14px;background:rgba(0,200,232,.05);border:1px solid rgba(0,200,232,.15);border-radius:var(--radius-s);font-size:var(--fs-xs);color:var(--text-muted);font-family:var(--mono)">
      ⚡ Click <b style="color:var(--text)">Run Attack</b> to generate incidents immediately. No engine required.
      &nbsp;<a href="/ATTACK_SIMULATION_GUIDE.md" target="_blank" style="color:var(--cyan)">📖 VM Guide →</a>
    </div>
    <div class="demo-grid">${cards}</div>`);
}

async function runDemo(id) {
  const card = document.getElementById(`card-${id}`);
  const term = document.getElementById(`term-${id}`);
  const btn  = document.getElementById(`btn-${id}`);
  card.classList.add('running');
  term.style.display = 'block'; term.textContent = '';
  btn.disabled = true; btn.textContent = '⏳ Running...';
  try {
    const res = await fetch(`/api/demo/run/${id}`,{method:'POST'});
    const reader = res.body.getReader(); const dec = new TextDecoder();
    while (true) {
      const {done,value} = await reader.read(); if (done) break;
      for (const line of dec.decode(value).split('\n')) {
        if (!line.startsWith('data: ')) continue;
        const text = line.slice(6);
        if (text==='__DONE__') { toast(`${id} complete — check Dashboard`,'ok'); updateStatus(); }
        else { term.textContent+=text+'\n'; term.scrollTop=term.scrollHeight; }
      }
    }
  } catch(e) { term.textContent+=`\nError: ${e.message}`; }
  card.classList.remove('running'); btn.disabled=false; btn.textContent='▶ Run Again';
}
function toggleTerm(id) { const t=document.getElementById(`term-${id}`); t.style.display=t.style.display==='none'?'block':'none'; }

// ── THREAT HUNT ────────────────────────────────────────────────────────
async function hunt() {
  setContent(`
    <div class="card" style="margin-bottom:14px">
      <div class="card-header"><span class="card-title">Threat Hunt</span></div>
      <div class="card-body">
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
          <input class="filter-input" id="hunt-q" placeholder="Search attack, IP, user, MITRE..." style="flex:1;min-width:200px" onkeydown="if(event.key==='Enter')runHunt()">
          <select class="filter-select" id="hunt-level"><option value="">Any Level</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>
          <button class="topbar-btn" style="background:var(--white);color:var(--bg);font-weight:700" onclick="runHunt()">🔍 Hunt</button>
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap">
          <button class="topbar-btn" onclick="quickHunt('CRITICAL')">All CRITICAL</button>
          <button class="topbar-btn" onclick="quickHunt('','REVERSE_SHELL')">Reverse Shells</button>
          <button class="topbar-btn" onclick="quickHunt('','CRON_PERSISTENCE')">Persistence</button>
          <button class="topbar-btn" onclick="quickHunt('','SSH_BRUTE_FORCE')">Brute Force</button>
          <button class="topbar-btn" onclick="quickHunt('','ANOMALY_DETECTED')">ML Anomalies</button>
          <button class="topbar-btn" onclick="quickHunt('','LOG_TAMPERING')">Defense Evasion</button>
        </div>
      </div>
    </div>
    <div id="hunt-results"><div class="empty-state"><div class="empty-icon">⊗</div><p>Enter a query or click a quick filter above</p></div></div>`);
}

async function runHunt() {
  const q=document.getElementById('hunt-q').value, lvl=document.getElementById('hunt-level').value;
  let url=`/api/incidents?limit=500`;
  if (lvl) url+=`&level=${lvl}`; if (q) url+=`&search=${encodeURIComponent(q)}`;
  document.getElementById('hunt-results').innerHTML = huntResults(await api(url)||[]);
}
async function quickHunt(level, attack) {
  let url=`/api/incidents?limit=500`;
  if (level) url+=`&level=${level}`; if (attack) url+=`&search=${attack}`;
  document.getElementById('hunt-results').innerHTML = huntResults(await api(url)||[]);
}
function huntResults(data) {
  if (!data.length) return '<div class="empty-state"><div class="empty-icon">✓</div><p>No matching incidents</p></div>';
  const rows = data.map((inc,i)=>`
    <tr class="inc-row" onclick="toggleDetail('hd${i}')">
      <td>${lvlBadge(inc.risk?.level)}</td>
      <td><div class="inc-attack">${inc.attack}</div><div class="inc-desc">${(inc.description||'').substring(0,70)}</div></td>
      <td style="font-family:var(--mono);font-size:var(--fs-sm)">${inc.attacker?.ip||'—'}</td>
      <td style="font-family:var(--mono);font-size:var(--fs-xs)">${inc.attacker?.user||'—'}</td>
      <td class="inc-mitre">${inc.mitre?.technique_id||'—'}</td>
      <td class="inc-time">${rel(inc.time)}</td>
    </tr>
    <tr><td colspan="6" style="padding:0;border:none"><div class="detail-panel" id="hd${i}">${detailPanel(inc)}</div></td></tr>`).join('');
  return `
    <div class="card">
      <div class="section-header">
        <span class="section-title">Results</span>
        <div class="section-line"></div>
        <span class="section-count">${data.length} matches</span>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Level</th><th>Attack</th><th>IP</th><th>User</th><th>MITRE</th><th>Time</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>`;
}

// ── ENGINE CONTROL ─────────────────────────────────────────────────────
function control() {
  setContent(`
    <div class="grid grid-2">
      <div class="card">
        <div class="card-header"><span class="card-title">Detection Engine</span><span class="card-tag">Process</span></div>
        <div class="control-grid">
          <button class="ctrl-btn success" onclick="engineCmd('start')"><span class="ctrl-label">Action</span>▶ Start Engine</button>
          <button class="ctrl-btn danger"  onclick="engineCmd('stop')"><span class="ctrl-label">Danger</span>⏹ Stop Engine</button>
        </div>
      </div>
      <div class="card">
        <div class="card-header"><span class="card-title">Data Management</span><span class="card-tag">Ops</span></div>
        <div class="control-grid">
          <button class="ctrl-btn danger" onclick="doClear()"><span class="ctrl-label">Cannot undo</span>🗑 Clear All Incidents</button>
          <button class="ctrl-btn"        onclick="window.location='/api/report/pdf'"><span class="ctrl-label">Export</span>⬇ Download PDF</button>
        </div>
      </div>
    </div>`);
}

async function engineCmd(action) {
  const d = await (await fetch(`/api/engine/${action}`,{method:'POST'})).json();
  toast(d.message||d.status||action,'ok');
  setTimeout(updateStatus,1500);
}
async function doClear() {
  if (!confirm('Delete ALL incidents? This cannot be undone.')) return;
  const d = await (await fetch('/api/incidents/clear',{method:'POST'})).json();
  toast(d.message||'Incidents cleared','ok');
  await updateStatus();
  if (['dashboard','incidents','logs','timeline'].includes(currentPage)) loadPage(currentPage);
}

// ── DISPLAY CONTROL PAGE ───────────────────────────────────────────────
function displayPage() {
  const allPages = [
    {id:'dashboard',label:'Dashboard'},{id:'incidents',label:'Incidents'},
    {id:'timeline', label:'Timeline'}, {id:'graph',    label:'Attack Graph'},
    {id:'mitre',    label:'MITRE'},    {id:'campaigns', label:'Campaigns'},
    {id:'anomalies',label:'ML Anomalies'},{id:'hunt',  label:'Threat Hunt'},
    {id:'demos',    label:'Demos'},    {id:'logs',     label:'Live Logs'},
    {id:'system',   label:'System'},   {id:'control',  label:'Control'},
    {id:'display',  label:'Display'},
  ];

  const themes = [
    {id:'dark',  label:'Dark',  dot:'#101010', border:'rgba(255,255,255,.2)'},
    {id:'light', label:'Light', dot:'#f8f8f8', border:'rgba(0,0,0,.2)'},
    {id:'cream', label:'Cream', dot:'#f5f0e8', border:'rgba(100,80,40,.3)'},
    {id:'brown', label:'Brown', dot:'#1a1208', border:'rgba(200,160,80,.3)'},
  ];

  const iconOptions = {
    dashboard: ['◈','⬡','◉','⊕','▦','◼'],
    incidents: ['⚠','⚡','🔴','◆','⊗','▲'],
    timeline:  ['◫','⏱','⌁','≡','◷','⊟'],
    graph:     ['⬡','◎','⊙','◌','⊚','⬢'],
    mitre:     ['◉','⊕','◈','⬡','⊞','◎'],
    campaigns: ['◎','⊙','◌','⬡','◉','⊚'],
    anomalies: ['⊕','◉','⬡','◈','⊞','⊙'],
    hunt:      ['⊗','◎','⊙','◌','⬡','⊕'],
    demos:     ['▶','⚡','◆','▷','▸','⬥'],
    logs:      ['≡','◫','⊟','⬛','◻','▬'],
    system:    ['◇','⬡','◈','⊕','◎','⊙'],
    control:   ['⚙','◇','⬡','◈','⊕','⊞'],
    display:   ['✦','◈','⊕','◉','◎','⬡'],
  };

  setContent(`
    <div class="grid grid-1">

      <!-- THEME -->
      <div class="card">
        <div class="card-header"><span class="card-title">Color Theme</span><span class="card-tag">4 themes</span></div>
        <div class="card-body">
          <div class="dp-row">
            ${themes.map(t=>`
              <div class="swatch ${DISPLAY.theme===t.id?'active':''}" onclick="setTheme('${t.id}')">
                <div class="swatch-dot" style="background:${t.dot};border:1px solid ${t.border}"></div>
                ${t.label}
              </div>`).join('')}
          </div>
        </div>
      </div>

      <!-- GLOW -->
      <div class="card">
        <div class="card-header"><span class="card-title">Glow Indicators</span><span class="card-tag">Ambient light on severity</span></div>
        <div class="card-body">
          <div class="dp-row">
            <div class="dp-toggle ${DISPLAY.glow==='on'?'active':''}" onclick="setGlow('on')">
              <div class="dp-toggle-dot"></div> Glow ON
            </div>
            <div class="dp-toggle ${DISPLAY.glow==='off'?'active':''}" onclick="setGlow('off')">
              <div class="dp-toggle-dot" style="background:var(--text-muted)"></div> Glow OFF
            </div>
          </div>
          <div class="dp-preview" style="display:flex;gap:20px;align-items:center;flex-wrap:wrap">
            <span class="badge badge-critical" style="${DISPLAY.glow==='on'?'box-shadow:0 0 8px var(--red)':''}">CRITICAL</span>
            <span class="badge badge-high"     style="${DISPLAY.glow==='on'?'box-shadow:0 0 8px var(--orange)':''}">HIGH</span>
            <span class="badge badge-medium"   style="${DISPLAY.glow==='on'?'box-shadow:0 0 8px var(--yellow)':''}">MEDIUM</span>
            <span class="badge badge-low"      style="${DISPLAY.glow==='on'?'box-shadow:0 0 8px var(--green)':''}">LOW</span>
            <div class="live-indicator" style="${DISPLAY.glow==='on'?'filter:drop-shadow(0 0 4px var(--green))':''}"><span class="live-dot"></span> LIVE</div>
          </div>
        </div>
      </div>

      <!-- FONT SIZE -->
      <div class="card">
        <div class="card-header"><span class="card-title">Font Size</span><span class="card-tag">Base scale</span></div>
        <div class="card-body">
          <div class="dp-row">
            ${['sm','md','lg','xl'].map(s=>`
              <button class="fs-btn ${DISPLAY.fontsize===s?'active':''}" onclick="setFontSize('${s}')" style="font-size:${s==='sm'?'12px':s==='md'?'14px':s==='lg'?'17px':'20px'}">
                ${s.toUpperCase()}
              </button>`).join('')}
          </div>
          <div class="dp-preview" style="margin-top:4px">
            <div style="font-size:var(--fs-base);margin-bottom:4px">Base text — <span style="font-family:var(--mono)">monospace data</span></div>
            <div style="font-size:var(--fs-stat);font-weight:800;letter-spacing:-2px;line-height:1">42</div>
            <div style="font-size:var(--fs-xs);color:var(--text-muted);font-family:var(--mono);letter-spacing:.1em">METRIC LABEL</div>
          </div>
        </div>
      </div>

      <!-- GRAPH TYPE -->
      <div class="card">
        <div class="card-header"><span class="card-title">Attack Graph Style</span><span class="card-tag">Graph page</span></div>
        <div class="card-body">
          <div class="dp-row" style="flex-wrap:wrap">
            ${[
              {id:'timing',  label:'Timing Chart', desc:'Hourly bar + attack breakdown'},
              {id:'heatmap', label:'Heatmap',       desc:'Day × Hour activity grid'},
              {id:'network', label:'Network Graph', desc:'D3 force-directed node graph'},
              {id:'none',    label:'Disabled',      desc:'Hide the graph page entirely'},
            ].map(g=>`
              <div class="graph-opt ${DISPLAY.graphType===g.id?'active':''}" onclick="setGraphType('${g.id}')">
                <div style="font-weight:700;margin-bottom:3px">${g.label}</div>
                <div style="font-size:var(--fs-xs);color:var(--text-muted)">${g.desc}</div>
              </div>`).join('')}
          </div>
        </div>
      </div>

      <!-- PAGE VISIBILITY -->
      <div class="card">
        <div class="card-header"><span class="card-title">Visible Pages</span><span class="card-tag">Sidebar navigation</span></div>
        <div class="card-body">
          <div class="page-toggle-grid">
            ${allPages.map(p=>`
              <div class="page-toggle ${DISPLAY.pages.includes(p.id)?'active':''}" onclick="togglePage('${p.id}')">
                <div class="page-toggle-check">${DISPLAY.pages.includes(p.id)?'✓':''}</div>
                <span class="nav-icon">${DISPLAY.icons[p.id]||'◦'}</span>
                ${p.label}
              </div>`).join('')}
          </div>
          <div style="margin-top:12px;font-size:var(--fs-xs);color:var(--text-muted);font-family:var(--mono)">Display page cannot be hidden (you'd have no way to get back)</div>
        </div>
      </div>

      <!-- ICON PICKER -->
      <div class="card">
        <div class="card-header"><span class="card-title">Navigation Icons</span><span class="card-tag">Per page</span></div>
        <div class="card-body">
          ${allPages.map(p=>`
            <div class="dp-row" style="margin-bottom:6px">
              <div class="dp-label">${p.label}</div>
              ${(iconOptions[p.id]||['◦']).map(ic=>`
                <button class="icon-opt ${DISPLAY.icons[p.id]===ic?'active':''}" onclick="setIcon('${p.id}','${ic}')" title="${ic}">${ic}</button>
              `).join('')}
            </div>`).join('')}
        </div>
      </div>

      <!-- RESET -->
      <div class="card">
        <div class="card-header"><span class="card-title">Reset</span><span class="card-tag">Restore defaults</span></div>
        <div class="card-body">
          <button class="ctrl-btn danger" onclick="resetDisplay()" style="width:auto;padding:10px 24px">
            <span class="ctrl-label">All customizations lost</span>↺ Reset to Defaults
          </button>
        </div>
      </div>

    </div>`);
}

// ── Display setters ────────────────────────────────────────────────────
function setTheme(t)     { DISPLAY.theme    = t; saveDisplay(); applyDisplay(); displayPage(); }
function setGlow(g)      { DISPLAY.glow     = g; saveDisplay(); applyDisplay(); displayPage(); }
function setFontSize(s)  { DISPLAY.fontsize = s; saveDisplay(); applyDisplay(); displayPage(); }
function setGraphType(g) { DISPLAY.graphType= g; saveDisplay(); displayPage(); }

function togglePage(id) {
  if (id === 'display') return; // always visible
  if (DISPLAY.pages.includes(id)) {
    if (DISPLAY.pages.length <= 2) { toast('Must keep at least 2 pages','err'); return; }
    DISPLAY.pages = DISPLAY.pages.filter(p=>p!==id);
  } else {
    DISPLAY.pages.push(id);
  }
  saveDisplay(); applyDisplay(); displayPage();
}

function setIcon(page, icon) {
  DISPLAY.icons[page] = icon;
  saveDisplay(); applyDisplay(); displayPage();
}

function resetDisplay() {
  if (!confirm('Reset all display settings to defaults?')) return;
  DISPLAY = {...DISPLAY_DEFAULTS, icons:{...DISPLAY_DEFAULTS.icons}, pages:[...DISPLAY_DEFAULTS.pages]};
  saveDisplay(); applyDisplay(); displayPage();
  toast('Display settings reset','ok');
}

// ── Boot ────────────────────────────────────────────────────────────────
window.addEventListener('load', () => {
  applyDisplay();
  const clock = document.getElementById('clock');
  setInterval(() => { if(clock) clock.textContent = new Date().toTimeString().split(' ')[0]; }, 1000);
  loadPage('dashboard');
  updateStatus();
  setInterval(updateStatus, 10000);
});
