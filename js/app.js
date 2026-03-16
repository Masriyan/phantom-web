// ============================================================
// PHANTOM Web — Main Application Controller
// ============================================================

// Global state
const State = {
  currentPage: 'dashboard',
  extractedIOCs: {},
  selectedTTPs: new Set(),
  attckFilter: null,
  lastFileResult: null,
  lastUpdated: Date.now(),
};

// Page metadata
const PAGE_META = {
  dashboard: { title: 'Dashboard', desc: 'Platform overview and quick stats' },
  ioc: { title: 'IOC Extractor', desc: 'Extract and analyze indicators from any text' },
  file: { title: 'File Analyzer', desc: 'Static analysis: hash, entropy, YARA-lite, strings' },
  attck: { title: 'ATT&CK Mapper', desc: 'Map TTPs to MITRE ATT&CK framework · Export Navigator layer' },
  diamond: { title: 'Diamond Model', desc: 'Build and persist Diamond Model instances' },
  database: { title: 'IOC Database', desc: 'Local IndexedDB · Export CSV / STIX 2.1' },
  report: { title: 'Report Builder', desc: 'Generate CTI reports with IOCs, TTPs, and analysis' },
  swiss: { title: 'Swiss Army Knife', desc: 'Encoder/Decoder · JWT · CIDR · Regex · Epoch — all offline' },
  hash: { title: 'Hash Identifier', desc: 'Identify hash algorithm by pattern, length, and charset — 30+ types' },
  urlanalyzer: { title: 'URL Analyzer', desc: 'Phishing detection · Entropy · Brand impersonation · Homoglyphs — zero API' },
  threatactor: { title: 'Threat Actor Cards', desc: 'Build and export professional threat actor profile cards' },
  cvss: { title: 'CVSS Calculator', desc: 'CVSS v3.1 Base & Temporal Score Calculator — offline' },
};

// ---- Navigation ----
function showPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const pageEl = document.getElementById(`page-${name}`);
  if (pageEl) pageEl.classList.add('active');
  const navEl = document.querySelector(`.nav-item[data-page="${name}"]`);
  if (navEl) navEl.classList.add('active');
  State.currentPage = name;
  const meta = PAGE_META[name] || {};
  document.getElementById('topbar-title').textContent = meta.title || name;
  document.getElementById('topbar-desc').textContent = meta.desc || '';
  if (name === 'database') refreshDatabase();
  if (name === 'dashboard') refreshStats();
  if (name === 'attck') initATTCK();
  if (name === 'diamond') refreshDiamondInstances();
  if (name === 'swiss') SwissKnife && SwissKnife.init();
  if (name === 'cvss') CVSSCalc && CVSSCalc.calc();
  if (name === 'threatactor') ThreatActorCards && ThreatActorCards.updatePreview();
}

document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => showPage(item.dataset.page));
});

// ---- Toast ----
function showToast(msg, type = 'success', duration = 3000) {
  const c = document.getElementById('toast-container');
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  const icons = { success: '✓', error: '✗', warning: '⚠', info: '◈' };
  t.innerHTML = `<span style="color:${type==='success'?'var(--accent)':type==='error'?'var(--red)':type==='warning'?'var(--yellow)':'var(--blue)'}">${icons[type]||'◈'}</span>${msg}`;
  c.appendChild(t);
  setTimeout(() => { t.style.opacity='0'; t.style.transition='opacity .3s'; setTimeout(()=>t.remove(), 300); }, duration);
}

// ---- Copy to clipboard ----
async function copyText(text, label='') {
  try {
    await navigator.clipboard.writeText(text);
    showToast(`${label || 'Text'} copied`);
  } catch { showToast('Copy failed', 'error'); }
}

// Safe copy from data attribute — avoids inline onclick injection issues
function copyFromAttr(el) {
  const text = el.getAttribute('data-copy') || el.textContent;
  const label = el.getAttribute('data-label') || '';
  copyText(text, label);
}

// ---- Stats ----
async function refreshStats() {
  const stats = await PhantomDB.getStats();
  document.getElementById('stat-total-ioc').textContent = stats.totalIOCs;
  document.getElementById('stat-domains').textContent = stats.byType?.domain || 0;
  document.getElementById('stat-ips').textContent = stats.byType?.ip || 0;
  document.getElementById('stat-hashes').textContent = stats.byType?.hash || 0;
  document.getElementById('ioc-nav-count').textContent = stats.totalIOCs;

  // Mini bar chart
  const chartEl = document.getElementById('ioc-chart');
  if (stats.totalIOCs === 0) {
    chartEl.innerHTML = `<div class="empty-state"><div class="empty-icon">◈</div><div class="empty-text">No IOCs yet</div></div>`;
    return;
  }
  const colorMap = { ip:'var(--orange)', domain:'var(--red)', url:'var(--blue)', hash:'var(--purple)', email:'var(--pink)', cve:'var(--yellow)', mitre:'var(--accent)', default:'var(--text3)' };
  const types = Object.entries(stats.byType).sort((a,b)=>b[1]-a[1]);
  const max = types[0]?.[1] || 1;
  chartEl.innerHTML = `<div style="width:100%">${types.map(([type,count])=>`
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
      <div style="width:70px;font-size:10px;color:var(--text3);text-align:right">${type}</div>
      <div style="flex:1;height:16px;background:var(--bg3);border-radius:3px;overflow:hidden">
        <div style="height:100%;width:${(count/max*100).toFixed(1)}%;background:${colorMap[type]||colorMap.default};border-radius:3px;transition:width .5s"></div>
      </div>
      <div style="width:30px;font-size:11px;color:var(--text0);font-weight:600">${count}</div>
    </div>`).join('')}
  </div>`;
}

// ============================================================
// IOC EXTRACTOR
// ============================================================

async function runIOCExtraction() {
  const text = document.getElementById('ioc-input').value.trim();
  if (!text) { showToast('Paste some text first', 'warning'); return; }
  const results = IOCEngine.extract(text);
  State.extractedIOCs = results;
  renderIOCResults(results);
  const total = Object.values(results).reduce((a,b)=>a+b.length,0);
  if (total > 0) showToast(`Extracted ${total} IOCs`, 'success');
  else showToast('No IOCs found in text', 'info');
}

function renderIOCResults(results) {
  const el = document.getElementById('ioc-results');
  const total = Object.values(results).reduce((a,arr)=>a+arr.length,0);
  document.getElementById('ioc-total-badge').textContent = total ? `${total} IOCs found` : '–';
  if (total === 0) {
    el.innerHTML = `<div class="empty-state"><div class="empty-icon">⬡</div><div class="empty-text">No IOCs found.</div></div>`;
    return;
  }
  const TYPE_ICONS = { ip:'⬡', domain:'◈', url:'⬢', email:'◆', hash:'⊞', cve:'⊹', mitre:'⊗', btc:'◎', asn:'⊠', cidr:'⊡', registry:'⊟', mutex:'⊛', default:'·' };
  const TYPE_COLORS = { ip:'var(--orange)', domain:'var(--red)', url:'var(--blue)', email:'var(--pink)', hash:'var(--purple)', cve:'var(--yellow)', mitre:'var(--accent)', btc:'var(--yellow)', asn:'var(--text1)', default:'var(--text2)' };
  let html = '';
  for (const [type, items] of Object.entries(results)) {
    if (!items.length) continue;
    const icon = TYPE_ICONS[type] || TYPE_ICONS.default;
    const color = TYPE_COLORS[type] || TYPE_COLORS.default;
    html += `<div class="ioc-section">
      <div class="ioc-section-header">
        <span style="color:${color}">${icon}</span>
        <span style="text-transform:uppercase;letter-spacing:1px">${type}</span>
        <span class="ioc-count">${items.length}</span>
      </div>`;
    for (const item of items) {
      const priv = item.private ? '<span class="tag tag-info" style="font-size:9px">RFC1918</span>' : '';
      const dga = type==='domain' ? (() => { const s=IOCEngine.scoreDomain(item.value); return s.dgaScore>30?`<span class="tag tag-high" style="font-size:9px">DGA?</span>`:'' })() : '';
      const algo = item.algo ? `<span class="tag tag-info" style="font-size:9px">${item.algo}</span>` : '';
      const safe = escapeHtml(item.value);
      html += `<div class="ioc-item">
        <span class="ioc-value copyable" data-copy="${safe}" data-label="${type}" onclick="copyFromAttr(this)">${safe}</span>
        ${priv}${dga}${algo}
        <span class="ioc-meta">${item.v ? `v${item.v}` : ''}</span>
      </div>`;
    }
    html += `</div>`;
  }
  el.innerHTML = html;
}

function copyAllIOCs() {
  const lines = [];
  for (const [type, items] of Object.entries(State.extractedIOCs)) {
    for (const item of items) lines.push(`${type}\t${item.value}${item.algo?'\t'+item.algo:''}`);
  }
  copyText(lines.join('\n'), 'All IOCs');
}

function exportIOCsCSV() {
  const rows = ['type,value,algo,notes'];
  for (const [type, items] of Object.entries(State.extractedIOCs)) {
    for (const item of items) rows.push(`${type},"${item.value}","${item.algo||''}",""`);
  }
  downloadText(rows.join('\n'), 'phantom-iocs.csv', 'text/csv');
}

async function saveAllIOCsToDB() {
  let count = 0;
  for (const [type, items] of Object.entries(State.extractedIOCs)) {
    for (const item of items) {
      await PhantomDB.addIOC(item.value, type, { algo: item.algo, source: 'ioc-extractor', confidence: 0.7 });
      count++;
    }
  }
  showToast(`${count} IOCs saved to database`);
  await refreshStats();
}

async function pasteFromClipboard() {
  try {
    const text = await navigator.clipboard.readText();
    document.getElementById('ioc-input').value = text;
    showToast('Pasted from clipboard');
  } catch { showToast('Clipboard access denied', 'error'); }
}

async function loadFileForIOC(input) {
  const file = input.files[0];
  if (!file) return;
  const text = await file.text();
  document.getElementById('ioc-input').value = text.slice(0, 500000);
  showToast(`Loaded: ${file.name}`);
}

// ============================================================
// FILE ANALYZER
// ============================================================

function handleDragOver(e) { e.preventDefault(); document.getElementById('upload-zone').classList.add('drag'); }
function handleDragLeave() { document.getElementById('upload-zone').classList.remove('drag'); }
function handleDrop(e) {
  e.preventDefault();
  document.getElementById('upload-zone').classList.remove('drag');
  const file = e.dataTransfer.files[0];
  if (file) analyzeFile(file);
}

async function analyzeFile(file) {
  if (!file) return;
  if (file.size > 52428800) { showToast('File too large (max 50MB)', 'error'); return; }
  document.getElementById('file-upload-area').innerHTML = `
    <div class="card" style="text-align:center;padding:24px">
      <div style="color:var(--accent);font-size:20px;margin-bottom:8px">⬢</div>
      <div style="font-size:13px">Analyzing <strong>${file.name}</strong>...</div>
      <div class="progress-bar" style="margin-top:12px;max-width:300px;margin-left:auto;margin-right:auto">
        <div class="progress-fill" style="width:100%;animation:pulse 1s infinite"></div>
      </div>
    </div>`;

  try {
    const result = await FileEngine.analyze(file);
    State.lastFileResult = result;
    renderFileResults(result);
  } catch (err) {
    showToast(`Analysis failed: ${err.message}`, 'error');
    resetFileUpload();
  }
}

function resetFileUpload() {
  document.getElementById('file-upload-area').innerHTML = `
    <div class="upload-zone" id="upload-zone" onclick="document.getElementById('file-input').click()" ondragover="handleDragOver(event)" ondragleave="handleDragLeave(event)" ondrop="handleDrop(event)">
      <div class="upload-icon">⬢</div>
      <div class="upload-text">Click or drag file to analyze</div>
      <div class="upload-sub">PE/ELF/APK/PDF/ZIP/Scripts — max 50MB — all analysis runs locally</div>
    </div>
    <input type="file" id="file-input" onchange="analyzeFile(this.files[0])">`;
}

function renderFileResults(r) {
  const uploadArea = document.getElementById('file-upload-area');
  uploadArea.innerHTML = `
    <div style="display:flex;gap:8px;align-items:center;margin-bottom:16px">
      <div style="flex:1">
        <div style="font-size:13px;color:var(--text0);font-weight:500">${r.name}</div>
        <div style="font-size:11px;color:var(--text3)">${r.sizeHuman} · ${r.fileType.name} · Modified ${r.lastModified.split('T')[0]}</div>
      </div>
      <button class="btn btn-ghost btn-sm" onclick="resetFileUpload()">Analyze another</button>
      <button class="btn btn-ghost btn-sm" onclick="exportFileReport()">Export JSON</button>
      <button class="btn btn-primary btn-sm" onclick="saveFileHashesToDB()">Save hashes to DB</button>
    </div>
    
    <div class="grid-3" style="margin-bottom:16px">
      <div class="stat-card ${r.yaraHits.length?'red':''}">
        <div class="stat-value" style="${r.yaraHits.length?'':'color:var(--accent)'}">${r.yaraHits.length}</div>
        <div class="stat-label">YARA Rule Hits</div>
      </div>
      <div class="stat-card" style="${parseFloat(r.entropy)>6.5?'border-top-color:var(--red)':''}">
        <div class="stat-value" style="font-size:22px;${parseFloat(r.entropy)>6.5?'color:var(--red)':''}">${r.entropy}</div>
        <div class="stat-label">Entropy (0-8)</div>
      </div>
      <div class="stat-card blue">
        <div class="stat-value" style="font-size:20px">${r.strings.printableCount + r.strings.unicodeCount}</div>
        <div class="stat-label">Extracted Strings</div>
      </div>
    </div>

    <div class="grid-2" style="gap:16px">
      <div class="flex-col" style="gap:16px">
        <div class="card">
          <div class="card-header"><span class="card-title">Hashes</span></div>
          <div class="card-body">
            ${Object.entries(r.hashes).map(([algo,hash])=>`
              <div class="hash-row">
                <div class="hash-algo">${algo}</div>
                <div class="hash-val copyable" data-copy="${hash}" data-label="${algo}" onclick="copyFromAttr(this)">${hash}</div>
              </div>`).join('')}
          </div>
        </div>
        
        ${r.peInfo ? `
        <div class="card">
          <div class="card-header"><span class="card-title">PE Analysis</span></div>
          <div class="card-body">
            <div class="grid-2" style="gap:8px;margin-bottom:12px">
              <div><div class="form-label">Architecture</div><div style="font-size:12px;color:var(--text0)">${r.peInfo.arch}</div></div>
              <div><div class="form-label">Type</div><div style="font-size:12px;color:var(--text0)">${r.peInfo.type}</div></div>
              <div><div class="form-label">Subsystem</div><div style="font-size:12px;color:var(--text0)">${r.peInfo.subsystem}</div></div>
              <div><div class="form-label">Sections</div><div style="font-size:12px;color:var(--text0)">${r.peInfo.numSections}</div></div>
              <div colspan="2"><div class="form-label">Compile Time</div><div style="font-size:12px;color:${r.peInfo.compileTimestamp < 978307200 ? 'var(--red)' : 'var(--text0)'}">${r.peInfo.compileTime}</div></div>
            </div>
            <div class="section-title">Sections</div>
            <table class="phantom-table">
              <thead><tr><th>Name</th><th>VSize</th><th>RawSize</th><th>Entropy</th></tr></thead>
              <tbody>
                ${r.peInfo.sections.map(s=>`<tr>
                  <td class="mono">${s.name}</td>
                  <td>${(s.virtualSize/1024).toFixed(1)}K</td>
                  <td>${(s.rawSize/1024).toFixed(1)}K</td>
                  <td style="color:${parseFloat(s.entropy)>7?'var(--red)':parseFloat(s.entropy)>6?'var(--yellow)':'var(--text1)'}">${s.entropy}</td>
                </tr>`).join('')}
              </tbody>
            </table>
          </div>
        </div>` : ''}

        <div class="card">
          <div class="card-header"><span class="card-title">Entropy Analysis</span></div>
          <div class="card-body">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
              <div style="font-size:22px;font-weight:800;color:${r.entropyLabel.color}">${r.entropy}</div>
              <div>
                <div style="font-size:11px;color:${r.entropyLabel.color}">${r.entropyLabel.label}</div>
                <div style="font-size:10px;color:var(--text3)">Shannon entropy / 8 bits maximum</div>
              </div>
            </div>
            <div class="entropy-bar">
              <div class="entropy-cursor" style="left:${(parseFloat(r.entropy)/8*100).toFixed(1)}%"></div>
            </div>
            <div style="display:flex;justify-content:space-between;font-size:9px;color:var(--text3);margin-top:4px">
              <span>0 · Plaintext</span><span>4 · Compiled</span><span>7 · Packed</span><span>8 · Max</span>
            </div>
          </div>
        </div>
      </div>

      <div class="flex-col" style="gap:16px">
        ${r.yaraHits.length ? `
        <div class="card">
          <div class="card-header"><span class="card-title">YARA Rule Matches</span></div>
          <div class="card-body">
            ${r.yaraHits.map(h=>`
              <div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border)">
                <span class="tag tag-${h.severity}">${h.severity.toUpperCase()}</span>
                <span style="font-size:12px;color:var(--text0)">${h.rule}</span>
              </div>`).join('')}
          </div>
        </div>` : `
        <div class="card">
          <div class="card-header"><span class="card-title">YARA Rule Matches</span></div>
          <div class="card-body"><div class="empty-state" style="padding:24px"><div class="empty-icon" style="color:var(--accent)">✓</div><div class="empty-text">No YARA rule matches detected</div></div></div>
        </div>`}

        ${Object.keys(r.iocs).length ? `
        <div class="card">
          <div class="card-header"><span class="card-title">IOCs in Strings</span>
            <button class="btn btn-ghost btn-sm" onclick="State.extractedIOCs=State.lastFileResult.iocs;renderIOCResults(State.lastFileResult.iocs);showPage('ioc')">View in Extractor</button>
          </div>
          <div class="card-body" style="max-height:200px;overflow-y:auto">
            ${Object.entries(r.iocs).map(([type,items])=>`
              <div style="margin-bottom:8px">
                <div class="ioc-section-header"><span>${type.toUpperCase()}</span><span class="ioc-count">${items.length}</span></div>
                ${items.slice(0,5).map(i=>`<div class="ioc-item"><span class="ioc-value">${i.value}</span></div>`).join('')}
                ${items.length>5?`<div style="font-size:10px;color:var(--text3);padding:4px 8px">+${items.length-5} more</div>`:''}
              </div>`).join('')}
          </div>
        </div>` : ''}

        <div class="card">
          <div class="card-header">
            <span class="card-title">Extracted Strings</span>
            <button class="btn btn-ghost btn-sm" id="copy-strings-btn">Copy</button>
          </div>
          <div class="card-body">
            <div class="code-block" style="max-height:200px;overflow-y:auto;font-size:10px">
              ${r.strings.sample.map(s=>`<div>${escapeHtml(s)}</div>`).join('')}
              ${r.strings.printableCount > 50 ? `<div style="color:var(--text3)">... +${r.strings.printableCount - 50} more strings</div>` : ''}
            </div>
          </div>
        </div>
      </div>
    </div>`;

  // Attach strings copy handler after DOM is built
  const copyBtn = document.getElementById('copy-strings-btn');
  if (copyBtn) {
    copyBtn.onclick = () => copyText((State.lastFileResult?.strings?.sample || []).join('\n'), 'Strings');
  }
}

function escapeHtml(str) {
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

async function saveFileHashesToDB() {
  if (!State.lastFileResult) return;
  const r = State.lastFileResult;
  for (const [algo, hash] of Object.entries(r.hashes)) {
    await PhantomDB.addIOC(hash, 'hash', { algo: algo.toLowerCase(), source: `file:${r.name}`, confidence: 1.0 });
  }
  showToast(`${Object.keys(r.hashes).length} hashes saved`);
  refreshStats();
}

function exportFileReport() {
  if (!State.lastFileResult) return;
  downloadText(JSON.stringify(State.lastFileResult, null, 2), `phantom-file-report-${State.lastFileResult.name}.json`);
}

// ============================================================
// ATT&CK MAPPER
// ============================================================

function initATTCK() {
  renderATTCKHeatmap();
  renderATTCKTacticFilter();
  renderATTCKSearch('');
  renderSelectedTTPs();
}

function renderATTCKTacticFilter() {
  const el = document.getElementById('attck-tactic-filter');
  el.innerHTML = ATTCK_DATA.tactics.map(t => `
    <button class="btn btn-ghost btn-sm ${State.attckFilter===t.id?'active':''}" style="${State.attckFilter===t.id?'border-color:var(--accent);color:var(--accent);':''};font-size:9px;padding:3px 8px" onclick="toggleATTCKFilter('${t.id}')">${t.short}</button>
  `).join('');
}

function toggleATTCKFilter(tacticId) {
  State.attckFilter = State.attckFilter === tacticId ? null : tacticId;
  renderATTCKTacticFilter();
  renderATTCKSearch(document.getElementById('attck-search').value);
}

function renderATTCKSearch(query) {
  const el = document.getElementById('attck-results');
  let techniques = ATTCK_DATA.techniques;
  if (State.attckFilter) techniques = techniques.filter(t => t.tactic === State.attckFilter);
  if (query) {
    const q = query.toLowerCase();
    techniques = techniques.filter(t => t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q) || t.desc.toLowerCase().includes(q));
  }
  if (!techniques.length) { el.innerHTML = `<div class="empty-text" style="text-align:center;padding:24px">No techniques found</div>`; return; }
  el.innerHTML = techniques.slice(0, 200).map(t => {
    const tactic = ATTCK_DATA.tactics.find(ta => ta.id === t.tactic);
    const selected = State.selectedTTPs.has(t.id);
    return `<div class="ttp-item ${selected?'selected':''}" onclick="toggleTTP('${t.id}')">
      <span class="ttp-id">${t.id}</span>
      <span class="ttp-name">${t.name}</span>
      <span class="ttp-tactic">${tactic?.short||''}</span>
    </div>`;
  }).join('');
}

function toggleTTP(id) {
  if (State.selectedTTPs.has(id)) State.selectedTTPs.delete(id);
  else State.selectedTTPs.add(id);
  renderATTCKSearch(document.getElementById('attck-search').value);
  renderSelectedTTPs();
  renderATTCKHeatmap();
}

function renderSelectedTTPs() {
  const el = document.getElementById('selected-ttps');
  const countEl = document.getElementById('ttp-count');
  countEl.textContent = `${State.selectedTTPs.size} selected`;
  if (!State.selectedTTPs.size) { el.innerHTML = `<div class="empty-text">No techniques selected</div>`; return; }
  el.innerHTML = [...State.selectedTTPs].sort().map(id => {
    const t = ATTCK_DATA.techniques.find(x => x.id === id);
    if (!t) return '';
    const tactic = ATTCK_DATA.tactics.find(ta => ta.id === t.tactic);
    return `<div class="ttp-item selected">
      <span class="ttp-id">${t.id}</span>
      <span class="ttp-name" style="font-size:11px">${t.name}</span>
      <span class="ttp-tactic">${tactic?.short||''}</span>
      <span onclick="toggleTTP('${id}')" style="cursor:pointer;color:var(--text3);padding:0 4px">✕</span>
    </div>`;
  }).join('');
}

function renderATTCKHeatmap() {
  const el = document.getElementById('attck-heatmap');
  if (!el) return;
  const countByTactic = {};
  for (const ttpId of State.selectedTTPs) {
    const t = ATTCK_DATA.techniques.find(x => x.id === ttpId);
    if (t) countByTactic[t.tactic] = (countByTactic[t.tactic] || 0) + 1;
  }
  el.innerHTML = ATTCK_DATA.tactics.map(tac => {
    const count = countByTactic[tac.id] || 0;
    return `<div class="attck-tactic ${count>0?'has-hits':''}" title="${tac.name}: ${count} technique(s)">
      <div class="attck-tactic-name">${tac.short}</div>
      <div class="attck-count">${count}</div>
    </div>`;
  }).join('');
}

function clearATTCKSelection() {
  State.selectedTTPs.clear();
  State.attckFilter = null;
  renderATTCKTacticFilter();
  renderATTCKSearch(document.getElementById('attck-search')?.value || '');
  renderSelectedTTPs();
  renderATTCKHeatmap();
}

function exportNavigatorLayer() {
  if (!State.selectedTTPs.size) { showToast('No techniques selected', 'warning'); return; }
  // Tactic shortname map — Navigator requires hyphenated lowercase, not TA#### IDs
  const tacticNames = {
    TA0043:'reconnaissance', TA0042:'resource-development', TA0001:'initial-access',
    TA0002:'execution', TA0003:'persistence', TA0004:'privilege-escalation',
    TA0005:'defense-evasion', TA0006:'credential-access', TA0007:'discovery',
    TA0008:'lateral-movement', TA0009:'collection', TA0011:'command-and-control',
    TA0010:'exfiltration', TA0040:'impact',
  };
  const layer = {
    name: 'PHANTOM Export',
    versions: { attack: '14', navigator: '4.9', layer: '4.5' },
    domain: 'enterprise-attack',
    description: `Generated by PHANTOM Web on ${new Date().toISOString()}`,
    techniques: [...State.selectedTTPs].map(id => {
      const tech = ATTCK_DATA.techniques.find(t=>t.id===id);
      const entry = { techniqueID: id, color: '#00d4aa', comment: '', enabled: true, score: 1 };
      if (tech?.tactic && tacticNames[tech.tactic]) entry.tactic = tacticNames[tech.tactic];
      return entry;
    }),
    gradient: { colors: ['#ffffff','#00d4aa'], minValue: 0, maxValue: 100 },
    legendItems: [],
    metadata: [],
    showTacticRowBackground: true,
    tacticRowBackground: '#0d1117',
  };
  downloadText(JSON.stringify(layer, null, 2), 'phantom-attck-layer.json');
  showToast('ATT&CK Navigator layer exported');
}

function exportTTPsText() {
  if (!State.selectedTTPs.size) { showToast('No techniques selected', 'warning'); return; }
  const lines = [...State.selectedTTPs].sort().map(id => {
    const t = ATTCK_DATA.techniques.find(x=>x.id===id);
    return t ? `${t.id}\t${t.name}` : id;
  });
  downloadText(lines.join('\n'), 'phantom-ttps.txt', 'text/plain');
}

// ============================================================
// DIAMOND MODEL
// ============================================================

function updateDiamondPreview() {
  const fields = ['adversary','capability','infrastructure','victim'];
  for (const f of fields) {
    const val = document.getElementById(`diamond-${f}`)?.value?.trim();
    document.getElementById(`dv-${f}`).textContent = val ? val.slice(0,80)+(val.length>80?'...':'') : 'Not set';
  }
}

['adversary','capability','infrastructure','victim','name','notes'].forEach(f => {
  const el = document.getElementById(`diamond-${f}`);
  if (el) el.addEventListener('input', updateDiamondPreview);
});

function clearDiamond() {
  ['adversary','capability','infrastructure','victim','name','notes'].forEach(f => {
    const el = document.getElementById(`diamond-${f}`);
    if (el) el.value = '';
  });
  document.getElementById('diamond-phase').value = '';
  updateDiamondPreview();
}

async function saveDiamond() {
  const name = document.getElementById('diamond-name').value.trim();
  if (!name) { showToast('Enter instance name', 'warning'); return; }
  const tlpEl = document.querySelector('input[name="tlp"]:checked');
  const instance = {
    name,
    adversary: document.getElementById('diamond-adversary').value,
    capability: document.getElementById('diamond-capability').value,
    infrastructure: document.getElementById('diamond-infrastructure').value,
    victim: document.getElementById('diamond-victim').value,
    phase: document.getElementById('diamond-phase').value,
    confidence: parseFloat(document.getElementById('diamond-confidence').value),
    tlp: tlpEl?.value || 'amber',
    notes: document.getElementById('diamond-notes').value,
    created: Date.now(),
  };
  await PhantomDB.put('investigations', instance);
  showToast('Diamond Model instance saved');
  refreshDiamondInstances();
}

async function refreshDiamondInstances() {
  const instances = await PhantomDB.getAll('investigations');
  const el = document.getElementById('diamond-instances');
  if (!instances.length) { el.innerHTML = `<div class="empty-state"><div class="empty-icon">◇</div><div class="empty-text">No saved instances yet.</div></div>`; return; }
  el.innerHTML = instances.sort((a,b)=>b.created-a.created).map(inst => `
    <div style="border:1px solid var(--border);border-radius:4px;padding:10px;margin-bottom:8px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
        <div style="flex:1;font-size:12px;color:var(--text0)">${escapeHtml(inst.name)}</div>
        <span class="tag tag-tlp-${inst.tlp}">TLP:${inst.tlp.toUpperCase()}</span>
        <span style="font-size:10px;color:var(--text3)">${Math.round((inst.confidence||.7)*100)}%</span>
        <button class="btn btn-danger btn-sm" onclick="deleteInstance('${inst.id}')">✕</button>
      </div>
      ${inst.adversary?`<div style="font-size:10px;color:var(--text3);margin-bottom:2px"><span style="color:var(--red)">Adversary:</span> ${escapeHtml(inst.adversary.slice(0,60))}</div>`:''}
      ${inst.victim?`<div style="font-size:10px;color:var(--text3);margin-bottom:2px"><span style="color:var(--yellow)">Victim:</span> ${escapeHtml(inst.victim.slice(0,60))}</div>`:''}
      ${inst.phase?`<div style="font-size:10px;color:var(--text3)"><span style="color:var(--blue)">Phase:</span> ${inst.phase}</div>`:''}
    </div>`).join('');
}

async function deleteInstance(id) {
  await PhantomDB.del('investigations', id);
  refreshDiamondInstances();
  showToast('Instance deleted', 'warning');
}

async function exportDiamondJSON() {
  const instances = await PhantomDB.getAll('investigations');
  downloadText(JSON.stringify(instances, null, 2), 'phantom-diamond-instances.json');
  showToast('Diamond instances exported');
}

// ============================================================
// IOC DATABASE
// ============================================================

async function refreshDatabase(query) {
  if (query === undefined) query = document.getElementById('db-search')?.value || '';
  const typeFilter = document.getElementById('db-type-filter')?.value || '';
  let iocs = await PhantomDB.getAll('iocs');
  if (typeFilter) iocs = iocs.filter(i => i.type === typeFilter);
  if (query) {
    const q = query.toLowerCase();
    iocs = iocs.filter(i => i.value.includes(q) || (i.tags||[]).join(',').includes(q) || (i.source||'').includes(q));
  }
  iocs.sort((a,b) => (b.lastSeen||0) - (a.lastSeen||0));
  const tbody = document.getElementById('db-table-body');
  if (!iocs.length) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;color:var(--text3);padding:32px">No IOCs match your filter</td></tr>`;
    return;
  }
  tbody.innerHTML = iocs.map(ioc => `
    <tr>
      <td class="mono copyable" data-copy="${escapeHtml(ioc.value)}" data-label="IOC" onclick="copyFromAttr(this)" title="Click to copy">${escapeHtml(ioc.value)}</td>
      <td><span class="tag tag-type">${ioc.type}</span></td>
      <td><span class="tag tag-tlp-${ioc.tlp||'amber'}">TLP:${(ioc.tlp||'amber').toUpperCase()}</span></td>
      <td>
        <div style="display:flex;align-items:center;gap:6px">
          <div class="progress-bar" style="width:60px"><div class="progress-fill" style="width:${((ioc.confidence||.5)*100).toFixed(0)}%"></div></div>
          <span style="font-size:10px;color:var(--text3)">${((ioc.confidence||.5)*100).toFixed(0)}%</span>
        </div>
      </td>
      <td style="font-size:10px;color:var(--text3)">${escapeHtml(ioc.source||'')}</td>
      <td>${(ioc.tags||[]).map(t=>`<span class="tag tag-info" style="font-size:9px">${t}</span>`).join(' ')}</td>
      <td style="font-size:10px;color:var(--text3)">${ioc.added ? new Date(ioc.added).toLocaleDateString() : '–'}</td>
      <td style="font-size:11px;color:var(--text2)">${ioc.count||1}</td>
      <td>
        <button class="btn btn-danger btn-sm" onclick="deleteIOC('${ioc.id}')">✕</button>
      </td>
    </tr>`).join('');
}

async function deleteIOC(id) {
  await PhantomDB.del('iocs', id);
  refreshDatabase();
  refreshStats();
  showToast('IOC removed', 'warning');
}

async function exportDBCSV() {
  const csv = await PhantomDB.exportCSV('iocs');
  if (!csv) { showToast('No IOCs to export', 'warning'); return; }
  downloadText(csv, 'phantom-iocs-db.csv', 'text/csv');
  showToast('IOC database exported as CSV');
}

async function exportDBSTIX() {
  const stix = await PhantomDB.exportSTIX();
  downloadText(stix, 'phantom-stix-bundle.json');
  showToast('STIX 2.1 bundle exported');
}

// ============================================================
// REPORT BUILDER
// ============================================================

function previewReport() {
  const r = gatherReportData();
  const preview = buildReportText(r);
  document.getElementById('report-preview').textContent = preview;
}

function gatherReportData() {
  return {
    title: document.getElementById('rpt-title').value || 'Threat Intelligence Report',
    analyst: document.getElementById('rpt-analyst').value || 'Unknown Analyst',
    org: document.getElementById('rpt-org').value || '',
    tlp: document.getElementById('rpt-tlp').value || 'AMBER',
    date: document.getElementById('rpt-date').value || new Date().toISOString().split('T')[0],
    summary: document.getElementById('rpt-summary').value,
    actor: document.getElementById('rpt-actor').value,
    campaign: document.getElementById('rpt-campaign').value,
    technical: document.getElementById('rpt-technical').value,
    recommendations: document.getElementById('rpt-recommendations').value,
    ttps: [...State.selectedTTPs].join(', '),
    iocCount: Object.values(State.extractedIOCs).reduce((a,b)=>a+b.length,0),
    generated: new Date().toISOString(),
  };
}

function buildReportText(r) {
  const sep = '═'.repeat(70);
  const sep2 = '─'.repeat(70);
  return `${sep}
TLP:${r.tlp}                                   PHANTOM TI Report
${sep}

TITLE:    ${r.title}
DATE:     ${r.date}
ANALYST:  ${r.analyst}${r.org ? ` · ${r.org}` : ''}
GENERATED: ${r.generated}
TLP:      ${r.tlp}

${sep2}
1. EXECUTIVE SUMMARY
${sep2}
${r.summary || '[Not provided]'}

${sep2}
2. THREAT ACTOR / ATTRIBUTION
${sep2}
${r.actor || '[Not provided]'}

${sep2}
3. CAMPAIGN DESCRIPTION
${sep2}
${r.campaign || '[Not provided]'}

${sep2}
4. TECHNICAL ANALYSIS
${sep2}
${r.technical || '[Not provided]'}

${sep2}
5. MITRE ATT&CK TECHNIQUES
${sep2}
${r.ttps ? [...State.selectedTTPs].sort().map(id => {
  const t = ATTCK_DATA.techniques.find(x=>x.id===id);
  return t ? `  ${t.id}  ${t.name}` : `  ${id}`;
}).join('\n') : '[No TTPs mapped]'}

${sep2}
6. INDICATORS OF COMPROMISE
${sep2}
IOCs in current session: ${r.iocCount}

${Object.entries(State.extractedIOCs).map(([type, items]) =>
  items.length ? `  ${type.toUpperCase()} (${items.length}):\n${items.map(i=>`    ${i.value}`).join('\n')}` : ''
).filter(Boolean).join('\n\n') || '[No IOCs extracted in this session]'}

${sep2}
7. RECOMMENDATIONS
${sep2}
${r.recommendations || '[Not provided]'}

${sep}
END OF REPORT — Generated by PHANTOM Web v1.0
TLP:${r.tlp} — ${r.org || 'PHANTOM Web'} — ${r.date}
${sep}`;
}

function downloadReportTXT() {
  const r = gatherReportData();
  const text = buildReportText(r);
  const filename = `phantom-report-${r.title.replace(/[^a-z0-9]/gi,'-').toLowerCase()}-${r.date}.txt`;
  downloadText(text, filename, 'text/plain');
  showToast('Report downloaded');
}

function downloadReportJSON() {
  const r = { ...gatherReportData(), ttps: [...State.selectedTTPs], iocs: State.extractedIOCs };
  downloadText(JSON.stringify(r, null, 2), 'phantom-report.json');
  showToast('Report JSON downloaded');
}

// ============================================================
// Utilities
// ============================================================

function downloadText(text, filename, type = 'application/json') {
  const blob = new Blob([text], { type });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ============================================================
// Init
// ============================================================

async function init() {
  await PhantomDB.open();
  await refreshStats();
  initATTCK();

  // Auto-populate report date with today
  const dateEl = document.getElementById('rpt-date');
  if (dateEl && !dateEl.value) dateEl.value = new Date().toISOString().split('T')[0];
  
  // Recent activity placeholder
  const recentEl = document.getElementById('recent-activity');
  const allIOCs = await PhantomDB.getAll('iocs');
  if (allIOCs.length) {
    const recent = allIOCs.sort((a,b)=>(b.lastSeen||0)-(a.lastSeen||0)).slice(0, 8);
    recentEl.innerHTML = `<div class="timeline">${recent.map(ioc=>`
      <div class="timeline-item">
        <div class="timeline-dot"></div>
        <div class="timeline-time">${new Date(ioc.added||Date.now()).toLocaleString()}</div>
        <div class="timeline-content"><span class="tag tag-type" style="font-size:9px">${ioc.type}</span> ${escapeHtml(ioc.value.slice(0,60))}</div>
      </div>`).join('')}</div>`;
  }
}

document.addEventListener('DOMContentLoaded', init);
