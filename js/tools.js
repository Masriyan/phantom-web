// ============================================================
// PHANTOM Web — Tools Module
// Cyber Swiss Army Knife · Hash Identifier · URL Analyzer
// Threat Actor Profile Cards · CVSS v3.1 Calculator
// ============================================================

// ============================================================
// 1. CYBER SWISS ARMY KNIFE
// ============================================================

const SwissKnife = {
  activeTab: 'encoder',

  init() {
    this.switchTab('encoder');
  },

  switchTab(tab) {
    this.activeTab = tab;
    document.querySelectorAll('.swiss-tab').forEach(t => {
      t.classList.toggle('active', t.dataset.tab === tab);
    });
    document.querySelectorAll('.swiss-panel').forEach(p => {
      p.style.display = p.id === `swiss-panel-${tab}` ? 'block' : 'none';
    });
  },

  // --- Encoder/Decoder ---
  encode(mode) {
    const input = document.getElementById('enc-input').value;
    const outputEl = document.getElementById('enc-output');
    try {
      let result = '';
      switch (mode) {
        case 'b64enc': result = btoa(unescape(encodeURIComponent(input))); break;
        case 'b64dec': result = decodeURIComponent(escape(atob(input))); break;
        case 'urlenc': result = encodeURIComponent(input); break;
        case 'urldec': result = decodeURIComponent(input); break;
        case 'htmlenc': result = input.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); break;
        case 'htmldec': { const d=document.createElement('div'); d.innerHTML=input; result=d.textContent; break; }
        case 'hexenc': result = Array.from(input).map(c=>c.charCodeAt(0).toString(16).padStart(2,'0')).join(' '); break;
        case 'hexdec': result = input.trim().split(/\s+/).map(h=>String.fromCharCode(parseInt(h,16))).join(''); break;
        case 'rot13': result = input.replace(/[a-zA-Z]/g, c => String.fromCharCode(c.charCodeAt(0) + (c.toLowerCase() < 'n' ? 13 : -13))); break;
        case 'binenc': result = Array.from(input).map(c=>c.charCodeAt(0).toString(2).padStart(8,'0')).join(' '); break;
        case 'bindec': result = input.trim().split(/\s+/).map(b=>String.fromCharCode(parseInt(b,2))).join(''); break;
        default: result = input;
      }
      outputEl.value = result;
    } catch(e) {
      outputEl.value = `[Error: ${e.message}]`;
    }
  },

  encXOR() {
    const input = document.getElementById('enc-input').value;
    const keyStr = document.getElementById('xor-key').value || 'A';
    const key = Array.from(keyStr).map(c=>c.charCodeAt(0));
    const result = Array.from(input).map((c,i)=>String.fromCharCode(c.charCodeAt(0)^key[i%key.length])).join('');
    document.getElementById('enc-output').value = result;
  },

  swapEnc() {
    const a = document.getElementById('enc-input');
    const b = document.getElementById('enc-output');
    const tmp = a.value; a.value = b.value; b.value = tmp;
  },

  clearEnc() {
    document.getElementById('enc-input').value = '';
    document.getElementById('enc-output').value = '';
  },

  // --- JWT Decoder ---
  decodeJWT() {
    const token = document.getElementById('jwt-input').value.trim();
    const el = document.getElementById('jwt-output');
    if (!token) { el.innerHTML = '<div class="empty-text">Paste a JWT token</div>'; return; }
    const parts = token.split('.');
    if (parts.length !== 3) { el.innerHTML = '<div style="color:var(--red)">Invalid JWT format (expected 3 parts)</div>'; return; }
    try {
      const decode = str => {
        try { return JSON.parse(atob(str.replace(/-/g,'+').replace(/_/g,'/'))); } catch { return {}; }
      };
      const header = decode(parts[0]);
      const payload = decode(parts[1]);
      const now = Math.floor(Date.now()/1000);
      const expired = payload.exp && payload.exp < now;
      const notBefore = payload.nbf && payload.nbf > now;
      el.innerHTML = `
        <div class="jwt-section">
          <div class="jwt-part-label" style="color:var(--red)">◈ HEADER · Algorithm &amp; Token Type</div>
          <pre class="code-block" style="font-size:11px;margin:6px 0">${JSON.stringify(header,null,2)}</pre>
        </div>
        <div class="jwt-section">
          <div class="jwt-part-label" style="color:var(--purple)">◈ PAYLOAD · Claims</div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;margin:6px 0">
            ${expired ? '<span class="tag tag-high">EXPIRED</span>' : payload.exp ? `<span class="tag tag-info">Expires: ${new Date(payload.exp*1000).toLocaleString()}</span>` : ''}
            ${notBefore ? '<span class="tag tag-high">NOT YET VALID</span>' : ''}
            ${payload.iss ? `<span class="tag tag-info">iss: ${payload.iss}</span>` : ''}
            ${payload.sub ? `<span class="tag tag-info">sub: ${payload.sub}</span>` : ''}
          </div>
          <pre class="code-block" style="font-size:11px;margin:6px 0">${JSON.stringify(payload,null,2)}</pre>
        </div>
        <div class="jwt-section">
          <div class="jwt-part-label" style="color:var(--text3)">◈ SIGNATURE (not verified — no key)</div>
          <div class="code-block" style="font-size:10px;word-break:break-all;margin:6px 0;color:var(--text3)">${parts[2]}</div>
        </div>`;
    } catch(e) {
      el.innerHTML = `<div style="color:var(--red)">Parse error: ${e.message}</div>`;
    }
  },

  // --- CIDR Calculator ---
  calcCIDR() {
    const input = document.getElementById('cidr-input').value.trim();
    const el = document.getElementById('cidr-output');
    try {
      const [ip, prefix] = input.split('/');
      if (!ip || prefix === undefined) { el.innerHTML = '<div style="color:var(--red)">Format: x.x.x.x/prefix</div>'; return; }
      const pfx = parseInt(prefix);
      if (pfx < 0 || pfx > 32) throw new Error('Prefix must be 0-32');
      const parts = ip.split('.').map(Number);
      if (parts.length !== 4 || parts.some(p=>p<0||p>255||isNaN(p))) throw new Error('Invalid IP address');
      const ipInt = ((parts[0]<<24)|(parts[1]<<16)|(parts[2]<<8)|parts[3])>>>0;
      const mask = pfx === 0 ? 0 : (~0 << (32-pfx))>>>0;
      const network = (ipInt & mask)>>>0;
      const broadcast = (network | ~mask)>>>0;
      const first = pfx < 31 ? network + 1 : network;
      const last = pfx < 31 ? broadcast - 1 : broadcast;
      const count = Math.pow(2, 32-pfx);
      const usable = pfx <= 30 ? count - 2 : count;
      const toIP = n => [(n>>>24)&255,(n>>>16)&255,(n>>>8)&255,n&255].join('.');
      const toMaskBin = m => [(m>>>24)&255,(m>>>16)&255,(m>>>8)&255,m&255].map(b=>b.toString(2).padStart(8,'0')).join('.');
      el.innerHTML = `
        <div class="cidr-result">
          ${[
            ['Network Address', toIP(network)],
            ['Broadcast Address', toIP(broadcast)],
            ['Subnet Mask', toIP(mask)],
            ['Wildcard Mask', toIP(~mask>>>0)],
            ['First Usable Host', toIP(first)],
            ['Last Usable Host', toIP(last)],
            ['Total Addresses', count.toLocaleString()],
            ['Usable Hosts', usable.toLocaleString()],
            ['IP Class', pfx<=8?'A':pfx<=16?'B':pfx<=24?'C':'Classless'],
            ['Binary Mask', `<span style="font-size:9px;color:var(--text3)">${toMaskBin(mask)}</span>`],
          ].map(([k,v])=>`<div class="cidr-row"><span class="cidr-key">${k}</span><span class="cidr-val copyable" data-copy="${v}" data-label="${k}" onclick="copyFromAttr(this)">${v}</span></div>`).join('')}
          ${pfx >= 8 ? `<div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border)">
            <div class="section-title" style="margin-bottom:6px">Subnet Breakdown (/${pfx+2}, ${(count/4).toLocaleString()} hosts each)</div>
            ${Array.from({length:Math.min(4,4)},(_,i)=>{
              const sub = (network + i*(count/4))>>>0;
              return `<div class="cidr-row"><span class="cidr-key">Subnet ${i+1}</span><span class="cidr-val">${toIP(sub)}/${pfx+2}</span></div>`;
            }).join('')}
          </div>` : ''}
        </div>`;
    } catch(e) {
      el.innerHTML = `<div style="color:var(--red)">Error: ${e.message}</div>`;
    }
  },

  // --- Regex Tester ---
  testRegex() {
    const pattern = document.getElementById('regex-pattern').value;
    const flags = document.getElementById('regex-flags').value;
    const input = document.getElementById('regex-input').value;
    const el = document.getElementById('regex-output');
    if (!pattern) { el.innerHTML = '<div class="empty-text">Enter a regex pattern</div>'; return; }
    try {
      const rx = new RegExp(pattern, flags);
      const matches = [];
      let m;
      if (flags.includes('g')) {
        while ((m = rx.exec(input)) !== null) matches.push(m);
      } else {
        m = rx.exec(input);
        if (m) matches.push(m);
      }
      if (!matches.length) {
        el.innerHTML = '<div style="color:var(--yellow);padding:8px">No matches found</div>';
        document.getElementById('regex-highlight').innerHTML = escapeHtmlTools(input);
        return;
      }
      let highlighted = input;
      let offset = 0;
      const sortedMatches = [...matches].sort((a,b)=>a.index-b.index);
      for (const match of sortedMatches) {
        const start = match.index + offset;
        const end = start + match[0].length;
        const tag = `<mark style="background:var(--accent);color:var(--bg0);border-radius:2px">${escapeHtmlTools(match[0])}</mark>`;
        highlighted = highlighted.slice(0,start) + tag + highlighted.slice(end);
        offset += tag.length - match[0].length;
      }
      document.getElementById('regex-highlight').innerHTML = highlighted;
      el.innerHTML = `
        <div style="color:var(--accent);margin-bottom:8px">✓ ${matches.length} match${matches.length>1?'es':''} found</div>
        ${matches.map((match,i)=>`
          <div style="border:1px solid var(--border);border-radius:4px;padding:8px;margin-bottom:6px">
            <div style="font-size:10px;color:var(--text3);margin-bottom:4px">Match ${i+1} · index ${match.index}</div>
            <div class="copyable" style="font-size:12px;color:var(--text0)" data-copy="${escapeHtmlTools(match[0])}" onclick="copyFromAttr(this)">${escapeHtmlTools(match[0])}</div>
            ${match.length>1 ? `<div style="margin-top:6px">${match.slice(1).map((g,gi)=>`<div style="font-size:10px;color:var(--text3)">Group ${gi+1}: <span style="color:var(--blue)">${g||'undefined'}</span></div>`).join('')}</div>` : ''}
          </div>`).join('')}`;
    } catch(e) {
      el.innerHTML = `<div style="color:var(--red)">Regex error: ${e.message}</div>`;
      document.getElementById('regex-highlight').innerHTML = escapeHtmlTools(input);
    }
  },

  // --- Epoch Converter ---
  convertEpoch() {
    const val = document.getElementById('epoch-input').value.trim();
    const el = document.getElementById('epoch-output');
    const ts = val ? parseInt(val) : Math.floor(Date.now()/1000);
    const ms = ts < 1e10 ? ts * 1000 : ts;
    const d = new Date(ms);
    if (isNaN(d.getTime())) { el.innerHTML = '<div style="color:var(--red)">Invalid timestamp</div>'; return; }
    const now = Date.now();
    const diff = Math.abs(now - ms);
    const diffStr = diff < 60000 ? 'just now' : diff < 3600000 ? `${Math.floor(diff/60000)}m ago/ahead` : diff < 86400000 ? `${Math.floor(diff/3600000)}h ago/ahead` : `${Math.floor(diff/86400000)}d ago/ahead`;
    el.innerHTML = [
      ['Unix (seconds)', ts < 1e10 ? ts : Math.floor(ts/1000)],
      ['Unix (milliseconds)', ms],
      ['UTC', d.toUTCString()],
      ['ISO 8601', d.toISOString()],
      ['Local', d.toLocaleString()],
      ['WIB (UTC+7)', new Date(ms + 7*3600000).toUTCString().replace('GMT','WIB')],
      ['WITA (UTC+8)', new Date(ms + 8*3600000).toUTCString().replace('GMT','WITA')],
      ['Relative', diffStr],
    ].map(([k,v])=>`<div class="cidr-row"><span class="cidr-key">${k}</span><span class="cidr-val copyable" data-copy="${v}" data-label="${k}" onclick="copyFromAttr(this)">${v}</span></div>`).join('');
  },

  epochNow() {
    document.getElementById('epoch-input').value = Math.floor(Date.now()/1000);
    this.convertEpoch();
  },

  dateToEpoch() {
    const val = document.getElementById('date-input').value;
    if (!val) return;
    document.getElementById('epoch-input').value = Math.floor(new Date(val).getTime()/1000);
    this.convertEpoch();
  },
};

// ============================================================
// 2. HASH IDENTIFIER
// ============================================================

const HashIdentifier = {
  HASH_TYPES: [
    { name: 'MD5', len: 32, charset: /^[0-9a-f]+$/i, confidence: 95, cat: 'crypto', desc: 'Message Digest 5 — weak, deprecated' },
    { name: 'NTLM', len: 32, charset: /^[0-9a-f]+$/i, confidence: 70, cat: 'windows', desc: 'Windows NTLM password hash' },
    { name: 'LM Hash', len: 32, charset: /^[0-9A-F]+$/, confidence: 50, cat: 'windows', desc: 'LAN Manager hash — very weak' },
    { name: 'SHA-1', len: 40, charset: /^[0-9a-f]+$/i, confidence: 95, cat: 'crypto', desc: 'Secure Hash Algorithm 1 — deprecated' },
    { name: 'MySQL 4.x', len: 16, charset: /^[0-9a-f]+$/i, confidence: 60, cat: 'database', desc: 'MySQL v4 password hash' },
    { name: 'SHA-256', len: 64, charset: /^[0-9a-f]+$/i, confidence: 95, cat: 'crypto', desc: 'SHA-2 family — widely used' },
    { name: 'SHA-384', len: 96, charset: /^[0-9a-f]+$/i, confidence: 90, cat: 'crypto', desc: 'SHA-2 — 384-bit variant' },
    { name: 'SHA-512', len: 128, charset: /^[0-9a-f]+$/i, confidence: 95, cat: 'crypto', desc: 'SHA-2 — 512-bit variant' },
    { name: 'SHA3-256', len: 64, charset: /^[0-9a-f]+$/i, confidence: 60, cat: 'crypto', desc: 'SHA-3 Keccak — 256-bit' },
    { name: 'SHA3-512', len: 128, charset: /^[0-9a-f]+$/i, confidence: 60, cat: 'crypto', desc: 'SHA-3 Keccak — 512-bit' },
    { name: 'RIPEMD-160', len: 40, charset: /^[0-9a-f]+$/i, confidence: 50, cat: 'crypto', desc: 'RIPEMD-160 — used in Bitcoin' },
    { name: 'RIPEMD-256', len: 64, charset: /^[0-9a-f]+$/i, confidence: 50, cat: 'crypto', desc: 'RIPEMD-256 variant' },
    { name: 'Whirlpool', len: 128, charset: /^[0-9a-f]+$/i, confidence: 60, cat: 'crypto', desc: 'Whirlpool 512-bit hash' },
    { name: 'MySQL 5.x', len: 41, charset: /^\*[0-9A-F]{40}$/, confidence: 95, cat: 'database', desc: 'MySQL v5+ password hash (asterisk prefix)' },
    { name: 'bcrypt', len: 60, charset: /^\$2[aby]?\$\d{2}\$.{53}$/, confidence: 99, cat: 'password', desc: 'bcrypt adaptive hash — strong' },
    { name: 'scrypt', len: 0, charset: /^\$s0\$/, confidence: 99, cat: 'password', desc: 'scrypt — memory-hard KDF' },
    { name: 'Argon2', len: 0, charset: /^\$argon2/, confidence: 99, cat: 'password', desc: 'Argon2 — PHC winner, very strong' },
    { name: 'SHA-512 Crypt', len: 0, charset: /^\$6\$/, confidence: 99, cat: 'unix', desc: 'Linux /etc/shadow SHA-512 crypt' },
    { name: 'SHA-256 Crypt', len: 0, charset: /^\$5\$/, confidence: 99, cat: 'unix', desc: 'Linux /etc/shadow SHA-256 crypt' },
    { name: 'MD5 Crypt', len: 0, charset: /^\$1\$/, confidence: 99, cat: 'unix', desc: 'Linux /etc/shadow MD5 crypt — weak' },
    { name: 'Django SHA1', len: 0, charset: /^sha1\$/, confidence: 99, cat: 'web', desc: 'Django SHA1 password format' },
    { name: 'Django SHA256', len: 0, charset: /^pbkdf2_sha256\$/, confidence: 99, cat: 'web', desc: 'Django PBKDF2-SHA256' },
    { name: 'WordPress MD5', len: 0, charset: /^\$P\$/, confidence: 99, cat: 'web', desc: 'WordPress/phpBB3 MD5 (phpass)' },
    { name: 'Joomla MD5', len: 0, charset: /^[a-f0-9]{32}:[a-zA-Z0-9]{32}$/, confidence: 99, cat: 'web', desc: 'Joomla MD5 with salt' },
    { name: 'CRC-32', len: 8, charset: /^[0-9a-f]+$/i, confidence: 40, cat: 'checksum', desc: 'CRC-32 checksum (8 hex chars)' },
    { name: 'Adler-32', len: 8, charset: /^[0-9a-f]+$/i, confidence: 30, cat: 'checksum', desc: 'Adler-32 checksum' },
    { name: 'BLAKE2-256', len: 64, charset: /^[0-9a-f]+$/i, confidence: 50, cat: 'crypto', desc: 'BLAKE2b 256-bit variant' },
    { name: 'BLAKE2-512', len: 128, charset: /^[0-9a-f]+$/i, confidence: 50, cat: 'crypto', desc: 'BLAKE2b 512-bit variant' },
    { name: 'Tiger/192', len: 48, charset: /^[0-9a-f]+$/i, confidence: 70, cat: 'crypto', desc: 'Tiger 192-bit hash' },
    { name: 'Haval-256', len: 64, charset: /^[0-9a-f]+$/i, confidence: 30, cat: 'crypto', desc: 'Haval 256-bit hash' },
    { name: 'NTLM v2', len: 32, charset: /^[0-9a-f]+$/i, confidence: 50, cat: 'windows', desc: 'NTLMv2 hash component' },
    { name: 'LANMAN', len: 48, charset: /^[0-9a-f]+$/i, confidence: 40, cat: 'windows', desc: 'LAN Manager challenge response' },
    { name: 'Kerberos AES-256', len: 64, charset: /^[0-9a-f]+$/i, confidence: 40, cat: 'windows', desc: 'Kerberos AES-256 ticket hash' },
  ],

  CAT_COLORS: {
    crypto: 'var(--accent)',
    windows: 'var(--blue)',
    database: 'var(--orange)',
    password: 'var(--red)',
    unix: 'var(--purple)',
    web: 'var(--pink)',
    checksum: 'var(--yellow)',
    default: 'var(--text2)',
  },

  identify(hash) {
    if (!hash) return [];
    hash = hash.trim();
    const len = hash.length;
    const results = [];

    for (const type of this.HASH_TYPES) {
      if (type.len === 0) {
        // Pattern-only match
        if (type.charset.test(hash)) {
          results.push({ ...type, confidence: type.confidence });
        }
      } else if (len === type.len && type.charset.test(hash)) {
        results.push({ ...type });
      }
    }

    return results.sort((a,b)=>b.confidence-a.confidence);
  },

  identifyAll() {
    const input = document.getElementById('hash-input').value;
    const hashes = input.split('\n').map(l=>l.trim()).filter(Boolean);
    const el = document.getElementById('hash-output');
    if (!hashes.length) { el.innerHTML = '<div class="empty-text">Enter hash(es) to identify</div>'; return; }

    let html = '';
    for (const hash of hashes) {
      const matches = this.identify(hash);
      const hashShort = hash.length > 64 ? hash.slice(0,32)+'…'+hash.slice(-8) : hash;
      html += `<div style="border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:10px">
        <div class="copyable" style="font-size:11px;color:var(--text1);word-break:break-all;margin-bottom:8px;font-family:var(--font-mono)" data-copy="${hash}" data-label="Hash" onclick="copyFromAttr(this)">${hashShort}</div>
        <div style="font-size:10px;color:var(--text3);margin-bottom:8px">Length: ${hash.length} chars · ${hash.length*4} bits</div>`;
      if (!matches.length) {
        html += `<div style="color:var(--yellow);font-size:11px">⚠ Unknown hash type or invalid input</div>`;
      } else {
        html += `<div style="display:flex;flex-wrap:wrap;gap:6px">`;
        for (const m of matches.slice(0,6)) {
          const color = this.CAT_COLORS[m.cat] || this.CAT_COLORS.default;
          html += `<div style="border:1px solid ${color}22;background:${color}11;border-radius:4px;padding:6px 10px;min-width:160px">
            <div style="font-size:12px;color:${color};font-weight:600">${m.name}</div>
            <div style="font-size:10px;color:var(--text3);margin-top:2px">${m.desc}</div>
            <div style="display:flex;align-items:center;gap:6px;margin-top:4px">
              <div style="flex:1;height:3px;background:var(--bg3);border-radius:2px">
                <div style="width:${m.confidence}%;height:100%;background:${color};border-radius:2px"></div>
              </div>
              <span style="font-size:9px;color:var(--text3)">${m.confidence}%</span>
            </div>
          </div>`;
        }
        html += `</div>`;
      }
      html += `</div>`;
    }
    el.innerHTML = html;
  },
};

// ============================================================
// 3. PHISHING URL ANALYZER
// ============================================================

const URLAnalyzer = {
  SUSPICIOUS_TLDS: ['xyz','top','icu','gq','ml','ga','cf','tk','pw','cc','buzz','click','link','online','site','website','store','shop','live'],
  BRAND_KEYWORDS: ['paypal','apple','google','microsoft','amazon','netflix','facebook','instagram','twitter','whatsapp','telegram','bank','secure','login','verify','account','update','confirm','support','helpdesk','signin','auth','wallet','crypto','bitcoin','coinbase','binance','bca','mandiri','bni','bri','danamon','cimb','ojk','pajak','bpjs','gojek','tokopedia','shopee','lazada','bukalapak'],
  HOMOGLYPHS: {'0':'o','1':'l','3':'e','4':'a','5':'s','6':'g','7':'t','@':['a']},

  analyze() {
    const input = document.getElementById('url-input').value.trim();
    const el = document.getElementById('url-output');
    if (!input) { el.innerHTML = '<div class="empty-text">Enter a URL to analyze</div>'; return; }

    // Refang if needed
    let url = input.replace(/hxxp/gi,'http').replace(/\[\.\]/g,'.').replace(/\[dot\]/gi,'.').replace(/\[at\]/gi,'@');
    if (!url.match(/^https?:\/\//i)) url = 'http://' + url;

    let parsed;
    try { parsed = new URL(url); } catch(e) {
      el.innerHTML = `<div style="color:var(--red)">Cannot parse URL: ${e.message}</div>`; return;
    }

    const hostname = parsed.hostname.toLowerCase();
    const domain = this.getBaseDomain(hostname);
    const tld = domain.split('.').pop();
    const subdomain = hostname !== domain ? hostname.slice(0, hostname.length - domain.length - 1) : '';

    const entropy = this.calcEntropy(domain);
    const entropyScore = entropy > 4.0 ? 'high' : entropy > 3.2 ? 'medium' : 'low';

    const findings = [];

    // Checks
    if (this.SUSPICIOUS_TLDS.includes(tld)) findings.push({ sev: 'high', msg: `Suspicious TLD: .${tld} — commonly abused in phishing` });
    if (entropy > 4.0) findings.push({ sev: 'high', msg: `High domain entropy: ${entropy.toFixed(2)} — likely DGA or random string` });
    else if (entropy > 3.5) findings.push({ sev: 'medium', msg: `Elevated domain entropy: ${entropy.toFixed(2)} — possible DGA` });
    if (parsed.protocol === 'http:') findings.push({ sev: 'medium', msg: 'Non-HTTPS — no TLS encryption' });
    if (subdomain && subdomain.split('.').length > 2) findings.push({ sev: 'high', msg: `Deep subdomain chain: ${subdomain} — common phishing technique` });
    if (/\d+\.\d+\.\d+\.\d+/.test(hostname)) findings.push({ sev: 'high', msg: 'IP address used instead of domain name' });
    if (hostname.length > 40) findings.push({ sev: 'medium', msg: `Long hostname: ${hostname.length} chars — may obscure brand impersonation` });
    if (parsed.searchParams.toString().length > 200) findings.push({ sev: 'medium', msg: 'Long query string — may contain encoded redirect or tracking data' });

    // Brand impersonation check
    const foundBrands = this.BRAND_KEYWORDS.filter(b => hostname.includes(b));
    if (foundBrands.length) findings.push({ sev: 'high', msg: `Brand keyword detected in hostname: [${foundBrands.join(', ')}] — possible impersonation` });

    // Homoglyph check
    const deglyphed = hostname.replace(/[0-9]/g, c => this.HOMOGLYPHS[c] || c);
    const foundBrandsAfterDeglyph = this.BRAND_KEYWORDS.filter(b => deglyphed.includes(b) && !hostname.includes(b));
    if (foundBrandsAfterDeglyph.length) findings.push({ sev: 'critical', msg: `Homoglyph substitution detected — "${hostname}" may impersonate [${foundBrandsAfterDeglyph.join(', ')}]` });

    // Suspicious path keywords
    const pathLower = (parsed.pathname + parsed.search).toLowerCase();
    const suspPathKw = ['login','signin','verify','confirm','secure','account','update','recover','password','wallet','invoice','banking'];
    const foundPath = suspPathKw.filter(k => pathLower.includes(k));
    if (foundPath.length) findings.push({ sev: 'medium', msg: `Suspicious path keywords: [${foundPath.join(', ')}]` });

    // Punycode
    if (hostname.includes('xn--')) findings.push({ sev: 'high', msg: 'Punycode/IDN domain — may be homograph attack using unicode characters' });

    // Redirect param
    const redirectParams = [...parsed.searchParams.entries()].filter(([k]) => ['url','redirect','next','r','return','goto','target','link'].includes(k.toLowerCase()));
    if (redirectParams.length) findings.push({ sev: 'medium', msg: `Open redirect parameter: ${redirectParams.map(([k,v])=>`${k}=${v.slice(0,30)}`).join(', ')}` });

    // Data URI
    if (url.startsWith('data:')) findings.push({ sev: 'critical', msg: 'Data URI scheme — can execute arbitrary HTML/JS' });

    // Credential in URL
    if (parsed.username || parsed.password) findings.push({ sev: 'critical', msg: 'Credentials embedded in URL — classic phishing technique' });

    const score = this.calcRiskScore(findings);
    const scoreColor = score >= 70 ? 'var(--red)' : score >= 40 ? 'var(--orange)' : score >= 20 ? 'var(--yellow)' : 'var(--accent)';
    const scoreLabel = score >= 70 ? 'CRITICAL' : score >= 40 ? 'HIGH RISK' : score >= 20 ? 'SUSPICIOUS' : 'LOW RISK';

    el.innerHTML = `
      <div style="display:flex;align-items:center;gap:16px;padding:16px;background:var(--bg3);border-radius:6px;margin-bottom:16px;border:1px solid ${scoreColor}33">
        <div style="text-align:center;min-width:70px">
          <div style="font-size:32px;font-weight:800;color:${scoreColor};font-family:var(--font-sans)">${score}</div>
          <div style="font-size:9px;color:${scoreColor};letter-spacing:1px">${scoreLabel}</div>
        </div>
        <div style="flex:1">
          <div style="height:6px;background:var(--bg2);border-radius:3px;margin-bottom:8px;overflow:hidden">
            <div style="height:100%;width:${score}%;background:${scoreColor};transition:width .5s;border-radius:3px"></div>
          </div>
          <div style="font-size:11px;color:var(--text2)">${findings.length} indicator${findings.length!==1?'s':''} found · Domain entropy: <span style="color:${entropyScore==='high'?'var(--red)':entropyScore==='medium'?'var(--yellow)':'var(--accent)'}">${entropy.toFixed(2)}</span></div>
        </div>
      </div>

      <div class="grid-2" style="gap:12px;margin-bottom:16px">
        ${[
          ['Protocol', parsed.protocol.replace(':',''), parsed.protocol==='http:'?'var(--yellow)':'var(--accent)'],
          ['Hostname', hostname, 'var(--text0)'],
          ['Base Domain', domain, 'var(--text0)'],
          ['Subdomain', subdomain || '(none)', subdomain?'var(--orange)':'var(--text3)'],
          ['TLD', `.${tld}`, this.SUSPICIOUS_TLDS.includes(tld)?'var(--red)':'var(--text0)'],
          ['Path', parsed.pathname || '/', 'var(--text1)'],
          ['Query', parsed.search || '(none)', 'var(--text1)'],
          ['Fragment', parsed.hash || '(none)', 'var(--text3)'],
          ['Port', parsed.port || `default (${parsed.protocol==='https:'?443:80})`, 'var(--text2)'],
          ['Full Length', `${url.length} chars`, url.length>100?'var(--yellow)':'var(--text2)'],
        ].map(([k,v,c])=>`
          <div style="border:1px solid var(--border);border-radius:4px;padding:8px">
            <div style="font-size:9px;color:var(--text3);margin-bottom:3px;letter-spacing:.5px;text-transform:uppercase">${k}</div>
            <div class="copyable" style="font-size:11px;color:${c};word-break:break-all;font-family:var(--font-mono)" data-copy="${v}" data-label="${k}" onclick="copyFromAttr(this)">${v}</div>
          </div>`).join('')}
      </div>

      ${findings.length ? `
      <div class="card-header" style="padding:0;margin-bottom:8px"><span class="card-title">Threat Indicators</span></div>
      <div>
        ${findings.map(f=>`
          <div style="display:flex;align-items:flex-start;gap:8px;padding:8px;border-radius:4px;margin-bottom:6px;background:${f.sev==='critical'?'rgba(255,68,68,.08)':f.sev==='high'?'rgba(255,68,68,.05)':f.sev==='medium'?'rgba(240,180,41,.05)':'rgba(0,212,170,.05)'}">
            <span class="tag tag-${f.sev==='critical'||f.sev==='high'?'critical':f.sev==='medium'?'high':'low'}" style="margin-top:1px;flex-shrink:0">${f.sev.toUpperCase()}</span>
            <span style="font-size:11px;color:var(--text1)">${f.msg}</span>
          </div>`).join('')}
      </div>` : `<div style="display:flex;align-items:center;gap:8px;color:var(--accent);font-size:12px"><span>✓</span>No obvious phishing indicators detected</div>`}`;
  },

  getBaseDomain(hostname) {
    const parts = hostname.replace(/^www\./, '').split('.');
    return parts.length > 2 ? parts.slice(-2).join('.') : hostname.replace(/^www\./,'');
  },

  calcEntropy(str) {
    if (!str) return 0;
    const freq = {};
    for (const c of str) freq[c] = (freq[c]||0) + 1;
    return -Object.values(freq).reduce((sum,f) => { const p=f/str.length; return sum + p*Math.log2(p); }, 0);
  },

  calcRiskScore(findings) {
    const sevScore = { critical: 35, high: 20, medium: 10, low: 5 };
    const raw = findings.reduce((s,f) => s + (sevScore[f.sev]||5), 0);
    return Math.min(100, raw);
  },
};

// ============================================================
// 4. THREAT ACTOR PROFILE CARDS
// ============================================================

const ThreatActorCards = {
  MOTIVATIONS: ['Financial','Espionage','Hacktivism','Destructive','Cyber Warfare','Data Theft','Ransomware','Intellectual Property'],
  COUNTRIES: {
    'Russia': { flag: '🇷🇺', code: 'RU' },
    'China': { flag: '🇨🇳', code: 'CN' },
    'North Korea': { flag: '🇰🇵', code: 'KP' },
    'Iran': { flag: '🇮🇷', code: 'IR' },
    'USA': { flag: '🇺🇸', code: 'US' },
    'Israel': { flag: '🇮🇱', code: 'IL' },
    'UK': { flag: '🇬🇧', code: 'GB' },
    'India': { flag: '🇮🇳', code: 'IN' },
    'Vietnam': { flag: '🇻🇳', code: 'VN' },
    'Pakistan': { flag: '🇵🇰', code: 'PK' },
    'Indonesia': { flag: '🇮🇩', code: 'ID' },
    'Unknown': { flag: '🌐', code: '?' },
  },
  THREAT_LEVEL_COLORS: { 'Critical': '#ff4444', 'High': '#ff8c42', 'Medium': '#f0b429', 'Low': '#00d4aa' },

  init() {
    this.renderMotivations();
    this.renderCountries();
    this.updatePreview();
  },

  renderMotivations() {
    const el = document.getElementById('ta-motivation-select');
    el.innerHTML = this.MOTIVATIONS.map(m=>`<option>${m}</option>`).join('');
  },

  renderCountries() {
    const el = document.getElementById('ta-country-select');
    el.innerHTML = Object.entries(this.COUNTRIES).map(([name,{flag}])=>`<option value="${name}">${flag} ${name}</option>`).join('');
  },

  gatherData() {
    return {
      name: document.getElementById('ta-name').value || 'Unknown Actor',
      aliases: document.getElementById('ta-aliases').value,
      country: document.getElementById('ta-country-select').value || 'Unknown',
      motivation: document.getElementById('ta-motivation-select').value || 'Unknown',
      targets: document.getElementById('ta-targets').value,
      ttps: document.getElementById('ta-ttps').value,
      tools: document.getElementById('ta-tools').value,
      firstSeen: document.getElementById('ta-first-seen').value || 'Unknown',
      lastSeen: document.getElementById('ta-last-seen').value || 'Active',
      confidence: document.getElementById('ta-confidence').value || '70',
      threatLevel: document.getElementById('ta-threat-level').value || 'High',
      description: document.getElementById('ta-description').value,
      tlp: document.querySelector('input[name="ta-tlp"]:checked')?.value || 'amber',
    };
  },

  updatePreview() {
    const d = this.gatherData();
    const el = document.getElementById('ta-card-preview');
    const country = this.COUNTRIES[d.country] || { flag: '🌐', code: '?' };
    const tlvColor = this.THREAT_LEVEL_COLORS[d.threatLevel] || '#ff8c42';
    const tlpColors = { red: '#ff4444', amber: '#f0b429', green: '#00d4aa', clear: '#4da6ff' };
    const tlpColor = tlpColors[d.tlp] || '#f0b429';

    el.innerHTML = `
      <div id="ta-export-card" style="background:linear-gradient(135deg,#0d1117 0%,#131922 60%,#1a2332 100%);border:1px solid #1e2d42;border-radius:12px;padding:0;overflow:hidden;width:100%;max-width:580px;font-family:'JetBrains Mono',monospace;position:relative">
        <!-- Header bar -->
        <div style="background:linear-gradient(90deg,${tlvColor}22,transparent);border-bottom:1px solid ${tlvColor}44;padding:16px 20px;display:flex;align-items:center;justify-content:space-between">
          <div style="display:flex;align-items:center;gap:12px">
            <div style="width:42px;height:42px;background:${tlvColor}22;border:2px solid ${tlvColor}55;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:20px">${country.flag}</div>
            <div>
              <div style="font-family:'Syne',sans-serif;font-size:16px;font-weight:800;color:#e8edf5;letter-spacing:1px">${d.name || 'UNKNOWN ACTOR'}</div>
              ${d.aliases ? `<div style="font-size:10px;color:#6a7f9a">AKA: ${d.aliases}</div>` : ''}
            </div>
          </div>
          <div style="text-align:right">
            <div style="background:${tlvColor}22;border:1px solid ${tlvColor};border-radius:4px;padding:3px 10px;font-size:11px;font-weight:700;color:${tlvColor};letter-spacing:1px">${d.threatLevel.toUpperCase()}</div>
            <div style="font-size:9px;color:${tlpColor};margin-top:4px;letter-spacing:1px">TLP:${d.tlp.toUpperCase()}</div>
          </div>
        </div>
        <!-- Body -->
        <div style="padding:16px 20px;display:grid;grid-template-columns:1fr 1fr;gap:12px">
          ${[
            ['Origin', `${country.flag} ${d.country}`],
            ['Motivation', d.motivation],
            ['First Seen', d.firstSeen],
            ['Last Active', d.lastSeen],
          ].map(([k,v])=>`<div style="background:#060810;border:1px solid #1e2d42;border-radius:6px;padding:8px 10px">
            <div style="font-size:9px;color:#3d5570;letter-spacing:.5px;margin-bottom:3px;text-transform:uppercase">${k}</div>
            <div style="font-size:12px;color:#a8b8cc">${v}</div>
          </div>`).join('')}
        </div>
        ${d.targets ? `<div style="padding:0 20px 12px">
          <div style="font-size:9px;color:#3d5570;letter-spacing:.5px;margin-bottom:6px;text-transform:uppercase">Target Sectors</div>
          <div style="display:flex;flex-wrap:wrap;gap:5px">
            ${d.targets.split(',').map(t=>`<span style="background:#1a2332;border:1px solid #253650;border-radius:3px;padding:2px 8px;font-size:10px;color:#a8b8cc">${t.trim()}</span>`).join('')}
          </div>
        </div>` : ''}
        ${d.tools ? `<div style="padding:0 20px 12px">
          <div style="font-size:9px;color:#3d5570;letter-spacing:.5px;margin-bottom:6px;text-transform:uppercase">Known Tools & Malware</div>
          <div style="display:flex;flex-wrap:wrap;gap:5px">
            ${d.tools.split(',').map(t=>`<span style="background:rgba(155,127,255,.1);border:1px solid rgba(155,127,255,.3);border-radius:3px;padding:2px 8px;font-size:10px;color:#9b7fff">${t.trim()}</span>`).join('')}
          </div>
        </div>` : ''}
        ${d.ttps ? `<div style="padding:0 20px 12px">
          <div style="font-size:9px;color:#3d5570;letter-spacing:.5px;margin-bottom:6px;text-transform:uppercase">ATT&CK TTPs</div>
          <div style="display:flex;flex-wrap:wrap;gap:5px">
            ${d.ttps.split(',').map(t=>`<span style="background:rgba(0,212,170,.08);border:1px solid rgba(0,212,170,.25);border-radius:3px;padding:2px 8px;font-size:10px;color:#00d4aa;font-weight:600">${t.trim()}</span>`).join('')}
          </div>
        </div>` : ''}
        ${d.description ? `<div style="padding:0 20px 12px">
          <div style="font-size:9px;color:#3d5570;letter-spacing:.5px;margin-bottom:6px;text-transform:uppercase">Description</div>
          <div style="font-size:11px;color:#6a7f9a;line-height:1.6">${d.description}</div>
        </div>` : ''}
        <!-- Confidence bar + footer -->
        <div style="border-top:1px solid #1e2d42;padding:12px 20px;display:flex;align-items:center;gap:12px">
          <div style="font-size:9px;color:#3d5570;white-space:nowrap">CONFIDENCE</div>
          <div style="flex:1;height:4px;background:#060810;border-radius:2px;overflow:hidden">
            <div style="width:${d.confidence}%;height:100%;background:${tlvColor};border-radius:2px"></div>
          </div>
          <div style="font-size:11px;font-weight:700;color:${tlvColor}">${d.confidence}%</div>
          <div style="font-size:9px;color:#1e2d42;margin-left:auto">PHANTOM Web</div>
        </div>
      </div>`;
  },

  exportPNG() {
    const card = document.getElementById('ta-export-card');
    if (!card) { showToast('Generate a card first', 'warning'); return; }
    // Use html2canvas via CDN approach — simple window.print fallback
    showToast('Use browser Print (Ctrl+P) → Save as PDF to export', 'info', 5000);
  },

  exportJSON() {
    const d = this.gatherData();
    downloadText(JSON.stringify(d, null, 2), `phantom-ta-${d.name.replace(/\s+/g,'-').toLowerCase()}.json`);
    showToast('Threat actor profile exported');
  },
};

// ============================================================
// 6. YARA RULE EDITOR
// ============================================================

const YaraEditor = {
  // Built-in rule library based on existing YARA-lite patterns from file-engine.js
  builtInRules: [
    {
      name: 'Mimikatz_Detection',
      meta: { author: 'PHANTOM Team', description: 'Detects Mimikatz credential theft tool strings', severity: 'critical', hash: 'builtin-001' },
      source: `rule Mimikatz_Detection {
    meta:
        author = "PHANTOM Team"
        description = "Detects Mimikatz credential theft tool strings"
        severity = "critical"
        reference = "https://github.com/gentilkiwi/mimikatz"
    
    strings:
        $s1 = "sekurlsa" nocase
        $s2 = "kerberos" nocase
        $s3 = "wdigest" nocase
        $s4 = "lsadump" nocase
        $s5 = "privilege::debug" nocase
    
    condition:
        any of them
}`
    },
    {
      name: 'CobaltStrike_Beacon',
      meta: { author: 'PHANTOM Team', description: 'Detects Cobalt Strike beacon artifacts', severity: 'critical', hash: 'builtin-002' },
      source: `rule CobaltStrike_Beacon {
    meta:
        author = "PHANTOM Team"
        description = "Detects Cobalt Strike beacon artifacts"
        severity = "critical"
        reference = "https://www.cobaltstrike.com"
    
    strings:
        $s1 = "ReflectiveDll" nocase
        $s2 = "beacon.x64" nocase
        $s3 = "cobaltstrike" nocase
        $s4 = "sleeptime" nocase
        $s5 = "jitter" nocase
    
    condition:
        2 of them
}`
    },
    {
      name: 'PowerShell_DownloadCradle',
      meta: { author: 'PHANTOM Team', description: 'Detects PowerShell download cradle patterns', severity: 'high', hash: 'builtin-003' },
      source: `rule PowerShell_DownloadCradle {
    meta:
        author = "PHANTOM Team"
        description = "Detects PowerShell download cradle patterns"
        severity = "high"
    
    strings:
        $ps1 = /powershell\\s+-[Ee][Nn][Cc](?:[Oo][Dd][Ee])?/ 
        $ps2 = "IEX("
        $ps3 = "DownloadString"
        $ps4 = "WebClient"
        $ps5 = "FromBase64String"
    
    condition:
        any of them
}`
    },
    {
      name: 'Meterpreter_Payload',
      meta: { author: 'PHANTOM Team', description: 'Detects Metasploit Meterpreter payload strings', severity: 'critical', hash: 'builtin-004' },
      source: `rule Meterpreter_Payload {
    meta:
        author = "PHANTOM Team"
        description = "Detects Metasploit Meterpreter payload strings"
        severity = "critical"
        reference = "https://www.metasploit.com"
    
    strings:
        $s1 = "meterpreter" nocase
        $s2 = "ReflectiveLoader" nocase
        $s3 = "stdapi_" nocase
        $s4 = "priv_" nocase
        $s5 = "kiwi_" nocase
    
    condition:
        any of them
}`
    },
    {
      name: 'AntiVM_Detection',
      meta: { author: 'PHANTOM Team', description: 'Detects anti-VM and anti-debugging strings', severity: 'medium', hash: 'builtin-005' },
      source: `rule AntiVM_Detection {
    meta:
        author = "PHANTOM Team"
        description = "Detects anti-VM and anti-debugging strings"
        severity = "medium"
    
    strings:
        $vm1 = "vmware" nocase
        $vm2 = "virtualbox" nocase
        $vm3 = "vbox" nocase
        $vm4 = "qemu" nocase
        $dbg1 = "OllyDbg" nocase
        $dbg2 = "x64dbg" nocase
        $dbg3 = "ida.exe" nocase
        $dbg4 = "procmon" nocase
    
    condition:
        2 of them
}`
    },
    {
      name: 'Ransomware_Extensions',
      meta: { author: 'PHANTOM Team', description: 'Detects common ransomware file extension patterns', severity: 'critical', hash: 'builtin-006' },
      source: `rule Ransomware_Extensions {
    meta:
        author = "PHANTOM Team"
        description = "Detects common ransomware file extension patterns"
        severity = "critical"
    
    strings:
        $ext1 = ".locked" nocase
        $ext2 = ".encrypted" nocase
        $ext3 = ".crypted" nocase
        $ext4 = ".crypt" nocase
        $ext5 = ".enc" nocase
        $ransom1 = "YOUR_FILES_ARE_ENCRYPTED" nocase
        $ransom2 = "decrypt" nocase
    
    condition:
        any of them
}`
    },
    {
      name: 'Process_Injection_API',
      meta: { author: 'PHANTOM Team', description: 'Detects Windows API calls commonly used for process injection', severity: 'high', hash: 'builtin-007' },
      source: `rule Process_Injection_API {
    meta:
        author = "PHANTOM Team"
        description = "Detects Windows API calls commonly used for process injection"
        severity = "high"
    
    strings:
        $api1 = "VirtualAllocEx"
        $api2 = "WriteProcessMemory"
        $api3 = "CreateRemoteThread"
        $api4 = "NtCreateThreadEx"
        $api5 = "RtlCreateUserThread"
    
    condition:
        2 of them
}`
    },
    {
      name: 'Tor_Onion_Address',
      meta: { author: 'PHANTOM Team', description: 'Detects Tor .onion addresses in text', severity: 'medium', hash: 'builtin-008' },
      source: `rule Tor_Onion_Address {
    meta:
        author = "PHANTOM Team"
        description = "Detects Tor .onion addresses in text"
        severity = "medium"
    
    strings:
        $onion = /[a-z2-7]{16,56}\\.onion/
    
    condition:
        $onion
}`
    }
  ],

  init() {
    this.renderLibrary();
  },

  renderLibrary() {
    const container = document.getElementById('yara-library');
    if (!container) return;
    
    let html = '<div style="display:flex;flex-direction:column;gap:6px">';
    this.builtInRules.forEach((rule, idx) => {
      const severityColor = rule.meta.severity === 'critical' ? 'var(--red)' : 
                           rule.meta.severity === 'high' ? 'var(--orange)' : 
                           rule.meta.severity === 'medium' ? 'var(--yellow)' : 'var(--text3)';
      html += `
        <div style="padding:8px;border:1px solid var(--border);border-radius:6px;cursor:pointer;transition:all .15s" 
             onmouseover="this.style.borderColor='${severityColor}';this.style.background='${severityColor}11'" 
             onmouseout="this.style.borderColor='var(--border)';this.style.background='transparent'"
             onclick="YaraEditor.loadBuiltInRule(${idx})">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
            <span style="font-size:11px;font-weight:700;color:${severityColor}">${rule.name}</span>
            <span style="font-size:9px;padding:2px 6px;border-radius:3px;background:${severityColor}22;color:${severityColor}">${rule.meta.severity.toUpperCase()}</span>
          </div>
          <div style="font-size:9px;color:var(--text3)">${rule.meta.description}</div>
        </div>`;
    });
    html += '</div>';
    container.innerHTML = html;
  },

  loadBuiltInRule(idx) {
    const rule = this.builtInRules[idx];
    if (!rule) return;
    
    document.getElementById('yara-rule-name').value = rule.name;
    document.getElementById('yara-rule-meta').value = JSON.stringify(rule.meta, null, 2);
    document.getElementById('yara-rule-source').value = rule.source;
    showToast(`Loaded built-in rule: ${rule.name}`);
  },

  newRule() {
    document.getElementById('yara-rule-name').value = '';
    document.getElementById('yara-rule-meta').value = '{}';
    document.getElementById('yara-rule-source').value = `rule New_Rule {
    meta:
        author = "Your Name"
        description = "Rule description here"
        severity = "medium"
    
    strings:
        $string1 = "example_string"
    
    condition:
        $string1
}`;
    document.getElementById('yara-test-input').value = '';
    document.getElementById('yara-results').innerHTML = '<div class="empty-state"><div class="empty-icon">⊣</div><div class="empty-text">Ready for a new rule.</div></div>';
    document.getElementById('yara-result-badge').textContent = '–';
    showToast('New rule template loaded');
  },

  loadExample() {
    this.loadBuiltInRule(2); // Load PowerShell Download Cradle as example
  },

  validateSyntax() {
    const source = document.getElementById('yara-rule-source').value.trim();
    const name = document.getElementById('yara-rule-name').value.trim();
    
    if (!source) {
      showToast('No rule source to validate', 'warning');
      return;
    }

    // Basic syntax validation (browser-based, no external YARA engine)
    const errors = [];
    
    // Check for required sections
    if (!/rule\s+\w+/i.test(source)) {
      errors.push('Missing rule declaration: rule <name>');
    }
    if (!/strings:/i.test(source)) {
      errors.push('Missing strings section');
    }
    if (!/condition:/i.test(source)) {
      errors.push('Missing condition section');
    }
    
    // Check for balanced braces
    const openBraces = (source.match(/\{/g) || []).length;
    const closeBraces = (source.match(/\}/g) || []).length;
    if (openBraces !== closeBraces) {
      errors.push(`Unbalanced braces: ${openBraces} opening, ${closeBraces} closing`);
    }
    
    // Check for string declarations
    const stringDecls = source.match(/\$[a-zA-Z_][a-zA-Z0-9_]*/g) || [];
    if (stringDecls.length === 0 && !/condition:\s*(?:all|any|none)\s+of\s+them/i.test(source)) {
      errors.push('No string variables declared');
    }
    
    // Check condition references defined strings
    const conditionSection = source.split(/condition:/i)[1] || '';
    const conditionStrings = conditionSection.match(/\$[a-zA-Z_][a-zA-Z0-9_]*/g) || [];
    conditionStrings.forEach(str => {
      if (!source.includes(`${str} =`)) {
        errors.push(`String variable ${str} referenced but not defined`);
      }
    });

    if (errors.length > 0) {
      document.getElementById('yara-results').innerHTML = `
        <div style="padding:12px;background:var(--red)11;border:1px solid var(--red);border-radius:6px">
          <div style="color:var(--red);font-weight:700;margin-bottom:8px">✗ Syntax Issues Found</div>
          <ul style="margin:0;padding-left:16px;font-size:11px;color:var(--text0)">
            ${errors.map(e => `<li>${e}</li>`).join('')}
          </ul>
        </div>`;
      document.getElementById('yara-result-badge').textContent = `${errors.length} issue(s)`;
      showToast(`Found ${errors.length} syntax issue(s)`, 'error');
    } else {
      document.getElementById('yara-results').innerHTML = `
        <div style="padding:12px;background:var(--accent)11;border:1px solid var(--accent);border-radius:6px;text-align:center">
          <div style="color:var(--accent);font-weight:700;font-size:14px">✓ Syntax Looks Valid</div>
          <div style="font-size:10px;color:var(--text3);margin-top:4px">Basic structure validated (full validation requires YARA engine)</div>
        </div>`;
      document.getElementById('yara-result-badge').textContent = 'Valid';
      showToast('Rule syntax looks valid');
    }
  },

  testRule() {
    const source = document.getElementById('yara-rule-source').value.trim();
    const testInput = document.getElementById('yara-test-input').value;
    
    if (!source) {
      showToast('Please enter a YARA rule first', 'warning');
      return;
    }
    if (!testInput) {
      showToast('Please provide test input (text or upload a file)', 'warning');
      return;
    }

    // Convert YARA-like patterns to JavaScript regex for browser-based testing
    const hits = [];
    const startTime = performance.now();
    
    try {
      // Extract strings section
      const stringsMatch = source.match(/strings:\s*([\s\S]*?)(?=condition:|$)/i);
      const conditionMatch = source.match(/condition:\s*([\s\S]*)/i);
      
      if (!stringsMatch || !conditionMatch) {
        throw new Error('Could not parse strings or condition section');
      }
      
      const stringsSection = stringsMatch[1];
      const conditionSection = conditionMatch[1].trim();
      
      // Parse string definitions
      const stringDefs = {};
      const stringRegex = /\$(\w+)\s*=\s*(?:\/(.+?)\/|"(.*?)")(\s+nocase)?/g;
      let match;
      
      while ((match = stringRegex.exec(stringsSection)) !== null) {
        const [, name, regexStr, literalStr, nocase] = match;
        let pattern;
        
        if (regexStr) {
          // It's a regex pattern
          pattern = new RegExp(regexStr, nocase ? 'gi' : 'g');
        } else if (literalStr) {
          // It's a literal string
          pattern = new RegExp(literalStr.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), nocase ? 'gi' : 'g');
        }
        
        if (pattern) {
          stringDefs[name] = { pattern, matches: [] };
        }
      }
      
      // Test each string against input
      Object.entries(stringDefs).forEach(([name, def]) => {
        def.pattern.lastIndex = 0;
        let m;
        while ((m = def.pattern.exec(testInput)) !== null) {
          def.matches.push({
            offset: m.index,
            value: m[0],
            length: m[0].length
          });
        }
      });
      
      // Evaluate condition (simplified - supports: all/any/none of them, specific strings, count operators)
      const matchedStrings = Object.entries(stringDefs).filter(([, def]) => def.matches.length > 0);
      const totalStrings = Object.keys(stringDefs).length;
      const matchedCount = matchedStrings.length;
      
      let conditionMet = false;
      
      if (/all\s+of\s+them/i.test(conditionSection)) {
        conditionMet = matchedCount === totalStrings;
      } else if (/any\s+of\s+them/i.test(conditionSection)) {
        conditionMet = matchedCount > 0;
      } else if (/none\s+of\s+them/i.test(conditionSection)) {
        conditionMet = matchedCount === 0;
      } else if (/(\d+)\s+of\s+them/i.test(conditionSection)) {
        const required = parseInt(conditionSection.match(/(\d+)\s+of\s+them/i)[1]);
        conditionMet = matchedCount >= required;
      } else {
        // Check for specific string references like: $string1 or $string1 and $string2
        const referencedStrings = conditionSection.match(/\$\w+/g) || [];
        if (referencedStrings.length > 0) {
          conditionMet = referencedStrings.every(s => stringDefs[s.substring(1)]?.matches.length > 0);
        } else {
          // Default: any match
          conditionMet = matchedCount > 0;
        }
      }
      
      const elapsed = ((performance.now() - startTime) / 1000).toFixed(3);
      
      // Render results
      if (conditionMet) {
        let html = `<div style="padding:12px;background:var(--accent)11;border:1px solid var(--accent);border-radius:6px;margin-bottom:12px">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <span style="color:var(--accent);font-weight:700">✓ Rule Matched!</span>
            <span style="font-size:10px;color:var(--text3)">Test completed in ${elapsed}s</span>
          </div>
          <div style="font-size:10px;color:var(--text3);margin-top:4px">${matchedCount} of ${totalStrings} string(s) matched</div>
        </div>`;
        
        matchedStrings.forEach(([name, def]) => {
          html += `<div style="margin-bottom:12px">
            <div style="font-size:10px;font-weight:700;color:var(--accent);margin-bottom:6px">$${name} (${def.matches.length} match${def.matches.length !== 1 ? 'es' : ''})</div>`;
          
          def.matches.slice(0, 5).forEach((m, i) => {
            const context = testInput.substring(Math.max(0, m.offset - 20), Math.min(testInput.length, m.offset + m.length + 20));
            const highlighted = context.replace(new RegExp(m.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'), 
              `<mark style="background:var(--accent);color:#000;padding:0 2px;border-radius:2px">${m.value}</mark>`);
            html += `<div style="font-size:10px;font-family:monospace;background:var(--bg1);padding:4px 6px;border-radius:4px;margin-bottom:4px;overflow-x:auto">
              ...${highlighted}... <span style="color:var(--text3)">[offset: ${m.offset}]</span>
            </div>`;
          });
          
          if (def.matches.length > 5) {
            html += `<div style="font-size:9px;color:var(--text3);text-align:center">+ ${def.matches.length - 5} more match(es)</div>`;
          }
          
          html += `</div>`;
        });
        
        document.getElementById('yara-results').innerHTML = html;
        document.getElementById('yara-result-badge').textContent = `${matchedCount} match${matchedCount !== 1 ? 'es' : ''}`;
        showToast(`Rule matched! Found ${matchedCount} string(s)`, 'success');
      } else {
        document.getElementById('yara-results').innerHTML = `
          <div style="padding:12px;background:var(--bg1);border:1px solid var(--border);border-radius:6px;text-align:center">
            <div style="color:var(--text3);font-weight:700">✗ No Match</div>
            <div style="font-size:10px;color:var(--text3);margin-top:4px">Condition not satisfied (${matchedCount}/${totalStrings} strings matched)</div>
          </div>`;
        document.getElementById('yara-result-badge').textContent = 'No match';
        showToast('Rule did not match the test input', 'info');
      }
      
    } catch (err) {
      document.getElementById('yara-results').innerHTML = `
        <div style="padding:12px;background:var(--red)11;border:1px solid var(--red);border-radius:6px">
          <div style="color:var(--red);font-weight:700">✗ Test Error</div>
          <div style="font-size:10px;color:var(--text0);margin-top:4px">${err.message}</div>
        </div>`;
      document.getElementById('yara-result-badge').textContent = 'Error';
      showToast('Test failed: ' + err.message, 'error');
    }
  },

  exportRule() {
    const name = document.getElementById('yara-rule-name').value.trim() || 'custom_rule';
    const source = document.getElementById('yara-rule-source').value.trim();
    
    if (!source) {
      showToast('No rule to export', 'warning');
      return;
    }
    
    const blob = new Blob([source], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${name}.yar`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast(`Exported ${name}.yar`);
  },

  importRule() {
    document.getElementById('yara-import-file').click();
  },

  handleImport(input) {
    const file = input.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      document.getElementById('yara-rule-source').value = content;
      
      // Try to extract rule name
      const nameMatch = content.match(/rule\s+(\w+)/i);
      if (nameMatch) {
        document.getElementById('yara-rule-name').value = nameMatch[1];
      }
      
      // Try to extract meta section
      const metaMatch = content.match(/meta:\s*([\s\S]*?)(?=strings:|condition:|$)/i);
      if (metaMatch) {
        const metaText = metaMatch[1];
        const metaObj = {};
        const metaLines = metaText.split('\n');
        metaLines.forEach(line => {
          const kv = line.match(/(\w+)\s*=\s*["']?([^"'\n]+)["']?/);
          if (kv) {
            metaObj[kv[1].trim()] = kv[2].trim();
          }
        });
        if (Object.keys(metaObj).length > 0) {
          document.getElementById('yara-rule-meta').value = JSON.stringify(metaObj, null, 2);
        }
      }
      
      showToast(`Imported ${file.name}`);
    };
    reader.readAsText(file);
    input.value = '';
  },

  loadTestFile(input) {
    const file = input.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      document.getElementById('yara-test-input').value = content.substring(0, 50000); // Limit to 50KB for display
      if (content.length > 50000) {
        showToast(`Loaded ${file.name} (truncated to 50KB for display)`, 'info');
      } else {
        showToast(`Loaded ${file.name} (${content.length} bytes)`);
      }
    };
    reader.readAsText(file);
    input.value = '';
  },

  clearTest() {
    document.getElementById('yara-test-input').value = '';
    document.getElementById('yara-results').innerHTML = '<div class="empty-state"><div class="empty-icon">⊣</div><div class="empty-text">Test input cleared.</div></div>';
    document.getElementById('yara-result-badge').textContent = '–';
    showToast('Test input cleared');
  }
};

// ============================================================
// 5. CVSS v3.1 CALCULATOR
// ============================================================

const CVSSCalc = {
  // Metric weights per CVSS 3.1 spec
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.20 },
  AC: { L: 0.77, H: 0.44 },
  PR_U: { N: 0.85, L: 0.62, H: 0.27 },   // Scope Unchanged
  PR_C: { N: 0.85, L: 0.50, H: 0.50 },   // Scope Changed
  UI: { N: 0.85, R: 0.62 },
  CIA: { N: 0.00, L: 0.22, H: 0.56 },
  // Temporal
  E: { X: 1.0, U: 0.91, P: 0.94, F: 0.97, H: 1.00 },
  RL: { X: 1.0, O: 0.95, T: 0.96, W: 0.97, U: 1.00 },
  RC: { X: 1.0, U: 0.92, R: 0.96, C: 1.00 },

  roundUp(x) {
    const i = Math.round(x * 100000);
    if (i % 10000 === 0) return i / 100000;
    return (Math.floor(i / 10000) + 1) / 10;
  },

  calc() {
    const g = id => document.querySelector(`input[name="${id}"]:checked`)?.value || document.getElementById(id)?.value;

    const av = g('cvss-av'), ac = g('cvss-ac'), pr = g('cvss-pr'), ui = g('cvss-ui');
    const scope = g('cvss-s'), conf = g('cvss-c'), integ = g('cvss-i'), avail = g('cvss-a');
    const tempE = g('cvss-e'), tempRL = g('cvss-rl'), tempRC = g('cvss-rc');

    if (!av||!ac||!pr||!ui||!scope||!conf||!integ||!avail) return;

    const scopeChanged = scope === 'C';
    const prVal = scopeChanged ? this.PR_C[pr] : this.PR_U[pr];

    const ISCBase = 1 - (1 - this.CIA[conf]) * (1 - this.CIA[integ]) * (1 - this.CIA[avail]);
    let ISC = scopeChanged ? Math.min(0.9731, 1.08 * ISCBase) : ISCBase;
    const Exploit = 8.22 * this.AV[av] * this.AC[ac] * prVal * this.UI[ui];

    let baseScore = 0;
    if (ISCBase > 0) {
      if (!scopeChanged) baseScore = this.roundUp(Math.min(ISC * 6.42 + Exploit, 10));
      else baseScore = this.roundUp(Math.min(7.52 * (ISC - 0.029) - 3.25 * Math.pow(ISC - 0.02, 15) + Exploit, 10));
    }

    const E = this.E[tempE||'X'];
    const RL = this.RL[tempRL||'X'];
    const RC = this.RC[tempRC||'X'];
    const tempScore = tempE||tempRL||tempRC ? this.roundUp(baseScore * E * RL * RC) : null;

    const displayScore = tempScore !== null ? tempScore : baseScore;
    const sev = displayScore === 0 ? 'None' : displayScore < 4 ? 'Low' : displayScore < 7 ? 'Medium' : displayScore < 9 ? 'High' : 'Critical';
    const sevColor = { None: 'var(--text3)', Low: 'var(--accent)', Medium: 'var(--yellow)', High: 'var(--orange)', Critical: 'var(--red)' }[sev];

    // Build CVSS string
    const base = `CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${scope}/C:${conf}/I:${integ}/A:${avail}`;
    const temporal = tempE&&tempRL&&tempRC ? `/E:${tempE}/RL:${tempRL}/RC:${tempRC}` : '';
    const cvssStr = base + temporal;

    document.getElementById('cvss-score-display').innerHTML = `
      <div style="font-size:56px;font-weight:800;color:${sevColor};font-family:var(--font-sans);line-height:1">${displayScore.toFixed(1)}</div>
      <div style="font-size:13px;font-weight:700;color:${sevColor};letter-spacing:2px;margin-top:4px">${sev.toUpperCase()}</div>
      ${tempScore!==null ? `<div style="font-size:10px;color:var(--text3);margin-top:4px">Base: ${baseScore.toFixed(1)} · Temporal: ${tempScore.toFixed(1)}</div>` : `<div style="font-size:10px;color:var(--text3);margin-top:4px">Base Score</div>`}
      <div style="margin-top:12px;height:6px;background:var(--bg3);border-radius:3px;overflow:hidden;width:140px">
        <div style="height:100%;width:${displayScore*10}%;background:${sevColor};border-radius:3px;transition:width .3s"></div>
      </div>`;

    document.getElementById('cvss-vector-display').textContent = cvssStr;
    document.getElementById('cvss-vector-copy').setAttribute('data-copy', cvssStr);

    document.getElementById('cvss-breakdown').innerHTML = `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
        ${[
          ['ISCBase', ISCBase.toFixed(4), 'Impact sub-score base'],
          ['ISC (adj)', ISC.toFixed(4), scopeChanged?'Scope changed adjustment':'Unchanged'],
          ['Exploitability', Exploit.toFixed(4), 'Attack ease score'],
          ['E × RL × RC', `${E}×${RL}×${RC}`, 'Temporal multipliers'],
        ].map(([k,v,d])=>`<div style="border:1px solid var(--border);border-radius:4px;padding:8px">
          <div style="font-size:9px;color:var(--text3)">${k}</div>
          <div style="font-size:13px;color:var(--text0);margin:2px 0">${v}</div>
          <div style="font-size:9px;color:var(--text3)">${d}</div>
        </div>`).join('')}
      </div>`;
  },
};

// ============================================================
// Shared Utilities
// ============================================================

function escapeHtmlTools(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ============================================================
// Init all tools on page load
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  // Swiss Knife auto-init
  SwissKnife.init();

  // Threat Actor live preview
  document.querySelectorAll('[data-ta-field]').forEach(el => {
    el.addEventListener('input', () => ThreatActorCards.updatePreview());
    el.addEventListener('change', () => ThreatActorCards.updatePreview());
  });

  // Epoch default
  SwissKnife.epochNow();

  // Initialize YARA Editor library
  if (typeof YaraEditor !== 'undefined') {
    YaraEditor.renderLibrary();
  }
});
