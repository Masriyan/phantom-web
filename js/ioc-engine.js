const IOCEngine = (() => {
  const PATTERNS = {
    ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    ipv6: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b/g,
    domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|edu|gov|io|co|uk|de|fr|jp|cn|ru|br|au|in|nl|se|no|fi|dk|be|ch|at|pl|cz|sk|hu|ro|bg|hr|si|lt|lv|ee|pt|es|it|gr|tr|za|eg|ng|ke|gh|tz|ug|rw|et|ma|dz|tn|ly|sd|so|er|dj|km|sc|mu|re|yt|mw|zm|zw|bw|na|sz|ls|bi|rw|cd|cg|ao|cm|sn|ml|bf|ne|td|cf|gn|sl|lr|ci|gh|tg|bj|gw|gm|cv|mr|info|biz|int|mil|mobi|name|pro|tel|travel|xyz|top|site|online|tech|store|app|dev|cloud|ai|ml|ir|iq|sy|lb|jo|sa|ye|om|ae|qa|kw|bh|pk|af|bd|lk|np|bt|mv|mm|kh|la|vn|th|my|id|ph|sg|bn|tl|pg|fj|to|ws|ck|nu|ki|fm|pw|nr|mh|pf|nc|vu|sb|wf|as|mp|gu|vi|pr|tt|bb|lc|vc|gd|dm|ag|kn|bs|ky|tc|vg|ai|ms|bm|mf|sx|cw|aw|gp|mq|pm|gl|fo|ax|je|gg|im|io|sh|ac|gg)\b/gi,
    url: /https?:\/\/(?:[\w\-]+\.)+[\w\-]+(?:\/[\w\-._~:/?#[\]@!$&'()*+,;=%]*)*/gi,
    email: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/gi,
    md5: /\b[a-fA-F0-9]{32}\b/g,
    sha1: /\b[a-fA-F0-9]{40}\b/g,
    sha256: /\b[a-fA-F0-9]{64}\b/g,
    sha512: /\b[a-fA-F0-9]{128}\b/g,
    cve: /CVE-\d{4}-\d{4,7}/gi,
    btc: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g,
    bech32: /\bbc1[a-zA-HJ-NP-Z0-9]{39,59}\b/g,
    mitre: /\bT\d{4}(?:\.\d{3})?\b/g,
    asn: /\bAS\d{1,10}\b/gi,
    cidr: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\/(?:[12]?\d|3[0-2])\b/g,
    registry_key: /\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s"'<>]+/gi,
    file_path_win: /[a-zA-Z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]*/g,
    file_path_unix: /\/(?:[a-zA-Z0-9._\-]+\/)+[a-zA-Z0-9._\-]+/g,
    mutex: /\bGlobal\\[a-zA-Z0-9_\-\.]{4,64}\b/g,
  };

  const PRIVATE_RANGES = [
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^127\./,
    /^0\./,
    /^169\.254\./,
    /^224\./,
    /^255\./,
  ];

  function isPrivateIP(ip) {
    return PRIVATE_RANGES.some(r => r.test(ip));
  }

  function defang(text) {
    return text
      .replace(/\[\.\]/g, '.')
      .replace(/\[dot\]/gi, '.')
      .replace(/\[at\]/gi, '@')
      .replace(/hxxp/gi, 'http')
      .replace(/hXXp/gi, 'http')
      .replace(/\(dot\)/gi, '.')
      .replace(/\(at\)/gi, '@');
  }

  function hashType(h) {
    if (h.length === 32) return 'md5';
    if (h.length === 40) return 'sha1';
    if (h.length === 64) return 'sha256';
    if (h.length === 128) return 'sha512';
    return 'hash';
  }

  function extract(rawText) {
    const text = defang(rawText);
    const results = {};
    const seen = new Set();

    function add(type, value, meta = {}) {
      const key = `${type}:${value.toLowerCase()}`;
      if (seen.has(key)) return;
      seen.add(key);
      if (!results[type]) results[type] = [];
      results[type].push({ value, ...meta });
    }

    // URLs first (consume them so domains don't double-match)
    const urls = [];
    let m;
    const urlPat = new RegExp(PATTERNS.url.source, 'gi');
    while ((m = urlPat.exec(text)) !== null) {
      // Strip trailing sentence punctuation that regex greedily consumed
      let url = m[0].replace(/[.,;:'")\]>]+$/, '');
      add('url', url);
      urls.push({ start: m.index, end: m.index + url.length });
      // Also extract any IP that appears as the hostname of this URL
      // (important for defanged IPs that become valid URLs after defang)
      try {
        const parsed = new URL(url);
        const ipPat4 = new RegExp(PATTERNS.ipv4.source);
        if (ipPat4.test(parsed.hostname)) {
          const priv = isPrivateIP(parsed.hostname);
          add('ip', parsed.hostname, { private: priv, v: 4, source: 'url-host' });
        }
      } catch {}
    }

    // Mask out URL spans before other extractions
    let masked = text;
    for (let i = urls.length - 1; i >= 0; i--) {
      const { start, end } = urls[i];
      masked = masked.slice(0, start) + ' '.repeat(end - start) + masked.slice(end);
    }

    const ipPat = new RegExp(PATTERNS.ipv4.source, 'g');
    while ((m = ipPat.exec(masked)) !== null) {
      const ip = m[0];
      const priv = isPrivateIP(ip);
      add('ip', ip, { private: priv, v: 4 });
    }

    const ip6Pat = new RegExp(PATTERNS.ipv6.source, 'g');
    while ((m = ip6Pat.exec(masked)) !== null) {
      add('ip', m[0], { v: 6 });
    }

    const cidrPat = new RegExp(PATTERNS.cidr.source, 'g');
    while ((m = cidrPat.exec(masked)) !== null) {
      add('cidr', m[0]);
    }

    const domPat = new RegExp(PATTERNS.domain.source, 'gi');
    while ((m = domPat.exec(masked)) !== null) {
      const dom = m[0].toLowerCase();
      if (dom.length > 255) continue;
      add('domain', dom);
    }

    const emailPat = new RegExp(PATTERNS.email.source, 'gi');
    while ((m = emailPat.exec(masked)) !== null) {
      add('email', m[0].toLowerCase());
    }

    // Hashes — longest first to avoid substring collision
    const sha512Pat = new RegExp(PATTERNS.sha512.source, 'g');
    const sha512Seen = new Set();
    while ((m = sha512Pat.exec(masked)) !== null) {
      add('hash', m[0].toLowerCase(), { algo: 'sha512' });
      sha512Seen.add(m[0].toLowerCase());
    }
    const sha256Pat = new RegExp(PATTERNS.sha256.source, 'g');
    const sha256Seen = new Set();
    while ((m = sha256Pat.exec(masked)) !== null) {
      const v = m[0].toLowerCase();
      if (!sha512Seen.has(v) && !sha512Seen.has(v.padEnd(128,'0'))) {
        const inSha512 = [...sha512Seen].some(h => h.includes(v));
        if (!inSha512) { add('hash', v, { algo: 'sha256' }); sha256Seen.add(v); }
      }
    }
    const sha1Pat = new RegExp(PATTERNS.sha1.source, 'g');
    const sha1Seen = new Set();
    while ((m = sha1Pat.exec(masked)) !== null) {
      const v = m[0].toLowerCase();
      const inLonger = [...sha512Seen, ...sha256Seen].some(h => h.includes(v));
      if (!inLonger) { add('hash', v, { algo: 'sha1' }); sha1Seen.add(v); }
    }
    const md5Pat = new RegExp(PATTERNS.md5.source, 'g');
    while ((m = md5Pat.exec(masked)) !== null) {
      const v = m[0].toLowerCase();
      const inLonger = [...sha512Seen, ...sha256Seen, ...sha1Seen].some(h => h.includes(v));
      if (!inLonger) add('hash', v, { algo: 'md5' });
    }

    const cvePat = new RegExp(PATTERNS.cve.source, 'gi');
    while ((m = cvePat.exec(text)) !== null) add('cve', m[0].toUpperCase());

    const mitrePat = new RegExp(PATTERNS.mitre.source, 'g');
    while ((m = mitrePat.exec(text)) !== null) add('mitre', m[0].toUpperCase());

    const btcPat = new RegExp(PATTERNS.btc.source, 'g');
    while ((m = btcPat.exec(text)) !== null) add('btc', m[0]);

    const bechPat = new RegExp(PATTERNS.bech32.source, 'gi');
    while ((m = bechPat.exec(text)) !== null) add('btc', m[0].toLowerCase());

    const asnPat = new RegExp(PATTERNS.asn.source, 'gi');
    while ((m = asnPat.exec(text)) !== null) add('asn', m[0].toUpperCase());

    const regPat = new RegExp(PATTERNS.registry_key.source, 'gi');
    while ((m = regPat.exec(text)) !== null) add('registry', m[0]);

    const mutexPat = new RegExp(PATTERNS.mutex.source, 'g');
    while ((m = mutexPat.exec(text)) !== null) add('mutex', m[0]);

    return results;
  }

  function shannon(str) {
    const freq = {};
    for (const c of str) freq[c] = (freq[c] || 0) + 1;
    const len = str.length;
    return -Object.values(freq).reduce((acc, f) => {
      const p = f / len;
      return acc + p * Math.log2(p);
    }, 0);
  }

  function scoreDomain(domain) {
    const label = domain.split('.')[0];
    const ent = shannon(label);
    const vowels = (label.match(/[aeiou]/gi) || []).length / label.length;
    const digits = (label.match(/\d/g) || []).length / label.length;
    let score = 0;
    if (ent > 3.5) score += 30;
    if (vowels < 0.2) score += 20;
    if (digits > 0.3) score += 15;
    if (label.length > 20) score += 15;
    if (/[0-9]{4,}/.test(label)) score += 10;
    return { entropy: ent.toFixed(2), vowelRatio: vowels.toFixed(2), dgaScore: score };
  }

  return { extract, defang, shannon, scoreDomain };
})();
