const PhantomDB = (() => {
  const DB_NAME = 'PhantomWeb';
  const DB_VERSION = 2;
  let db = null;

  const STORES = {
    iocs: { keyPath: 'id', indexes: [
      { name: 'value', keyPath: 'value', unique: false },
      { name: 'type', keyPath: 'type', unique: false },
      { name: 'added', keyPath: 'added', unique: false },
      { name: 'tlp', keyPath: 'tlp', unique: false },
    ]},
    campaigns: { keyPath: 'id' },
    actors: { keyPath: 'id' },
    investigations: { keyPath: 'id' },
    notes: { keyPath: 'id' },
  };

  async function open() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        for (const [name, cfg] of Object.entries(STORES)) {
          let store;
          if (db.objectStoreNames.contains(name)) {
            store = e.target.transaction.objectStore(name);
          } else {
            store = db.createObjectStore(name, { keyPath: cfg.keyPath });
          }
          if (cfg.indexes) {
            for (const idx of cfg.indexes) {
              if (!store.indexNames.contains(idx.name)) {
                store.createIndex(idx.name, idx.keyPath, { unique: idx.unique || false });
              }
            }
          }
        }
      };
      req.onsuccess = (e) => { db = e.target.result; resolve(db); };
      req.onerror = reject;
    });
  }

  function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
  }

  async function put(storeName, data) {
    if (!db) await open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, 'readwrite');
      const store = tx.objectStore(storeName);
      if (!data.id) data.id = generateId();
      const req = store.put(data);
      req.onsuccess = () => resolve(data);
      req.onerror = reject;
    });
  }

  async function get(storeName, id) {
    if (!db) await open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, 'readonly');
      const store = tx.objectStore(storeName);
      const req = store.get(id);
      req.onsuccess = () => resolve(req.result);
      req.onerror = reject;
    });
  }

  async function getAll(storeName) {
    if (!db) await open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, 'readonly');
      const store = tx.objectStore(storeName);
      const req = store.getAll();
      req.onsuccess = () => resolve(req.result);
      req.onerror = reject;
    });
  }

  async function del(storeName, id) {
    if (!db) await open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, 'readwrite');
      const store = tx.objectStore(storeName);
      const req = store.delete(id);
      req.onsuccess = () => resolve();
      req.onerror = reject;
    });
  }

  async function search(storeName, query) {
    const all = await getAll(storeName);
    if (!query) return all;
    const q = query.toLowerCase();
    return all.filter(item => JSON.stringify(item).toLowerCase().includes(q));
  }

  async function addIOC(value, type, meta = {}) {
    const existing = await searchIOC(value, type);
    if (existing) {
      existing.lastSeen = Date.now();
      existing.count = (existing.count || 1) + 1;
      return put('iocs', existing);
    }
    return put('iocs', {
      value: value.toLowerCase().trim(),
      type,
      tlp: meta.tlp || 'amber',
      confidence: meta.confidence || 0.5,
      tags: meta.tags || [],
      source: meta.source || 'manual',
      notes: meta.notes || '',
      added: Date.now(),
      lastSeen: Date.now(),
      count: 1,
      ...meta,
    });
  }

  async function searchIOC(value, type) {
    const all = await getAll('iocs');
    return all.find(i => i.value === value.toLowerCase().trim() && (!type || i.type === type)) || null;
  }

  async function getIOCsByType(type) {
    const all = await getAll('iocs');
    return type ? all.filter(i => i.type === type) : all;
  }

  async function exportCSV(storeName) {
    const data = await getAll(storeName);
    if (!data.length) return '';
    const headers = Object.keys(data[0]);
    const rows = data.map(row => headers.map(h => {
      const v = row[h];
      if (Array.isArray(v)) return `"${v.join(',')}"`; 
      if (typeof v === 'object') return `"${JSON.stringify(v).replace(/"/g,'""')}"`;
      return typeof v === 'string' && v.includes(',') ? `"${v}"` : v;
    }).join(','));
    return [headers.join(','), ...rows].join('\n');
  }

  async function exportSTIX(campaignId) {
    const iocs = await getAll('iocs');
    const bundle = {
      type: 'bundle',
      id: `bundle--${crypto.randomUUID()}`,
      spec_version: '2.1',
      created: new Date().toISOString(),
      objects: iocs.map(ioc => ({
        type: 'indicator',
        spec_version: '2.1',
        id: `indicator--${crypto.randomUUID()}`,
        created: new Date(ioc.added).toISOString(),
        modified: new Date(ioc.lastSeen).toISOString(),
        name: `${ioc.type}: ${ioc.value}`,
        pattern: buildSTIXPattern(ioc),
        pattern_type: 'stix',
        valid_from: new Date(ioc.added).toISOString(),
        labels: ioc.tags,
        confidence: Math.round((ioc.confidence || 0.5) * 100),
        object_marking_refs: [`marking-definition--${tlpToId(ioc.tlp)}`],
      })),
    };
    return JSON.stringify(bundle, null, 2);
  }

  function buildSTIXPattern(ioc) {
    const typeMap = {
      ip: "ipv4-addr:value = '",
      domain: "domain-name:value = '",
      url: "url:value = '",
      email: "email-message:from_ref.value = '",
      hash: `file:hashes.'${(ioc.algo||'SHA-256').toUpperCase()}' = '`,
      cve: "vulnerability:name = '",
    };
    const prefix = typeMap[ioc.type] || "artifact:payload_bin = '";
    return `[${prefix}${ioc.value}']`;
  }

  function tlpToId(tlp) {
    const ids = { red:'5e57c739-391a-4eb3-b6be-7d15ca92d5ed', amber:'f88d31f6-1208-47ed-8e57-43a3ef872ee4', green:'2f669986-b40b-4423-b720-4396ca6a462b', white:'613f2e26-407d-48c7-9eca-b8e91df99dc9', clear:'613f2e26-407d-48c7-9eca-b8e91df99dc9' };
    return ids[tlp] || ids.amber;
  }

  async function getStats() {
    const iocs = await getAll('iocs');
    const byType = {};
    const byTlp = {};
    for (const ioc of iocs) {
      byType[ioc.type] = (byType[ioc.type] || 0) + 1;
      byTlp[ioc.tlp] = (byTlp[ioc.tlp] || 0) + 1;
    }
    const campaigns = await getAll('campaigns');
    const actors = await getAll('actors');
    return { totalIOCs: iocs.length, byType, byTlp, totalCampaigns: campaigns.length, totalActors: actors.length };
  }

  async function clearAll() {
    if (!db) await open();
    for (const storeName of Object.keys(STORES)) {
      await new Promise((res, rej) => {
        const tx = db.transaction(storeName, 'readwrite');
        tx.objectStore(storeName).clear().onsuccess = res;
        tx.onerror = rej;
      });
    }
  }

  return { open, put, get, getAll, del, search, addIOC, searchIOC, getIOCsByType, exportCSV, exportSTIX, getStats, clearAll, generateId };
})();
