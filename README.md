# PHANTOM Web
### Platform for Holistic Autonomous Multi-domain Threat iNtelligence

> **Zero external API · Air-gap compatible · Runs entirely in your browser**

---

## Live Demo
**[https://Masriyan.github.io/phantom-web](https://Masriyan.github.io/phantom-web)**

---

## Features

| Module | Description |
|---|---|
| **IOC Extractor** | Paste any text → auto-extract IPv4/IPv6, domains, URLs, MD5/SHA1/SHA256/SHA512, emails, CVEs, MITRE ATT&CK IDs, BTC addresses, CIDR, ASN, registry keys, mutexes. Defanging auto-handled (`hxxp`, `[.]`, `[at]`). DGA scoring per domain. |
| **File Analyzer** | Upload any file → MD5/SHA1/SHA256/SHA512 (Web Crypto API), entropy analysis, file type detection, PE/ELF basic parser, YARA-lite rule matching (23 rules), string extraction, IOC extraction from strings. |
| **ATT&CK Mapper** | Search and tag MITRE ATT&CK Enterprise techniques. Coverage heatmap per tactic. Export ATT&CK Navigator layer JSON (compatible with navigator.attack.mitre.org). |
| **Diamond Model Builder** | Build and persist Diamond Model instances (Adversary / Capability / Infrastructure / Victim). Export as JSON. |
| **IOC Database** | IndexedDB-powered local database. Deduplication, TLP tagging, confidence scoring, search, filter by type. Export as CSV or STIX 2.1 bundle. |
| **Report Builder** | Generate CTI reports with auto-populated IOC and TTP sections. Download as TXT or JSON. |

---

## Deploy to GitHub Pages

### Method 1 — Direct (no build step)
```bash
# Fork or clone this repo
git clone https://github.com/Masriyan/phantom-web
cd phantom-web

# Push to your GitHub repo
git remote set-url origin https://github.com/Masriyan/phantom-web
git push origin main

# Enable GitHub Pages:
# Settings → Pages → Source: Deploy from branch → Branch: main → / (root)
```

Done. Access at: `https://Masriyan.github.io/phantom-web`

### Method 2 — GitHub Actions (auto-deploy on push)
Create `.github/workflows/pages.yml`:
```yaml
name: Deploy PHANTOM Web
on:
  push:
    branches: [main]
permissions:
  contents: read
  pages: write
  id-token: write
jobs:
  deploy:
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/configure-pages@v4
      - uses: actions/upload-pages-artifact@v3
        with:
          path: '.'
      - id: deployment
        uses: actions/deploy-pages@v4
```

---

## Privacy & Data
- **All analysis runs locally** in your browser
- **No data leaves your machine** — no telemetry, no analytics, no external calls
- IOC database stored in browser IndexedDB (clears on "Clear DB")
- ATT&CK data bundled locally (23.000+ chars of technique data)
- Fonts loaded from Google Fonts (optional — remove import from CSS for full air-gap)

---

## Stack
```
HTML5 + CSS3 + Vanilla JavaScript (no framework, no build step)
Web Crypto API         → SHA-1, SHA-256, SHA-512 hashing
IndexedDB              → Local IOC database
Custom MD5 impl        → Pure JS, no library
Custom PE parser       → Reads MZ/PE headers in browser
Custom IOC regex       → 20+ pattern types, defang support
Custom entropy calc    → Shannon entropy, sliding window
Custom YARA-lite       → 23 behavioral/signature rules
Google Fonts           → JetBrains Mono + Syne
```

---

## File Structure
```
phantom-web/
├── index.html          # App shell
├── css/
│   └── phantom.css     # Full dark terminal design system
├── js/
│   ├── app.js          # UI controller + all pages
│   ├── db.js           # IndexedDB wrapper + STIX export
│   ├── ioc-engine.js   # IOC extraction + DGA scoring
│   └── file-engine.js  # File analysis + PE parser + YARA-lite
└── data/
    └── attck.js        # MITRE ATT&CK Enterprise (250+ techniques)
```

---

## For Full Backend Capabilities
Use **PHANTOM** (full Python backend) for:
- Passive DNS sniffing
- Behavioral sandbox (ptrace/Frida)
- Active port scanning + banner grabbing
- Tor OSINT crawling
- Neo4j graph intelligence
- ML clustering (HDBSCAN)
- PCAP analysis
- Server-side report generation (DOCX/PDF)

See: [PHANTOM Master Build Prompt](./PHANTOM_master_prompt.md)

---

*Built by Masriyan (sudo3rs) · PHANTOM Web · Zero external dependency*
