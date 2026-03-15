const FileEngine = (() => {

  // --- Magic bytes signatures ---
  const MAGIC = [
    { sig: [0x4D,0x5A], name:'PE/EXE (Windows)', type:'pe', ext:'.exe/.dll' },
    { sig: [0x7F,0x45,0x4C,0x46], name:'ELF (Linux/Unix)', type:'elf', ext:'.elf' },
    { sig: [0x50,0x4B,0x03,0x04], name:'ZIP Archive', type:'zip', ext:'.zip' },
    { sig: [0x50,0x4B,0x05,0x06], name:'ZIP Archive (empty)', type:'zip', ext:'.zip' },
    { sig: [0x50,0x4B,0x07,0x08], name:'ZIP Archive (spanned)', type:'zip', ext:'.zip' },
    { sig: [0x25,0x50,0x44,0x46], name:'PDF Document', type:'pdf', ext:'.pdf' },
    { sig: [0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1], name:'MS Office (OLE)', type:'ole', ext:'.doc/.xls/.ppt' },
    { sig: [0xFF,0xD8,0xFF], name:'JPEG Image', type:'jpeg', ext:'.jpg' },
    { sig: [0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A], name:'PNG Image', type:'png', ext:'.png' },
    { sig: [0x47,0x49,0x46,0x38], name:'GIF Image', type:'gif', ext:'.gif' },
    { sig: [0x1F,0x8B], name:'GZIP Archive', type:'gzip', ext:'.gz' },
    { sig: [0x42,0x5A,0x68], name:'BZIP2 Archive', type:'bzip2', ext:'.bz2' },
    { sig: [0x37,0x7A,0xBC,0xAF,0x27,0x1C], name:'7-Zip Archive', type:'7z', ext:'.7z' },
    { sig: [0x52,0x61,0x72,0x21,0x1A,0x07], name:'RAR Archive', type:'rar', ext:'.rar' },
    { sig: [0xCA,0xFE,0xBA,0xBE], name:'Java Class File / Mach-O Fat', type:'java', ext:'.class' },
    { sig: [0xCE,0xFA,0xED,0xFE], name:'Mach-O 32-bit LE', type:'macho', ext:'.dylib' },
    { sig: [0xCF,0xFA,0xED,0xFE], name:'Mach-O 64-bit LE', type:'macho', ext:'.dylib' },
    { sig: [0x50,0x4B], name:'APK/JAR (ZIP-based)', type:'apk', ext:'.apk/.jar' },
    { sig: [0x4D,0x5A,0x90,0x00], name:'PE Executable (MZ stub)', type:'pe', ext:'.exe' },
    { sig: [0xDE,0xAD,0xBE,0xEF], name:'PowerPC (BE)', type:'macho', ext:'.macho' },
  ];

  // YARA-lite patterns (regex-based, client-side)
  const YARA_RULES = [
    { name:'Mimikatz strings', severity:'critical', pattern:/sekurlsa|kerberos|wdigest|lsadump|privilege::debug|sekurlsa::logonpasswords/i },
    { name:'Cobalt Strike beacon', severity:'critical', pattern:/ReflectiveDll|beacon\.x64|cobaltstrike|sleeptime|jitter|pipename/i },
    { name:'Meterpreter payload', severity:'critical', pattern:/meterpreter|ReflectiveLoader|stdapi_|priv_|kiwi_/i },
    { name:'PowerShell download cradle', severity:'high', pattern:/IEX\s*\(|Invoke-Expression|DownloadString|WebClient|FromBase64String|EncodedCommand/i },
    { name:'Base64 encoded PowerShell', severity:'high', pattern:/powershell.*-[Ee][Nn][Cc](?:[Oo][Dd][Ee](?:[Dd])?)?(?:[Cc](?:[Oo][Mm][Mm][Aa][Nn][Dd])?)?\s+[A-Za-z0-9+/=]{20,}/i },
    { name:'Shellcode NOP sled', severity:'high', pattern:/(?:\x90{16,}|(?:\\x90){10,})/i },
    { name:'Registry persistence keys', severity:'medium', pattern:/CurrentVersion\\Run|Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce|HKCU\\Software\\Microsoft\\Windows NT/i },
    { name:'Anti-VM strings', severity:'medium', pattern:/vmware|virtualbox|vbox|qemu|sandboxie|wireshark|fiddler|procmon|OllyDbg|x64dbg|ida\.exe/i },
    { name:'C2 HTTP beacon pattern', severity:'high', pattern:/User-Agent.*Mozilla.*Windows.*Trident|Accept-Language.*en-US.*q=0\.5/i },
    { name:'DNS over HTTPS', severity:'medium', pattern:/dns\.google\/dns-query|cloudflare-dns\.com\/dns-query|1\.1\.1\.1.*resolve/i },
    { name:'WMI execution', severity:'medium', pattern:/Win32_Process.*Create|wmic.*process.*call.*create|Get-WmiObject.*Win32_Process/i },
    { name:'Process injection API', severity:'high', pattern:/VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|RtlCreateUserThread/i },
    { name:'Credential theft strings', severity:'critical', pattern:/password|passwd|credential|lsass\.exe|SAM\\|ntds\.dit|shadow.*password|\/etc\/shadow/i },
    { name:'Ransomware extension list', severity:'critical', pattern:/\.locked|\.encrypted|\.crypted|\.crypt|\.enc|\.pay2decrypt|\.fucked|YOUR_FILES_ARE_ENCRYPTED/i },
    { name:'Bitcoin wallet address', severity:'medium', pattern:/\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/i },
    { name:'Tor .onion address', severity:'medium', pattern:/[a-z2-7]{16,56}\.onion/i },
    { name:'Reverse shell patterns', severity:'high', pattern:/bash\s+-i.*>&.*\/dev\/tcp|nc\s+-e\s+\/bin\/(?:bash|sh)|python.*socket.*connect.*subprocess/i },
    { name:'Privilege escalation (Linux)', severity:'high', pattern:/\/etc\/passwd|\/etc\/sudoers|chmod\s+[0-7]*s|SUID|sudo\s+-l/i },
    { name:'Scheduled task abuse', severity:'medium', pattern:/schtasks.*\/create|at\.exe\s+\d|crontab\s+-[el]|\/etc\/cron/i },
    { name:'Lateral movement tools', severity:'high', pattern:/psexec|wce\.exe|fgdump|pwdump|pass-the-hash|pth-winexe|CrackMapExec|crackmapexec/i },
    { name:'DGA-like domain pattern', severity:'medium', pattern:/(?:[a-z]{15,30}\.(?:xyz|top|club|online|site|fun|live|info))/i },
    { name:'Suspicious imports (PE)', severity:'high', pattern:/GetAsyncKeyState|SetWindowsHookEx|CreateToolhelp32Snapshot.*Process32|OpenProcess.*PROCESS_ALL_ACCESS/i },
    { name:'Macro execution strings', severity:'high', pattern:/AutoOpen|Document_Open|Workbook_Open|Shell\(|CreateObject.*WScript|WScript\.Shell/i },
  ];

  async function computeHashes(buffer) {
    const hashTypes = ['SHA-1', 'SHA-256', 'SHA-512'];
    const results = {};
    for (const algo of hashTypes) {
      const hashBuf = await crypto.subtle.digest(algo, buffer);
      results[algo.replace('-', '')] = Array.from(new Uint8Array(hashBuf))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    }
    // MD5 (not in WebCrypto — use a simple implementation)
    results.MD5 = md5(new Uint8Array(buffer));
    return results;
  }

  function detectMagic(bytes) {
    for (const { sig, name, type, ext } of MAGIC) {
      if (sig.every((b, i) => bytes[i] === b)) {
        return { name, type, ext };
      }
    }
    // Check if printable text
    const sample = bytes.slice(0, 512);
    const printable = sample.filter(b => (b >= 0x20 && b < 0x7F) || b === 0x09 || b === 0x0A || b === 0x0D).length;
    if (printable / sample.length > 0.85) return { name: 'Text / Script', type: 'text', ext: '.txt/.sh/.py/.js' };
    return { name: 'Unknown / Binary', type: 'unknown', ext: '' };
  }

  function computeEntropy(bytes) {
    const freq = new Array(256).fill(0);
    for (const b of bytes) freq[b]++;
    const len = bytes.length;
    let entropy = 0;
    for (const f of freq) {
      if (f === 0) continue;
      const p = f / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  function entropyLabel(e) {
    if (e < 3) return { label: 'Low (plaintext/data)', color: '#00d4aa' };
    if (e < 5) return { label: 'Medium (compiled code)', color: '#f0b429' };
    if (e < 7) return { label: 'High (compressed/obfuscated)', color: '#ff8c42' };
    return { label: 'Very High (likely packed/encrypted)', color: '#ff4444' };
  }

  function slidingEntropy(bytes, windowSize = 256) {
    const results = [];
    for (let i = 0; i < bytes.length - windowSize; i += windowSize) {
      const window = bytes.slice(i, i + windowSize);
      results.push({ offset: i, entropy: computeEntropy(window) });
    }
    return results;
  }

  function extractStrings(bytes, minLen = 4) {
    const printable = [];
    const unicode = [];
    let current = '';
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b >= 0x20 && b < 0x7F) {
        current += String.fromCharCode(b);
      } else {
        if (current.length >= minLen) printable.push(current);
        current = '';
      }
    }
    if (current.length >= minLen) printable.push(current);

    // Unicode (UTF-16 LE naive scan)
    current = '';
    for (let i = 0; i < bytes.length - 1; i += 2) {
      const b0 = bytes[i], b1 = bytes[i+1];
      if (b0 >= 0x20 && b0 < 0x7F && b1 === 0x00) {
        current += String.fromCharCode(b0);
      } else {
        if (current.length >= minLen) unicode.push(current);
        current = '';
      }
    }
    if (current.length >= minLen) unicode.push(current);

    return { printable: [...new Set(printable)], unicode: [...new Set(unicode)] };
  }

  function yaraLiteScan(strings, textContent) {
    const hits = [];
    for (const rule of YARA_RULES) {
      if (rule.pattern.test(textContent)) {
        hits.push({ rule: rule.name, severity: rule.severity });
      }
    }
    return hits;
  }

  function parsePEBasic(bytes) {
    if (bytes[0] !== 0x4D || bytes[1] !== 0x5A) return null;
    const view = new DataView(bytes.buffer || bytes);
    try {
      const peOffset = view.getUint32(0x3C, true);
      if (peOffset + 4 > bytes.length) return null;
      const sig = view.getUint32(peOffset, true);
      if (sig !== 0x00004550) return null; // "PE\0\0"

      const machine = view.getUint16(peOffset + 4, true);
      const machineMap = { 0x014c: 'x86 (i386)', 0x8664: 'x64 (AMD64)', 0xAA64: 'ARM64', 0x01c0: 'ARM', 0x0200: 'IA64' };
      const numSections = view.getUint16(peOffset + 6, true);
      const timestamp = view.getUint32(peOffset + 8, true);
      const characteristics = view.getUint16(peOffset + 22, true);
      const optHeaderSize = view.getUint16(peOffset + 20, true);
      const magic = optHeaderSize > 0 ? view.getUint16(peOffset + 24, true) : 0;
      const is64 = magic === 0x20B;

      const compileTime = new Date(timestamp * 1000);
      const isDLL = (characteristics & 0x2000) !== 0;
      const isConsole = optHeaderSize > 0 ? view.getUint16(peOffset + 24 + (is64 ? 68 : 52), true) === 3 : false;

      // Read sections
      const sections = [];
      const sectionOffset = peOffset + 24 + optHeaderSize;
      for (let i = 0; i < Math.min(numSections, 16); i++) {
        const s = sectionOffset + i * 40;
        if (s + 40 > bytes.length) break;
        const nameBytes = bytes.slice(s, s+8);
        const name = String.fromCharCode(...nameBytes).replace(/\0/g, '');
        const virtualSize = view.getUint32(s + 8, true);
        const rawSize = view.getUint32(s + 16, true);
        const secChars = view.getUint32(s + 36, true);
        const rawOffset = view.getUint32(s + 20, true);
        const secBytes = bytes.slice(rawOffset, rawOffset + Math.min(rawSize, 65536));
        const ent = computeEntropy(secBytes);
        sections.push({ name, virtualSize, rawSize, entropy: ent.toFixed(2), chars: secChars });
      }

      return {
        arch: machineMap[machine] || `Unknown (0x${machine.toString(16)})`,
        type: isDLL ? 'DLL' : 'EXE',
        compileTime: compileTime.toISOString(),
        compileTimestamp: timestamp,
        numSections,
        sections,
        is64,
        subsystem: isConsole ? 'Console' : 'GUI',
        characteristics: characteristics.toString(16).padStart(4,'0'),
      };
    } catch { return null; }
  }

  async function analyze(file) {
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    const textDecoder = new TextDecoder('utf-8', { fatal: false });
    const textContent = textDecoder.decode(bytes.slice(0, Math.min(bytes.length, 500000)));

    const hashes = await computeHashes(buffer);
    const fileType = detectMagic(bytes);
    const entropy = computeEntropy(bytes);
    const entLabel = entropyLabel(entropy);
    const stringsData = extractStrings(bytes);
    const yaraHits = yaraLiteScan(stringsData, textContent);
    const peInfo = fileType.type === 'pe' || (bytes[0] === 0x4D && bytes[1] === 0x5A) ? parsePEBasic(bytes) : null;
    const entropyMap = slidingEntropy(bytes);

    // IOC extraction from strings
    const allStrings = [...stringsData.printable, ...stringsData.unicode].join('\n');
    const iocs = IOCEngine.extract(allStrings);

    return {
      name: file.name,
      size: file.size,
      sizeHuman: formatBytes(file.size),
      lastModified: new Date(file.lastModified).toISOString(),
      fileType,
      hashes,
      entropy: entropy.toFixed(4),
      entropyLabel: entLabel,
      entropyMap,
      strings: {
        printableCount: stringsData.printable.length,
        unicodeCount: stringsData.unicode.length,
        sample: stringsData.printable.slice(0, 50),
      },
      yaraHits,
      peInfo,
      iocs,
    };
  }

  function formatBytes(b) {
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b/1024).toFixed(1) + ' KB';
    if (b < 1073741824) return (b/1048576).toFixed(1) + ' MB';
    return (b/1073741824).toFixed(2) + ' GB';
  }

  // Minimal MD5 implementation
  function md5(bytes) {
    function safeAdd(x,y){const lsw=(x&0xFFFF)+(y&0xFFFF);return(((x>>16)+(y>>16)+(lsw>>16))<<16)|(lsw&0xFFFF);}
    function bitRotateLeft(num,cnt){return(num<<cnt)|(num>>>(32-cnt));}
    function md5cmn(q,a,b,x,s,t){return safeAdd(bitRotateLeft(safeAdd(safeAdd(a,q),safeAdd(x,t)),s),b);}
    function md5ff(a,b,c,d,x,s,t){return md5cmn((b&c)|((~b)&d),a,b,x,s,t);}
    function md5gg(a,b,c,d,x,s,t){return md5cmn((b&d)|(c&(~d)),a,b,x,s,t);}
    function md5hh(a,b,c,d,x,s,t){return md5cmn(b^c^d,a,b,x,s,t);}
    function md5ii(a,b,c,d,x,s,t){return md5cmn(c^(b|(~d)),a,b,x,s,t);}

    const len8 = bytes.length;
    const nblks = ((len8+8>>6)+1);
    const blks = new Array(nblks*16).fill(0);
    for(let i=0;i<len8;i++) blks[i>>2]|=bytes[i]<<((i%4)*8);
    blks[len8>>2]|=0x80<<((len8%4)*8);
    blks[nblks*16-2]=len8*8;

    let a=1732584193,b=-271733879,c=-1732584194,d=271733878;
    for(let i=0;i<blks.length;i+=16){
      const olda=a,oldb=b,oldc=c,oldd=d;
      a=md5ff(a,b,c,d,blks[i],7,-680876936);d=md5ff(d,a,b,c,blks[i+1],12,-389564586);c=md5ff(c,d,a,b,blks[i+2],17,606105819);b=md5ff(b,c,d,a,blks[i+3],22,-1044525330);
      a=md5ff(a,b,c,d,blks[i+4],7,-176418897);d=md5ff(d,a,b,c,blks[i+5],12,1200080426);c=md5ff(c,d,a,b,blks[i+6],17,-1473231341);b=md5ff(b,c,d,a,blks[i+7],22,-45705983);
      a=md5ff(a,b,c,d,blks[i+8],7,1770035416);d=md5ff(d,a,b,c,blks[i+9],12,-1958414417);c=md5ff(c,d,a,b,blks[i+10],17,-42063);b=md5ff(b,c,d,a,blks[i+11],22,-1990404162);
      a=md5ff(a,b,c,d,blks[i+12],7,1804603682);d=md5ff(d,a,b,c,blks[i+13],12,-40341101);c=md5ff(c,d,a,b,blks[i+14],17,-1502002290);b=md5ff(b,c,d,a,blks[i+15],22,1236535329);
      a=md5gg(a,b,c,d,blks[i+1],5,-165796510);d=md5gg(d,a,b,c,blks[i+6],9,-1069501632);c=md5gg(c,d,a,b,blks[i+11],14,643717713);b=md5gg(b,c,d,a,blks[i],20,-373897302);
      a=md5gg(a,b,c,d,blks[i+5],5,-701558691);d=md5gg(d,a,b,c,blks[i+10],9,38016083);c=md5gg(c,d,a,b,blks[i+15],14,-660478335);b=md5gg(b,c,d,a,blks[i+4],20,-405537848);
      a=md5gg(a,b,c,d,blks[i+9],5,568446438);d=md5gg(d,a,b,c,blks[i+14],9,-1019803690);c=md5gg(c,d,a,b,blks[i+3],14,-187363961);b=md5gg(b,c,d,a,blks[i+8],20,1163531501);
      a=md5gg(a,b,c,d,blks[i+13],5,-1444681467);d=md5gg(d,a,b,c,blks[i+2],9,-51403784);c=md5gg(c,d,a,b,blks[i+7],14,1735328473);b=md5gg(b,c,d,a,blks[i+12],20,-1926607734);
      a=md5hh(a,b,c,d,blks[i+5],4,-378558);d=md5hh(d,a,b,c,blks[i+8],11,-2022574463);c=md5hh(c,d,a,b,blks[i+11],16,1839030562);b=md5hh(b,c,d,a,blks[i+14],23,-35309556);
      a=md5hh(a,b,c,d,blks[i+1],4,-1530992060);d=md5hh(d,a,b,c,blks[i+4],11,1272893353);c=md5hh(c,d,a,b,blks[i+7],16,-155497632);b=md5hh(b,c,d,a,blks[i+10],23,-1094730640);
      a=md5hh(a,b,c,d,blks[i+13],4,681279174);d=md5hh(d,a,b,c,blks[i],11,-358537222);c=md5hh(c,d,a,b,blks[i+3],16,-722521979);b=md5hh(b,c,d,a,blks[i+6],23,76029189);
      a=md5hh(a,b,c,d,blks[i+9],4,-640364487);d=md5hh(d,a,b,c,blks[i+12],11,-421815835);c=md5hh(c,d,a,b,blks[i+15],16,530742520);b=md5hh(b,c,d,a,blks[i+2],23,-995338651);
      a=md5ii(a,b,c,d,blks[i],6,-198630844);d=md5ii(d,a,b,c,blks[i+7],10,1126891415);c=md5ii(c,d,a,b,blks[i+14],15,-1416354905);b=md5ii(b,c,d,a,blks[i+5],21,-57434055);
      a=md5ii(a,b,c,d,blks[i+12],6,1700485571);d=md5ii(d,a,b,c,blks[i+3],10,-1894986606);c=md5ii(c,d,a,b,blks[i+10],15,-1051523);b=md5ii(b,c,d,a,blks[i+1],21,-2054922799);
      a=md5ii(a,b,c,d,blks[i+8],6,1873313359);d=md5ii(d,a,b,c,blks[i+15],10,-30611744);c=md5ii(c,d,a,b,blks[i+6],15,-1560198380);b=md5ii(b,c,d,a,blks[i+13],21,1309151649);
      a=md5ii(a,b,c,d,blks[i+4],6,-145523070);d=md5ii(d,a,b,c,blks[i+11],10,-1120210379);c=md5ii(c,d,a,b,blks[i+2],15,718787259);b=md5ii(b,c,d,a,blks[i+9],21,-343485551);
      a=safeAdd(a,olda);b=safeAdd(b,oldb);c=safeAdd(c,oldc);d=safeAdd(d,oldd);
    }
    return [a,b,c,d].map(n=>Array.from({length:4},(_,i)=>((n>>(i*8))&0xFF).toString(16).padStart(2,'0')).join('')).join('');
  }

  return { analyze, computeEntropy, extractStrings, yaraLiteScan, parsePEBasic, entropyLabel, YARA_RULES };
})();
