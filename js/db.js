/* CodeShield — local database (IndexedDB).
   Everything lives only in this browser:
     scans — scan history (summary, rule, line number and the single flagged line; never full source code)
     kv    — your learning progress (XP, badges, streak, lessons) and preferences */
const DB_NAME = "codeshield", DB_VER = 2;
let dbp = null;

function open(){
  if (dbp) return dbp;
  dbp = new Promise((resolve, reject) => {
    if (!("indexedDB" in window)) return reject(new Error("IndexedDB unavailable"));
    const req = indexedDB.open(DB_NAME, DB_VER);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains("scans")){
        const s = db.createObjectStore("scans", { keyPath:"id", autoIncrement:true });
        s.createIndex("at", "at");
      }
      if (!db.objectStoreNames.contains("kv")) db.createObjectStore("kv");
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return dbp;
}

function tx(store, mode, fn){
  return open().then(db => new Promise((resolve, reject) => {
    const t = db.transaction(store, mode);
    const out = fn(t.objectStore(store));
    t.oncomplete = () => resolve(out && "result" in out ? out.result : out);
    t.onerror = () => reject(t.error);
  }));
}

/* strip a scan down to what we keep */
export function toRecord(scan){
  return {
    at:new Date().toISOString(),
    source:scan.source,            // "paste" | "github" | "upload"
    label:scan.label,              // e.g. "Python snippet" or "owner/repo"
    lang:scan.lang || null,
    lines:scan.lines, files:scan.files || 1,
    score:scan.score,
    summary:scan.summary,
    findings:scan.findings.map(f => ({
      rule:f.ruleId, cwe:f.cwe, severity:f.severity, file:f.file, line:f.line,
      snippet:f.snippet, status:f.verify ? f.verify.status : "test_generated"
    }))
  };
}

export const db = {
  add:rec => tx("scans", "readwrite", s => s.add(rec)),
  put:rec => tx("scans", "readwrite", s => s.put(rec)),
  all:() => tx("scans", "readonly", s => s.getAll()).then(r => (r || []).sort((a, b) => b.at.localeCompare(a.at))),
  remove:id => tx("scans", "readwrite", s => s.delete(id)),
  clear:() => tx("scans", "readwrite", s => s.clear())
};

export const kv = {
  get:key => tx("kv", "readonly", s => s.get(key)),
  set:(key, value) => tx("kv", "readwrite", s => s.put(value, key)),
  del:key => tx("kv", "readwrite", s => s.delete(key))
};
