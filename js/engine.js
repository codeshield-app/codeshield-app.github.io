/* CodeShield — scan engine and Proof Lab verification.
   Everything here runs in the browser; no code is sent anywhere. */
import { RULES, COMMENT_LINE } from "./rules.js";
import { generateTest } from "./tests.js";
import { autoPatch } from "./patch.js";
import { taintScan, flowStillOpen, flowPatch } from "./taint.js";

export const ENGINE_VERSION = "0.4";

const EXT_LANG = {
  py:"python", js:"javascript", jsx:"javascript", ts:"javascript", tsx:"javascript", mjs:"javascript", cjs:"javascript", vue:"javascript",
  php:"php", rb:"ruby", sh:"shell", bash:"shell", zsh:"shell", env:"shell", yml:"shell", yaml:"shell", java:"javascript", go:"javascript", cs:"javascript"
};

export function langFromPath(path){
  const name = path.split("/").pop().toLowerCase();
  if (name === ".env" || name.startsWith(".env.")) return "shell";
  if (name === "dockerfile") return "shell";
  return EXT_LANG[name.split(".").pop()] || null;
}

export function detectLanguage(code, hint){
  if (hint && hint !== "auto") return hint;
  if (/<\?php|\$_(GET|POST|SERVER)|->/.test(code)) return "php";
  if (/\bdef\s+\w+\s*\(.*\)\s*:|^\s*import\s+\w+|^\s*from\s+\w+\s+import\b|\bself\b/m.test(code)) return "python";
  if (/\bfunction\b|\bconst\b|=>|\brequire\(|\bexport\b/.test(code)) return "javascript";
  if (/\bend\b|\bdo\s*\|/.test(code)) return "ruby";
  if (/^#!\/bin\/(ba)?sh|\bfi\b|\besac\b/m.test(code)) return "shell";
  return "javascript";
}

let nextId = 1;

/* Scan one piece of code. `file` is an optional path (for repository scans). */
export function scanCode(code, lang, file){
  const lines = code.split(/\r?\n/);
  const findings = [];
  lines.forEach((raw, i) => {
    if (!raw.trim() || COMMENT_LINE.test(raw) || raw.length > 2000) return;
    for (const r of RULES){
      let hit = false;
      try { hit = r.test(raw); } catch (e) { hit = false; }
      if (!hit) continue;
      const ap = autoPatch(r.id, raw, lang);
      findings.push({
        id:nextId++, file:file || null, lang,
        ruleId:r.id, cwe:r.cwe, owasp:r.owasp, severity:r.severity,
        name_en:r.en, name_ar:r.ar, why_en:r.why_en, why_ar:r.why_ar, fix_en:r.fix_en, fix_ar:r.fix_ar,
        line:i + 1, raw, snippet:raw.trim().slice(0, 240),
        proof:generateTest(r.id, i + 1, lang),
        autoPatch:ap, patch:ap || raw, verify:null
      });
    }
  });
  // second pass: input that reaches a dangerous call on a later line
  const skip = new Set(findings.map(f => `${f.ruleId}@${f.line}`));
  taintScan(lines, lang, skip).forEach(fl => {
    const r = RULES.find(x => x.id === fl.kind);
    const ap = flowPatch(fl.kind, fl.raw, fl.var, lang);
    findings.push({
      id:nextId++, file:file || null, lang,
      ruleId:r.id, cwe:r.cwe, owasp:r.owasp, severity:r.severity,
      name_en:r.en, name_ar:r.ar, why_en:r.why_en, why_ar:r.why_ar, fix_en:r.fix_en, fix_ar:r.fix_ar,
      line:fl.line, raw:fl.raw, snippet:fl.raw.trim().slice(0, 240),
      flow:{ var:fl.var, sourceLine:fl.sourceLine, sourceCode:(lines[fl.sourceLine - 1] || "").trim().slice(0, 200) },
      proof:generateTest(r.id, fl.line, lang),
      autoPatch:ap, patch:ap || fl.raw, verify:null
    });
  });
  findings.sort((a, b) => a.line - b.line);
  return { findings, lineCount:lines.length, lang };
}

export function hitsOn(code){
  const out = [];
  code.split(/\r?\n/).forEach((ln, i) => {
    if (!ln.trim() || COMMENT_LINE.test(ln)) return;
    RULES.forEach(r => { let h = false; try { h = r.test(ln); } catch (e) {} if (h) out.push({ rule:r.id, line:i + 1 }); });
  });
  return out;
}

/* Proof Lab. A finding becomes "verified" only when BOTH checks are recorded:
   1) its rule FAILS on the original line (the flaw is reproduced)
   2) all rules PASS on the patched code (the flaw is closed and nothing new appears) */
export function verifyFinding(f, patched){
  if (patched !== undefined) f.patch = patched;
  const rule = RULES.find(r => r.id === f.ruleId);
  const t = new Date().toISOString().replace("T", " ").slice(0, 19);
  // flow findings are checked with the data-flow check; line findings with their rule
  const check = code => f.flow ? flowStillOpen(f.ruleId, code, f.flow.var, f.lang) : (() => { try { return rule.test(code); } catch (e) { return false; } })();
  const orig = check(f.raw);
  const changed = !!f.patch.trim() && f.patch.trim() !== f.raw.trim();
  const hits = changed ? hitsOn(f.patch) : [];
  if (changed && f.flow && flowStillOpen(f.ruleId, f.patch, f.flow.var, f.lang)) hits.unshift({ rule:f.ruleId, line:1 });
  const same = hits.filter(h => h.rule === f.ruleId), added = hits.filter(h => h.rule !== f.ruleId);
  const evidence = [
    { t, step:"original", rule:f.ruleId + (f.flow ? " (data flow)" : ""), input:f.raw.trim(), result:orig ? "FAIL" : "PASS" },
    { t, step:"patched", rules:RULES.length, input:f.patch.trim(), result:!changed ? "NOT_RUN" : hits.length ? "FAIL" : "PASS", hits:hits.map(h => `${h.rule}@${h.line}`) }
  ];
  let status = "verified", reason = "ok";
  if (!orig) { status = "failed"; reason = "not_reproduced"; }
  else if (!changed) { status = "failed"; reason = "unchanged"; }
  else if (same.length) { status = "failed"; reason = "still_vulnerable"; }
  else if (added.length) { status = "failed"; reason = "new_issue"; }
  f.verify = { status, reason, newRules:added.map(h => h.rule), evidence, at:t };
  return f.verify;
}

export function summarize(findings){
  const c = { total:findings.length, HIGH:0, MEDIUM:0, LOW:0, verified:0, byRule:{} };
  findings.forEach(f => {
    c[f.severity]++;
    c.byRule[f.ruleId] = (c.byRule[f.ruleId] || 0) + 1;
    if (f.verify && f.verify.status === "verified") c.verified++;
  });
  return c;
}

/* 0–100 security score: weighted open findings per 1,000 lines (min. 200 lines),
   decaying exponentially. Verified fixes no longer count against the score. */
export function securityScore(findings, lines){
  const open = findings.filter(f => !(f.verify && f.verify.status === "verified"));
  const weight = open.reduce((s, f) => s + (f.severity === "HIGH" ? 10 : f.severity === "MEDIUM" ? 4 : 1), 0);
  const perKloc = weight / (Math.max(lines, 200) / 1000);
  return Math.round(100 * Math.exp(-perKloc / 60));
}
