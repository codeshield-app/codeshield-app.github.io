/* CodeShield — exports: fixed source files and SARIF 2.1.0. */
import { RULES } from "./rules.js";

/* Apply every VERIFIED fix to the original source. One fix per line;
   a fix may span several lines (e.g. a guard inserted above the call). */
export function applyFixes(code, findings){
  const lines = code.split(/\r?\n/);
  const byLine = new Map();
  let skipped = 0;
  findings.filter(f => f.verify && f.verify.status === "verified")
    .forEach(f => { if (byLine.has(f.line)) skipped++; else byLine.set(f.line, f); });
  const out = [];
  lines.forEach((ln, i) => {
    const f = byLine.get(i + 1);
    out.push(f && ln === f.raw ? f.patch : ln);
  });
  const eol = /\r\n/.test(code) ? "\r\n" : "\n";
  return { code:out.join(eol), applied:byLine.size, skipped };
}

/* line-level diff of a single finding: original line → fixed lines */
export function diffLines(f){
  const minus = [f.raw.replace(/\s+$/, "")];
  const plus = f.patch.split(/\r?\n/).map(s => s.replace(/\s+$/, ""));
  return { minus, plus };
}

const LEVEL = { HIGH:"error", MEDIUM:"warning", LOW:"note" };

/* SARIF 2.1.0 — the format GitHub code scanning and most security tools import */
export function buildSarif(scan, version){
  const used = [...new Set(scan.findings.map(f => f.ruleId))];
  const rules = used.map(id => {
    const r = RULES.find(x => x.id === id);
    return {
      id:r.id, name:r.en.replace(/[^A-Za-z0-9]+/g, ""),
      shortDescription:{ text:r.en }, fullDescription:{ text:r.why_en },
      help:{ text:r.fix_en, markdown:`**Fix:** ${r.fix_en}\n\n**Arabic:** ${r.fix_ar}` },
      defaultConfiguration:{ level:LEVEL[r.severity] },
      properties:{ tags:["security", r.cwe, r.owasp.split(" — ")[0]], "security-severity":r.severity === "HIGH" ? "8.0" : r.severity === "MEDIUM" ? "5.5" : "3.0" }
    };
  });
  return {
    $schema:"https://json.schemastore.org/sarif-2.1.0.json",
    version:"2.1.0",
    runs:[{
      tool:{ driver:{ name:"CodeShield", version, informationUri:"https://codeshield-app.github.io", rules } },
      results:scan.findings.map(f => ({
        ruleId:f.ruleId, ruleIndex:used.indexOf(f.ruleId), level:LEVEL[f.severity],
        message:{ text:f.why_en + (f.flow ? ` (Untrusted data from line ${f.flow.sourceLine} via '${f.flow.var}'.)` : "") },
        locations:[{ physicalLocation:{
          artifactLocation:{ uri:f.file || "snippet" + extFor(f.lang) },
          region:{ startLine:f.line, snippet:{ text:f.snippet } }
        } }],
        ...(f.flow ? { codeFlows:[{ threadFlows:[{ locations:[
          { location:{ physicalLocation:{ artifactLocation:{ uri:f.file || "snippet" + extFor(f.lang) }, region:{ startLine:f.flow.sourceLine } }, message:{ text:"untrusted input" } } },
          { location:{ physicalLocation:{ artifactLocation:{ uri:f.file || "snippet" + extFor(f.lang) }, region:{ startLine:f.line } }, message:{ text:"dangerous use" } } }
        ] }] }] } : {}),
        fixes:f.patch && f.patch !== f.raw ? [{ description:{ text:f.fix_en }, artifactChanges:[{
          artifactLocation:{ uri:f.file || "snippet" + extFor(f.lang) },
          replacements:[{ deletedRegion:{ startLine:f.line, endLine:f.line }, insertedContent:{ text:f.patch + "\n" } }]
        }] }] : undefined,
        properties:{ cwe:f.cwe, verification:f.verify ? f.verify.status : "test_generated_not_run" }
      }))
    }]
  };
}

export function extFor(lang){
  return { python:".py", javascript:".js", php:".php", ruby:".rb", shell:".sh" }[lang] || ".txt";
}
