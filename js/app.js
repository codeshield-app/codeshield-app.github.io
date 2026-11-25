/* CodeShield — user interface. */
import { RULES } from "./rules.js";
import { ENGINE_VERSION, detectLanguage, scanCode, verifyFinding, summarize, securityScore, langFromPath } from "./engine.js";
import { db, toRecord } from "./db.js";
import { fetchRepo } from "./github.js";
import { printReport } from "./report.js";
import { SAMPLES } from "./samples.js";
import { runBenchmark, CASES } from "./benchmark.js";
import { applyFixes, diffLines, buildSarif, extFor } from "./export.js";
import { loadProgress, onProgress, track, setName, progress, levelOf } from "./progress.js";
import { kv } from "./db.js";
import { initAcademy } from "./academy.js";
import { ATTACKS } from "./attacks.js";
import { initBooth } from "./booth.js";

/* ---------------- state ---------------- */
const state = { lang:"ar", theme:"dark", scans:{ scan:null, repo:null }, filter:{ scan:{ sev:"ALL", q:"" }, repo:{ sev:"ALL", q:"" } } };
const $ = id => document.getElementById(id);
const T = (en, ar) => state.lang === "ar" ? ar : en;
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c]));
const store = {
  get:k => { try { return localStorage.getItem("codeshield-" + k); } catch (e) { return null; } },
  set:(k, v) => { try { localStorage.setItem("codeshield-" + k, v); } catch (e) {} }
};

/* ---------------- i18n ---------------- */
function applyI18n(){
  document.querySelectorAll("[data-en]").forEach(el => {
    if (el.dataset.ar === undefined) el.dataset.ar = el.innerHTML;
    el.innerHTML = state.lang === "ar" ? el.dataset.ar : el.dataset.en;
  });
  document.querySelectorAll("[data-ph-en]").forEach(el => {
    if (el.dataset.phAr === undefined) el.dataset.phAr = el.placeholder;
    el.placeholder = state.lang === "ar" ? el.dataset.phAr : el.dataset.phEn;
  });
  document.querySelectorAll("[data-aria-en]").forEach(el => {
    if (el.dataset.ariaAr === undefined) el.dataset.ariaAr = el.getAttribute("aria-label") || "";
    el.setAttribute("aria-label", state.lang === "ar" ? el.dataset.ariaAr : el.dataset.ariaEn);
  });
}
document.addEventListener("click", e => {
  const s = e.target.closest(".skip-link"); if (!s) return;
  e.preventDefault(); document.querySelector("main")?.focus();
});
function setLang(lang){
  state.lang = lang; store.set("lang", lang);
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  $("langBtn").textContent = lang === "ar" ? "EN" : "ع";
  applyI18n();
  rerenderAll();
  if (tour.el) tourRender();
}
function setTheme(theme){
  state.theme = theme; store.set("theme", theme);
  document.body.classList.toggle("light", theme === "light");
}

/* ---------------- navigation ---------------- */
const SCREENS = ["home", "scanner", "github", "learn", "dashboard", "rules", "checklist", "about"];
function go(screen, push = true){
  if (!SCREENS.includes(screen)) screen = "home";
  document.querySelectorAll(".screen").forEach(s => s.classList.toggle("active", s.id === screen));
  document.querySelectorAll(".nav-btn").forEach(b => b.classList.toggle("active", b.dataset.go === screen));
  $("nav").classList.remove("open");
  if (push && location.hash !== "#" + screen) history.pushState(null, "", "#" + screen);
  if (screen === "dashboard") renderDashboard();
  if (screen === "learn" && academy) academy.render();
  if (screen === "checklist") renderChecklist();
  window.scrollTo({ top:0 });
}

let toastTimer, booth = null;
function toast(msg){
  const el = $("toast"); el.textContent = msg; el.classList.add("show");
  clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.remove("show"), 2800);
}

/* ---------------- shared rendering ---------------- */
const sevLabel = s => T(s, { HIGH:"عالية", MEDIUM:"متوسطة", LOW:"منخفضة" }[s]);
const ruleName = r => T(r.en, r.ar);

function ring(score){
  const c = 2 * Math.PI * 28, off = c * (1 - score / 100);
  const col = score >= 80 ? "var(--success)" : score >= 50 ? "var(--warning)" : "var(--danger)";
  return `<div class="ring"><svg viewBox="0 0 66 66"><circle class="bg" cx="33" cy="33" r="28" fill="none" stroke-width="6"/>
    <circle class="fg" cx="33" cy="33" r="28" fill="none" stroke-width="6" stroke-linecap="round" stroke="${col}" stroke-dasharray="${c}" stroke-dashoffset="${off}"/></svg><b>${score}</b></div>`;
}

function renderSummary(el, scan){
  const s = scan ? scan.summary : { total:0, HIGH:0, MEDIUM:0, LOW:0, verified:0 };
  el.innerHTML = `
    <div class="sum score" title="${T("Approximate score: open findings lower it, verified fixes restore it.", "مؤشر تقريبي: الثغرات المفتوحة تخفضه، والإصلاحات المُتحقَّقة ترفعه.")}">${scan ? ring(scan.score) : ring(100)}<div class="k">${T("Security score", "مؤشر الأمان")}</div></div>
    <div class="sum"><div class="v">${scan ? scan.lines : 0}</div><div class="k">${T("Lines scanned", "أسطر مفحوصة")}</div></div>
    <div class="sum high"><div class="v">${s.HIGH}</div><div class="k">${T("High", "عالية")}</div></div>
    <div class="sum med"><div class="v">${s.MEDIUM + s.LOW}</div><div class="k">${T("Medium / low", "متوسطة / منخفضة")}</div></div>
    <div class="sum ok"><div class="v">${s.verified}</div><div class="k">${T("Fixes verified", "إصلاحات مُتحقَّقة")}</div></div>`;
}

function vChip(f){
  if (!f.verify) return `<span class="chip vstate">${T("Test generated", "تم توليد الاختبار")}</span>`;
  return f.verify.status === "verified"
    ? `<span class="chip vstate verified">✓ ${T("Fix verified", "تم التحقق")}</span>`
    : `<span class="chip vstate failed">✗ ${T("Not verified", "لم يتحقق")}</span>`;
}

const REASONS = {
  ok:["Recorded: the check failed on the original and passed on the fix. Fix verified.", "مُسجَّل: فشل الفحص على الأصل ونجح على الإصلاح. تم التحقق من الإصلاح."],
  not_reproduced:["Could not reproduce the flaw on the original line, so there is nothing to prove.", "تعذّر إعادة إنتاج الثغرة على السطر الأصلي، فلا يوجد ما يُثبَت."],
  unchanged:["The fix is empty or identical to the vulnerable line.", "الإصلاح فارغ أو مطابق للسطر المصاب."],
  still_vulnerable:["The same flaw is still detected in the fixed code.", "الثغرة نفسها ما زالت موجودة في الكود المعدَّل."],
  new_issue:["The fix introduces a new issue: ", "الإصلاح أدخل ثغرة جديدة: "]
};

function labHTML(f){
  const v = f.verify, e0 = v && v.evidence[0], e1 = v && v.evidence[1];
  const s1 = !v ? "" : e0.result === "FAIL" ? "red" : "";
  const s2 = !v ? "" : e1.result === "PASS" ? "green" : "red";
  const st1 = !v ? T("not run yet", "لم يُشغَّل بعد") : e0.result === "FAIL" ? T("✗ failed — flaw reproduced", "✗ فشل — الثغرة موجودة فعلًا") : T("passed — not reproduced", "نجح — لم تظهر الثغرة");
  const st2 = !v ? T("not run yet", "لم يُشغَّل بعد") : e1.result === "PASS" ? T("✓ passed — flaw closed", "✓ نجح — الثغرة انسدّت")
    : e1.result === "NOT_RUN" ? T("not run — nothing changed", "لم يُشغَّل — لا يوجد تعديل") : T("✗ failed — still vulnerable", "✗ فشل — ما زال مصابًا");
  const st3 = !v ? T("waiting for both checks", "بانتظار الفحصين") : v.status === "verified" ? T("✓ fix verified", "✓ تم التحقق من الإصلاح") : T("✗ not verified", "✗ لم يتحقق");
  const reason = v ? T(REASONS[v.reason][0], REASONS[v.reason][1]) + (v.reason === "new_issue" ? v.newRules.join(", ") : "") : "";
  const ev = v ? v.evidence.map(e => e.step === "original"
      ? `[${e.t}] original · rule ${e.rule} on the vulnerable line → <span class="${e.result === "FAIL" ? "bad" : ""}">${e.result}</span>`
      : `[${e.t}] patched  · all ${e.rules} rules on the fixed code → <span class="${e.result === "PASS" ? "ok" : "bad"}">${e.result}</span>${e.hits.length ? " (" + e.hits.join(", ") + ")" : ""}`).join("\n") : "";
  return `
    <div class="box lab">
      <div class="label">${T("PROOF LAB — verify the fix", "مختبر الإثبات — تحقّق من الإصلاح")}</div>
      <p>${f.autoPatch ? T("CodeShield drafted the fixed code below. Edit it if you like, then run the verification.", "جهّز كودشيلد الكود المعدَّل بالأسفل. عدّله إن أردت، ثم شغّل التحقق.")
                       : T("No safe automatic rewrite for this pattern — write your fix below, then run the verification.", "لا يوجد إصلاح تلقائي آمن لهذا النمط — اكتب إصلاحك بالأسفل ثم شغّل التحقق.")}</p>
      <textarea class="patch-input" data-patch="${f.id}" spellcheck="false" aria-label="${T("Fixed code", "الكود المعدَّل")}">${esc(f.patch)}</textarea>
      <div class="row">
        <button class="btn primary sm" data-action="verify" data-fid="${f.id}">${T("▶ Run verification", "▶ شغّل التحقق")}</button>
        ${f.autoPatch ? `<button class="btn sm" data-action="reset" data-fid="${f.id}">${T("Reset fix", "استرجع الإصلاح المقترح")}</button>` : ""}
        <button class="btn sm" data-action="copy-fix" data-fid="${f.id}">📋 ${T("Copy fixed code", "انسخ الكود المعدَّل")}</button>
      </div>
      <div class="proof-steps">
        <div class="pstep ${s1}"><b>1 · ${T("Check on original", "الفحص على الأصل")}</b><span class="st">${st1}</span></div>
        <div class="pstep ${s2}"><b>2 · ${T("Check on fixed code", "الفحص على الإصلاح")}</b><span class="st">${st2}</span></div>
        <div class="pstep ${v ? (v.status === "verified" ? "green" : "red") : "gen"}"><b>3 · ${T("Fix status", "حالة الإصلاح")}</b><span class="st">${st3}</span></div>
      </div>
      ${v ? `<p style="margin-top:8px">${esc(reason)}</p><div class="evidence ltr">${ev}</div>` : ""}
      ${f.patch.trim() !== f.raw.trim() ? (() => { const d = diffLines(f); return `
        <div class="code-label">${T("Change (diff)", "التغيير (Diff)")}</div>
        <div class="diff ltr">${d.minus.map(x => `<div class="del">- ${esc(x)}</div>`).join("")}${d.plus.map(x => `<div class="add">+ ${esc(x)}</div>`).join("")}</div>`; })() : ""}
      <p style="margin-top:8px;font-size:12px">${T("Evidence type: a rule re-check of the original and the fixed code, recorded with a timestamp. The unit test below is a separate file to run in your own project.",
        "نوع الدليل: إعادة فحص بالقواعد للكود الأصلي والمعدَّل، مُسجَّلة بتوقيت. اختبار الوحدة بالأسفل ملف منفصل يُشغَّل داخل مشروعك.")}</p>
    </div>`;
}

/* "How would an attacker use this?" — a classic teaching example per rule */
function attackHTML(f){
  const a = ATTACKS[f.ruleId]; if (!a) return "";
  return `<div class="box attack">
    <div class="label">⚔ ${T("How would an attacker use this?", "كيف يستغلها المهاجم؟")}</div>
    <div class="attack-in"><span>${T("Attacker sends", "المهاجم يرسل")}</span><code class="ltr">${esc(a.input)}</code></div>
    <p>${esc(T(a.en, a.ar))}</p>
    <div class="attack-note">${T("Teaching example — never test on systems you don't own.", "مثال تعليمي — لا تجرّبه أبدًا على أنظمة ما تملكها.")}</div>
  </div>`;
}

/* severity filter + search over a findings list */
const SEVS = ["ALL", "HIGH", "MEDIUM", "LOW"];
function applyFilter(list, target){
  const f = state.filter[target], q = f.q.trim().toLowerCase();
  return list.filter(x => (f.sev === "ALL" || x.severity === f.sev) &&
    (!q || [x.name_en, x.name_ar, x.cwe, x.ruleId, x.file, x.snippet].some(v => String(v || "").toLowerCase().includes(q))));
}
function filterBar(target, all, shown){
  if (all.length < 2) return "";
  const f = state.filter[target], n = s => s === "ALL" ? all.length : all.filter(x => x.severity === s).length;
  return `<div class="filterbar">
    <div class="sev-chips">${SEVS.filter(s => s === "ALL" || n(s)).map(s => `<button class="fchip ${s.toLowerCase()} ${f.sev === s ? "on" : ""}" data-action="filter-sev" data-target="${target}" data-sev="${s}">${s === "ALL" ? T("All", "الكل") : sevLabel(s)} <b>${n(s)}</b></button>`).join("")}</div>
    <input class="fsearch" type="search" data-filter-q="${target}" value="${esc(f.q)}" placeholder="${T("Search: name, CWE, file…", "ابحث: اسم الثغرة، CWE، الملف…")}" aria-label="${T("Search findings", "ابحث في النتائج")}">
    ${shown.length !== all.length ? `<span class="note">${T(`Showing ${shown.length} of ${all.length}`, `يعرض ${shown.length} من ${all.length}`)}</span>` : ""}
  </div>`;
}
const filterEmpty = () => `<div class="empty"><div class="big">⌕</div>${T("No findings match this filter.", "ما فيه نتائج تطابق هذا الفلتر.")}</div>`;

/* "fix these first": the three most severe findings that are not verified yet */
function priorityHTML(scan){
  const open = sortF(scan.findings.filter(f => !(f.verify && f.verify.status === "verified")));
  if (!scan.findings.length) return "";
  if (!open.length) return `<div class="priority done">🎉 ${T("Every fix in this scan is verified.", "كل الإصلاحات في هذا الفحص مُتحقَّق منها.")}</div>`;
  return `<div class="priority">
    <div class="label">🎯 ${T("Fix these first", "ابدأ بهذول أول")}</div>
    <ol>${open.slice(0, 3).map(f => `<li><button class="prio-item" data-action="jump" data-fid="${f.id}">
      <span class="chip ${f.severity.toLowerCase()}">${sevLabel(f.severity)}</span>
      <span class="prio-name">${esc(T(f.name_en, f.name_ar))}</span>
      <span class="prio-where${f.file ? " ltr" : ""}">${f.file ? esc(f.file) + ":" + f.line : T("line ", "سطر ") + f.line}</span></button></li>`).join("")}</ol>
    ${open.length > 3 ? `<div class="note">${T(`+ ${open.length - 3} more after these`, `+ ${open.length - 3} غيرها بعدهم`)}</div>` : ""}
  </div>`;
}
const rerenderTarget = t => t === "repo" ? renderRepo() : renderScanFindings();

function findingHTML(f, open){
  return `
  <div class="finding${open ? " open" : ""}" data-fid="${f.id}">
    <button class="finding-head" data-action="toggle" data-fid="${f.id}" aria-expanded="${!!open}">
      <span class="finding-title">${esc(T(f.name_en, f.name_ar))}</span>
      <span class="finding-meta">
        <span class="chip ${f.severity.toLowerCase()}">${sevLabel(f.severity)}</span>
        <span class="chip meta">${f.cwe}</span>
        <span class="chip line">${T("line", "سطر")} ${f.line}</span>
        ${f.flow ? `<span class="chip flow">⇢ ${T("data flow", "تدفّق بيانات")}</span>` : ""}
        ${vChip(f)}
      </span>
    </button>
    <div class="finding-body">
      ${f.file ? `<div class="file-path">${esc(f.file)}:${f.line}</div>` : ""}
      ${f.flow ? `
        <div class="flow-box">
          <div class="label">${T("Data flow across lines", "تدفّق البيانات عبر الأسطر")}</div>
          <div class="flow-step"><span class="chip line">${T("line", "سطر")} ${f.flow.sourceLine}</span><span>${T("untrusted input enters", "يدخل مدخل غير موثوق")}</span></div>
          <div class="finding-code src">${esc(f.flow.sourceCode)}</div>
          <div class="flow-arrow">↓ <span class="ltr">${esc(f.flow.var)}</span></div>
          <div class="flow-step"><span class="chip line">${T("line", "سطر")} ${f.line}</span><span>${T("reaches a dangerous call", "يصل إلى استدعاء خطِر")}</span></div>
        </div>` : `<div class="code-label">${T("Vulnerable line", "السطر المصاب")}</div>`}
      <div class="finding-code">${esc(f.snippet)}</div>
      <p class="why">${esc(T(f.why_en, f.why_ar))}</p>
      <button class="btn soft sm lesson-link" data-go="learn" data-ac="open" data-rule="${f.ruleId}">📘 ${T("Learn this vulnerability in the Academy", "تعلّم هذه الثغرة في الأكاديمية")}</button>
      ${attackHTML(f)}
      <div class="box fix"><div class="label">${T("Suggested fix", "الإصلاح المقترح")}</div><p>${esc(T(f.fix_en, f.fix_ar))}</p></div>
      ${labHTML(f)}
      <div class="box proof">
        <div class="label">${T("Generated unit test — not run here", "اختبار وحدة مُولَّد — لا يُشغَّل هنا")}</div>
        <p style="margin-bottom:8px">${T("Written to fail on the vulnerable version and pass after the fix, for your own test suite. Rename the function under test to match your code.",
          "مكتوب ليفشل على النسخة المصابة وينجح بعد الإصلاح، لتضيفه إلى اختبارات مشروعك. غيّر اسم الدالة المُختبَرة لتطابق كودك.")}</p>
        <div class="code test ltr">${esc(f.proof)}</div>
      </div>
      <div class="note" style="margin-top:8px" dir="ltr">${esc(f.owasp)}</div>
    </div>
  </div>`;
}

const ORDER = { HIGH:0, MEDIUM:1, LOW:2 };
const sortF = arr => [...arr].sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || (a.file || "").localeCompare(b.file || "") || a.line - b.line);

function openIds(container){ return new Set([...container.querySelectorAll(".finding.open")].map(e => Number(e.dataset.fid))); }

function renderScanFindings(){
  const box = $("scanFindings"), scan = state.scans.scan;
  renderSummary($("scanSummary"), scan);
  if (!scan){ box.innerHTML = `<div class="empty"><div class="big">⌘</div>${T("Paste code, or load a sample, then press Scan code.", "الصق كودًا، أو حمّل مثالًا، ثم اضغط «افحص الكود».")}</div>`; return; }
  if (!scan.findings.length){ box.innerHTML = `<div class="empty"><div class="big">✓</div>${T("No flaw matched the active rules.<br>Remember: the engine works line by line.", "لم تطابق أي ثغرة القواعد الفعّالة.<br>تذكّر: يعمل المحرك سطرًا بسطر.")}</div>`; return; }
  const open = openIds(box), first = !open.size;
  const shown = applyFilter(scan.findings, "scan");
  box.innerHTML = priorityHTML(scan) + shareBar(scan) + filterBar("scan", scan.findings, shown) + fixBar("scan", null, scan) + `<div class="findings">${shown.length ? sortF(shown).map((f, i) => findingHTML(f, first ? i === 0 : open.has(f.id))).join("") : filterEmpty()}</div>`;
}

/* "download the fixed file" strip — active once at least one fix is verified */
function fixBar(target, file, scan){
  const list = scan.findings.filter(f => (file === null || f.file === file));
  const ok = list.filter(f => f.verify && f.verify.status === "verified").length;
  return `<div class="fixbar">
    <span class="note">${ok ? T(`${ok} of ${list.length} fixes verified and ready to apply.`, `${ok} من ${list.length} إصلاحات مُتحقَّقة وجاهزة للتطبيق.`)
                            : T("Verify fixes to download a fixed file.", "بعد التحقق من الإصلاحات يمكن تنزيل ملف مُصلَّح.")}</span>
    <button class="btn soft sm" data-action="download-fixed" data-target="${target}" ${file !== null ? `data-file="${esc(file)}"` : ""} ${ok ? "" : "disabled"}>⬇ ${T("Download fixed file", "نزّل الملف المُصلَّح")}</button>
  </div>`;
}

function renderRepo(){
  const el = $("repoResult"), scan = state.scans.repo;
  if (!scan){ el.innerHTML = ""; return; }
  const openFiles = new Set([...el.querySelectorAll("details[open]")].map(d => d.dataset.file));
  const open = openIds(el);
  const byFile = {};
  const shown = applyFilter(scan.findings, "repo");
  sortF(shown).forEach(f => (byFile[f.file] = byFile[f.file] || []).push(f));
  const files = Object.keys(byFile).sort((a, b) => byFile[b].filter(f => f.severity === "HIGH").length - byFile[a].filter(f => f.severity === "HIGH").length || byFile[b].length - byFile[a].length);
  el.innerHTML = `
    <div class="card card-pad" style="margin-bottom:14px">
      <div class="repo-head">
        <div><div class="eyebrow">${scan.source === "github" ? T("REPOSITORY", "المستودع") : T("UPLOADED FILES", "ملفات مرفوعة")}</div>
        <h3 class="ltr">${scan.url ? `<a href="${esc(scan.url)}" target="_blank" rel="noopener noreferrer">${esc(scan.label)}</a> <span class="muted" style="font-size:13px">@${esc(scan.branch)}</span>` : esc(scan.label)}</h3>
        <p class="note">${scan.files} ${T("files scanned", "ملف مفحوص")} · ${scan.lines.toLocaleString()} ${T("lines", "سطر")} · ${files.length} ${T("files with findings", "ملف فيه ثغرات")}${scan.truncated ? ` · ${T(`first ${scan.files} of ${scan.totalCandidates} files`, `أول ${scan.files} من ${scan.totalCandidates} ملف`)}` : ""}</p></div>
        <div class="row">
          <button class="btn primary sm" data-action="verify-all" data-target="repo">${T("Verify all fixes", "تحقّق من كل الإصلاحات")}</button>
          <button class="btn sm" data-action="pdf" data-target="repo">${T("PDF report", "تقرير PDF")}</button>
          <button class="btn sm" data-action="sarif" data-target="repo">SARIF</button>
          <button class="btn sm" data-action="json" data-target="repo">JSON</button>
        </div>
      </div>
    </div>
    <div class="summary" id="repoSummary"></div>
    ${scan.findings.length ? priorityHTML(scan) + filterBar("repo", scan.findings, shown) : ""}
    ${files.length ? files.map((file, i) => `
      <details class="file-group" data-file="${esc(file)}" ${openFiles.has(file) || (!openFiles.size && i === 0) ? "open" : ""}>
        <summary><span class="file-path" style="margin:0">${esc(file)}</span>
          <span class="finding-meta">${["HIGH", "MEDIUM", "LOW"].map(s => { const n = byFile[file].filter(f => f.severity === s).length; return n ? `<span class="chip ${s.toLowerCase()}">${n} ${sevLabel(s)}</span>` : ""; }).join("")}</span></summary>
        ${fixBar("repo", file, scan)}
        <div class="findings">${byFile[file].map(f => findingHTML(f, open.has(f.id))).join("")}</div>
      </details>`).join("")
    : scan.findings.length ? filterEmpty() : `<div class="card empty"><div class="big">✓</div>${T("No flaw matched the active rules in this repository.", "لم تطابق أي ثغرة القواعد الفعّالة في هذا المستودع.")}</div>`}`;
  renderSummary($("repoSummary"), scan);
}

/* ---------------- scans ---------------- */
function buildScan(source, label, findings, lines, extra = {}){
  const scan = { source, label, findings, lines, files:1, engine:ENGINE_VERSION, ...extra };
  refreshScan(scan);
  return scan;
}
function refreshScan(scan){
  scan.summary = summarize(scan.findings);
  scan.score = securityScore(scan.findings, scan.lines);
}
async function persist(scan){
  try {
    const rec = toRecord(scan);
    if (scan.dbId){ rec.id = scan.dbId; rec.at = scan.dbAt; await db.put(rec); }
    else { scan.dbId = await db.add(rec); scan.dbAt = rec.at; }
  } catch (e) { /* history is a convenience; scanning still works without it */ }
}
let persistTimer;
const persistSoon = scan => { clearTimeout(persistTimer); persistTimer = setTimeout(() => persist(scan), 400); };

function runScan(){
  const code = $("codeInput").value;
  if (!code.trim()){ toast(T("Paste some code first.", "الصق كودًا أولًا.")); return; }
  const lang = detectLanguage(code, $("langHint").value);
  state.filter.scan = { sev:"ALL", q:"" };
  const res = scanCode(code, lang);
  const names = { python:"Python", javascript:"JavaScript", php:"PHP", ruby:"Ruby", shell:"Shell" };
  state.scans.scan = buildScan("paste", `${names[lang]} · ${res.lineCount} ${T("lines", "سطر")}`, res.findings, res.lineCount, { lang, code });
  $("scanFindings").innerHTML = "";
  renderScanFindings();
  persist(state.scans.scan);
  track("scan");
  const s = state.scans.scan.summary;
  toast(s.total ? T(`${s.total} finding(s) — ${s.HIGH} high.`, `${s.total} ثغرة — منها ${s.HIGH} عالية الخطورة.`) : T("No issues matched the active rules.", "لم تطابق أي ثغرة القواعد الفعّالة."));
}

async function runRepo(){
  const input = $("repoInput").value.trim();
  if (!input){ toast(T("Paste a repository link first.", "الصق رابط المستودع أولًا.")); return; }
  const btn = $("repoBtn"), bar = $("repoBar"), status = $("repoStatus");
  btn.disabled = true; bar.style.width = "3%";
  try {
    const repo = await fetchRepo(input, p => {
      if (p.phase === "meta") status.textContent = T("Reading repository…", "جارٍ قراءة المستودع…");
      else { bar.style.width = Math.round(p.done / p.total * 100) + "%"; status.textContent = `${T("Downloading", "تنزيل")} ${p.done}/${p.total} · ${p.path}`; }
    });
    const s = scanFiles("github", `${repo.owner}/${repo.repo}`, repo.files,
      { url:repo.url, branch:repo.branch, truncated:repo.truncated, totalCandidates:repo.totalCandidates });
    bar.style.width = "100%";
    status.textContent = T(`Done: ${repo.files.length} files, ${s.findings.length} findings. Nothing was uploaded.`, `تم: ${repo.files.length} ملف، ${s.findings.length} ثغرة. لم يُرفع أي شيء.`);
  } catch (e) {
    bar.style.width = "0";
    const msg = {
      bad_url:["That doesn't look like a GitHub repository link.", "هذا لا يبدو رابط مستودع GitHub."],
      not_found:["Repository not found, or it is private.", "المستودع غير موجود أو خاص."],
      private:["Private repositories are not supported.", "المستودعات الخاصة غير مدعومة."],
      rate_limited:["GitHub's hourly limit was reached for this network. Try again later.", "وصلت شبكتك للحد الساعي في GitHub. حاول لاحقًا."]
    }[e.message] || ["Could not read the repository (" + e.message + ").", "تعذّرت قراءة المستودع (" + e.message + ")."];
    status.textContent = T(msg[0], msg[1]);
  } finally { btn.disabled = false; }
}

/* scan a set of files { path, lang, code } (GitHub or local upload) */
function scanFiles(source, label, files, extra = {}){
  let findings = [], lines = 0;
  const codes = {};
  files.forEach(f => { codes[f.path] = f.code; const r = scanCode(f.code, f.lang, f.path); findings = findings.concat(r.findings); lines += r.lineCount; });
  state.filter.repo = { sev:"ALL", q:"" };
  state.scans.repo = buildScan(source, label, findings, lines, { files:files.length, codes, ...extra });
  $("repoResult").innerHTML = "";
  renderRepo();
  persist(state.scans.repo);
  track("project_scan");
  $("repoResult").scrollIntoView({ behavior:"smooth", block:"start" });
  return state.scans.repo;
}

/* local files: drag & drop or file / folder picker. Read with FileReader — nothing leaves the browser. */
const MAX_LOCAL = 300, MAX_LOCAL_BYTES = 500 * 1024;
async function scanLocal(fileList){
  const all = [...fileList].map(f => ({ f, path:f.webkitRelativePath || f.name }));
  const picked = all.filter(x => langFromPath(x.path) && x.f.size <= MAX_LOCAL_BYTES && !/(^|\/)(node_modules|vendor|dist|build|\.git|venv|\.venv|__pycache__)\//.test(x.path)).slice(0, MAX_LOCAL);
  if (!picked.length){ toast(T("No supported source files (.py .js .php .rb .sh …) were found.", "لم يُعثر على ملفات برمجية مدعومة (‎.py .js .php .rb .sh‎ …).")); return; }
  $("repoStatus").textContent = T(`Reading ${picked.length} files locally…`, `قراءة ${picked.length} ملف محليًا…`);
  const files = await Promise.all(picked.map(async x => ({ path:x.path, lang:langFromPath(x.path), code:await x.f.text() })));
  const root = picked[0].path.includes("/") ? picked[0].path.split("/")[0] : (picked.length === 1 ? picked[0].path : T(`${picked.length} files`, `${picked.length} ملفات`));
  const s = scanFiles("upload", root, files);
  $("repoStatus").textContent = T(`Done: ${files.length} files, ${s.findings.length} findings. Read locally — nothing was uploaded.`, `تم: ${files.length} ملف، ${s.findings.length} ثغرة. قُرئت محليًا — لم يُرفع أي شيء.`);
}

function downloadText(text, name, type = "text/plain"){
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type:type + ";charset=utf-8" }));
  a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

function refreshFixBars(){
  document.querySelectorAll(".fixbar").forEach(bar => {
    const btn = bar.querySelector("[data-action='download-fixed']");
    const target = btn.dataset.target, file = btn.dataset.file === undefined ? null : btn.dataset.file;
    const scan = state.scans[target]; if (!scan) return;
    const tmp = document.createElement("div"); tmp.innerHTML = fixBar(target, file, scan).trim();
    bar.replaceWith(tmp.firstChild);
  });
}

/* stable key so the same fix only earns XP once */
const fkey = (scan, f) => `${scan.source}|${scan.source === "paste" ? f.raw.trim() : scan.label + "|" + f.file}|${f.line}|${f.ruleId}`;

/* ---------------- finding interactions ---------------- */
function locate(fid){
  for (const key of ["scan", "repo"]){
    const scan = state.scans[key];
    const f = scan && scan.findings.find(x => x.id === fid);
    if (f) return { scan, key, f };
  }
  return null;
}
function rerenderFinding(fid){
  const hit = locate(fid); if (!hit) return;
  document.querySelectorAll(`.finding[data-fid="${fid}"]`).forEach(el => {
    const tmp = document.createElement("div"); tmp.innerHTML = findingHTML(hit.f, el.classList.contains("open")).trim();
    el.replaceWith(tmp.firstChild);
  });
  refreshScan(hit.scan);
  renderSummary(hit.key === "scan" ? $("scanSummary") : $("repoSummary"), hit.scan);
  refreshFixBars();
  persistSoon(hit.scan);
}

document.addEventListener("click", e => {
  const goEl = e.target.closest("[data-go]");
  if (goEl){ go(goEl.dataset.go); return; }
  const a = e.target.closest("[data-action]");
  if (!a) return;
  const fid = Number(a.dataset.fid), act = a.dataset.action;
  if (act === "toggle"){
    const el = a.closest(".finding"); el.classList.toggle("open"); a.setAttribute("aria-expanded", el.classList.contains("open"));
  } else if (act === "verify"){
    const hit = locate(fid); if (!hit) return;
    const ta = document.querySelector(`[data-patch="${fid}"]`);
    const v = verifyFinding(hit.f, ta ? ta.value : undefined);
    if (v.status === "verified") track("verify", { key:fkey(hit.scan, hit.f) });
    rerenderFinding(fid);
    toast(v.status === "verified" ? T("Fix verified ✓", "تم التحقق من الإصلاح ✓") : T("Not verified — see the evidence.", "لم يتحقق الإصلاح — راجع الدليل."));
  } else if (act === "share-scan"){
    shareScan();
  } else if (act === "rule-link"){
    activeRule = a.dataset.ruleId; go("rules"); renderRules(); $("ruleDetail").scrollIntoView({ behavior:"smooth", block:"start" });
  } else if (act === "check-reset"){
    ticks = {}; store.set("checklist", "{}"); renderChecklist();
  } else if (act === "copy-fix"){
    const ta = document.querySelector(`[data-patch="${fid}"]`); if (!ta) return;
    const done = () => toast(T("Fixed code copied ✓", "تم نسخ الكود المعدَّل ✓"));
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(ta.value).then(done, () => { ta.select(); document.execCommand("copy"); done(); });
    else { ta.select(); document.execCommand("copy"); done(); }
  } else if (act === "filter-sev"){
    state.filter[a.dataset.target].sev = a.dataset.sev; rerenderTarget(a.dataset.target);
  } else if (act === "jump"){
    const hit = locate(fid); if (!hit) return;
    const t = hit.key, fl = state.filter[t];
    if (!applyFilter([hit.f], t).length){ fl.sev = "ALL"; fl.q = ""; rerenderTarget(t); }
    const el = document.querySelector(`.finding[data-fid="${fid}"]`); if (!el) return;
    const d = el.closest("details"); if (d) d.open = true;
    el.classList.add("open"); el.querySelector(".finding-head").setAttribute("aria-expanded", "true");
    el.scrollIntoView({ behavior:"smooth", block:"start" });
  } else if (act === "reset"){
    const hit = locate(fid); if (!hit) return;
    hit.f.patch = hit.f.autoPatch || hit.f.raw; hit.f.verify = null;
    rerenderFinding(fid);
  } else if (act === "verify-all"){
    const scan = state.scans[a.dataset.target];
    if (!scan || !scan.findings.length){ toast(T("Scan some code first.", "افحص كودًا أولًا.")); return; }
    scan.findings.forEach(f => { if (verifyFinding(f).status === "verified") track("verify", { key:fkey(scan, f) }); });
    refreshScan(scan);
    a.dataset.target === "scan" ? renderScanFindings() : renderRepo();
    persist(scan);
    toast(T(`${scan.summary.verified} of ${scan.summary.total} fixes verified.`, `تم التحقق من ${scan.summary.verified} من ${scan.summary.total} إصلاحات.`));
  } else if (act === "pdf"){
    const scan = state.scans[a.dataset.target];
    if (!scan){ toast(T("Nothing to export yet.", "لا توجد نتائج للتصدير بعد.")); return; }
    printReport(scan, state.lang);
    toast(T("Choose “Save as PDF” in the print window.", "اختر «حفظ كـ PDF» في نافذة الطباعة."));
  } else if (act === "json"){
    const scan = state.scans[a.dataset.target];
    if (!scan){ toast(T("Nothing to export yet.", "لا توجد نتائج للتصدير بعد.")); return; }
    downloadJSON(scanJSON(scan), "codeshield-report.json");
  } else if (act === "sarif"){
    const scan = state.scans[a.dataset.target];
    if (!scan){ toast(T("Nothing to export yet.", "لا توجد نتائج للتصدير بعد.")); return; }
    downloadText(JSON.stringify(buildSarif(scan, ENGINE_VERSION), null, 2), "codeshield.sarif", "application/sarif+json");
    toast(T("SARIF downloaded — import it into GitHub code scanning or any SARIF viewer.", "تم تنزيل SARIF — يمكن استيراده في GitHub Code Scanning أو أي عارض SARIF."));
  } else if (act === "download-fixed"){
    const scan = state.scans[a.dataset.target]; if (!scan) return;
    const file = a.dataset.file;
    const code = file ? scan.codes[file] : scan.code;
    const res = applyFixes(code, scan.findings.filter(f => file ? f.file === file : true));
    const base = file ? file.split("/").pop() : "codeshield-fixed" + extFor(scan.lang);
    downloadText(res.code, base.replace(/(\.[^.]+)?$/, m => ".fixed" + (m || "")));
    toast(T(`${res.applied} fix(es) applied${res.skipped ? `, ${res.skipped} skipped (same line)` : ""}.`, `طُبّق ${res.applied} إصلاح${res.skipped ? `، وتُرك ${res.skipped} (على نفس السطر)` : ""}.`));
  } else if (act === "run-bench"){
    renderBenchmark(true);
  } else if (act === "del-scan"){
    db.remove(Number(a.dataset.id)).then(renderDashboard);
  }
});

document.addEventListener("input", e => {
  const ta = e.target.closest("[data-patch]");
  if (ta){ const hit = locate(Number(ta.dataset.patch)); if (hit) hit.f.patch = ta.value; }
});

function scanJSON(scan){
  return {
    tool:"CodeShield", engine:"rule-based v" + scan.engine + " + proof lab",
    generated_at:new Date().toISOString(), source:scan.source, target:scan.label,
    lines_scanned:scan.lines, files_scanned:scan.files, security_score:scan.score,
    summary:{ total:scan.summary.total, high:scan.summary.HIGH, medium:scan.summary.MEDIUM, low:scan.summary.LOW, verified:scan.summary.verified },
    findings:scan.findings.map(f => ({
      rule:f.ruleId, cwe:f.cwe, owasp:f.owasp, severity:f.severity, file:f.file, line:f.line, snippet:f.snippet,
      data_flow:f.flow ? { variable:f.flow.var, source_line:f.flow.sourceLine } : undefined,
      explanation:f.why_en, suggested_fix:f.fix_en, patched_code:f.patch, verification_test:f.proof,
      verification:f.verify ? { status:f.verify.status, at:f.verify.at, evidence:f.verify.evidence } : { status:"test_generated_not_run" }
    }))
  };
}
function downloadJSON(obj, name){
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([JSON.stringify(obj, null, 2)], { type:"application/json" }));
  a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  toast(T("Downloaded.", "تم التنزيل."));
}

/* ---------------- dashboard ---------------- */
async function renderDashboard(){
  let rows = [];
  try { rows = await db.all(); } catch (e) {
    $("kpis").innerHTML = `<div class="card kpi" style="grid-column:1/-1">${T("This browser blocks local storage, so history is unavailable here.", "هذا المتصفح يمنع التخزين المحلي، لذلك السجل غير متاح هنا.")}</div>`;
    return;
  }
  $("scoreChart").innerHTML = scoreChartHTML(rows);
  const allF = rows.flatMap(r => r.findings);
  const verified = allF.filter(f => f.status === "verified").length;
  const avg = rows.length ? Math.round(rows.reduce((s, r) => s + (r.score || 0), 0) / rows.length) : 0;
  $("kpis").innerHTML = `
    <div class="card kpi"><div class="k">${T("Scans", "عدد الفحوصات")}</div><div class="v">${rows.length}</div></div>
    <div class="card kpi"><div class="k">${T("Findings", "الثغرات المكتشفة")}</div><div class="v" style="color:var(--danger)">${allF.length}</div></div>
    <div class="card kpi"><div class="k">${T("Fixes verified", "إصلاحات مُتحقَّقة")}</div><div class="v" style="color:var(--success)">${verified}</div></div>
    <div class="card kpi"><div class="k">${T("Average score", "متوسط مؤشر الأمان")}</div><div class="v">${rows.length ? avg : "—"}</div></div>`;

  const counts = {};
  allF.forEach(f => counts[f.rule] = (counts[f.rule] || 0) + 1);
  const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const max = top.length ? top[0][1] : 1;
  $("ruleBars").innerHTML = top.length ? top.map(([id, n]) => {
    const r = RULES.find(x => x.id === id);
    return `<div class="bar-row"><span class="name" title="${esc(ruleName(r))}">${esc(ruleName(r))}</span><span class="bar"><span style="width:${n / max * 100}%"></span></span><span class="num">${n}</span></div>`;
  }).join("") : `<div class="empty">${T("Run a scan to see statistics.", "شغّل فحصًا لتظهر الإحصائيات.")}</div>`;

  const sev = { HIGH:0, MEDIUM:0, LOW:0 }; allF.forEach(f => sev[f.severity]++);
  const tot = allF.length || 1;
  $("sevSplit").innerHTML = allF.length ? `
    <div><div class="note" style="margin-bottom:6px">${T("By severity", "حسب الخطورة")}</div>
      <div class="stack"><span style="width:${sev.HIGH / tot * 100}%;background:var(--danger)"></span><span style="width:${sev.MEDIUM / tot * 100}%;background:var(--warning)"></span><span style="width:${sev.LOW / tot * 100}%;background:var(--muted)"></span></div>
      <div class="legend" style="margin-top:8px"><span><i style="background:var(--danger)"></i>${T("High", "عالية")} ${sev.HIGH}</span><span><i style="background:var(--warning)"></i>${T("Medium", "متوسطة")} ${sev.MEDIUM}</span><span><i style="background:var(--muted)"></i>${T("Low", "منخفضة")} ${sev.LOW}</span></div></div>
    <div><div class="note" style="margin-bottom:6px">${T("Verification", "التحقق")}</div>
      <div class="stack"><span style="width:${verified / tot * 100}%;background:var(--success)"></span><span style="width:${(allF.length - verified) / tot * 100}%;background:var(--warning)"></span></div>
      <div class="legend" style="margin-top:8px"><span><i style="background:var(--success)"></i>${T("Verified", "مُتحقَّق")} ${verified}</span><span><i style="background:var(--warning)"></i>${T("Not yet verified", "لم يُتحقَّق بعد")} ${allF.length - verified}</span></div></div>`
    : `<div class="empty">${T("No data yet.", "لا توجد بيانات بعد.")}</div>`;

  $("histTable").innerHTML = rows.length ? `<table><thead><tr>
      <th>${T("Date", "التاريخ")}</th><th>${T("Source", "المصدر")}</th><th>${T("Target", "الهدف")}</th><th>${T("Lines", "الأسطر")}</th>
      <th>${T("Findings", "الثغرات")}</th><th>${T("High", "عالية")}</th><th>${T("Verified", "مُتحقَّق")}</th><th>${T("Score", "المؤشر")}</th><th></th></tr></thead><tbody>
    ${rows.map(r => `<tr>
      <td>${new Date(r.at).toLocaleString(state.lang === "ar" ? "ar-SA" : "en-GB", { dateStyle:"medium", timeStyle:"short" })}</td>
      <td>${r.source === "github" ? "GitHub" : r.source === "upload" ? T("Uploaded files", "ملفات مرفوعة") : T("Pasted code", "كود ملصوق")}</td>
      <td class="ltr src">${esc(r.label)}</td><td>${r.lines.toLocaleString()}</td>
      <td>${r.summary.total}</td><td style="color:var(--danger)">${r.summary.HIGH}</td>
      <td style="color:var(--success)">${r.findings.filter(f => f.status === "verified").length}</td><td><b>${r.score}</b></td>
      <td><button class="btn danger sm" data-action="del-scan" data-id="${r.id}">${T("Delete", "حذف")}</button></td></tr>`).join("")}
    </tbody></table>` : `<div class="empty"><div class="big">🗂️</div>${T("No scans yet. Every scan you run is saved here.", "لا توجد فحوصات بعد. كل فحص تشغّله يُحفظ هنا.")}</div>`;
}

/* ---------------- rules catalog ---------------- */
let activeRule = RULES[0].id;
function renderRules(){
  const q = ($("ruleFilter").value || "").toLowerCase();
  const list = RULES.filter(r => !q || [r.en, r.ar, r.cwe, r.owasp, r.id].join(" ").toLowerCase().includes(q));
  $("ruleList").innerHTML = list.map(r => `
    <button class="rule-card${r.id === activeRule ? " active" : ""}" data-rule="${r.id}">
      <div class="rule-top"><span class="rule-name">${esc(ruleName(r))}</span><span class="chip ${r.severity.toLowerCase()}">${sevLabel(r.severity)}</span></div>
      <div class="rule-sub">${r.cwe} · ${esc(r.owasp)}</div>
    </button>`).join("") || `<div class="empty">${T("No rule matches.", "لا توجد قاعدة مطابقة.")}</div>`;
  const r = RULES.find(x => x.id === activeRule);
  $("ruleDetail").innerHTML = `
    <div class="row"><span class="chip ${r.severity.toLowerCase()}">${sevLabel(r.severity)}</span><span class="chip meta">${r.cwe}</span></div>
    <h3>${esc(ruleName(r))}</h3>
    <p class="why" style="margin-top:0">${esc(T(r.why_en, r.why_ar))}</p>
    <div class="box fix"><div class="label">${T("How CodeShield fixes it", "كيف يصلحها كودشيلد")}</div><p>${esc(T(r.fix_en, r.fix_ar))}</p></div>
    ${ruleExamplesHTML(r.id)}
    <p class="note ltr" style="margin-top:12px">${esc(r.owasp)}</p>`;
}
document.addEventListener("click", e => {
  const c = e.target.closest("[data-rule]"); if (!c) return;
  activeRule = c.dataset.rule; renderRules();
  if (window.innerWidth < 960) $("ruleDetail").scrollIntoView({ behavior:"smooth", block:"start" });   // on phones the detail sits below the list
});

/* ---------------- accuracy (benchmark) ---------------- */
let bench = null;
function renderBenchmark(rerun){
  if (!bench || rerun){ const t0 = performance.now(); bench = runBenchmark(); bench.ms = Math.round(performance.now() - t0); }
  const b = bench, pct = x => (x * 100).toFixed(1).replace(/\.0$/, "") + "%";
  $("statAcc").textContent = pct(b.detection);
  $("benchBox").innerHTML = `
    <div class="kpis" style="margin-bottom:12px">
      <div class="card kpi"><div class="k">${T("Detection rate", "معدّل الاكتشاف")}</div><div class="v" style="color:var(--success)">${pct(b.detection)}</div><div class="note">${b.tp}/${b.positives} ${T("vulnerable cases caught", "حالة مصابة اكتُشفت")}</div></div>
      <div class="card kpi"><div class="k">${T("False-positive rate", "معدّل الإنذار الكاذب")}</div><div class="v">${pct(b.falsePositiveRate)}</div><div class="note">${b.fp}/${b.negatives} ${T("safe cases wrongly flagged", "حالة سليمة أُنذر عنها خطأً")}</div></div>
      <div class="card kpi"><div class="k">${T("Precision", "الدقة")}</div><div class="v">${pct(b.precision)}</div><div class="note">${T("of reported findings are real", "من النتائج المُبلَّغ عنها حقيقية")}</div></div>
      <div class="card kpi"><div class="k">${T("Data-flow cases", "حالات تدفّق البيانات")}</div><div class="v">${b.flowOk}/${b.flowTotal}</div><div class="note">${T("multi-line cases answered correctly", "حالة متعددة الأسطر صحيحة")}</div></div>
    </div>
    <div class="card">
      <div class="panel-title"><h3>${T("Per rule", "لكل قاعدة")}</h3>
        <div class="row"><span class="note">${b.total} ${T("cases", "حالة")} · ${b.ms} ms</span><button class="btn sm" data-action="run-bench">↻ ${T("Run again", "أعد التشغيل")}</button></div></div>
      <div class="table-wrap"><table><thead><tr><th>${T("Rule", "القاعدة")}</th><th>CWE</th><th>${T("Caught", "اكتُشف")}</th><th>${T("Missed", "فات")}</th><th>${T("False alarms", "إنذار كاذب")}</th><th>${T("Correctly silent", "سليم وصحيح")}</th></tr></thead><tbody>
      ${RULES.map(r => { const p = b.per[r.id] || { tp:0, fn:0, fp:0, tn:0 }; return `<tr><td>${esc(ruleName(r))}</td><td class="ltr">${r.cwe}</td>
        <td style="color:var(--success)">${p.tp}</td><td style="color:${p.fn ? "var(--danger)" : "var(--muted)"}">${p.fn}</td><td style="color:${p.fp ? "var(--danger)" : "var(--muted)"}">${p.fp}</td><td>${p.tn}</td></tr>`; }).join("")}
      </tbody></table></div>
    </div>
    ${b.misses.length ? `<div class="card card-pad" style="margin-top:12px"><div class="label">${T("Cases the engine gets wrong", "حالات يخطئ فيها المحرك")}</div>${b.misses.map(m => `<div class="finding-code" style="margin-top:6px">${m.kind === "missed" ? "MISSED" : "FALSE POSITIVE"} · ${m.rule}\n${esc(m.code)}</div>`).join("")}</div>` : ""}
    <p class="note" style="margin-top:12px">${T("Honest note: this is CodeShield's own labelled test set, written alongside the rules — a regression check, not an independent benchmark. Real-world accuracy will be lower; measuring against the OWASP Benchmark is on the roadmap.",
      "ملاحظة بصراحة: هذه مجموعة اختبار خاصة بكودشيلد كُتبت مع القواعد — هدفها كشف أي تراجع، وليست معيارًا مستقلًا. الدقة في المشاريع الحقيقية ستكون أقل، والقياس على OWASP Benchmark ضمن خارطة الطريق.")}</p>`;
}

/* ---------------- guided demo (exhibition tour) ----------------
   A step card at the bottom of the screen walks through scan → understand → fix → prove.
   The presenter moves with Next/Back, the arrow keys or Enter; Esc closes. Open it directly with #demo. */
const tour = { i:-1, el:null, focus:null };
const tourSqli = () => state.scans.scan && state.scans.scan.findings.find(f => f.ruleId === "SQLI");
const tourFinding = () => { const f = tourSqli(); return f && document.querySelector(`#scanFindings .finding[data-fid="${f.id}"]`); };
const TOUR = [
  { title:["Paste your code", "الصق كودك"],
    text:() => T("We'll use a small Python file with real-world mistakes. You can paste any Python, JavaScript, PHP, Ruby or shell code here.",
                 "نستخدم ملف بايثون صغير فيه أخطاء أمنية شائعة. تقدر تلصق هنا أي كود Python أو JavaScript أو PHP أو Ruby أو Shell."),
    run:() => { go("scanner"); state.filter.scan = { sev:"ALL", q:"" }; state.scans.scan = null; renderScanFindings(); $("codeInput").value = SAMPLES.python; $("langHint").value = "python"; },
    target:() => $("codeInput") },
  { title:["Scan", "افحص"],
    text:() => { const s = state.scans.scan.summary;
      return T(`${s.total} vulnerabilities found in under a second, ${s.HIGH} of them high severity. 23 rules check every line, and data-flow tracking follows untrusted input across lines. Nothing was sent to a server.`,
               `اكتشف ${s.total} ثغرة في أقل من ثانية، منها ${s.HIGH} عالية الخطورة. ٢٣ قاعدة تفحص كل سطر، ومتتبّع البيانات يلاحق المدخل غير الموثوق عبر الأسطر. ولا شي انرسل لأي خادم.`); },
    run:() => runScan(), target:() => $("scanSummary") },
  { title:["Understand it", "افهم الثغرة"],
    text:() => T("SQL injection: user input is glued into a database query. Every finding shows its severity, its CWE number, the exact line, and why it is dangerous, in full Arabic.",
                 "حقن SQL: مدخل المستخدم ملصوق داخل استعلام قاعدة البيانات. كل ثغرة معها درجة خطورتها، ورقمها في CWE، والسطر بالضبط، وشرح بالعربي ليش هي خطيرة."),
    run:() => { const box = $("scanFindings"); box.querySelectorAll(".finding.open").forEach(el => el.classList.remove("open")); const el = tourFinding(); if (el) el.classList.add("open"); },
    target:() => tourFinding() },
  { title:["Fix it", "أصلحها"],
    text:() => T("CodeShield drafts the fixed code: the value is passed as a parameter, so the database never treats it as SQL. You can edit the fix before checking it.",
                 "كودشيلد يجهّز الكود المعدَّل: القيمة تُمرَّر كمعامل منفصل، فقاعدة البيانات ما تعاملها كأمر SQL. وتقدر تعدّل الإصلاح قبل التحقق منه."),
    run:() => {}, target:() => { const el = tourFinding(); return el && el.querySelector(".box.lab"); } },
  { title:["Prove it", "أثبت الإصلاح"],
    text:() => T("The Proof Lab re-scans both versions: the original FAILS (the flaw is real), the fixed code PASSES all 23 rules. Only then is the fix marked verified, with timestamped evidence.",
                 "مختبر الإثبات يعيد فحص النسختين: الأصل يفشل (يعني الثغرة حقيقية)، والمعدَّل ينجح بكل القواعد الـ٢٣. وبعدها بس يصير الإصلاح «مُتحقَّق منه»، مع دليل مسجّل بالوقت."),
    run:() => { const f = tourSqli(); if (f){ verifyFinding(f); rerenderFinding(f.id); const el = tourFinding(); if (el) el.classList.add("open"); } },
    target:() => { const el = tourFinding(); return el && el.querySelector(".proof-steps"); } },
  { title:["Your turn", "دورك"],
    text:() => T("Find it, fix it, prove it. Try your own code, scan a GitHub repository, or learn in the Academy.",
                 "اكتشفها، أصلحها، وأثبت الإصلاح. جرّب كودك أنت، أو افحص مستودع GitHub، أو تعلّم في الأكاديمية."),
    run:() => {}, target:() => null,
    extra:() => `<div class="tour-links"><button class="btn soft sm" data-tour="own">${T("Try my own code", "أجرّب كودي")}</button><button class="btn soft sm" data-tour="github">GitHub</button><button class="btn soft sm" data-tour="learn">${T("Academy", "الأكاديمية")}</button></div>` }
];
function tourFocus(el){
  if (tour.focus) tour.focus.classList.remove("tour-focus");
  tour.focus = el || null;
  if (el){ el.classList.add("tour-focus"); el.scrollIntoView({ behavior:"smooth", block:"start" }); }   // just under the header, clear of the step card
}
function tourRender(){
  const s = TOUR[tour.i], n = TOUR.length;
  tour.el.innerHTML = `
    <div class="tour-top"><span class="tour-step">${T("Step", "خطوة")} ${tour.i + 1} / ${n}</span>
      <div class="tour-dots">${TOUR.map((_, k) => `<span class="${k === tour.i ? "on" : k < tour.i ? "done" : ""}"></span>`).join("")}</div>
      <button class="tour-x" data-tour="close" aria-label="${T("Close demo", "إغلاق العرض")}">✕</button></div>
    <h3>${T(s.title[0], s.title[1])}</h3>
    <p>${esc(s.text())}</p>
    ${s.extra ? s.extra() : ""}
    <div class="tour-nav">
      <button class="btn sm" data-tour="back" ${tour.i ? "" : "disabled"}>${T("Back", "السابق")}</button>
      <button class="btn primary sm" data-tour="next">${tour.i === n - 1 ? T("Finish", "إنهاء") : T("Next", "التالي")}</button>
    </div>`;
  tourFocus(s.target());
}
function tourGo(i){
  if (i < 0 || i >= TOUR.length) return;
  if (i < tour.i) for (let k = 0; k <= i; k++) TOUR[k].run();   // going back: replay quietly up to that step
  else for (let k = tour.i + 1; k <= i; k++) TOUR[k].run();
  tour.i = i; tourRender();
}
function tourClose(){
  tourFocus(null);
  if (tour.el){ tour.el.remove(); tour.el = null; }
  tour.i = -1;
  if (location.hash === "#demo") history.replaceState(null, "", "#scanner");
}
function demo(){
  if (!tour.el){
    tour.el = document.createElement("div"); tour.el.className = "tour"; tour.el.setAttribute("role", "dialog"); tour.el.setAttribute("aria-live", "polite");
    document.body.appendChild(tour.el);
  }
  $("welcome").classList.remove("show");   // the demo takes over; the welcome card can wait for a normal visit
  tour.i = -1; tourGo(0);
}
document.addEventListener("click", e => {
  const b = e.target.closest("[data-tour]"); if (!b) return;
  const a = b.dataset.tour;
  if (a === "next") tour.i === TOUR.length - 1 ? tourClose() : tourGo(tour.i + 1);
  else if (a === "back") tourGo(tour.i - 1);
  else if (a === "close") tourClose();
  else if (a === "own"){ tourClose(); go("scanner"); $("codeInput").value = ""; state.scans.scan = null; renderScanFindings(); $("codeInput").focus(); }
  else { tourClose(); go(a); }
});
document.addEventListener("keydown", e => {
  if (!tour.el || /^(TEXTAREA|INPUT|SELECT)$/.test(document.activeElement.tagName)) return;
  const rtl = document.documentElement.dir === "rtl";
  if (e.key === "Escape") tourClose();
  else if (e.key === "Enter" || e.key === (rtl ? "ArrowLeft" : "ArrowRight")){ e.preventDefault(); tour.i === TOUR.length - 1 ? tourClose() : tourGo(tour.i + 1); }
  else if (e.key === (rtl ? "ArrowRight" : "ArrowLeft")){ e.preventDefault(); tourGo(tour.i - 1); }
});

/* ---------------- share a scan ----------------
   The pasted code travels inside the link's #fragment, which browsers never send to a server. */
const SHARE_MAX = 8000;
const b64url = s => { const b = new TextEncoder().encode(s); let bin = ""; for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]); return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const unb64url = s => new TextDecoder().decode(Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0)));
function shareBar(scan){
  if (!scan || scan.source !== "paste") return "";
  return `<div class="sharebar"><button class="btn soft sm" data-action="share-scan">🔗 ${T("Share this scan", "شارك هذا الفحص")}</button>
    <span class="note">${T("The code goes inside the link itself, not to any server. Don't share it if the code holds real secrets.", "الكود ينحط داخل الرابط نفسه، ما يروح لأي خادم. لا تشاركه إذا الكود فيه أسرار حقيقية.")}</span></div>`;
}
function shareScan(){
  const scan = state.scans.scan; if (!scan || !scan.code) return;
  if (scan.code.length > SHARE_MAX){ toast(T(`Too long to share (over ${SHARE_MAX} characters).`, `الكود أطول من إنه ينشارك (أكثر من ${SHARE_MAX} حرف).`)); return; }
  const url = `${location.origin}${location.pathname}#scan=${b64url(scan.code)}&l=${scan.lang || ""}`;
  const done = () => toast(T("Link copied — anyone who opens it sees this scan.", "تم نسخ الرابط ✓ أي أحد يفتحه يشوف هذا الفحص."));
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(url).then(done, () => prompt(T("Copy this link:", "انسخ هذا الرابط:"), url));
  else prompt(T("Copy this link:", "انسخ هذا الرابط:"), url);
}
function openShared(){
  const m = location.hash.match(/^#scan=([A-Za-z0-9_-]+)(?:&l=(\w*))?/); if (!m) return false;
  try {
    const code = unb64url(m[1]); go("scanner", false);
    $("codeInput").value = code; if (m[2]) $("langHint").value = m[2];
    runScan(); toast(T("Opened a shared scan.", "انفتح فحص مُشارَك معك."));
  } catch (e) { go("scanner", false); toast(T("This shared link is damaged.", "رابط المشاركة هذا تالف.")); }
  return true;
}

/* ---------------- vulnerable vs safe example for a rule (from the labelled test set) ---------------- */
function ruleExamplesHTML(id){
  const bad = CASES.find(c => c.rule === id && c.vuln && !c.flow) || CASES.find(c => c.rule === id && c.vuln);
  if (!bad) return "";
  const good = CASES.find(c => c.rule === id && !c.vuln && c.lang === bad.lang) || CASES.find(c => c.rule === id && !c.vuln);
  const langName = l => ({ python:"Python", javascript:"JavaScript", php:"PHP", ruby:"Ruby", shell:"Shell" }[l] || l);
  return `<div class="rule-ex">
    <div class="ex bad"><div class="label">✗ ${T("Vulnerable", "مصاب")} <span class="note">${langName(bad.lang)}</span></div><div class="code ltr">${esc(bad.code)}</div></div>
    ${good ? `<div class="ex good"><div class="label">✓ ${T("Safe", "آمن")} <span class="note">${langName(good.lang)}</span></div><div class="code ltr">${esc(good.code)}</div></div>` : ""}
  </div>
  <p class="note" style="margin-top:6px">${T("Both come from CodeShield's labelled test set: the engine must flag the first and stay quiet on the second.", "المثالين من مجموعة اختبار كودشيلد: لازم المحرك يكتشف الأول ويسكت عن الثاني.")}</p>`;
}

/* ---------------- security score over time (dashboard) ---------------- */
function scoreChartHTML(rows){
  const pts = rows.slice(0, 12).reverse();
  if (pts.length < 2) return `<div class="empty">${T("Run at least two scans to see your progress.", "سوّ فحصين على الأقل عشان يطلع لك تطوّرك.")}</div>`;
  const W = 480, H = 210, L = 36, R = 16, Tp = 14, B = 34, xs = i => L + i * (W - L - R) / (pts.length - 1), ys = v => Tp + (1 - v / 100) * (H - Tp - B);
  const col = v => v >= 80 ? "var(--success)" : v >= 50 ? "var(--warning)" : "var(--danger)";
  const line = pts.map((r, i) => `${i ? "L" : "M"}${xs(i).toFixed(1)},${ys(r.score).toFixed(1)}`).join(" ");
  const area = `${line} L${xs(pts.length - 1).toFixed(1)},${H - B} L${L},${H - B} Z`;
  const d = r => new Date(r.at).toLocaleDateString(state.lang === "ar" ? "ar-SA" : "en-GB", { day:"numeric", month:"short" });
  const first = pts[0].score, last = pts[pts.length - 1].score, diff = last - first;
  return `<svg class="score-chart" viewBox="0 0 ${W} ${H}" dir="ltr" role="img" aria-label="${T("Security score per scan", "مؤشر الأمان لكل فحص")}">
      <defs><linearGradient id="scoreFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="var(--accent)" stop-opacity=".28"/><stop offset="1" stop-color="var(--accent)" stop-opacity="0"/></linearGradient></defs>
      ${[0, 50, 100].map(v => `<line x1="${L}" x2="${W - R}" y1="${ys(v)}" y2="${ys(v)}" class="grid"/><text x="${L - 6}" y="${ys(v) + 4}" class="axis" text-anchor="end">${v}</text>`).join("")}
      <path d="${area}" fill="url(#scoreFill)"/><path d="${line}" class="line"/>
      ${pts.map((r, i) => `<circle cx="${xs(i)}" cy="${ys(r.score)}" r="6" fill="${col(r.score)}"><title>${d(r)}: ${r.score}</title></circle>
        <text x="${xs(i)}" y="${H - 10}" class="axis" text-anchor="${i === 0 ? "start" : i === pts.length - 1 ? "end" : "middle"}">${pts.length <= 5 || i % 3 === 0 || i === pts.length - 1 ? d(r) : ""}</text>`).join("")}
    </svg>
    <p class="note">${diff > 0 ? T(`Up ${diff} points from your first scan here. Keep going!`, `تحسّنت ${diff} نقطة من أول فحص هنا. استمر!`)
      : diff < 0 ? T(`Down ${-diff} points from your first scan here — check the newest findings.`, `نزلت ${-diff} نقطة من أول فحص هنا. راجع آخر الثغرات.`)
      : T("Same score as your first scan here.", "نفس المؤشر من أول فحص هنا.")}</p>`;
}

/* ---------------- pre-launch checklist ---------------- */
const CHECKS = [
  { group:["Secrets & settings", "الأسرار والإعدادات"], items:[
    { id:"secrets", rule:"SECRET", en:"No passwords, API keys or tokens are written in the code — they come from environment variables.", ar:"ما فيه كلمات مرور أو مفاتيح أو توكنات مكتوبة في الكود، وكلها تجي من متغيرات البيئة." },
    { id:"gitignore", en:"The .env file (and any key files) are listed in .gitignore and never pushed.", ar:"ملف ‎.env‎ وأي ملفات مفاتيح مضافة في ‎.gitignore‎ وما تنرفع أبدًا." },
    { id:"debug", rule:"DEBUG", en:"Debug mode is off in production.", ar:"وضع التصحيح (Debug) مقفول في النسخة المنشورة." },
    { id:"perms", rule:"PERMS", en:"Files have the narrowest permissions they need (no 777).", ar:"صلاحيات الملفات أقل شي محتاجته (بدون 777)." } ] },
  { group:["Data & input", "البيانات والمدخلات"], items:[
    { id:"sql", rule:"SQLI", en:"Every database query uses parameters, never string building.", ar:"كل استعلامات قاعدة البيانات معلمنة، وما فيه دمج نصوص." },
    { id:"xss", rule:"XSS", en:"User input is escaped before it is shown on a page.", ar:"مدخلات المستخدم تنرمّز (escape) قبل ما تنعرض في الصفحة." },
    { id:"upload", rule:"UPLOAD", en:"Uploaded files are checked for type, size and name.", ar:"الملفات المرفوعة يُتحقّق من نوعها وحجمها واسمها." },
    { id:"paths", rule:"PATH", en:"File paths built from user input are validated.", ar:"مسارات الملفات اللي تجي من المستخدم يُتحقّق منها." } ] },
  { group:["Connections & sessions", "الاتصال والجلسات"], items:[
    { id:"https", rule:"CLEARTEXT", en:"The whole site is served over HTTPS.", ar:"الموقع كامل يشتغل على HTTPS." },
    { id:"tls", rule:"TLSOFF", en:"Certificate checks are never turned off.", ar:"التحقق من الشهادات ما ينطفي أبدًا." },
    { id:"cookies", rule:"COOKIE", en:"Session cookies are Secure, HttpOnly and SameSite.", ar:"كعكات الجلسة فيها Secure و HttpOnly و SameSite." },
    { id:"cors", rule:"CORS", en:"CORS only allows your own sites, not *.", ar:"CORS يسمح لمواقعك بس، مو للكل (*)." },
    { id:"hash", rule:"WEAKHASH", en:"Passwords are stored with a slow hash (bcrypt or Argon2), not MD5 or SHA-1.", ar:"كلمات المرور تنخزن بتجزئة بطيئة (bcrypt أو Argon2)، مو MD5 أو SHA-1." },
    { id:"jwt", rule:"JWT", en:"Token signatures are always verified.", ar:"توقيع التوكنات يُتحقّق منه دائمًا." } ] },
  { group:["Before launch", "قبل الإطلاق"], items:[
    { id:"scan", en:"The whole project was scanned with CodeShield and the high findings are fixed and verified.", ar:"المشروع كامل انفحص بكودشيلد، والثغرات العالية انصلحت وانتحقّق منها." },
    { id:"deps", en:"Libraries are up to date (CodeShield doesn't check this — use your package manager's audit).", ar:"المكتبات محدّثة (كودشيلد ما يفحص هذا، استخدم أمر audit حق مدير الحزم)." },
    { id:"logs", en:"Error logs don't contain passwords or personal data.", ar:"سجلات الأخطاء ما فيها كلمات مرور أو بيانات شخصية." },
    { id:"backup", en:"There is a backup, and you have tried restoring it once.", ar:"فيه نسخة احتياطية، وجرّبت ترجعها مرة وحدة على الأقل." } ] }
];
let ticks = {};
try { ticks = JSON.parse(store.get("checklist") || "{}"); } catch (e) { ticks = {}; }
function renderChecklist(){
  const all = CHECKS.flatMap(g => g.items), done = all.filter(i => ticks[i.id]).length, pct = Math.round(done / all.length * 100);
  $("checkBody").innerHTML = `
    <div class="card card-pad check-progress">
      <div class="row" style="justify-content:space-between"><b>${T(`${done} of ${all.length} checked`, `${done} من ${all.length} جاهزة`)}</b><span class="note">${pct}%</span></div>
      <div class="stack" style="margin-top:8px"><span style="width:${pct}%;background:${pct === 100 ? "var(--success)" : "var(--accent)"}"></span></div>
      ${pct === 100 ? `<p style="margin-top:8px;color:var(--success);font-weight:700">🎉 ${T("Ready to launch!", "جاهز للنشر!")}</p>` : ""}
    </div>
    ${CHECKS.map(g => `<div class="card card-pad check-group"><h3>${T(g.group[0], g.group[1])}</h3>
      ${g.items.map(i => `<label class="check-item${ticks[i.id] ? " on" : ""}"><input type="checkbox" data-check="${i.id}" ${ticks[i.id] ? "checked" : ""}>
        <span class="check-text">${esc(T(i.en, i.ar))}</span>
        ${i.rule ? `<button class="btn sm" data-action="rule-link" data-rule-id="${i.rule}">${T("Learn", "اعرف أكثر")}</button>` : ""}</label>`).join("")}
    </div>`).join("")}
    <div class="row" style="margin-top:14px"><button class="btn primary sm" data-go="scanner">${T("Scan my code now", "افحص كودي الحين")}</button>
      <button class="btn sm" data-action="check-reset">${T("Untick all", "شيل كل العلامات")}</button></div>`;
}
document.addEventListener("change", e => {
  const id = e.target.dataset && e.target.dataset.check; if (!id) return;
  ticks[id] = e.target.checked; if (!ticks[id]) delete ticks[id];
  store.set("checklist", JSON.stringify(ticks)); renderChecklist();
});

/* ---------------- wiring ---------------- */
function rerenderAll(){
  renderScanFindings(); renderRepo(); renderRules(); renderBenchmark();
  if (academy){ renderHomeProgress(); if ($("learn").classList.contains("active")) academy.render(); }
  if ($("dashboard").classList.contains("active")) renderDashboard();
  if ($("checklist").classList.contains("active")) renderChecklist();
  if (booth && booth.isOpen()) booth.open();
}

$("langBtn").addEventListener("click", () => setLang(state.lang === "ar" ? "en" : "ar"));
$("themeBtn").addEventListener("click", () => setTheme(state.theme === "dark" ? "light" : "dark"));
$("menuBtn").addEventListener("click", () => $("nav").classList.toggle("open"));
$("scanBtn").addEventListener("click", runScan);
$("clearBtn").addEventListener("click", () => { $("codeInput").value = ""; state.scans.scan = null; renderScanFindings(); });
$("sampleSel").addEventListener("change", e => {
  const k = e.target.value; if (!k) return;
  $("codeInput").value = SAMPLES[k]; $("langHint").value = k; e.target.value = ""; runScan();
});
$("codeInput").addEventListener("keydown", e => { if ((e.metaKey || e.ctrlKey) && e.key === "Enter") runScan(); });
$("repoBtn").addEventListener("click", runRepo);
$("repoInput").addEventListener("keydown", e => { if (e.key === "Enter") runRepo(); });
document.querySelectorAll("[data-repo]").forEach(b => b.addEventListener("click", () => { $("repoInput").value = b.dataset.repo; runRepo(); }));
$("ruleFilter").addEventListener("input", renderRules);
document.addEventListener("input", e => {
  const t = e.target.dataset && e.target.dataset.filterQ; if (!t) return;
  state.filter[t].q = e.target.value; const pos = e.target.selectionStart;
  rerenderTarget(t);
  const box = document.querySelector(`[data-filter-q="${t}"]`); if (box){ box.focus(); box.setSelectionRange(pos, pos); }
});
$("demoBtn").addEventListener("click", demo);
$("histClear").addEventListener("click", async () => {
  if (!confirm(T("Delete all saved scans from this browser? This cannot be undone.", "حذف كل الفحوصات المحفوظة من هذا المتصفح؟ لا يمكن التراجع."))) return;
  try { await db.clear(); } catch (e) {}
  renderDashboard(); toast(T("History cleared.", "تم مسح السجل."));
});
$("histExport").addEventListener("click", async () => {
  try { downloadJSON({ tool:"CodeShield", exported_at:new Date().toISOString(), scans:await db.all() }, "codeshield-history.json"); } catch (e) {}
});
window.addEventListener("popstate", () => location.hash === "#booth" ? booth.open() : (booth.isOpen() && booth.close(), location.hash === "#demo" ? demo() : openShared() || go(location.hash.slice(1), false)));

/* local upload: picker, folder picker, drag & drop */
$("fileInput").addEventListener("change", e => { scanLocal(e.target.files); e.target.value = ""; });
$("folderInput").addEventListener("change", e => { scanLocal(e.target.files); e.target.value = ""; });
const drop = $("dropZone");
["dragenter", "dragover"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", async e => {
  const items = [...(e.dataTransfer.items || [])];
  const entries = items.map(i => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
  if (!entries.length){ scanLocal(e.dataTransfer.files); return; }
  const files = [];
  const walk = (entry, path) => new Promise(res => {
    if (entry.isFile) entry.file(f => { Object.defineProperty(f, "webkitRelativePath", { value:path + f.name }); files.push(f); res(); }, () => res());
    else if (entry.isDirectory){
      const reader = entry.createReader(), all = [];
      const read = () => reader.readEntries(async batch => {
        if (!batch.length){ await Promise.all(all.map(en => walk(en, path + entry.name + "/"))); res(); }
        else { all.push(...batch); read(); }
      }, () => res());
      read();
    } else res();
  });
  await Promise.all(entries.map(en => walk(en, "")));
  scanLocal(files);
});

/* offline support (installable app) */
if ("serviceWorker" in navigator && location.protocol.startsWith("http")){
  window.addEventListener("load", () => navigator.serviceWorker.register("sw.js").catch(() => {}));
}

/* ---------------- academy, progress, welcome ---------------- */
let academy = null;

function renderHomeProgress(){
  const P = progress(), L = levelOf(P.xp);
  $("homeProgress").innerHTML = `
    <div class="card card-pad home-prog">
      <div class="profile-level">${L.ic}</div>
      <div style="flex:1;min-width:0">
        <b>${P.name ? T(`Welcome back, ${esc(P.name)}`, `أهلًا ${esc(P.name)}`) : T("Your progress", "تقدّمك")}</b>
        <div class="note">${T(L.en, L.ar)} · <span class="ltr">${P.xp} XP</span> · 🔥 ${P.streak} ${T("days", "يوم")} · ${Object.keys(P.badges).length} ${T("badges", "شارة")}</div>
        <div class="xpbar"><span style="width:${Math.round(L.pct * 100)}%"></span></div>
      </div>
      <button class="btn primary" data-go="learn">🎯 ${T("Play Vulnerability Hunt", "العب صيد الثغرات")}</button>
    </div>`;
}

/* celebration queue for badges / level-ups */
const pops = [];
let popBusy = false;
function pop(icon, title, sub){
  pops.push({ icon, title, sub });
  if (popBusy) return;
  const showNext = () => {
    const p = pops.shift(); if (!p){ popBusy = false; return; }
    popBusy = true;
    const el = $("badgePop");
    el.innerHTML = `<div class="bp-ic">${p.icon}</div><div><b>${esc(p.title)}</b><div class="note">${esc(p.sub)}</div></div>`;
    el.classList.add("show");
    setTimeout(() => { el.classList.remove("show"); setTimeout(showNext, 350); }, 2600);
  };
  showNext();
}

onProgress((P, evt) => {
  if (evt.type === "xp" && evt.amount) toast(`+${evt.amount} XP`);
  if (evt.levelUp) pop(evt.levelUp.ic, T("Level up!", "مستوى جديد!"), T(evt.levelUp.en, evt.levelUp.ar));
  (evt.newBadges || []).forEach(b => pop(b.ic, T("New badge", "شارة جديدة"), T(b.en, b.ar)));
  renderHomeProgress();
  if (academy && $("learn").classList.contains("active")) academy.renderHeader();
});

function askName(first){
  const ov = $("welcome");
  ov.classList.toggle("first", !!first);
  $("welName").value = progress().name || "";
  ov.classList.add("show");
  setTimeout(() => $("welName").focus(), 50);
}
function closeWelcome(save){
  if (save) setName($("welName").value);
  $("welcome").classList.remove("show");
  kv.set("welcomed", true).catch(() => {});
  renderHomeProgress();
  if (academy && $("learn").classList.contains("active")) academy.render();
}
$("welStart").addEventListener("click", () => closeWelcome(true));
$("welSkip").addEventListener("click", () => closeWelcome(false));
$("welName").addEventListener("keydown", e => { if (e.key === "Enter") closeWelcome(true); });

$("statRules").textContent = RULES.length;
$("statCwe").textContent = new Set(RULES.map(r => r.cwe)).size;
setTheme(store.get("theme") || "dark");
academy = initAcademy({ $, T, esc, toast, askName:() => askName(false) });
setLang(store.get("lang") || "ar");
booth = initBooth({ T, esc, go });
if (location.hash === "#booth"){ go("home", false); booth.open(); }
else if (location.hash === "#demo") demo(); else if (!openShared()) go(location.hash.slice(1) || "home", false);

loadProgress().then(async () => {
  renderHomeProgress();
  if ($("learn").classList.contains("active")) academy.render();
  let welcomed = false;
  try { welcomed = await kv.get("welcomed"); } catch (e) { welcomed = true; }
  if (!welcomed && !tour.el && !booth.isOpen()) askName(true);
});

/* exposed for debugging in the console */
window.CodeShield = { state, RULES };
