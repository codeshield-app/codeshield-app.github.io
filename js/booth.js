/* CodeShield — booth mode for exhibitions. Open it with #booth; it is not linked from the normal navigation.
   1) A self-running demo on loop: code is typed, scanned, fixed and verified by the real engine.
   2) A QR code to the live site so visitors can try it on their own phone.
   3) A local "hall of fame": Vulnerability Hunt rounds played on THIS device can be saved with a name.
      Scores stay in this browser's localStorage only. */
import { scanCode, verifyFinding, securityScore } from "./engine.js";

const SITE = "codeshield-sa.netlify.app";
/* QR for https://codeshield-sa.netlify.app (generated with Core Image, error level M, decoded back to check) */
const QR = "11111110101101110010001111111,10000010110001110101101000001,10111010110111100010101011101,10111010000110110101101011101,10111010110101010111101011101,10000010000111100100101000001,11111110101010101010101111111,00000000000100100001100000000,10011111100011111101010010111,00100000010010100001010110110,11000111111000100100010010100,01011100001010110111010011001,00111011010101101001001100001,01101001000110000110001111111,11010110011000111001110010101,10101001110101101010001110101,11011011100010011001100101000,10100101100000010011000010110,11010011111101111111110001001,11110101000011000001010101100,11011010011101010101111111110,00000000101001010010100011000,11111110100001011001101011000,10000010101101001111100010011,10111010101101011001111111011,10111010111101111101110000001,10111010010000111010110110111,10000010011100110000011101101,11111110111110100011100110000".split(",");

/* Demo code: every vulnerable line here is found, fixed and verified by the engine (checked before shipping). */
const DEMO = `const express = require("express");
const app = express();
const API_KEY = "sk_live_51H8xQbLmNpQrStUv";

app.get("/user", async (req, res) => {
  const rows = await db.query("SELECT * FROM users WHERE id=" + req.query.id);
  res.json(rows);
});

function show(msg){
  document.getElementById("out").innerHTML = msg;
}
const token = Math.random().toString(36);`;

const FLAG = "codeshield-booth", BOARD = "codeshield-booth-board", IDLE_MS = 90000;
const ls = { get(k, d){ try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch (e) { return d; } },
             set(k, v){ try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) {} },
             del(k){ try { localStorage.removeItem(k); } catch (e) {} } };
const sleep = ms => new Promise(r => setTimeout(r, ms));

function qrSVG(){
  const n = QR.length; let d = "";
  QR.forEach((row, y) => { for (let x = 0; x < row.length; x++) if (row[x] === "1") d += `M${x} ${y}h1v1h-1z`; });
  return `<svg viewBox="-2 -2 ${n + 4} ${n + 4}" shape-rendering="crispEdges" aria-label="QR: ${SITE}"><rect x="-2" y="-2" width="${n + 4}" height="${n + 4}" fill="#fff"/><path d="${d}" fill="#0a0f1a"/></svg>`;
}

export function initBooth({ T, esc, go }){
  let el = null, runId = 0, idleTimer = null, pill = null;
  const isOn = () => ls.get(FLAG, false) === true;
  const board = () => ls.get(BOARD, []).sort((a, b) => b.xp - a.xp || b.score - a.score || a.at - b.at);

  /* ---------- layout ---------- */
  function shell(){
    el = document.createElement("div");
    el.id = "booth"; el.className = "booth";
    document.body.appendChild(el); document.body.classList.add("booth-open");
    render();
  }
  function render(){
    if (!el) return;
    el.setAttribute("dir", document.documentElement.dir || "rtl");
    el.innerHTML = `
      <header class="booth-top">
        <div class="booth-brand"><img class="booth-logo" src="icon.svg" alt=""><div><b>CodeShield <span>كودشيلد</span></b>
          <small>${T("Find it. Fix it. Prove the fix.", "اكتشفها. أصلحها. أثبت الإصلاح.")}</small></div></div>
        <div class="booth-tools">
          <button class="booth-mini" data-b="full" title="${T("Full screen", "ملء الشاشة")}">⛶</button>
          <button class="booth-mini" data-b="exit">${T("Exit booth mode", "خروج من وضع المعرض")}</button>
        </div>
      </header>
      <main class="booth-grid">
        <section class="booth-stage">
          <ol class="booth-steps" id="bSteps">
            ${[["Write", "كتابة"], ["Scan", "فحص"], ["Fix", "إصلاح"], ["Prove", "إثبات"]].map(([e, a], i) => `<li data-i="${i}"><span>${i + 1}</span>${T(e, a)}</li>`).join("")}
          </ol>
          <div class="booth-caption" id="bCap"></div>
          <div class="booth-code ltr" id="bCode"></div>
          <div class="booth-bottom">
            <div class="booth-score" id="bScore"></div>
            <div class="booth-finds" id="bFinds"></div>
          </div>
        </section>
        <aside class="booth-side">
          <div class="booth-card booth-qr">
            ${qrSVG()}
            <div><b>${T("Try it on your phone", "جرّبه من جوالك 📱")}</b><span class="ltr">${SITE}</span>
            <small>${T("Free · runs in your browser · your code never leaves your device", "مجاني · يشتغل في المتصفح · كودك ما يطلع من جهازك")}</small></div>
          </div>
          <div class="booth-card booth-board">
            <div class="booth-board-head"><b>🏆 ${T("Booth hall of fame", "أبطال المعرض")}</b><small>${T("Vulnerability Hunt", "صيد الثغرات")}</small></div>
            <ol id="bBoard"></ol>
            <button class="btn primary booth-play" data-b="play">${T("Take the challenge →", "تحدَّ نفسك ←")}</button>
          </div>
        </aside>
      </main>`;
    renderBoard();
  }
  function renderBoard(){
    const ol = el && el.querySelector("#bBoard"); if (!ol) return;
    const top = board().slice(0, 10);
    ol.innerHTML = top.length ? top.map((r, i) => `
      <li class="${i < 3 ? "podium p" + i : ""}"><span class="rk">${["🥇", "🥈", "🥉"][i] || i + 1}</span>
        <span class="nm">${esc(r.name)}</span><span class="lv">${esc(T(r.levelEn, r.levelAr))}</span><b class="ltr">${r.xp} XP</b></li>`).join("")
      : `<li class="empty">${T("No scores yet. Be the first!", "ما فيه نتائج للحين. كن أول بطل!")}</li>`;
  }

  /* ---------- demo loop ---------- */
  const $b = id => el && el.querySelector("#" + id);
  function step(i){ el && el.querySelectorAll("#bSteps li").forEach(li => { const k = +li.dataset.i; li.classList.toggle("on", k === i); li.classList.toggle("done", k < i); }); }
  function cap(html){ const c = $b("bCap"); if (c){ c.classList.remove("in"); void c.offsetWidth; c.innerHTML = html; c.classList.add("in"); } }
  function codeHTML(lines, marks = {}){
    return lines.map((ln, i) => {
      const m = marks[i + 1] || {};
      return `<div class="bl ${m.cls || ""}"><span class="no">${i + 1}</span><span class="tx">${esc(ln) || " "}</span>${m.tag ? `<span class="tag">${m.tag}</span>` : ""}</div>`;
    }).join("");
  }
  function scoreHTML(v, label){
    const col = v >= 80 ? "var(--success)" : v >= 50 ? "var(--warning)" : "var(--danger)";
    return `<div class="ring" style="--v:${v};--c:${col}"><b>${v}</b></div><div><small>${label}</small><span>${T("Security score", "درجة الأمان")}</span></div>`;
  }
  async function loop(){
    const id = ++runId;
    const alive = () => id === runId && el;
    const wait = async ms => { await sleep(ms); return alive(); };
    while (alive()){
      const lines = DEMO.split("\n"), code = $b("bCode"), finds = $b("bFinds"), sc = $b("bScore");
      finds.innerHTML = ""; sc.innerHTML = "";
      // 1 · write
      step(0); cap(T("A developer writes ordinary-looking code…", "مطوّر يكتب كود يبان عادي…"));
      for (let i = 1; i <= lines.length; i++){ code.innerHTML = codeHTML(lines.slice(0, i)); if (!await wait(lines[i - 1].trim() ? 260 : 120)) return; }
      if (!await wait(900)) return;
      // 2 · scan (real engine, timed)
      step(1); cap(T("CodeShield scans it, right here in the browser…", "كودشيلد يفحصه هنا داخل المتصفح…"));
      for (let i = 1; i <= lines.length; i++){ code.innerHTML = codeHTML(lines, { [i]:{ cls:"sweep" } }); if (!await wait(70)) return; }
      const t0 = performance.now(); const scan = scanCode(DEMO, "javascript"); const ms = Math.max(1, Math.round(performance.now() - t0));
      const F = scan.findings, before = securityScore(F, scan.lineCount);
      const marks = {}; F.forEach((f, k) => marks[f.line] = { cls:"bad", tag:`${k + 1} · ${esc(T(f.name_en, f.name_ar))}` });
      code.innerHTML = codeHTML(lines, marks);
      const fast = ms < 1000;   // measured, not claimed
      cap(T(`<b>${F.length} vulnerabilities</b> found ${fast ? "in a fraction of a second" : `in ${(ms / 1000).toFixed(1)} s`}, without the code leaving the device.`,
            `لقى <b>${F.length} ثغرات</b> ${fast ? "في جزء من الثانية" : `خلال ${(ms / 1000).toFixed(1)} ثانية`}، وبدون ما يطلع الكود من الجهاز.`));
      sc.innerHTML = scoreHTML(before, T("before", "قبل"));
      finds.innerHTML = F.map((f, k) => `<span class="bf ${f.severity.toLowerCase()}"><i>${k + 1}</i>${esc(T(f.name_en, f.name_ar))}</span>`).join("");
      if (!await wait(4200)) return;
      // 3 · fix
      step(2); cap(T("It writes a ready fix for each one…", "ويكتب إصلاح جاهز لكل وحدة…"));
      for (let k = 0; k < F.length; k++){
        const out = [], m = {};   // original code with fixes 1..k applied (a fix may span several lines)
        lines.forEach((ln, i) => {
          const j = F.findIndex(f => f.line === i + 1);
          if (j >= 0 && j <= k) F[j].patch.split("\n").forEach((p, z) => { out.push(p); m[out.length] = { cls:"fix", tag:z === 0 ? `${j + 1} · ${T("fixed", "أُصلح")}` : "" }; });
          else { out.push(ln); if (j >= 0) m[out.length] = { cls:"bad", tag:`${j + 1}` }; }
        });
        code.innerHTML = codeHTML(out, m);
        if (!await wait(1300)) return;
      }
      // 4 · prove
      step(3); cap(T("…then proves it: the flaw is reproduced on the original line and gone from the fix.",
                     "…وبعدها يثبت: الثغرة تتكرر في السطر الأصلي، وتختفي من الإصلاح."));
      const res = F.map(f => verifyFinding(f).status === "verified");
      finds.innerHTML = F.map((f, k) => `<span class="bf ${res[k] ? "ok" : "high"}"><i>${res[k] ? "✓" : "!"}</i>${esc(T(f.name_en, f.name_ar))}</span>`).join("");
      const after = securityScore(F, scan.lineCount);
      sc.innerHTML = scoreHTML(after, T(`was ${before}`, `كانت ${before}`));
      if (!await wait(2600)) return;
      cap(T(`<b>${res.filter(Boolean).length}/${F.length} fixes verified.</b> Scan the QR and try it with your own code.`,
            `<b>${res.filter(Boolean).length}/${F.length} إصلاحات تم إثباتها.</b> امسح الـ QR وجرّبه على كودك.`));
      if (!await wait(5200)) return;
    }
  }

  /* ---------- open / close ---------- */
  function open(){
    ls.set(FLAG, true); hidePill(); clearTimeout(idleTimer);
    if (!el) shell(); else render();
    if (location.hash !== "#booth") history.replaceState(null, "", "#booth");
    loop();
  }
  function close(toScreen){
    runId++; if (el){ el.remove(); el = null; } document.body.classList.remove("booth-open");
    if (toScreen) go(toScreen);
    if (isOn()){ showPill(); armIdle(); }
  }
  function exit(){
    if (!confirm(T("Leave booth mode on this device?", "تبين تطلعين من وضع المعرض على هذا الجهاز؟"))) return;
    ls.del(FLAG); hidePill(); clearTimeout(idleTimer); close("home");
  }

  /* floating way back while visitors use the rest of the site */
  function showPill(){
    if (pill) return;
    pill = document.createElement("button"); pill.className = "booth-pill"; pill.textContent = "🏁 " + T("Booth screen", "شاشة المعرض");
    pill.addEventListener("click", open); document.body.appendChild(pill);
  }
  function hidePill(){ if (pill){ pill.remove(); pill = null; } }
  function armIdle(){ clearTimeout(idleTimer); if (isOn() && !el) idleTimer = setTimeout(() => { if (isOn() && !el && !document.querySelector(".booth-save")) open(); }, IDLE_MS); }
  ["pointerdown", "keydown", "scroll", "touchstart"].forEach(ev => window.addEventListener(ev, () => { if (isOn() && !el) armIdle(); }, { passive:true }));

  /* save a finished Hunt round to the board (only on a device in booth mode) */
  window.addEventListener("codeshield:round", e => {
    if (!isOn()) return;
    const r = e.detail, box = document.createElement("div");
    box.className = "booth-save"; box.setAttribute("dir", document.documentElement.dir || "rtl");
    box.innerHTML = `<div class="booth-card">
      <div class="hunt-hero">${r.score === r.total ? "🏆" : "🎯"}</div>
      <h3>${T("Join the booth hall of fame", "ادخل لوحة أبطال المعرض")}</h3>
      <p class="note">${T(`${r.score}/${r.total} fully correct · `, `${r.score}/${r.total} إجابة كاملة · `)}<b class="ltr">${r.xp} XP</b></p>
      <input id="bName" maxlength="20" autocomplete="off" placeholder="${T("Your name or nickname", "اسمك أو لقبك")}">
      <div class="row" style="justify-content:center;margin-top:12px">
        <button class="btn primary" data-s="save">${T("Save my score", "احفظ نتيجتي")}</button>
        <button class="btn" data-s="skip">${T("Skip", "تخطي")}</button>
      </div></div>`;
    document.body.appendChild(box);
    const inp = box.querySelector("#bName"); setTimeout(() => inp.focus(), 50);
    const done = save => {
      const name = inp.value.trim().slice(0, 20);
      if (save && name){ const b = ls.get(BOARD, []); b.push({ name, xp:r.xp, score:r.score, total:r.total, levelEn:r.levelEn, levelAr:r.levelAr, at:Date.now() }); ls.set(BOARD, b.slice(-200)); }
      box.remove(); open();
    };
    box.addEventListener("click", ev => { const s = ev.target.closest("[data-s]"); if (s) done(s.dataset.s === "save"); });
    inp.addEventListener("keydown", ev => { if (ev.key === "Enter") done(true); });
  });

  document.addEventListener("click", e => {
    const b = el && e.target.closest("#booth [data-b]"); if (!b) return;
    const a = b.dataset.b;
    if (a === "exit") exit();
    else if (a === "play") close("learn");
    else if (a === "full"){ try { document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen(); } catch (err) {} }
  });
  document.addEventListener("keydown", e => {
    if (!el) return;
    if (e.key === "f" || e.key === "F"){ try { document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen(); } catch (err) {} }
    if (e.key === "Escape" && e.shiftKey) exit();
    // Shift+Backspace clears the board (for the presenter only)
    if (e.key === "Backspace" && e.shiftKey && confirm(T("Clear the booth hall of fame?", "تبين تمسحين لوحة الأبطال؟"))){ ls.del(BOARD); renderBoard(); }
  });
  document.addEventListener("visibilitychange", () => { if (el){ if (document.hidden) runId++; else loop(); } });

  if (isOn() && location.hash !== "#booth"){ showPill(); armIdle(); }
  return { open, close, render, isOpen:() => !!el };
}
