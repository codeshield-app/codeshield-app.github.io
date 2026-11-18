/* CodeShield Academy — "Vulnerability Hunt" game + one lesson per rule.
   Every challenge is assembled from the labelled test cases and then checked by the
   real engine, so the "right answer" is exactly what CodeShield itself detects. */
import { RULES } from "./rules.js";
import { CASES } from "./benchmark.js";
import { scanCode } from "./engine.js";
import { progress, track, levelOf, BADGES, DAILY_GOAL } from "./progress.js";

const FILLERS = {
  python:[
    "import logging", "from flask import Flask, jsonify", "app = Flask(__name__)", "def get_profile(user_id):",
    "user = db.session.get(User, user_id)", "return jsonify(user.to_dict())", "items = [x for x in data if x.active]",
    "total = sum(item.price for item in cart)", "logger.info(\"request handled\")", "@app.route(\"/health\")",
    "if not user:", "abort(404)", "page_size = 20", "orders = Order.query.filter_by(owner=current_user.id).all()"
  ],
  javascript:[
    "const express = require(\"express\");", "const router = express.Router();", "const items = await Item.find({ active: true });",
    "res.json({ ok: true });", "const total = cart.reduce((s, i) => s + i.price, 0);", "if (!user) return res.status(404).end();",
    "logger.info(\"request handled\");", "const port = process.env.PORT || 3000;", "app.listen(port);",
    "const fullName = `${user.first} ${user.last}`;", "router.get(\"/health\", (req, res) => res.send(\"ok\"));", "module.exports = router;"
  ],
  php:[
    "require_once 'config.php';", "$items = getActiveItems();", "$total = array_sum($prices);", "if (!$user) { http_response_code(404); exit; }",
    "error_log('request handled');", "$title = 'Dashboard';", "foreach ($items as $item) { render_item($item); }", "$pageSize = 20;"
  ],
  ruby:[ "require 'json'", "class SessionsController < ApplicationController", "def show", "end", "render json: { ok: true }", "@page = 1" ],
  shell:[ "set -euo pipefail", "echo \"Deploying...\"", "cd /srv/app", "git pull --ff-only", "npm ci", "systemctl restart app" ]
};

const shuffle = a => { const b = [...a]; for (let i = b.length - 1; i > 0; i--){ const j = Math.floor(Math.random() * (i + 1)); [b[i], b[j]] = [b[j], b[i]]; } return b; };
const pick = (a, n) => shuffle(a).slice(0, n);

/* build one verified challenge from a vulnerable test case */
function makeChallenge(c, size){
  const block = c.code.split("\n");
  for (let attempt = 0; attempt < 6; attempt++){
    const fill = pick(FILLERS[c.lang] || FILLERS.python, Math.max(0, size - block.length));
    const at = Math.floor(Math.random() * (fill.length + 1));
    const lines = [...fill.slice(0, at), ...block, ...fill.slice(at)];
    const res = scanCode(lines.join("\n"), c.lang);
    if (res.findings.length === 1 && res.findings[0].ruleId === c.rule){
      return { lines, answer:res.findings[0].line, rule:c.rule, lang:c.lang, flow:!!res.findings[0].flow, finding:res.findings[0] };
    }
  }
  return null;
}

export const LEVELS_GAME = {
  easy:  { en:"Beginner",     ar:"مبتدئ",  size:4, flow:false, mult:1,   time:45 },
  medium:{ en:"Intermediate", ar:"متوسط",  size:6, flow:false, mult:1.5, time:40 },
  hard:  { en:"Advanced",     ar:"محترف",  size:7, flow:true,  mult:2,   time:35 }
};

export function buildRound(level, n = 10){
  const L = LEVELS_GAME[level];
  const pos = CASES.filter(c => c.vuln);
  let pool = L.flow ? [...shuffle(pos.filter(c => c.flow)), ...shuffle(pos.filter(c => !c.flow))] : shuffle(pos.filter(c => !c.flow));
  const out = [], seenRules = {};
  for (const c of pool){
    if (out.length >= n) break;
    if ((seenRules[c.rule] || 0) >= 2) continue;          // variety: max 2 per rule
    const ch = makeChallenge(c, L.size);
    if (ch){ out.push(ch); seenRules[c.rule] = (seenRules[c.rule] || 0) + 1; }
  }
  return L.flow ? shuffle(out) : out;
}

function options(rule){
  const others = pick(RULES.filter(r => r.id !== rule).map(r => r.id), 3);
  return shuffle([rule, ...others]);
}

/* ---------------------------------------------------------------- UI */
export function initAcademy(ui){
  const { $, T, esc, toast } = ui;
  let tab = "hunt";
  let game = null;          // { level, qs, i, phase, picked, opts, chosen, score, xp, timer, left }
  let lessonOpen = null, lessonQuiz = null;

  const ruleName = id => { const r = RULES.find(x => x.id === id); return T(r.en, r.ar); };

  function greeting(){
    const h = new Date().getHours();
    const g = h < 12 ? T("Good morning", "صباح الخير") : h < 18 ? T("Good afternoon", "مساء الخير") : T("Good evening", "مساء النور");
    const n = progress().name;
    return `${g}${n ? (state_lang() === "ar" ? "، " : ", ") + esc(n) : ""} 👋`;
  }
  const state_lang = () => document.documentElement.lang;

  function renderHeader(){
    const P = progress(), L = levelOf(P.xp);
    const goal = Math.min(1, P.dayXp / DAILY_GOAL);
    const week = [...Array(7)].map((_, k) => { const d = new Date(); d.setDate(d.getDate() - (6 - k)); const key = d.toLocaleDateString("en-CA");
      return { on:(P.history[key] || 0) > 0, label:d.toLocaleDateString(state_lang() === "ar" ? "ar-SA" : "en-GB", { weekday:"narrow" }) }; });
    $("acadHeader").innerHTML = `
      <div class="card card-pad profile">
        <div class="profile-main">
          <div class="profile-level">${L.ic}</div>
          <div style="flex:1;min-width:0">
            <div class="profile-greet">${greeting()}</div>
            <div class="note">${T(L.en, L.ar)} · <b class="ltr">${P.xp} XP</b>${L.next ? ` · ${T(`${L.next.xp - P.xp} XP to ${L.next.en}`, `باقي ${L.next.xp - P.xp} نقطة لـ${L.next.ar}`)}` : ""}</div>
            <div class="xpbar"><span style="width:${Math.round(L.pct * 100)}%"></span></div>
          </div>
          <button class="btn sm" data-ac="name">${P.name ? T("Edit name", "تعديل الاسم") : T("Add your name", "أضف اسمك")}</button>
        </div>
        <div class="profile-stats">
          <div class="pstat"><div class="v">🔥 ${P.streak}</div><div class="k">${T("day streak", "أيام متواصلة")}</div>
            <div class="week">${week.map(w => `<span class="${w.on ? "on" : ""}" title="${w.label}">${w.label}</span>`).join("")}</div></div>
          <div class="pstat"><div class="v">${P.dayXp}/${DAILY_GOAL}</div><div class="k">${T("today's goal (XP)", "هدف اليوم (نقاط)")}</div>
            <div class="xpbar sm"><span style="width:${Math.round(goal * 100)}%;background:var(--success)"></span></div>
            <div class="note" style="font-size:11.5px;margin-top:4px">${goal >= 1 ? T("Goal reached 🎉", "حقّقت هدف اليوم 🎉") : T("Play a round or finish a lesson", "العب جولة أو أكمل درسًا")}</div></div>
          <div class="pstat"><div class="v">${Object.keys(P.badges).length}/${BADGES.length}</div><div class="k">${T("badges", "الشارات")}</div></div>
          <div class="pstat"><div class="v">${Object.keys(P.lessons).length}/${RULES.length}</div><div class="k">${T("lessons", "الدروس")}</div></div>
        </div>
      </div>`;
    document.querySelectorAll("[data-actab]").forEach(b => b.classList.toggle("active", b.dataset.actab === tab));
  }

  /* ---------- game ---------- */
  function startRound(level){
    const qs = buildRound(level);
    game = { level, qs, i:0, phase:"line", picked:null, chosen:null, opts:options(qs[0].rule), score:0, lineOk:0, xp:0, left:LEVELS_GAME[level].time };
    startTimer(); renderBody();
  }
  function startTimer(){
    clearInterval(game && game.timer);
    if (!game) return;
    game.left = LEVELS_GAME[game.level].time;
    game.timer = setInterval(() => {
      if (!game || game.phase === "result") return clearInterval(game && game.timer);
      game.left--;
      const bar = document.getElementById("huntTime");
      if (bar){ bar.style.width = (game.left / LEVELS_GAME[game.level].time * 100) + "%"; bar.classList.toggle("low", game.left <= 10); }
      if (game.left <= 0){ clearInterval(game.timer); finishQuestion(true); }
    }, 1000);
  }
  function finishQuestion(timeout){
    const q = game.qs[game.i], L = LEVELS_GAME[game.level];
    const lineOk = game.picked === q.answer, typeOk = game.chosen === q.rule;
    const gained = Math.round(((lineOk ? 5 : 0) + (typeOk ? 5 : 0)) * L.mult);
    game.phase = "result"; game.timeout = !!timeout;
    if (lineOk) game.lineOk++;
    if (lineOk && typeOk) game.score++;
    game.xp += gained;
    clearInterval(game.timer);
    track("hunt", { correct:lineOk && typeOk, rule:q.rule, flow:q.flow, xp:gained });
    renderBody();
  }
  function next(){
    game.i++;
    if (game.i >= game.qs.length){
      game.phase = "done";
      const res = track("round", { perfect:game.score === game.qs.length });
      game.newBadges = res && res.newBadges || [];
    } else {
      game.phase = "line"; game.picked = null; game.chosen = null; game.opts = options(game.qs[game.i].rule); startTimer();
    }
    renderBody();
  }

  function huntHTML(){
    if (!game) return `
      <div class="card card-pad hunt-intro">
        <div class="hunt-hero">🎯</div>
        <h3>${T("Vulnerability Hunt", "صيد الثغرات")}</h3>
        <p class="note">${T("Each round has 10 short code snippets. Tap the vulnerable line, then name the flaw. Every challenge is checked by the CodeShield engine itself.",
          "كل جولة فيها ١٠ مقاطع كود قصيرة. اضغط على السطر المصاب، ثم حدّد نوع الثغرة. كل تحدٍّ يتحقّق منه محرك كودشيلد نفسه.")}</p>
        <div class="levels">${Object.entries(LEVELS_GAME).map(([k, L]) => `
          <button class="card level-card" data-ac="start" data-level="${k}">
            <b>${T(L.en, L.ar)}</b>
            <span class="note">${L.size} ${T("lines", "أسطر")} · ${L.time}${T("s", " ث")}${L.flow ? ` · ${T("data flow", "تدفّق بيانات")}` : ""}</span>
            <span class="chip meta">×${L.mult} XP</span>
          </button>`).join("")}</div>
      </div>`;
    if (game.phase === "done") return `
      <div class="card card-pad hunt-intro">
        <div class="hunt-hero">${game.score === game.qs.length ? "🏆" : game.score >= 7 ? "🎉" : "💪"}</div>
        <h3>${T("Round complete", "انتهت الجولة")}</h3>
        <div class="round-stats">
          <div><b>${game.score}/${game.qs.length}</b><span>${T("fully correct", "إجابة كاملة")}</span></div>
          <div><b>${game.lineOk}/${game.qs.length}</b><span>${T("lines found", "سطر صحيح")}</span></div>
          <div><b class="ltr">+${game.xp}</b><span>XP</span></div>
        </div>
        ${game.newBadges.length ? `<p class="note">${T("New badges:", "شارات جديدة:")} ${game.newBadges.map(b => `${b.ic} ${T(b.en, b.ar)}`).join(" · ")}</p>` : ""}
        <div class="row" style="justify-content:center;margin-top:14px">
          <button class="btn primary" data-ac="start" data-level="${game.level}">${T("Play again", "جولة جديدة")}</button>
          <button class="btn" data-ac="quit">${T("Change level", "غيّر المستوى")}</button>
        </div>
      </div>`;
    const q = game.qs[game.i], L = LEVELS_GAME[game.level], res = game.phase === "result";
    const f = q.finding;
    return `
      <div class="card card-pad">
        <div class="hunt-top">
          <span class="chip meta">${T(L.en, L.ar)}</span>
          <span class="note">${T("Question", "سؤال")} ${game.i + 1}/${game.qs.length} · <b class="ltr">${game.xp} XP</b></span>
          <button class="btn sm" data-ac="quit">${T("Quit", "خروج")}</button>
        </div>
        <div class="timebar"><span id="huntTime" style="width:${res ? 0 : game.left / L.time * 100}%"></span></div>
        <p class="hunt-q">${game.phase === "line" ? T("1 · Tap the vulnerable line", "١ · اضغط على السطر المصاب")
          : game.phase === "type" ? T("2 · What kind of flaw is it?", "٢ · ما نوع الثغرة؟") : (game.timeout ? T("⏰ Time's up", "⏰ انتهى الوقت") : "")}</p>
        <div class="hunt-code ltr">${q.lines.map((ln, k) => {
          const n = k + 1;
          const cls = res ? (n === q.answer ? "ok" : n === game.picked ? "bad" : "") : (n === game.picked ? "sel" : "");
          const src = res && q.flow && f.flow && n === f.flow.sourceLine ? " src" : "";
          return `<button class="hl ${cls}${src}" data-ac="line" data-n="${n}" ${game.phase !== "line" ? "tabindex='-1'" : ""}><span class="ln">${n}</span><span class="tx">${esc(ln)}</span></button>`;
        }).join("")}</div>
        ${game.phase === "type" || res ? `<div class="opts">${game.opts.map(id => {
          const cls = res ? (id === q.rule ? "ok" : id === game.chosen ? "bad" : "") : "";
          return `<button class="btn opt ${cls}" data-ac="type" data-rule="${id}" ${res ? "disabled" : ""}>${esc(ruleName(id))}</button>`; }).join("")}</div>` : ""}
        ${res ? `
          <div class="box ${game.picked === q.answer && game.chosen === q.rule ? "fix" : "lab"}" style="margin-top:14px">
            <div class="label">${game.picked === q.answer && game.chosen === q.rule ? T("Correct! ", "إجابة صحيحة! ") : T("The answer: ", "الإجابة: ")}${esc(ruleName(q.rule))} — ${T("line", "سطر")} ${q.answer}${q.flow ? ` · ${T(`input enters on line ${f.flow.sourceLine}`, `المدخل يدخل في سطر ${f.flow.sourceLine}`)}` : ""}</div>
            <p>${esc(T(f.why_en, f.why_ar))}</p>
            <p style="margin-top:6px"><b>${T("Fix:", "الإصلاح:")}</b> ${esc(T(f.fix_en, f.fix_ar))}</p>
          </div>
          <div class="row" style="margin-top:12px;justify-content:flex-end"><button class="btn primary" data-ac="next">${game.i + 1 < game.qs.length ? T("Next →", "التالي ←") : T("See results", "النتيجة")}</button></div>` : ""}
      </div>`;
  }

  /* ---------- lessons ---------- */
  function lessonData(id){
    const ex = CASES.find(c => c.rule === id && c.vuln && !c.flow) || CASES.find(c => c.rule === id && c.vuln);
    const safe = CASES.find(c => c.rule === id && !c.vuln);
    let fixed = null;
    if (ex){ const f = scanCode(ex.code, ex.lang).findings.find(x => x.ruleId === id); if (f && f.autoPatch) fixed = ex.code.split("\n").map((l, k) => k + 1 === f.line ? f.patch : l).join("\n"); }
    return { ex, safe, fixed };
  }
  function lessonsHTML(){
    const P = progress();
    if (lessonOpen){
      const r = RULES.find(x => x.id === lessonOpen), d = lessonData(r.id), done = !!P.lessons[r.id];
      if (!lessonQuiz) lessonQuiz = { order:shuffle(["safe", "vuln"]), chosen:null };
      const q = lessonQuiz;
      return `
        <div class="card card-pad lesson">
          <div class="row" style="justify-content:space-between"><button class="btn sm" data-ac="lessons">${T("← All lessons", "→ كل الدروس")}</button>
            <span class="row"><span class="chip ${r.severity.toLowerCase()}">${r.severity}</span><span class="chip meta">${r.cwe}</span>${done ? `<span class="chip vstate verified">✓ ${T("Completed", "مكتمل")}</span>` : ""}</span></div>
          <h3>${esc(T(r.en, r.ar))}</h3>
          <div class="lesson-sec"><div class="label">${T("What is it?", "ما هي؟")}</div><p>${esc(T(r.why_en, r.why_ar))}</p></div>
          ${d.ex ? `<div class="lesson-sec"><div class="label">${T("Vulnerable example", "مثال مصاب")}</div><div class="finding-code ltr">${esc(d.ex.code)}</div></div>` : ""}
          ${d.fixed ? `<div class="lesson-sec"><div class="label" style="color:var(--success)">${T("After the fix", "بعد الإصلاح")}</div><div class="code ltr" style="border-inline-start:3px solid var(--success)">${esc(d.fixed)}</div></div>` : ""}
          <div class="lesson-sec"><div class="label">${T("How to protect yourself", "كيف تحمي كودك")}</div><p>${esc(T(r.fix_en, r.fix_ar))}</p></div>
          <p class="note ltr">${esc(r.owasp)}</p>
          ${d.safe && d.ex ? `
          <div class="box lab" style="margin-top:14px">
            <div class="label">${T("Quick check: which snippet is SAFE?", "اختبار سريع: أي الكودين آمن؟")}</div>
            <div class="quiz">${q.order.map(k => {
              const c = k === "safe" ? d.safe : d.ex;
              const cls = q.chosen ? (k === "safe" ? "ok" : q.chosen === k ? "bad" : "") : "";
              return `<button class="quiz-opt ${cls}" data-ac="quiz" data-k="${k}" ${q.chosen ? "disabled" : ""}><span class="ltr">${esc(c.code)}</span></button>`; }).join("")}</div>
            ${q.chosen ? `<p style="margin-top:8px">${q.chosen === "safe" ? T("Correct — lesson complete! +20 XP the first time.", "صحيح — اكتمل الدرس! +٢٠ نقطة في أول مرة.") : T("Not quite — the highlighted one is safe. Try the next lesson or come back later.", "ليست هذه — المحدّد بالأخضر هو الآمن. جرّب مرة أخرى لاحقًا.")}</p>
              <div class="row" style="margin-top:8px">${q.chosen !== "safe" ? `<button class="btn sm" data-ac="retry">${T("Try again", "حاول مرة أخرى")}</button>` : ""}${nextLessonBtn(r.id)}</div>` : ""}
          </div>` : ""}
        </div>`;
    }
    return `<div class="lesson-grid">${RULES.map(r => `
      <button class="card lesson-card ${P.lessons[r.id] ? "done" : ""}" data-ac="open" data-rule="${r.id}">
        <span class="row" style="justify-content:space-between;width:100%"><span class="chip ${r.severity.toLowerCase()}">${r.severity}</span>${P.lessons[r.id] ? "✅" : "<span class='note'>+20 XP</span>"}</span>
        <b>${esc(T(r.en, r.ar))}</b><span class="note ltr">${r.cwe}</span>
      </button>`).join("")}</div>`;
  }
  function nextLessonBtn(id){
    const i = RULES.findIndex(r => r.id === id), n = RULES[i + 1];
    return n ? `<button class="btn primary sm" data-ac="open" data-rule="${n.id}">${T("Next lesson →", "الدرس التالي ←")}</button>` : "";
  }

  function badgesHTML(){
    const P = progress();
    return `<div class="badge-grid">${BADGES.map(b => `
      <div class="card badge-card ${P.badges[b.id] ? "got" : ""}">
        <div class="badge-ic">${b.ic}</div><b>${esc(T(b.en, b.ar))}</b><span class="note">${esc(T(b.d_en, b.d_ar))}</span>
        ${P.badges[b.id] ? `<span class="chip vstate verified">${T("Earned", "حصلت عليها")} · ${P.badges[b.id]}</span>` : `<span class="chip line">🔒 ${T("Locked", "مقفلة")}</span>`}
      </div>`).join("")}</div>`;
  }

  function renderBody(){
    renderHeader();
    $("acadBody").innerHTML = tab === "hunt" ? huntHTML() : tab === "lessons" ? lessonsHTML() : badgesHTML();
  }

  document.addEventListener("click", e => {
    const t = e.target.closest("[data-actab]");
    if (t){ tab = t.dataset.actab; if (tab !== "lessons"){ lessonOpen = null; lessonQuiz = null; } renderBody(); return; }
    const a = e.target.closest("[data-ac]"); if (!a) return;
    const act = a.dataset.ac;
    if (act === "start") startRound(a.dataset.level);
    else if (act === "quit"){ clearInterval(game && game.timer); game = null; renderBody(); }
    else if (act === "line" && game && game.phase === "line"){ game.picked = Number(a.dataset.n); game.phase = "type"; renderBody(); }
    else if (act === "type" && game && game.phase === "type"){ game.chosen = a.dataset.rule; finishQuestion(false); }
    else if (act === "next") next();
    else if (act === "open"){ lessonOpen = a.dataset.rule; lessonQuiz = null; tab = "lessons"; renderBody(); document.getElementById("learn").scrollIntoView({ block:"start" }); }
    else if (act === "lessons"){ lessonOpen = null; lessonQuiz = null; renderBody(); }
    else if (act === "quiz" && lessonQuiz && !lessonQuiz.chosen){ lessonQuiz.chosen = a.dataset.k; if (a.dataset.k === "safe") track("lesson", { rule:lessonOpen }); renderBody(); }
    else if (act === "retry"){ lessonQuiz = null; renderBody(); }
    else if (act === "name"){ ui.askName(); }
  });

  return { render:renderBody, renderHeader, isPlaying:() => !!game && game.phase !== "done" };
}
