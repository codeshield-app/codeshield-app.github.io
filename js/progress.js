/* CodeShield — learning progress: XP, shield levels, daily goal, streak and badges.
   Stored in the local IndexedDB "kv" store. No account, nothing leaves the browser. */
import { kv } from "./db.js";

export const DAILY_GOAL = 100;  // XP per day

/* shield tiers — gender-neutral, object-based titles */
export const LEVELS = [
  { xp:0,    en:"Starter shield",  ar:"درع مبتدئ",  ic:"🛡️" },
  { xp:150,  en:"Bronze shield",   ar:"درع برونزي", ic:"🥉" },
  { xp:400,  en:"Silver shield",   ar:"درع فضي",    ic:"🥈" },
  { xp:900,  en:"Gold shield",     ar:"درع ذهبي",   ic:"🥇" },
  { xp:1800, en:"Diamond shield",  ar:"درع ماسي",   ic:"💎" },
  { xp:3500, en:"Legendary shield",ar:"درع أسطوري", ic:"👑" }
];

export const BADGES = [
  { id:"first_scan",    ic:"🔍", en:"First scan",          ar:"أول فحص",            d_en:"Run your first scan.",                          d_ar:"شغّل أول فحص." },
  { id:"first_verify",  ic:"✅", en:"First proven fix",    ar:"أول إصلاح مُثبت",     d_en:"Verify a fix in the Proof Lab.",                d_ar:"تحقّق من إصلاح في مختبر الإثبات." },
  { id:"verify_10",     ic:"🛠️", en:"Ten proven fixes",    ar:"عشرة إصلاحات",        d_en:"Verify 10 fixes.",                              d_ar:"تحقّق من ١٠ إصلاحات." },
  { id:"project_scan",  ic:"📦", en:"Project scanner",     ar:"فاحص مشاريع",         d_en:"Scan a GitHub repository or a folder.",         d_ar:"افحص مستودع GitHub أو مجلدًا." },
  { id:"first_hunt",    ic:"🎯", en:"First catch",         ar:"أول صيدة",            d_en:"Find a flaw in Vulnerability Hunt.",            d_ar:"اكتشف ثغرة في «صيد الثغرات»." },
  { id:"perfect_round", ic:"💯", en:"Perfect round",       ar:"جولة كاملة",          d_en:"Answer every question of a round correctly.",   d_ar:"أجب عن كل أسئلة جولة إجابة صحيحة." },
  { id:"sqli_hunter",   ic:"💉", en:"SQL injection hunter",ar:"صائد حقن SQL",        d_en:"Catch 5 SQL injections in the game.",           d_ar:"اصطد ٥ ثغرات حقن SQL في اللعبة." },
  { id:"xss_hunter",    ic:"🕸️", en:"XSS hunter",          ar:"صائد XSS",            d_en:"Catch 5 XSS flaws in the game.",                d_ar:"اصطد ٥ ثغرات XSS في اللعبة." },
  { id:"flow_tracker",  ic:"⇢",  en:"Data-flow tracker",   ar:"متتبّع البيانات",      d_en:"Solve 3 multi-line (data-flow) challenges.",    d_ar:"حُلّ ٣ تحديات متعددة الأسطر." },
  { id:"lessons_5",     ic:"📚", en:"Keen learner",        ar:"طالب علم",            d_en:"Complete 5 lessons.",                           d_ar:"أكمل ٥ دروس." },
  { id:"lessons_all",   ic:"🎓", en:"Academy graduate",    ar:"خرّيج الأكاديمية",     d_en:"Complete every lesson.",                        d_ar:"أكمل كل الدروس." },
  { id:"streak_3",      ic:"🔥", en:"3-day streak",        ar:"٣ أيام متواصلة",      d_en:"Learn on 3 days in a row.",                     d_ar:"تعلّم ٣ أيام متتالية." },
  { id:"streak_7",      ic:"🌟", en:"7-day streak",        ar:"أسبوع متواصل",        d_en:"Learn on 7 days in a row.",                     d_ar:"تعلّم ٧ أيام متتالية." },
  { id:"gold",          ic:"🥇", en:"Gold shield",         ar:"الدرع الذهبي",        d_en:"Reach 900 XP.", d_ar:"اجمع ٩٠٠ نقطة." }
];

const today = () => new Date().toLocaleDateString("en-CA");          // YYYY-MM-DD, local time
const dayDiff = (a, b) => Math.round((new Date(b) - new Date(a)) / 86400000);

const EMPTY = () => ({
  name:"", xp:0, badges:{}, lessons:{}, counters:{}, verifiedIds:{},
  day:today(), dayXp:0, streak:0, lastActive:null, history:{}
});

let P = EMPTY();
const listeners = new Set();
let saveTimer;
function save(){ clearTimeout(saveTimer); saveTimer = setTimeout(() => kv.set("progress", P).catch(() => {}), 200); }
const emit = evt => listeners.forEach(fn => fn(P, evt));

export async function loadProgress(){
  try { const v = await kv.get("progress"); if (v) P = { ...EMPTY(), ...v }; } catch (e) {}
  rollDay();
  return P;
}
export const onProgress = fn => listeners.add(fn);
export const progress = () => P;

function rollDay(){
  const t = today();
  if (P.day !== t){ P.day = t; P.dayXp = 0; }
  if (P.lastActive && dayDiff(P.lastActive, t) > 1) P.streak = 0;   // missed a day
}

export function levelOf(xp){
  let i = 0; while (i + 1 < LEVELS.length && xp >= LEVELS[i + 1].xp) i++;
  const cur = LEVELS[i], next = LEVELS[i + 1];
  return { index:i, ...cur, next, into:xp - cur.xp, span:next ? next.xp - cur.xp : 1, pct:next ? (xp - cur.xp) / (next.xp - cur.xp) : 1 };
}

/* add XP; returns { gained, levelUp, newBadges } */
export function addXp(amount, reason){
  rollDay();
  const before = levelOf(P.xp).index;
  P.xp += amount; P.dayXp += amount;
  P.history[P.day] = (P.history[P.day] || 0) + amount;
  const t = today();
  if (P.lastActive !== t){
    P.streak = P.lastActive && dayDiff(P.lastActive, t) === 1 ? P.streak + 1 : 1;
    P.lastActive = t;
  }
  const newBadges = checkBadges();
  const levelUp = levelOf(P.xp).index > before ? levelOf(P.xp) : null;
  save(); emit({ type:"xp", amount, reason, levelUp, newBadges });
  return { gained:amount, levelUp, newBadges };
}

export function count(key, by = 1){ P.counters[key] = (P.counters[key] || 0) + by; return P.counters[key]; }

/* events from the app */
export function track(event, data = {}){
  switch (event){
    case "scan":         count("scans"); return addXp(5, "scan");
    case "project_scan": count("projects"); count("scans"); return addXp(15, "project");
    case "verify":
      if (P.verifiedIds[data.key]) return null;          // XP once per finding
      P.verifiedIds[data.key] = 1; count("verified");
      return addXp(5, "verify");
    case "lesson":
      if (P.lessons[data.rule]) return null;
      P.lessons[data.rule] = today();
      return addXp(20, "lesson");
    case "hunt": {
      count("hunt_answers");
      if (data.correct){ count("hunt_correct"); count("hunt_" + data.rule); if (data.flow) count("hunt_flow"); }
      return data.xp ? addXp(data.xp, "hunt") : (checkBadges(), save(), null);
    }
    case "round":
      count("rounds"); if (data.perfect) count("perfect_rounds");
      { const nb = checkBadges(); save(); emit({ type:"badges", newBadges:nb }); return { newBadges:nb }; }
  }
  return null;
}

function checkBadges(){
  const c = P.counters, got = [];
  const rules = {
    first_scan:(c.scans || 0) >= 1, first_verify:(c.verified || 0) >= 1, verify_10:(c.verified || 0) >= 10,
    project_scan:(c.projects || 0) >= 1, first_hunt:(c.hunt_correct || 0) >= 1, perfect_round:(c.perfect_rounds || 0) >= 1,
    sqli_hunter:(c.hunt_SQLI || 0) >= 5, xss_hunter:(c.hunt_XSS || 0) >= 5, flow_tracker:(c.hunt_flow || 0) >= 3,
    lessons_5:Object.keys(P.lessons).length >= 5, lessons_all:Object.keys(P.lessons).length >= 23,
    streak_3:P.streak >= 3, streak_7:P.streak >= 7, gold:P.xp >= 900
  };
  for (const [id, ok] of Object.entries(rules)) if (ok && !P.badges[id]){ P.badges[id] = today(); got.push(BADGES.find(b => b.id === id)); }
  return got;
}

export function setName(name){ P.name = String(name || "").trim().slice(0, 30); save(); emit({ type:"name" }); }
export async function resetProgress(){ P = EMPTY(); try { await kv.del("progress"); } catch (e) {} emit({ type:"reset" }); }
