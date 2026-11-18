/* CodeShield — cross-line data-flow ("taint") tracking.
   Follows untrusted input from where it enters (request.args, req.query, $_GET …)
   through variable assignments, and reports when it reaches a dangerous call
   on a later line. Lightweight and intra-file: it follows straight assignments,
   not function calls or object fields. */
import { USER_INPUT, COMMENT_LINE } from "./rules.js";

/* dangerous calls, and what counts as a sanitiser for each */
export const SINKS = {
  PATH:{
    sink:/(?:(?<![\w.])open|\b(?:os|io|codecs)\.open|\b(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|send_file|sendFile|file_get_contents|fopen|readfile|unlink|include|include_once|require_once))\s*\(|\b(include|require)(_once)?\s+\$/,
    safe:/basename|secure_filename|realpath|path\.normalize\([^)]*\)\.startsWith/
  },
  SSRF:{
    sink:/\b(requests\.(get|post|put|request)|urlopen|fetch|axios(\.(get|post|request))?|https?\.get|got|curl_init|file_get_contents|HttpClient)\s*\(/,
    safe:/ALLOWED_HOSTS|allowed_hosts|allowlist/i
  },
  REDIRECT:{
    sink:/\b(redirect|res\.redirect|HttpResponseRedirect|redirect_to|sendRedirect)\s*\(|header\s*\(\s*["']Location:/i,
    safe:/url_for\(|reverse\(|startswith\(\s*["']\/["']\s*\)|startsWith\(\s*["']\/["']\s*\)|str_starts_with\(|is_safe_url|url_has_allowed_host/
  },
  SSTI:{
    sink:/\b(render_template_string|Template|from_string|ejs\.render|Handlebars\.compile|pug\.render|nunjucks\.renderString)\s*\(/,
    safe:/(?!)/
  },
  XSS:{
    sink:/^\s*(echo|print)\s+[$"'(]|\bres\.(send|write)\s*\(|\.innerHTML\s*\+?=|\bdocument\.write(ln)?\s*\(/,
    safe:/htmlspecialchars|htmlentities|escapeHtml|escape\(|DOMPurify|sanitize|textContent|createTextNode/i
  }
};

/* anything wrapped in one of these is no longer treated as raw input */
const CLEAN = /\b(int|float|bool|parseInt|parseFloat|Number|Boolean|intval|floatval|abs|len|basename|secure_filename|htmlspecialchars|htmlentities|escape|escapeHtml|shlex\.quote|escapeshellarg|encodeURIComponent|uuid)\s*\(/;

const varRe = (v, lang) => lang === "php" ? new RegExp("\\$" + v + "\\b") : new RegExp("(^|[^\\w$.])" + v.replace(/\$/g, "\\$") + "\\b");

function assignment(line, lang){
  let m;
  if (lang === "php"){
    if ((m = line.match(/^\s*\$(\w+)\s*(?:\.=|=)(?!=)\s*(.+?);?\s*$/))) return { names:[m[1]], rhs:m[2] };
    return null;
  }
  if ((m = line.match(/^\s*(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(.+?);?\s*$/)))
    return { names:m[1].split(",").map(s => s.split(":").pop().split("=")[0].trim()).filter(Boolean), rhs:m[2] };
  if ((m = line.match(/^\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*(?:\+=|=)(?!=)\s*(.+?);?\s*$/)))
    return { names:[m[1]], rhs:m[2] };
  if (lang === "python" && (m = line.match(/^\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*)\s*=\s*(.+)$/)))
    return { names:[m[1], m[2]], rhs:m[3] };
  return null;
}

/* Returns flow findings: { kind, line (1-based), raw, var, sourceLine } */
export function taintScan(lines, lang, skip = new Set()){
  const tainted = new Map();       // name -> line where it became tainted
  const guarded = new Set();       // "name:KIND" pairs that passed a sanitiser check
  const out = [];
  lines.forEach((raw, i) => {
    if (!raw.trim() || COMMENT_LINE.test(raw) || raw.length > 2000) return;
    const a = assignment(raw, lang);
    if (a){
      const fromInput = USER_INPUT.test(a.rhs) || [...tainted.keys()].some(v => varRe(v, lang).test(a.rhs));
      const cleaned = CLEAN.test(a.rhs);
      a.names.forEach(n => {
        if (fromInput && !cleaned){
          tainted.set(n, tainted.get(n) || (i + 1));
          if (!varRe(n, lang).test(a.rhs)) [...guarded].forEach(g => { if (g.startsWith(n + ":")) guarded.delete(g); });
        }
        else if (!/\+=|\.=/.test(raw)) tainted.delete(n);
      });
      // an assignment line can still be a sink, e.g. data = requests.get(url)
    }
    if (!tainted.size) return;
    // a guard such as `if not nxt.startswith("/")` or an allow-list check sanitises that variable for that sink kind
    for (const [kind, s] of Object.entries(SINKS)){
      if (!s.safe.test(raw) || s.sink.test(raw)) continue;
      [...tainted.keys()].forEach(n => { if (varRe(n, lang).test(raw)) guarded.add(`${n}:${kind}`); });
    }
    if (USER_INPUT.test(raw)) return;   // direct input is handled by the line rules
    for (const [kind, s] of Object.entries(SINKS)){
      if (skip.has(`${kind}@${i + 1}`)) continue;
      const m = s.sink.exec(raw);
      if (!m || s.safe.test(raw)) continue;
      const after = raw.slice(m.index);
      const v = [...tainted.keys()].find(n => !guarded.has(`${n}:${kind}`) && varRe(n, lang).test(after) && !(a && a.names.includes(n) && !varRe(n, lang).test(a.rhs)));
      if (!v) continue;
      out.push({ kind, line:i + 1, raw, var:v, sourceLine:tainted.get(v) });
    }
  });
  return out;
}

/* Does `code` still let tainted variable `v` reach a `kind` sink? Used by the Proof Lab. */
export function flowStillOpen(kind, code, v, lang){
  const s = SINKS[kind];
  if (s.safe.test(code)) return false;
  return code.split(/\r?\n/).some(ln => {
    const m = s.sink.exec(ln);
    return m && varRe(v, lang).test(ln.slice(m.index));
  });
}

/* Suggested fix for a flow finding */
export function flowPatch(kind, raw, v, lang){
  const ind = (raw.match(/^\s*/) || [""])[0], l = raw.trim();
  const P = lang === "python", H = lang === "php";
  const ref = H ? "$" + v : v;
  switch (kind){
    case "PATH": {
      const safe = P ? `os.path.join(BASE_DIR, os.path.basename(${ref}))` : H ? `BASE_DIR . "/" . basename(${ref})` : `path.join(BASE_DIR, path.basename(${ref}))`;
      return ind + l.replace(H ? new RegExp("\\$" + v + "\\b") : new RegExp("\\b" + v + "\\b"), safe);
    }
    case "SSRF":
      if (P) return `${ind}if urlparse(${ref}).scheme != "https" or urlparse(${ref}).hostname not in ALLOWED_HOSTS: raise ValueError("host not allowed")\n${raw}`;
      if (H) return `${ind}if (!in_array(parse_url(${ref}, PHP_URL_HOST), ALLOWED_HOSTS, true)) { exit("host not allowed"); }\n${raw}`;
      return `${ind}if (!ALLOWED_HOSTS.includes(new URL(${ref}).hostname)) throw new Error("host not allowed");\n${raw}`;
    case "REDIRECT":
      if (P) return `${ind}${ref} = ${ref} if ${ref}.startswith("/") and not ${ref}.startswith("//") else "/"\n${raw}`;
      if (H) return `${ind}${ref} = (str_starts_with(${ref}, "/") && !str_starts_with(${ref}, "//")) ? ${ref} : "/";\n${raw}`;
      return `${ind}${ref} = (String(${ref}).startsWith("/") && !String(${ref}).startsWith("//")) ? ${ref} : "/";\n${raw}`;
    case "SSTI":
      if (P && /render_template_string\s*\(/.test(l)) return ind + l.replace(/render_template_string\s*\(/, `render_template("page.html", data=`);
      return null;
    case "XSS":
      if (H) return ind + l.replace(new RegExp("\\$" + v + "\\b"), `htmlspecialchars($${v}, ENT_QUOTES, "UTF-8")`);
      if (/\.innerHTML\s*\+?=/.test(l)) return ind + l.replace(/\.innerHTML(\s*\+?=)/, ".textContent$1");
      if (/\bres\.(send|write)\s*\(/.test(l)) return ind + l.replace(new RegExp("\\b" + v + "\\b"), `escapeHtml(${v})`);
      if (/document\.write/.test(l)) return `${ind}document.body.append(document.createTextNode(${v}));`;
      if (P) return ind + l.replace(new RegExp("\\b" + v + "\\b"), `escape(${v})`);
      return null;
  }
  return null;
}
