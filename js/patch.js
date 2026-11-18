function envName(n){ return n.replace(/([a-z])([A-Z])/g, "$1_$2").replace(/[^A-Za-z0-9]/g, "_").toUpperCase(); }

/* the user-controlled expression on a line, e.g. request.args.get("next") or $_GET['url'] */
function inputExpr(l){
  const m = l.match(/request\.(?:args|form|values)\.get\([^)]*\)|request\.(?:args|form|values|GET|POST|cookies)\[[^\]]+\]|req\.(?:query|body|params|headers)(?:\.\w+|\[[^\]]+\])|\$_(?:GET|POST|REQUEST|COOKIE)\[[^\]]+\]/);
  return m ? m[0] : null;
}

export function autoPatch(ruleId, raw, lang){
  const ind = (raw.match(/^\s*/) || [""])[0];
  const l = raw.trim();
  const P = lang === "python", H = lang === "php", R = lang === "ruby", S = lang === "shell";
  let m;
  switch (ruleId){
    case "SQLI": {
      const ph = P ? "%s" : "?";
      const wrap = v => P ? `(${v},)` : `[${v}]`;
      if (H && (m = l.match(/^\$(\w+)\s*=\s*(["'])(.*?)\2\s*\.\s*(\$[\w\[\]'"]+)\s*;?$/)))
        return `${ind}$stmt = $pdo->prepare("${m[3]}?");\n${ind}$stmt->execute([${m[4]}]);`;
      if ((m = l.match(/^((?:const|let|var)\s+)?(\w+)\s*=\s*(["'])(.*?)\3\s*\+\s*([\w.]+)\s*;?$/))){
        const decl = m[1] || "";
        return P ? `${ind}${m[2]}, params = "${m[4]}${ph}", ${wrap(m[5])}`
                 : `${ind}${decl}${m[2]} = "${m[4]}${ph}";\n${ind}${decl || "const "}${m[2]}Params = ${wrap(m[5])};`;
      }
      if ((m = l.match(/^(.*?\(\s*)(["'])(.*?)\2\s*\+\s*([\w.]+)\s*\)(.*)$/)))
        return `${ind}${m[1]}"${m[3]}${ph}", ${wrap(m[4])})${m[5]}`;
      if ((m = l.match(/^(.*?)f(["'])(.*?)\{(\w+)\}(.*?)\2(.*)$/)))
        return `${ind}${m[1]}"${m[3]}%s${m[5]}", (${m[4]},)${m[6]}`;
      if ((m = l.match(/^(.*?)`(.*?)\$\{([\w.]+)\}(.*?)`(.*)$/)))
        return `${ind}${m[1]}"${m[2]}?${m[4]}", [${m[3]}]${m[5]}`;
      return null;
    }
    case "WEAKHASH": {
      // balanced-parenthesis call: returns { start, end, args } for the first match of `re`
      const call = re => {
        const mm = re.exec(l); if (!mm) return null;
        let depth = 1, i = mm.index + mm[0].length;
        for (; i < l.length && depth; i++){ if (l[i] === "(") depth++; else if (l[i] === ")") depth--; }
        if (depth) return null;
        return { start:mm.index, end:i, args:l.slice(mm.index + mm[0].length, i - 1) };
      };
      let c;
      if (P && (c = call(/hashlib\.(?:md5|sha1)\s*\(/))){
        const tail = l.slice(c.end).replace(/^\.hexdigest\(\)/, "");
        return `${ind}${l.slice(0, c.start)}bcrypt.hashpw(${c.args}, bcrypt.gensalt()).decode()${tail}`;
      }
      if (H && (c = call(/\b(?:md5|sha1)\s*\(/)))
        return `${ind}${l.slice(0, c.start)}password_hash(${c.args}, PASSWORD_DEFAULT)${l.slice(c.end)}`;
      if (/createHash\s*\(\s*["'](md5|sha1)["']/i.test(l))
        return ind + l.replace(/createHash\s*\(\s*["'](md5|sha1)["']\s*\)/i, `createHash("sha256")`);
      if (/MessageDigest\.getInstance/.test(l))
        return ind + l.replace(/["'](MD5|SHA-?1)["']/i, `"SHA-256"`);
      return null;
    }
    case "SECRET": {
      if ((m = l.match(/^(.*?\b([A-Za-z_]\w*)["']?\s*[:=]\s*)(["'])[^"']*\3(.*)$/))){
        const n = envName(m[2]);
        const src = P ? `os.environ["${n}"]` : H ? `getenv("${n}")` : R ? `ENV.fetch("${n}")` : S ? `"\${${n}}"` : `process.env.${n}`;
        return `${ind}${m[1]}${src}${m[4]}`;
      }
      if ((m = l.match(/^([A-Z][A-Z0-9_]*)\s*=\s*\S+$/))) return `${ind}${m[1]}=\${${m[1]}}`;
      return null;
    }
    case "CMDI": {
      const argv = (str, v) => str.trim().split(/\s+/).filter(Boolean).map(a => `"${a}"`).concat(v ? [v] : []);
      if ((m = l.match(/^(.*?)(?:os\.system|subprocess\.(?:run|call|Popen|check_output))\(\s*(["'])(.*?)\2\s*\+\s*([\w.]+)\s*(?:,\s*shell\s*=\s*True\s*)?\)(.*)$/)))
        return `${ind}${m[1]}subprocess.run([${argv(m[3], m[4]).join(", ")}], check=True)${m[5]}`;
      if ((m = l.match(/^(.*?)child_process\.(?:exec|execSync)\(\s*(["'`])(.*?)\2\s*\+\s*([\w.]+)\s*\)(.*)$/))){
        const a = argv(m[3], m[4]);
        return `${ind}${m[1]}child_process.execFile(${a[0]}, [${a.slice(1).join(", ")}])${m[5]}`;
      }
      if (S && (m = l.match(/^eval\s+"(.*)"$/))) return ind + m[1].split(/\s+/).map(a => /^\$/.test(a) ? `"${a}"` : a).join(" ");
      if (P && /\beval\s*\(/.test(l)) return ind + l.replace(/\beval\s*\(/, "ast.literal_eval(");
      if (/\beval\s*\(/.test(l)) return ind + l.replace(/\beval\s*\(/, "JSON.parse(");
      return null;
    }
    case "XSS": {
      if (/\.innerHTML\s*\+?=/.test(l)) return ind + l.replace(/\.innerHTML(\s*\+?=)/, ".textContent$1");
      if ((m = l.match(/^(.*?)\.outerHTML\s*=\s*(.*?);?$/))) return `${ind}${m[1]}.replaceWith(document.createTextNode(${m[2]}));`;
      if ((m = l.match(/document\.write(?:ln)?\s*\((.*)\)\s*;?$/))) return `${ind}document.body.append(document.createTextNode(${m[1]}));`;
      if ((m = l.match(/<(\w+)([^>]*?)\s*dangerouslySetInnerHTML=\{\{\s*__html:\s*(.*?)\s*\}\}\s*\/>/)))
        return ind + l.replace(m[0], `<${m[1]}${m[2]}>{${m[3]}}</${m[1]}>`);
      if (/\bv-html\s*=/.test(l)) return ind + l.replace(/\bv-html\s*=/, "v-text=");
      if ((m = l.match(/\becho\s+(\$_(?:GET|POST|REQUEST)\[[^\]]+\])/)))
        return ind + l.replace(m[0], `echo htmlspecialchars(${m[1]}, ENT_QUOTES, "UTF-8")`);
      return null;
    }
    case "DESERIAL":
      if (/\bc?[Pp]ickle\.loads?\s*\(/.test(l)) return ind + l.replace(/\bc?[Pp]ickle\.loads?\s*\(/, "json.loads(");
      if (/\byaml\.load\s*\(/.test(l)) return ind + l.replace(/\byaml\.load\s*\(/, "yaml.safe_load(").replace(/,\s*Loader\s*=\s*[\w.]+/, "");
      if (/\bMarshal\.load\s*\(/.test(l)) return ind + l.replace(/\bMarshal\.load\s*\(/, "JSON.parse(");
      if (/\bunserialize\s*\(/.test(l)) return ind + l.replace(/\bunserialize\s*\((.*?)\)/, "json_decode($1, true)");
      return null;
    case "TLSOFF":
      return ind + l.replace(/\bverify\s*=\s*False\b/, "verify=True")
        .replace(/rejectUnauthorized\s*:\s*false/i, "rejectUnauthorized: true")
        .replace(/InsecureSkipVerify\s*:\s*true/i, "InsecureSkipVerify: false")
        .replace(/(NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?)0/, "$11")
        .replace(/(CURLOPT_SSL_VERIFYPEER\s*,\s*)(false|0)\b/i, "$1true")
        .replace(/(CURLOPT_SSL_VERIFYHOST\s*,\s*)(false|0)\b/i, "$12");
    case "WEAKRAND": {
      if ((m = l.match(/random\.randint\(\s*(\d+)\s*,\s*(\d+)\s*\)/)))
        return ind + l.replace(m[0], `secrets.randbelow(${Number(m[2]) - Number(m[1]) + 1}) + ${m[1]}`);
      if (/random\.(random|randint|choice|randrange)\s*\(/.test(l))
        return ind + l.replace(/random\.(random|randint|choice|randrange)\s*\([^)]*\)/, "secrets.token_urlsafe(32)");
      if ((m = l.match(/^(.*?[:=]\s*)([^;\n]*Math\.random\s*\([^;\n]*?)(;?)$/))) return `${ind}${m[1]}crypto.randomUUID()${m[3]}`;
      return null;
    }
    case "UPLOAD":
      if (/move_uploaded_file\s*\(/.test(l))
        return `${ind}$ext = strtolower(pathinfo($_FILES["file"]["name"], PATHINFO_EXTENSION));\n` +
               `${ind}if (in_array($ext, ["jpg", "png", "pdf"], true)) { move_uploaded_file($_FILES["file"]["tmp_name"], "/var/uploads/" . bin2hex(random_bytes(16)) . "." . $ext); }`;
      return null;

    /* ---------- v0.3 rules ---------- */
    case "PATH": {
      const mm = /\b(open|readFile|readFileSync|createReadStream|writeFile|writeFileSync|send_file|sendFile|file_get_contents|fopen|readfile|unlink|include|include_once|require_once)\s*\(/.exec(l);
      if (!mm) return null;
      let depth = 1, i = mm.index + mm[0].length, comma = -1;
      for (; i < l.length && depth; i++){
        const ch = l[i];
        if (ch === "(" || ch === "[" || ch === "{") depth++;
        else if (ch === ")" || ch === "]" || ch === "}") depth--;
        else if (ch === "," && depth === 1 && comma < 0) comma = i;
      }
      if (depth) return null;
      const a0 = mm.index + mm[0].length, aEnd = comma > 0 ? comma : i - 1;
      const arg = l.slice(a0, aEnd).trim();
      const safe = P ? `os.path.join(BASE_DIR, os.path.basename(${arg}))`
                 : H ? `BASE_DIR . "/" . basename(${arg})`
                 : `path.join(BASE_DIR, path.basename(${arg}))`;
      return `${ind}${l.slice(0, a0)}${safe}${l.slice(aEnd)}`;
    }
    case "REDIRECT": {
      const x = inputExpr(l); if (!x) return null;
      if (P) return `${ind}next_url = ${x}\n${ind}${l.replace(x, `(next_url if next_url.startswith("/") and not next_url.startswith("//") else "/")`)}`;
      if (H) return `${ind}$next = ${x} ?? "/";\n${ind}${l.replace(x, `((str_starts_with($next, "/") && !str_starts_with($next, "//")) ? $next : "/")`)}`;
      return `${ind}const nextUrl = String(${x} || "/");\n${ind}${l.replace(x, `(nextUrl.startsWith("/") && !nextUrl.startsWith("//") ? nextUrl : "/")`)}`;
    }
    case "SSRF": {
      const x = inputExpr(l); if (!x) return null;
      if (P) return `${ind}target = urlparse(${x})\n${ind}if target.scheme != "https" or target.hostname not in ALLOWED_HOSTS: raise ValueError("host not allowed")\n${ind}${l.replace(x, "target.geturl()")}`;
      if (H) return `${ind}$target = ${x};\n${ind}if (!in_array(parse_url($target, PHP_URL_HOST), ALLOWED_HOSTS, true)) { exit("host not allowed"); }\n${ind}${l.replace(x, "$target")}`;
      return `${ind}const target = new URL(${x});\n${ind}if (target.protocol !== "https:" || !ALLOWED_HOSTS.includes(target.hostname)) throw new Error("host not allowed");\n${ind}${l.replace(x, "target.href")}`;
    }
    case "DEBUG":
      if (/\bdebug\s*=\s*True/.test(l)) return ind + l.replace(/\bdebug\s*=\s*True/, `debug=os.environ.get("FLASK_DEBUG") == "1"`);
      if (/^DEBUG\s*=\s*True/.test(l)) return ind + l.replace(/DEBUG\s*=\s*True/, `DEBUG = os.environ.get("DEBUG") == "1"`);
      if (/display_errors/i.test(l)) return ind + l.replace(/(["']?)(1|On|true)(["']?)(\s*\)?\s*;?\s*)$/i, "$10$3$4");
      return null;
    case "CORS":
      if (/\bCORS\s*\(\s*app\s*\)/.test(l)) return ind + l.replace(/\bCORS\s*\(\s*app\s*\)/, `CORS(app, origins=["https://your-domain.example"])`);
      if (/\bcors\s*\(\s*\)/.test(l)) return ind + l.replace(/\bcors\s*\(\s*\)/, `cors({ origin: ["https://your-domain.example"] })`);
      if (/CORS_(ORIGIN_ALLOW_ALL|ALLOW_ALL_ORIGINS)\s*=\s*True/.test(l)) return ind + l.replace(/=\s*True/, "= False");
      return ind + l.replace(/(["'])\*\1/, `"https://your-domain.example"`).replace(/(Access-Control-Allow-Origin:\s*)\*/i, "$1https://your-domain.example");
    case "JWT":
      if (/verify_signature["']?\s*:\s*False/.test(l)) return ind + l.replace(/(verify_signature["']?\s*:\s*)False/, "$1True");
      if (/\bverify\s*=\s*False/.test(l)) return ind + l.replace(/\bverify\s*=\s*False/, `algorithms=["HS256"]`);
      if (/["']none["']/i.test(l)) return ind + l.replace(/(["'])none\1/i, `"HS256"`);
      return null;
    case "CIPHER":
      return ind + l.replace(/\b(DES3|DES|ARC4|RC4|Blowfish)\.new\s*\(/, "AES.new(")
        .replace(/\b(?:DES3|DES|ARC4|RC4|Blowfish|AES)\.MODE_\w+/, "AES.MODE_GCM").replace(/\bMODE_ECB\b/, "MODE_GCM")
        .replace(/(["'])(des[\w-]*|rc4|bf[\w-]*|aes-\d+-ecb)\1/i, `"aes-256-gcm"`)
        .replace(/Cipher\.getInstance\s*\(\s*["'][^"']*["']/, `Cipher.getInstance("AES/GCM/NoPadding"`);
    case "XXE":
      return ind + l.replace(/resolve_entities\s*=\s*True/, "resolve_entities=False").replace(/load_dtd\s*=\s*True/, "load_dtd=False")
        .replace(/\s*\|\s*LIBXML_NOENT\b|\bLIBXML_NOENT\s*\|\s*/, "").replace(/\bLIBXML_NOENT\b/, "LIBXML_NONET")
        .replace(/libxml_disable_entity_loader\s*\(\s*false/i, "libxml_disable_entity_loader(true")
        .replace(/(external-general-entities["']\s*,\s*)true/, "$1false").replace(/\bnoent\s*:\s*true/, "noent: false");
    case "COOKIE":
      return ind + l.replace(/\b(secure|httponly|httpOnly|http_only)(\s*[=:]\s*)False\b/g, "$1$2True")
        .replace(/\b(secure|httponly|httpOnly|http_only)(\s*[=:]\s*)false\b/g, "$1$2true")
        .replace(/(SESSION_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*)False/, "$1True")
        .replace(/(session\.cookie_(?:secure|httponly)["']?\s*,?\s*=?\s*["']?)(0|false|Off)/i, "$11");
    case "NOSQL":
      if (/["']?\$where["']?\s*:/.test(l)) return null;
      return ind + l.replace(/\(\s*req\.(body|query|params)\s*([,)])/, "(mongoSanitize.sanitize(req.$1)$2");
    case "CLEARTEXT":
      return ind + l.replace(/(["'`])http:\/\/(?!localhost|127\.0\.0\.1)/g, "$1https://").replace(/(["'`])ws:\/\/(?!localhost|127\.0\.0\.1)/g, "$1wss://");
    case "SSTI":
      if (P && (m = l.match(/render_template_string\s*\((.*)\)/))) return ind + l.replace(m[0], `render_template("page.html", data=${m[1]})`);
      return null;
    case "TEMPFILE":
      if (/tempfile\.mktemp\s*\(/.test(l)) return ind + l.replace(/(\w+)\s*=\s*tempfile\.mktemp\s*\(/, "_fd, $1 = tempfile.mkstemp(").replace(/tempfile\.mktemp\s*\(/, "tempfile.mkstemp(");
      return null;
    case "PERMS":
      return ind + l.replace(/\b0o777\b/, "0o755").replace(/\b0777\b/, "0755").replace(/(chmod\s+(?:-R\s+)?)777\b/, "$1755")
        .replace(/(chmod\s+(?:-R\s+)?)a\+rwx/, "$1u+rwx,go+rx").replace(/\bumask\s*\(\s*0+\s*\)/, "umask(0o077)")
        .replace(/(chmod(?:Sync)?\s*\([^)]*?)\b777\b/, "$1755");
  }
  return null;
}

