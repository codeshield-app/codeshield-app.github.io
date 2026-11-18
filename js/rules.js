/* CodeShield — detection rules. Each rule: id, CWE, OWASP, severity, bilingual text, and a line test. */
export const RESOLVED_FROM_ENV = /(getenv|environ|process\.env|dotenv|\$\{|\$\(|vault|secret_?manager|keyvault|ssm|<[A-Z_]+>|\bNone\b|\bnull\b|\bnil\b)/i;

export const RULES = [
  {
    id:"SQLI", cwe:"CWE-89", owasp:"A03:2021 — Injection", severity:"HIGH",
    en:"SQL Injection", ar:"حقن SQL",
    why_en:"The query is assembled by joining raw user input into a SQL string. An attacker who controls that input controls the query, and can read, modify or destroy the whole table.",
    why_ar:"يُبنى الاستعلام بدمج مدخل المستخدم مباشرة داخل نص SQL. من يتحكّم بهذا المدخل يتحكّم بالاستعلام، فيستطيع قراءة الجدول كاملًا أو تعديله أو حذفه.",
    fix_en:"Use a parameterized query. Pass values as bound parameters so the database never treats them as SQL syntax.",
    fix_ar:"استخدم استعلامًا معلمنًا (parameterized). مرّر القيم كمعاملات مربوطة حتى لا تتعامل معها قاعدة البيانات كأوامر SQL.",
    test:(l) => {
      const sql = /["'`]/.test(l) && (
        /\bSELECT\b[^"'`]*\bFROM\b/i.test(l) || /\bINSERT\s+INTO\b/i.test(l) ||
        /\bUPDATE\b[^"'`]*\bSET\b/i.test(l) || /\bDELETE\s+FROM\b/i.test(l) ||
        /\bWHERE\b[^"'`]*=/i.test(l)
      );
      if (!sql) return false;
      return /["'`]\s*(\+|\.)\s*[\w$]/.test(l)
        || /\bf["'][^"']*\b(SELECT|INSERT|UPDATE|DELETE)\b[^"']*\{/i.test(l)
        || /["'`]\s*%\s*[\w(]/.test(l)
        || /\$\{[^}]+\}/.test(l)
        || /\$_(GET|POST|REQUEST)\[/.test(l);
    }
  },
  {
    id:"WEAKHASH", cwe:"CWE-327", owasp:"A02:2021 — Cryptographic Failures", severity:"MEDIUM",
    en:"Weak Hashing Algorithm", ar:"خوارزمية تجزئة ضعيفة",
    why_en:"MD5 and SHA-1 are broken for security use. They are fast to compute, which makes brute-forcing stored password hashes cheap, and practical collisions exist.",
    why_ar:"خوارزميتا MD5 وSHA-1 مكسورتان أمنيًا. حسابهما سريع جدًا، ما يجعل تخمين كلمات المرور المخزَّنة رخيصًا، كما أن تصادماتهما العملية معروفة.",
    fix_en:"For passwords use bcrypt, scrypt or Argon2 with a per-user salt. For integrity checks use SHA-256 or stronger.",
    fix_ar:"لكلمات المرور استخدم bcrypt أو scrypt أو Argon2 مع ملح (salt) لكل مستخدم. وللتحقق من السلامة استخدم SHA-256 أو أقوى.",
    test:(l) => /\b(hashlib\.)?(md5|sha1)\s*\(/i.test(l)
      || /MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-?1)["']/i.test(l)
      || /createHash\s*\(\s*["'](md5|sha1)["']/i.test(l)
  },
  {
    id:"SECRET", cwe:"CWE-798", owasp:"A07:2021 — Identification & Authentication Failures", severity:"HIGH",
    en:"Hardcoded Credentials", ar:"بيانات اعتماد مكتوبة في الكود",
    why_en:"A live key or password written into source code is exposed to everyone with repository access, survives in git history forever, and leaks instantly if the repo is ever made public.",
    why_ar:"المفتاح أو كلمة المرور المكتوبة داخل الشيفرة مكشوفة لكل من يملك صلاحية على المستودع، وتبقى في سجلّ git إلى الأبد، وتتسرّب فورًا إذا أصبح المستودع عامًا.",
    fix_en:"Move the value to an environment variable or a secrets manager, and rotate the exposed credential immediately — it must be considered compromised.",
    fix_ar:"انقل القيمة إلى متغيّر بيئة أو مدير أسرار، وغيّر بيانات الاعتماد المكشوفة فورًا — يجب اعتبارها مخترقة.",
    test:(l) => /\b(sk_live_|sk_test_|ghp_|gho_|github_pat_)[A-Za-z0-9_]{6,}/.test(l)
      || /\bAKIA[0-9A-Z]{16}\b/.test(l)
      || /\bAIza[0-9A-Za-z\-_]{20,}/.test(l)
      || /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/.test(l)
      || (/\b(password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?key)\b\s*[:=]\s*["'][^"']{6,}["']/i.test(l) && !RESOLVED_FROM_ENV.test(l))
      || (/^\s*(export\s+)?(DB_PASSWORD|DB_PASS|API_KEY|SECRET_KEY|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY|AUTH_TOKEN)\s*=\s*["']?[^\s"'()]{6,}["']?\s*$/.test(l) && !RESOLVED_FROM_ENV.test(l))
  },
  {
    id:"CMDI", cwe:"CWE-78", owasp:"A03:2021 — Injection", severity:"HIGH",
    en:"Command / Code Injection", ar:"حقن أوامر أو تنفيذ كود",
    why_en:"User-controlled text reaches a shell or an evaluator. A single ';' or '&&' lets an attacker run arbitrary commands with the privileges of your process.",
    why_ar:"نص يتحكّم به المستخدم يصل إلى الشِل أو إلى مُقيّم كود. حرف ';' أو '&&' واحد يكفي ليشغّل المهاجم أوامر عشوائية بصلاحيات عمليتك.",
    fix_en:"Never build a shell string. Pass the command and its arguments as an array with shell disabled, and drop eval entirely.",
    fix_ar:"لا تبنِ نص أمر للشِل أبدًا. مرّر الأمر ومعاملاته كمصفوفة مع تعطيل الشِل، واستغنِ عن eval كليًا.",
    test:(l) => /\beval\s*[\(\s]/.test(l)
      || /\bos\.system\s*\(/.test(l)
      || /\bsubprocess\.(run|call|Popen|check_output)\s*\(.*shell\s*=\s*True/.test(l)
      || /\bchild_process\.(exec|execSync)\s*\(/.test(l)
      || /\b(shell_exec|passthru|proc_open|popen)\s*\(/.test(l)
      || /\bsystem\s*\(\s*\$/.test(l)
      || /\bnew\s+Function\s*\(/.test(l)
      || /\.\s*(exec|execSync|spawn|spawnSync)\s*\(\s*["'`][^"'`]*["'`]\s*\+/.test(l)
  },
  {
    id:"XSS", cwe:"CWE-79", owasp:"A03:2021 — Injection", severity:"HIGH",
    en:"Cross-Site Scripting (XSS)", ar:"برمجة عابرة للمواقع (XSS)",
    why_en:"Untrusted content is written into the page as HTML rather than as text, so any script inside it executes with the full privileges of your origin — including access to session cookies.",
    why_ar:"يُكتب محتوى غير موثوق في الصفحة كـ HTML لا كنص، فينفَّذ أي سكربت بداخله بكامل صلاحيات نطاقك — بما في ذلك الوصول إلى كعكات الجلسة.",
    fix_en:"Assign through textContent, or render as escaped text. If HTML is genuinely required, sanitize with a vetted library such as DOMPurify.",
    fix_ar:"استخدم textContent للإسناد، أو اعرض المحتوى كنص مُهرَّب. وإن كان HTML ضروريًا فعلًا، فنقِّه بمكتبة موثوقة مثل DOMPurify.",
    test:(l) => /dangerouslySetInnerHTML/.test(l)
      || /\.innerHTML\s*(\+)?=/.test(l)
      || /\bdocument\.write(ln)?\s*\(/.test(l)
      || /\bv-html\s*=/.test(l)
      || /\becho\s+\$_(GET|POST|REQUEST)/.test(l)
      || /\.outerHTML\s*=/.test(l)
  },
  {
    id:"DESERIAL", cwe:"CWE-502", owasp:"A08:2021 — Software & Data Integrity Failures", severity:"HIGH",
    en:"Insecure Deserialization", ar:"فك تسلسل غير آمن",
    why_en:"These functions rebuild arbitrary objects from a byte stream. A crafted payload can trigger code execution during deserialization itself — before any of your validation runs.",
    why_ar:"تعيد هذه الدوال بناء كائنات عشوائية من تدفّق بايتات. حمولة مُصمَّمة بعناية قد تُنفّذ كودًا أثناء فك التسلسل نفسه — قبل أن يعمل أي تحقّق لديك.",
    fix_en:"Use a data-only format such as JSON, or the library's safe loader (yaml.safe_load, JSON.parse), and validate the resulting shape against a schema.",
    fix_ar:"استخدم صيغة بيانات فقط مثل JSON، أو المُحمِّل الآمن للمكتبة (yaml.safe_load أو JSON.parse)، ثم تحقّق من بنية الناتج مقابل مخطّط محدّد.",
    test:(l) => /\bpickle\.loads?\s*\(/.test(l)
      || /\bMarshal\.load\s*\(/.test(l)
      || /\bunserialize\s*\(/.test(l)
      || (/\byaml\.load\s*\(/.test(l) && !/SafeLoader|safe_load/.test(l))
      || /\bcPickle\.loads?\s*\(/.test(l)
  },
  {
    id:"TLSOFF", cwe:"CWE-295", owasp:"A02:2021 — Cryptographic Failures", severity:"HIGH",
    en:"TLS Verification Disabled", ar:"تعطيل التحقق من شهادة TLS",
    why_en:"With certificate verification switched off, the connection is still encrypted but no longer authenticated. Anyone positioned on the network can present their own certificate and read or alter the traffic.",
    why_ar:"مع تعطيل التحقق من الشهادة يبقى الاتصال مشفّرًا لكنه غير موثّق. أي طرف على المسار الشبكي يستطيع تقديم شهادته الخاصة وقراءة البيانات أو تعديلها.",
    fix_en:"Re-enable verification. If the target uses an internal certificate authority, add that CA to the trust store instead of disabling the check.",
    fix_ar:"أعد تفعيل التحقق. وإذا كان الطرف المقابل يستخدم سلطة شهادات داخلية، فأضف تلك السلطة إلى مخزن الثقة بدل تعطيل التحقق.",
    test:(l) => (/\bverify\s*=\s*False\b/.test(l) && !/\bjwt\b/i.test(l))
      || /rejectUnauthorized\s*:\s*false/i.test(l)
      || /InsecureSkipVerify\s*:\s*true/i.test(l)
      || /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0/.test(l)
      || /CURLOPT_SSL_VERIFY(PEER|HOST)\s*,\s*(false|0)\b/i.test(l)
  },
  {
    id:"WEAKRAND", cwe:"CWE-338", owasp:"A02:2021 — Cryptographic Failures", severity:"MEDIUM",
    en:"Weak Randomness for a Security Value", ar:"عشوائية ضعيفة لقيمة أمنية",
    why_en:"General-purpose random generators are predictable. Given a few outputs, an attacker can recover the internal state and compute every future token — including password-reset links.",
    why_ar:"مولّدات العشوائية العامة قابلة للتنبؤ. من عدد قليل من المخرجات يستطيع المهاجم استرجاع الحالة الداخلية وحساب كل رمز لاحق — بما في ذلك روابط إعادة تعيين كلمة المرور.",
    fix_en:"Use a cryptographically secure source: secrets.token_urlsafe in Python, crypto.randomBytes in Node, or crypto.getRandomValues in the browser.",
    fix_ar:"استخدم مصدرًا عشوائيًا آمنًا تشفيريًا: secrets.token_urlsafe في بايثون، أو crypto.randomBytes في نود، أو crypto.getRandomValues في المتصفح.",
    test:(l) => /\b(token|password|secret|otp|nonce|session|salt|key|reset)\w*\s*[:=][^;\n]*\bMath\.random\s*\(/i.test(l)
      || /\b(token|password|secret|otp|nonce|session|salt|key|reset)\w*\s*[:=][^;\n]*\brandom\.(random|randint|choice|randrange)\s*\(/i.test(l)
  },
  {
    id:"UPLOAD", cwe:"CWE-434", owasp:"A04:2021 — Insecure Design", severity:"MEDIUM",
    en:"Unrestricted File Upload", ar:"رفع ملفات بدون قيود",
    why_en:"The uploaded file is stored under a name the user controls, with no extension check. Uploading a .php or .jsp file into a web-served directory turns the upload form into remote code execution.",
    why_ar:"يُخزَّن الملف المرفوع باسم يتحكّم به المستخدم دون التحقق من امتداده. رفع ملف ‎.php‎ أو ‎.jsp‎ إلى مجلد يخدمه الخادم يحوّل نموذج الرفع إلى تنفيذ كود عن بُعد.",
    fix_en:"Whitelist allowed extensions, generate the stored filename yourself, and keep the upload directory outside the web root with execution disabled.",
    fix_ar:"حدّد قائمة امتدادات مسموحة، وولّد اسم الملف المخزَّن بنفسك، واحفظ مجلد الرفع خارج جذر الويب مع تعطيل التنفيذ فيه.",
    test:(l) => (/\bmove_uploaded_file\s*\(/.test(l) && !/in_array|pathinfo|allowed|whitelist/i.test(l))
      || (/\$_FILES\[[^\]]*\]\[["']name["']\]/.test(l) && /(move_uploaded_file|fopen|file_put_contents)/.test(l))
  },

  /* ---------------- v0.3 rules ---------------- */
  {
    id:"PATH", cwe:"CWE-22", owasp:"A01:2021 — Broken Access Control", severity:"HIGH",
    en:"Path Traversal", ar:"اجتياز المسارات",
    why_en:"A file path is built from user input. Sending '../../etc/passwd' walks out of the intended folder and reads (or overwrites) any file the process can reach.",
    why_ar:"يُبنى مسار الملف من مدخل المستخدم. إرسال ‎'../../etc/passwd'‎ يخرج من المجلد المقصود ويقرأ (أو يكتب فوق) أي ملف تصل إليه العملية.",
    fix_en:"Never pass raw input to file APIs. Keep only the base name, resolve the full path, and reject it unless it stays inside the allowed directory.",
    fix_ar:"لا تمرّر المدخل الخام لدوال الملفات. خذ اسم الملف فقط، واحسب المسار الكامل، وارفضه إن خرج عن المجلد المسموح.",
    test:(l) => /(?:(?<![\w.])open|\b(?:os|io|codecs)\.open|\b(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|send_file|sendFile|file_get_contents|fopen|include|require_once|include_once|readfile|unlink))\s*\(/.test(l) && USER_INPUT.test(l)
      && !/basename|secure_filename|realpath|normalize\(.*startsWith/.test(l)
  },
  {
    id:"SSRF", cwe:"CWE-918", owasp:"A10:2021 — Server-Side Request Forgery", severity:"HIGH",
    en:"Server-Side Request Forgery (SSRF)", ar:"تزوير الطلبات من جهة الخادم (SSRF)",
    why_en:"The server fetches a URL the user supplies. An attacker can point it at internal services or cloud metadata endpoints (169.254.169.254) and read what only the server can see.",
    why_ar:"يجلب الخادم رابطًا يحدّده المستخدم. يستطيع المهاجم توجيهه إلى خدمات داخلية أو إلى عنوان بيانات السحابة (169.254.169.254) فيقرأ ما لا يراه إلا الخادم.",
    fix_en:"Allow only a fixed list of hosts, resolve the address and block private and link-local ranges, and never forward the raw user URL.",
    fix_ar:"اسمح بقائمة ثابتة من النطاقات فقط، وتحقّق من العنوان وامنع النطاقات الداخلية والخاصة، ولا تمرّر رابط المستخدم كما هو.",
    test:(l) => /\b(requests\.(get|post|put|request)|urlopen|urllib\.request|fetch|axios(\.(get|post|request))?|http\.get|https\.get|got|curl_init|file_get_contents|HttpClient)\s*\(/.test(l) && USER_INPUT.test(l)
  },
  {
    id:"REDIRECT", cwe:"CWE-601", owasp:"A01:2021 — Broken Access Control", severity:"MEDIUM",
    en:"Open Redirect", ar:"إعادة توجيه مفتوحة",
    why_en:"The redirect target comes straight from the request. Attackers send victims a link on your trusted domain that bounces them to a phishing page.",
    why_ar:"وجهة إعادة التوجيه مأخوذة مباشرة من الطلب. يرسل المهاجم للضحية رابطًا على نطاقك الموثوق يحوّله إلى صفحة تصيّد.",
    fix_en:"Redirect only to relative paths or to an allow-list of known destinations; map user choices to fixed URLs instead of accepting raw URLs.",
    fix_ar:"أعد التوجيه إلى مسارات نسبية أو إلى قائمة وجهات معروفة فقط، واربط اختيار المستخدم بروابط ثابتة بدل قبول الرابط الخام.",
    test:(l) => (/\b(redirect|res\.redirect|HttpResponseRedirect|redirect_to|sendRedirect)\s*\(/.test(l) || /header\s*\(\s*["']Location:/i.test(l)) && USER_INPUT.test(l) && !/url_for\(|reverse\(/.test(l)
  },
  {
    id:"DEBUG", cwe:"CWE-489", owasp:"A05:2021 — Security Misconfiguration", severity:"MEDIUM",
    en:"Debug Mode Enabled", ar:"وضع التصحيح مفعّل",
    why_en:"Debug mode shows stack traces, configuration and sometimes an interactive console to anyone who triggers an error. In production that is a free map of your system.",
    why_ar:"وضع التصحيح يعرض تفاصيل الأخطاء والإعدادات، وأحيانًا وحدة تحكّم تفاعلية، لأي شخص يسبّب خطأ. في بيئة الإنتاج هذه خريطة مجانية لنظامك.",
    fix_en:"Turn debug off in production and read the flag from an environment variable, so it can only be enabled on a developer machine.",
    fix_ar:"عطّل وضع التصحيح في الإنتاج، واقرأ قيمته من متغيّر بيئة حتى لا يُفعَّل إلا على جهاز المطوّر.",
    test:(l) => /\.run\s*\(.*\bdebug\s*=\s*True/.test(l) || /^\s*DEBUG\s*=\s*True\b/.test(l)
      || /display_errors["']?\s*,\s*["']?(1|On|true)/i.test(l) || /^\s*display_errors\s*=\s*(1|On)/i.test(l)
  },
  {
    id:"CORS", cwe:"CWE-942", owasp:"A05:2021 — Security Misconfiguration", severity:"MEDIUM",
    en:"Permissive CORS Policy", ar:"سياسة CORS مفتوحة للجميع",
    why_en:"Allowing every origin lets any website call your API from a visitor's browser. Combined with credentials, a malicious page can read the user's private data.",
    why_ar:"السماح لكل النطاقات يتيح لأي موقع استدعاء واجهتك من متصفح الزائر. ومع ملفات الاعتماد تستطيع صفحة خبيثة قراءة بيانات المستخدم الخاصة.",
    fix_en:"List the exact origins that may call the API instead of '*', and never combine a wildcard with credentials.",
    fix_ar:"حدّد النطاقات المسموح لها بالاسم بدل '*'، ولا تجمع أبدًا بين النجمة وملفات الاعتماد.",
    test:(l) => /Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']/i.test(l) || /Access-Control-Allow-Origin:\s*\*/i.test(l)
      || /\borigins?\s*[:=]\s*["']\*["']/.test(l) || /\bCORS\s*\(\s*app\s*\)/.test(l)
      || /CORS_(ORIGIN_ALLOW_ALL|ALLOW_ALL_ORIGINS)\s*=\s*True/.test(l) || /\bcors\s*\(\s*\)/.test(l)
  },
  {
    id:"JWT", cwe:"CWE-347", owasp:"A02:2021 — Cryptographic Failures", severity:"HIGH",
    en:"JWT Signature Not Verified", ar:"توقيع JWT غير مُتحقَّق منه",
    why_en:"The token is accepted without checking its signature (or with the 'none' algorithm). Anyone can forge a token that says they are an administrator.",
    why_ar:"يُقبل الرمز دون التحقق من توقيعه (أو بخوارزمية 'none'). أي شخص يستطيع تزوير رمز يقول إنه مدير النظام.",
    fix_en:"Always verify the signature with your secret or public key and pin the expected algorithm, e.g. algorithms=[\"HS256\"].",
    fix_ar:"تحقّق دائمًا من التوقيع بمفتاحك السري أو العام وثبّت الخوارزمية المتوقعة، مثل ‎algorithms=[\"HS256\"]‎.",
    test:(l) => /verify_signature["']?\s*:\s*False/.test(l) || (/\bjwt\b/i.test(l) && /\bverify\s*=\s*False\b/.test(l))
      || /\balgorithms?\s*[:=]\s*\[?\s*["']none["']/i.test(l) || /\bjwt\.decode\s*\([^)]*complete\s*:\s*true/.test(l)
  },
  {
    id:"CIPHER", cwe:"CWE-327", owasp:"A02:2021 — Cryptographic Failures", severity:"MEDIUM",
    en:"Weak Cipher or ECB Mode", ar:"تشفير ضعيف أو نمط ECB",
    why_en:"DES, RC4 and Blowfish are broken or too weak, and ECB mode encrypts identical blocks identically, leaking the structure of the data.",
    why_ar:"خوارزميات DES وRC4 وBlowfish مكسورة أو ضعيفة، ونمط ECB يشفّر الكتل المتطابقة بالشكل نفسه فيكشف بنية البيانات.",
    fix_en:"Use AES-256-GCM (or ChaCha20-Poly1305) with a fresh random IV for every message.",
    fix_ar:"استخدم AES-256-GCM (أو ChaCha20-Poly1305) مع متّجه ابتدائي (IV) عشوائي جديد لكل رسالة.",
    test:(l) => /\b(DES|DES3|ARC4|RC4|Blowfish)\.new\s*\(/.test(l) || /\bMODE_ECB\b/.test(l)
      || /createCipheriv?\s*\(\s*["'](des[\w-]*|rc4|bf[\w-]*|aes-\d+-ecb)["']/i.test(l)
      || /Cipher\.getInstance\s*\(\s*["'](DES|RC4|AES\/ECB|AES["'])/i.test(l)
      || /openssl_encrypt\s*\([^)]*["'](des[\w-]*|rc4|aes-\d+-ecb|bf[\w-]*)["']/i.test(l)
  },
  {
    id:"XXE", cwe:"CWE-611", owasp:"A05:2021 — Security Misconfiguration", severity:"HIGH",
    en:"XML External Entities (XXE)", ar:"كيانات XML خارجية (XXE)",
    why_en:"The XML parser is told to resolve external entities, so a crafted document can read local files or make the server send requests.",
    why_ar:"مُحلّل XML مضبوط على تحميل الكيانات الخارجية، فتستطيع وثيقة مُصمَّمة قراءة ملفات محلية أو جعل الخادم يرسل طلبات.",
    fix_en:"Disable DTDs and external entities in the parser (resolve_entities=False), or use a hardened parser such as defusedxml.",
    fix_ar:"عطّل DTD والكيانات الخارجية في المُحلّل (‎resolve_entities=False‎)، أو استخدم مُحلّلًا آمنًا مثل defusedxml.",
    test:(l) => /resolve_entities\s*=\s*True/.test(l) || /\bLIBXML_NOENT\b/.test(l) || /libxml_disable_entity_loader\s*\(\s*false/i.test(l)
      || /load_dtd\s*=\s*True/.test(l) || /external-general-entities["']\s*,\s*true/.test(l) || /\bnoent\s*:\s*true/.test(l)
  },
  {
    id:"COOKIE", cwe:"CWE-614", owasp:"A05:2021 — Security Misconfiguration", severity:"MEDIUM",
    en:"Insecure Cookie Flags", ar:"خصائص كعكات غير آمنة",
    why_en:"Without Secure the cookie travels over plain HTTP; without HttpOnly any injected script can steal it. Session cookies need both.",
    why_ar:"بدون Secure تنتقل الكعكة عبر HTTP غير المشفّر، وبدون HttpOnly يستطيع أي سكربت محقون سرقتها. كعكات الجلسة تحتاج الاثنتين.",
    fix_en:"Set Secure, HttpOnly and SameSite=Lax (or Strict) on every session or authentication cookie.",
    fix_ar:"فعّل Secure وHttpOnly وSameSite=Lax (أو Strict) على كل كعكة جلسة أو مصادقة.",
    test:(l) => /\b(secure|httponly|httpOnly|http_only)\s*[=:]\s*(False|false)\b/.test(l)
      || /SESSION_COOKIE_(SECURE|HTTPONLY)\s*=\s*False/.test(l) || /session\.cookie_(secure|httponly)["']?\s*,?\s*=?\s*["']?(0|false|Off)/i.test(l)
  },
  {
    id:"NOSQL", cwe:"CWE-943", owasp:"A03:2021 — Injection", severity:"HIGH",
    en:"NoSQL Injection", ar:"حقن NoSQL",
    why_en:"A raw request object is passed as a database query, or $where runs JavaScript. Sending {\"$ne\": null} as a password logs in as anyone.",
    why_ar:"يُمرَّر كائن الطلب الخام كاستعلام لقاعدة البيانات، أو يُشغَّل ‎$where‎ ككود. إرسال ‎{\"$ne\": null}‎ ككلمة مرور يكفي للدخول بأي حساب.",
    fix_en:"Build the query from validated, typed fields (cast to String), reject keys starting with '$', and never use $where.",
    fix_ar:"ابنِ الاستعلام من حقول مُتحقَّق منها ومحوّلة لنوعها (مثل String)، وارفض المفاتيح التي تبدأ بـ '$'، ولا تستخدم ‎$where‎ أبدًا.",
    test:(l) => /["']?\$where["']?\s*:/.test(l)
      || /\.(find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany|update|remove|countDocuments)\s*\(\s*req\.(body|query|params)\s*[,)]/.test(l)
  },
  {
    id:"CLEARTEXT", cwe:"CWE-319", owasp:"A02:2021 — Cryptographic Failures", severity:"MEDIUM",
    en:"Cleartext HTTP Connection", ar:"اتصال HTTP غير مشفّر",
    why_en:"Data is sent over plain http:// (or ws://). Anyone on the same network can read or change it, including tokens and personal data.",
    why_ar:"تُرسل البيانات عبر ‎http://‎ (أو ‎ws://‎) غير المشفّر. أي شخص على الشبكة نفسها يستطيع قراءتها أو تعديلها، بما فيها الرموز والبيانات الشخصية.",
    fix_en:"Use https:// (and wss://) for every external connection.",
    fix_ar:"استخدم ‎https://‎ (و‎wss://‎) لكل اتصال خارجي.",
    test:(l) => /["'`](http|ws):\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|www\.w3\.org|schemas\.|example\.(com|org))[^"'`\s]+["'`]/.test(l)
      && /(requests\.|fetch\s*\(|axios|urlopen|http\.get|https?\.request|curl_init|CURLOPT_URL|new\s+WebSocket|HttpClient|\bAPI_URL|BASE_URL|_URL\s*=)/i.test(l)
  },
  {
    id:"SSTI", cwe:"CWE-1336", owasp:"A03:2021 — Injection", severity:"HIGH",
    en:"Server-Side Template Injection", ar:"حقن القوالب من جهة الخادم",
    why_en:"User input is compiled as a template. Template syntax such as {{7*7}} is evaluated on the server and can escalate to running code.",
    why_ar:"يُترجَم مدخل المستخدم كقالب. صيغة القوالب مثل ‎{{7*7}}‎ تُنفَّذ على الخادم وقد تصل إلى تشغيل كود.",
    fix_en:"Keep templates fixed and pass user input only as data (render_template('page.html', name=name)).",
    fix_ar:"اجعل القوالب ثابتة ومرّر مدخل المستخدم كبيانات فقط (‎render_template('page.html', name=name)‎).",
    test:(l) => /\b(render_template_string|Template|Environment\(\)\.from_string|ejs\.render|Handlebars\.compile|pug\.render|nunjucks\.renderString)\s*\(/.test(l) && USER_INPUT.test(l)
  },
  {
    id:"TEMPFILE", cwe:"CWE-377", owasp:"A04:2021 — Insecure Design", severity:"LOW",
    en:"Insecure Temporary File", ar:"ملف مؤقت غير آمن",
    why_en:"mktemp only returns a name; another process can create that file first (a race) and read or replace your data.",
    why_ar:"الدالة mktemp تعيد اسمًا فقط؛ قد تسبقك عملية أخرى بإنشاء الملف نفسه فتقرأ بياناتك أو تستبدلها.",
    fix_en:"Use tempfile.mkstemp() or NamedTemporaryFile(), which create the file atomically with safe permissions.",
    fix_ar:"استخدم ‎tempfile.mkstemp()‎ أو ‎NamedTemporaryFile()‎ لأنهما تنشئان الملف دفعة واحدة بصلاحيات آمنة.",
    test:(l) => /\btempfile\.mktemp\s*\(/.test(l) || /\bos\.tempnam\s*\(/.test(l) || /\btmpnam\s*\(/.test(l)
  },
  {
    id:"PERMS", cwe:"CWE-732", owasp:"A01:2021 — Broken Access Control", severity:"MEDIUM",
    en:"World-Writable Permissions", ar:"صلاحيات مفتوحة للجميع",
    why_en:"Mode 777 lets every user on the machine read, change or replace the file — including swapping a script for a malicious one.",
    why_ar:"الصلاحية 777 تسمح لكل مستخدم على الجهاز بقراءة الملف أو تعديله أو استبداله — ومنها استبدال سكربت بآخر خبيث.",
    fix_en:"Grant the least privilege needed: 0o644 for files, 0o755 for executables and directories, 0o600 for secrets.",
    fix_ar:"امنح أقل صلاحية لازمة: 0o644 للملفات، و0o755 للملفات التنفيذية والمجلدات، و0o600 للأسرار.",
    test:(l) => /\bchmod(Sync)?\s*\([^)]*\b0?o?777\b/.test(l) || /\bchmod\s+(-R\s+)?(0?777|a\+rwx)\b/.test(l) || /\bumask\s*\(\s*0+\s*\)/.test(l)
  }
];

/* where untrusted input usually comes from */
export const USER_INPUT = /(request\.(args|form|values|GET|POST|json|data|params|query|body|files|cookies)|req\.(query|params|body|headers|cookies)|\$_(GET|POST|REQUEST|COOKIE|SERVER)|\bparams\[|\buser_?input\b|\binput\s*\(|\bargv\b|ctx\.(query|params|request))/;

export const COMMENT_LINE = /^\s*(\/\/|#|\*|--|<!--|\/\*)/;
