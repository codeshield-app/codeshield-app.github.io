/* CodeShield — accuracy test suite.
   Each case is a small snippet with the expected answer:
     vuln:true  → the rule MUST report it (a miss is a false negative)
     vuln:false → safe code; the rule must NOT report it (a hit is a false positive)
   This is our own labelled test set, not an industry benchmark. */
import { scanCode } from "./engine.js";

const C = (rule, lang, vuln, code, flow = false) => ({ rule, lang, vuln, code, flow });

export const CASES = [
  // ---------- SQL injection ----------
  C("SQLI","python",true,`query = "SELECT * FROM users WHERE id=" + user_id`),
  C("SQLI","python",true,`cursor.execute(f"SELECT * FROM orders WHERE user = {uid}")`),
  C("SQLI","python",true,`sql = "DELETE FROM posts WHERE id=%s" % post_id`),
  C("SQLI","javascript",true,"db.query(`SELECT * FROM users WHERE email = '${email}'`)"),
  C("SQLI","php",true,`$q = "SELECT * FROM users WHERE id=" . $_GET['id'];`),
  C("SQLI","python",false,`cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`),
  C("SQLI","javascript",false,`db.query("SELECT * FROM users WHERE id = ?", [id])`),
  C("SQLI","php",false,`$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");`),
  C("SQLI","python",false,`message = "Select an item from the list"`),
  // ---------- weak hashing ----------
  C("WEAKHASH","python",true,`h = hashlib.md5(password.encode()).hexdigest()`),
  C("WEAKHASH","python",true,`digest = hashlib.sha1(data).hexdigest()`),
  C("WEAKHASH","javascript",true,`const h = crypto.createHash("md5").update(pw).digest("hex");`),
  C("WEAKHASH","php",true,`$h = md5($password);`),
  C("WEAKHASH","python",false,`h = hashlib.sha256(data).hexdigest()`),
  C("WEAKHASH","python",false,`hashed = bcrypt.hashpw(pw, bcrypt.gensalt())`),
  C("WEAKHASH","javascript",false,`const h = crypto.createHash("sha256").update(x).digest("hex");`),
  // ---------- hardcoded secrets ----------
  C("SECRET","python",true,`API_KEY = "sk_live_51H8xQbLmNpQrStUv"`),
  C("SECRET","javascript",true,`const aws = "AKIAIOSFODNN7EXAMPLE";`),
  C("SECRET","python",true,`password = "SuperSecret2026"`),
  C("SECRET","shell",true,`DB_PASSWORD=admin12345`),
  C("SECRET","javascript",true,`const token = "ghp_abcdefghijklmnopqrstuvwxyz123456";`),
  C("SECRET","python",false,`API_KEY = os.environ["API_KEY"]`),
  C("SECRET","javascript",false,`const apiKey = process.env.API_KEY;`),
  C("SECRET","python",false,`api_key = models.CharField(max_length=32)`),
  C("SECRET","python",false,`password = getpass.getpass()`),
  C("SECRET","shell",false,`DB_PASSWORD=\${DB_PASSWORD}`),
  // ---------- command injection ----------
  C("CMDI","python",true,`os.system("ping " + host)`),
  C("CMDI","python",true,`subprocess.run("convert " + name, shell=True)`),
  C("CMDI","javascript",true,`child_process.exec("ls " + dir);`),
  C("CMDI","javascript",true,`eval(userCode);`),
  C("CMDI","php",true,`$out = shell_exec("whois " . $domain);`),
  C("CMDI","python",false,`subprocess.run(["ping", "-c", "1", host], check=True)`),
  C("CMDI","javascript",false,`child_process.execFile("ls", [dir]);`),
  C("CMDI","python",false,`evaluation = model.evaluate(x_test)`),
  // ---------- XSS ----------
  C("XSS","javascript",true,`el.innerHTML = userInput;`),
  C("XSS","javascript",true,`document.write(location.hash);`),
  C("XSS","javascript",true,`<div dangerouslySetInnerHTML={{__html: bio}} />`),
  C("XSS","php",true,`echo $_GET['name'];`),
  C("XSS","javascript",false,`el.textContent = userInput;`),
  C("XSS","php",false,`echo htmlspecialchars($_GET['name'], ENT_QUOTES, "UTF-8");`),
  C("XSS","javascript",false,`const html = template.render(data);`),
  // ---------- insecure deserialisation ----------
  C("DESERIAL","python",true,`obj = pickle.loads(request.data)`),
  C("DESERIAL","python",true,`cfg = yaml.load(open("c.yml"))`),
  C("DESERIAL","ruby",true,`obj = Marshal.load(params[:data])`),
  C("DESERIAL","php",true,`$o = unserialize($_COOKIE['session']);`),
  C("DESERIAL","python",false,`cfg = yaml.safe_load(open("c.yml"))`),
  C("DESERIAL","python",false,`obj = json.loads(request.data)`),
  // ---------- TLS verification ----------
  C("TLSOFF","python",true,`r = requests.get(url, verify=False)`),
  C("TLSOFF","javascript",true,`const agent = new https.Agent({ rejectUnauthorized: false });`),
  C("TLSOFF","php",true,`curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);`),
  C("TLSOFF","python",false,`r = requests.get(url, timeout=5)`),
  C("TLSOFF","python",false,`payload = jwt.decode(token, key, algorithms=["HS256"])`),
  // ---------- weak randomness ----------
  C("WEAKRAND","python",true,`reset_token = random.randint(100000, 999999)`),
  C("WEAKRAND","javascript",true,`const sessionId = Math.random().toString(36);`),
  C("WEAKRAND","python",true,`otp = random.choice(digits)`),
  C("WEAKRAND","python",false,`reset_token = secrets.token_urlsafe(32)`),
  C("WEAKRAND","javascript",false,`const delay = Math.random() * 1000;`),
  C("WEAKRAND","python",false,`colour = random.choice(colours)`),
  // ---------- file upload ----------
  C("UPLOAD","php",true,`move_uploaded_file($_FILES["f"]["tmp_name"], "up/" . $_FILES["f"]["name"]);`),
  C("UPLOAD","php",true,`move_uploaded_file($tmp, $dest);`),
  C("UPLOAD","php",false,`if (in_array($ext, $allowed)) { move_uploaded_file($tmp, $dest); }`),
  // ---------- path traversal ----------
  C("PATH","python",true,`return open(request.args.get("file")).read()`),
  C("PATH","javascript",true,`fs.readFile(req.query.name, cb);`),
  C("PATH","php",true,`include($_GET['page']);`),
  C("PATH","python",true,`name = request.args.get("f")\nreturn send_file(name)`, true),
  C("PATH","python",false,`return open(os.path.join(BASE, secure_filename(request.args.get("f")))).read()`),
  C("PATH","python",false,`return open("static/help.txt").read()`),
  C("PATH","python",false,`file = request.files["image"]\nimg = Image.open(file)`, true),   // found in pygoat: an uploaded file object, not a path
  C("PATH","python",false,`name = request.args.get("f")\nsafe = os.path.basename(name)\nreturn send_file(safe)`, true),
  // ---------- SSRF ----------
  C("SSRF","python",true,`r = requests.get(request.args["url"])`),
  C("SSRF","javascript",true,`const r = await fetch(req.query.target);`),
  C("SSRF","javascript",true,`const target = req.body.url;\nconst r = await axios.get(target);`, true),
  C("SSRF","python",false,`r = requests.get("https://api.example.com/v1/rates")`),
  C("SSRF","javascript",false,`const target = req.body.url;\nif (!ALLOWED_HOSTS.includes(new URL(target).hostname)) throw new Error();\nconst r = await axios.get(target);`, true),
  // ---------- open redirect ----------
  C("REDIRECT","python",true,`return redirect(request.args.get("next"))`),
  C("REDIRECT","javascript",true,`res.redirect(req.query.returnTo);`),
  C("REDIRECT","php",true,`header("Location: " . $_GET['next']);`),
  C("REDIRECT","python",true,`nxt = request.args.get("next")\nreturn redirect(nxt)`, true),
  C("REDIRECT","python",false,`return redirect(url_for("index"))`),
  C("REDIRECT","python",false,`filename = request.form["name"]\nreturn redirect(url_for("view_blog", filename=filename))`, true),   // found in pygoat: internal route
  C("REDIRECT","python",false,`nxt = request.args.get("next")\nif not nxt.startswith("/"): nxt = "/"\nreturn redirect(nxt)`, true),
  // ---------- debug ----------
  C("DEBUG","python",true,`app.run(host="0.0.0.0", debug=True)`),
  C("DEBUG","python",true,`DEBUG = True`),
  C("DEBUG","php",true,`ini_set('display_errors', '1');`),
  C("DEBUG","python",false,`app.run(debug=os.environ.get("FLASK_DEBUG") == "1")`),
  C("DEBUG","python",false,`DEBUG = False`),
  // ---------- CORS ----------
  C("CORS","javascript",true,`res.setHeader("Access-Control-Allow-Origin", "*");`),
  C("CORS","javascript",true,`app.use(cors());`),
  C("CORS","python",true,`CORS(app)`),
  C("CORS","python",true,`CORS_ALLOW_ALL_ORIGINS = True`),
  C("CORS","javascript",false,`app.use(cors({ origin: ["https://myapp.sa"] }));`),
  C("CORS","python",false,`CORS(app, origins=["https://myapp.sa"])`),
  // ---------- JWT ----------
  C("JWT","python",true,`data = jwt.decode(token, options={"verify_signature": False})`),
  C("JWT","python",true,`data = jwt.decode(token, verify=False)`),
  C("JWT","javascript",true,`jwt.verify(token, key, { algorithms: ["none"] });`),
  C("JWT","python",false,`data = jwt.decode(token, key, algorithms=["HS256"])`),
  C("JWT","javascript",false,`jwt.verify(token, key, { algorithms: ["RS256"] });`),
  // ---------- weak cipher ----------
  C("CIPHER","python",true,`cipher = DES.new(key, DES.MODE_ECB)`),
  C("CIPHER","python",true,`c = AES.new(key, AES.MODE_ECB)`),
  C("CIPHER","javascript",true,`const c = crypto.createCipheriv("aes-128-ecb", key, null);`),
  C("CIPHER","javascript",true,`const c = crypto.createCipheriv("des-ede3", key, iv);`),
  C("CIPHER","python",false,`c = AES.new(key, AES.MODE_GCM)`),
  C("CIPHER","javascript",false,`const c = crypto.createCipheriv("aes-256-gcm", key, iv);`),
  // ---------- XXE ----------
  C("XXE","python",true,`parser = etree.XMLParser(resolve_entities=True)`),
  C("XXE","php",true,`$doc->loadXML($xml, LIBXML_NOENT);`),
  C("XXE","php",true,`libxml_disable_entity_loader(false);`),
  C("XXE","python",false,`parser = etree.XMLParser(resolve_entities=False)`),
  C("XXE","python",false,`tree = defusedxml.ElementTree.parse(f)`),
  // ---------- cookies ----------
  C("COOKIE","javascript",true,`res.cookie("sid", id, { httpOnly: false });`),
  C("COOKIE","python",true,`SESSION_COOKIE_SECURE = False`),
  C("COOKIE","python",true,`resp.set_cookie("sid", sid, secure=False)`),
  C("COOKIE","javascript",false,`res.cookie("sid", id, { httpOnly: true, secure: true, sameSite: "lax" });`),
  C("COOKIE","python",false,`SESSION_COOKIE_SECURE = True`),
  // ---------- NoSQL ----------
  C("NOSQL","javascript",true,`const user = await Users.findOne(req.body);`),
  C("NOSQL","javascript",true,`db.users.find({ $where: "this.name == '" + name + "'" });`),
  C("NOSQL","javascript",false,`const user = await Users.findOne({ email: String(req.body.email) });`),
  C("NOSQL","javascript",false,`const user = await Users.findOne({ _id: id });`),
  // ---------- cleartext ----------
  C("CLEARTEXT","javascript",true,`const r = await fetch("http://api.bank-example.sa/v1/balance");`),
  C("CLEARTEXT","python",true,`r = requests.post("http://payments.example.net/charge", data=d)`),
  C("CLEARTEXT","javascript",true,`const ws = new WebSocket("ws://chat.example.net");`),
  C("CLEARTEXT","javascript",false,`const r = await fetch("https://api.bank-example.sa/v1/balance");`),
  C("CLEARTEXT","javascript",false,`const r = await fetch("http://localhost:3000/health");`),
  C("CLEARTEXT","python",false,`ns = "http://www.w3.org/2000/svg"`),
  // ---------- SSTI ----------
  C("SSTI","python",true,`return render_template_string(request.args.get("tpl"))`),
  C("SSTI","javascript",true,`res.send(ejs.render(req.body.template, data));`),
  C("SSTI","python",true,`tpl = request.form["t"]\nreturn render_template_string(tpl)`, true),
  C("SSTI","python",false,`return render_template("page.html", name=request.args.get("name"))`),
  // ---------- temp files ----------
  C("TEMPFILE","python",true,`path = tempfile.mktemp()`),
  C("TEMPFILE","python",true,`name = os.tempnam()`),
  C("TEMPFILE","python",false,`fd, path = tempfile.mkstemp()`),
  C("TEMPFILE","python",false,`with tempfile.NamedTemporaryFile() as f: pass`),
  // ---------- permissions ----------
  C("PERMS","python",true,`os.chmod(path, 0o777)`),
  C("PERMS","shell",true,`chmod -R 777 /var/www`),
  C("PERMS","javascript",true,`fs.chmodSync(file, 0o777);`),
  C("PERMS","python",false,`os.chmod(path, 0o644)`),
  C("PERMS","shell",false,`chmod 755 deploy.sh`),
  // ---------- XSS via data flow ----------
  C("XSS","php",true,`$name = $_GET['name'];\necho $name;`, true),
  C("XSS","javascript",true,`const q = req.query.q;\nres.send("<h1>" + q + "</h1>");`, true),
  C("XSS","php",false,`$name = htmlspecialchars($_GET['name']);\necho $name;`, true),
  C("XSS","javascript",false,`const id = parseInt(req.query.id);\nres.send("Item " + id);`, true)
];

export function runBenchmark(){
  const per = {};
  const misses = [];
  let tp = 0, fn = 0, fp = 0, tn = 0, flowTotal = 0, flowOk = 0;
  for (const c of CASES){
    const res = scanCode(c.code, c.lang);
    const hit = res.findings.some(f => f.ruleId === c.rule);
    const p = per[c.rule] = per[c.rule] || { tp:0, fn:0, fp:0, tn:0 };
    if (c.vuln && hit){ tp++; p.tp++; }
    else if (c.vuln && !hit){ fn++; p.fn++; misses.push({ ...c, kind:"missed" }); }
    else if (!c.vuln && hit){ fp++; p.fp++; misses.push({ ...c, kind:"false_positive" }); }
    else { tn++; p.tn++; }
    if (c.flow){ flowTotal++; if (c.vuln === hit) flowOk++; }
  }
  const pos = tp + fn, neg = fp + tn;
  return {
    total:CASES.length, positives:pos, negatives:neg, tp, fn, fp, tn,
    detection:pos ? tp / pos : 0,            // recall
    falsePositiveRate:neg ? fp / neg : 0,
    precision:tp + fp ? tp / (tp + fp) : 0,
    flowTotal, flowOk, per, misses
  };
}
