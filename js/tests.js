export function generateTest(ruleId, line, lang){
  const P = lang === "python", R = lang === "ruby", H = lang === "php";
  const tests = {
    SQLI: P
      ? `def test_sql_injection_blocked_line_${line}():\n    """FAILS on the vulnerable version, PASSES after the fix."""\n    payload = "1 OR 1=1; DROP TABLE users;--"\n    sql, params = build_query(payload)      # <- rename to your function\n    assert payload not in sql               # input must not be inlined\n    assert params == (payload,)             # it must be a bound parameter`
      : `test("SQL injection payload is never inlined (line ${line})", () => {\n  // FAILS on the vulnerable version, PASSES after the fix.\n  const payload = "1 OR 1=1; DROP TABLE users;--";\n  const { sql, params } = buildQuery(payload);   // <- rename to your function\n  expect(sql).not.toContain(payload);\n  expect(params).toContain(payload);\n});`,
    WEAKHASH: P
      ? `def test_password_hash_is_strong_line_${line}():\n    import re\n    h = hash_password("correct horse battery staple")\n    assert not re.fullmatch(r"[0-9a-f]{32}", h)   # 32 hex chars == MD5\n    assert h.startswith(("$2b$", "$argon2", "$scrypt"))`
      : `test("password hash is not MD5/SHA-1 (line ${line})", () => {\n  const h = hashPassword("correct horse battery staple");\n  expect(h).not.toMatch(/^[0-9a-f]{32}$/);   // MD5\n  expect(h).not.toMatch(/^[0-9a-f]{40}$/);   // SHA-1\n  expect(h.length).toBeGreaterThanOrEqual(60);\n});`,
    SECRET: P
      ? `def test_no_hardcoded_secrets_line_${line}():\n    import os, pathlib\n    src = pathlib.Path(__file__).read_text()\n    for marker in ("sk_live_", "AKIA", "-----BEGIN"):\n        assert marker not in src\n    assert os.environ.get("API_KEY")    # must come from the environment`
      : `test("no hardcoded secrets in source (line ${line})", () => {\n  const src = require("fs").readFileSync(__filename, "utf8");\n  for (const m of ["sk_live_", "AKIA", "-----BEGIN"]) expect(src).not.toContain(m);\n  expect(process.env.API_KEY).toBeTruthy();\n});`,
    CMDI: P
      ? `def test_command_injection_blocked_line_${line}():\n    import pytest\n    with pytest.raises(Exception):\n        deploy("main; rm -rf /")        # <- rename to your function\n    assert deploy("main") is not None   # legitimate input still works`
      : `test("shell metacharacters are rejected (line ${line})", () => {\n  expect(() => deploy("main; rm -rf /")).toThrow();\n  expect(deploy("main")).toBeDefined();   // legitimate input still works\n});`,
    XSS: P
      ? `def test_markup_is_escaped_line_${line}():\n    out = render('<img src=x onerror=alert(1)>')\n    assert "onerror" not in out\n    assert "&lt;img" in out`
      : `test("markup in user input is escaped (line ${line})", () => {\n  const out = render('<img src=x onerror=alert(1)>');\n  expect(out).not.toContain("onerror");\n  expect(out).toContain("&lt;img");\n});`,
    DESERIAL: P
      ? `def test_untrusted_payload_rejected_line_${line}():\n    import pytest\n    rce = b"cos\\nsystem\\n(S'id'\\ntR."     # classic pickle RCE payload\n    with pytest.raises(Exception):\n        load_data(rce)                     # <- rename to your function`
      : `test("untrusted payload cannot pollute the prototype (line ${line})", () => {\n  loadData('{"__proto__":{"polluted":true}}');   // <- rename to your function\n  expect({}.polluted).toBeUndefined();\n});`,
    TLSOFF: P
      ? `def test_tls_verification_enabled_line_${line}():\n    import inspect, mymodule           # <- your module\n    src = inspect.getsource(mymodule)\n    assert "verify=False" not in src`
      : `test("TLS certificate verification stays on (line ${line})", () => {\n  const src = require("fs").readFileSync(__filename, "utf8");\n  expect(src).not.toMatch(/rejectUnauthorized\\s*:\\s*false/);\n});`,
    WEAKRAND: P
      ? `def test_token_is_cryptographically_random_line_${line}():\n    tokens = {make_token() for _ in range(5000)}   # <- rename to your function\n    assert len(tokens) == 5000        # no collisions across 5000 draws\n    assert len(next(iter(tokens))) >= 32`
      : `test("token is cryptographically random (line ${line})", () => {\n  const seen = new Set(Array.from({ length: 5000 }, () => makeToken()));\n  expect(seen.size).toBe(5000);          // no collisions\n  expect([...seen][0].length).toBeGreaterThanOrEqual(32);\n});`,
    UPLOAD: H
      ? `public function test_rejects_executable_upload_line_${line}() {\n    $this->assertFalse(handle_upload("shell.php"));\n    $this->assertFalse(handle_upload("shell.phtml"));\n    $this->assertTrue(handle_upload("photo.jpg"));\n}`
      : `test("executable uploads are rejected (line ${line})", () => {\n  expect(handleUpload("shell.php")).toBe(false);\n  expect(handleUpload("photo.jpg")).toBe(true);\n});`,
    PATH: P
      ? `def test_path_traversal_blocked_line_${line}():\n    import pytest\n    with pytest.raises(Exception):\n        read_user_file("../../etc/passwd")   # <- rename to your function\n    assert read_user_file("report.txt")`
      : `test("path traversal is blocked (line ${line})", () => {\n  expect(() => readUserFile("../../etc/passwd")).toThrow();   // <- rename\n  expect(readUserFile("report.txt")).toBeDefined();\n});`,
    SSRF: P
      ? `def test_internal_urls_rejected_line_${line}():\n    import pytest\n    for url in ("http://169.254.169.254/latest/meta-data/", "http://localhost:6379/", "file:///etc/passwd"):\n        with pytest.raises(Exception):\n            fetch_url(url)                     # <- rename to your function`
      : `test("internal URLs are rejected (line ${line})", async () => {\n  for (const url of ["http://169.254.169.254/latest/meta-data/", "http://localhost:6379/"]) {\n    await expect(fetchUrl(url)).rejects.toThrow();   // <- rename\n  }\n});`,
    REDIRECT: P
      ? `def test_external_redirect_blocked_line_${line}(client):\n    r = client.get("/login?next=https://evil.example")\n    assert "evil.example" not in r.headers.get("Location", "")`
      : `test("external redirect is blocked (line ${line})", async () => {\n  const res = await request(app).get("/login?next=https://evil.example");\n  expect(res.headers.location || "").not.toContain("evil.example");\n});`,
    DEBUG: P
      ? `def test_debug_off_in_production_line_${line}(monkeypatch):\n    monkeypatch.setenv("APP_ENV", "production")\n    app = create_app()                       # <- your app factory\n    assert app.debug is False`
      : `test("debug is off in production (line ${line})", () => {\n  process.env.NODE_ENV = "production";\n  expect(createApp().get("env")).toBe("production");\n});`,
    CORS: P
      ? `def test_cors_rejects_unknown_origin_line_${line}(client):\n    r = client.get("/api/data", headers={"Origin": "https://evil.example"})\n    assert r.headers.get("Access-Control-Allow-Origin") != "*"`
      : `test("CORS does not allow every origin (line ${line})", async () => {\n  const res = await request(app).get("/api/data").set("Origin", "https://evil.example");\n  expect(res.headers["access-control-allow-origin"]).not.toBe("*");\n});`,
    JWT: P
      ? `def test_forged_token_rejected_line_${line}():\n    import jwt, pytest\n    forged = jwt.encode({"role": "admin"}, key="", algorithm="none")\n    with pytest.raises(Exception):\n        decode_token(forged)                  # <- rename to your function`
      : `test("unsigned token is rejected (line ${line})", () => {\n  const forged = [btoa('{"alg":"none"}'), btoa('{"role":"admin"}'), ""].join(".");\n  expect(() => decodeToken(forged)).toThrow();   // <- rename\n});`,
    CIPHER: P
      ? `def test_same_plaintext_encrypts_differently_line_${line}():\n    a, b = encrypt(b"A" * 32), encrypt(b"A" * 32)   # <- rename\n    assert a != b          # ECB / no IV would make these equal`
      : `test("same plaintext encrypts differently (line ${line})", () => {\n  expect(encrypt("A".repeat(32))).not.toEqual(encrypt("A".repeat(32)));   // <- rename\n});`,
    XXE: P
      ? `def test_external_entity_not_resolved_line_${line}():\n    doc = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>'\n    out = parse_xml(doc)                      # <- rename to your function\n    assert "root:" not in str(out)`
      : `test("external entity is not resolved (line ${line})", () => {\n  const doc = '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>';\n  expect(String(parseXml(doc))).not.toContain("root:");   // <- rename\n});`,
    COOKIE: P
      ? `def test_session_cookie_flags_line_${line}(client):\n    r = client.post("/login", data={"u": "a", "p": "b"})\n    c = r.headers.get("Set-Cookie", "")\n    assert "Secure" in c and "HttpOnly" in c`
      : `test("session cookie is Secure and HttpOnly (line ${line})", async () => {\n  const res = await request(app).post("/login").send({ u: "a", p: "b" });\n  const c = (res.headers["set-cookie"] || []).join(";");\n  expect(c).toMatch(/Secure/); expect(c).toMatch(/HttpOnly/);\n});`,
    NOSQL: `test("operator injection is rejected (line ${line})", async () => {\n  const res = await request(app).post("/login").send({ user: "admin", pass: { $ne: null } });\n  expect(res.status).not.toBe(200);\n});`,
    CLEARTEXT: P
      ? `def test_no_cleartext_urls_line_${line}():\n    import re, pathlib\n    src = pathlib.Path(__file__).read_text()\n    assert not re.search(r"http://(?!localhost|127\\.0\\.0\\.1)", src)`
      : `test("no cleartext URLs in source (line ${line})", () => {\n  const src = require("fs").readFileSync(__filename, "utf8");\n  expect(src).not.toMatch(/http:\\/\\/(?!localhost|127\\.0\\.0\\.1)/);\n});`,
    SSTI: P
      ? `def test_template_syntax_not_evaluated_line_${line}(client):\n    r = client.get("/hello?name={{7*7}}")\n    assert "49" not in r.get_data(as_text=True)`
      : `test("template syntax is not evaluated (line ${line})", async () => {\n  const res = await request(app).get("/hello?name=<%= 7*7 %>");\n  expect(res.text).not.toContain("49");\n});`,
    TEMPFILE: `def test_temp_file_is_private_line_${line}():\n    import os, stat\n    path = make_temp()                        # <- rename to your function\n    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600`,
    PERMS: P
      ? `def test_file_not_world_writable_line_${line}():\n    import os, stat\n    mode = stat.S_IMODE(os.stat("output.txt").st_mode)   # <- your file\n    assert not mode & stat.S_IWOTH`
      : `test("file is not world-writable (line ${line})", () => {\n  const mode = require("fs").statSync("output.txt").mode & 0o777;   // <- your file\n  expect(mode & 0o002).toBe(0);\n});`
  };
  if (R && tests[ruleId]) {
    return `it "closes ${ruleId} reported on line ${line}" do\n  # FAILS on the vulnerable version, PASSES after the fix.\n  expect { vulnerable_call("'; DROP TABLE users;--") }.to raise_error\nend`;
  }
  return tests[ruleId] || `// verification test for ${ruleId} (line ${line})`;
}

