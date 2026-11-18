/* Intentionally vulnerable sample code for demos. Do not copy into real projects. */
export const SAMPLES = {
python: `import hashlib, pickle, os, subprocess, requests, random, tempfile
from flask import Flask, request, redirect, render_template_string

app = Flask(__name__)
API_KEY = "sk_live_51H8xQbLmNpQrStUvWxYz"
DB_PASSWORD = "admin123"

def get_user(user_id):
    query = "SELECT * FROM users WHERE id=" + user_id
    return cursor.execute(query)

def hash_password(p):
    return hashlib.md5(p.encode()).hexdigest()

def load_session(data):
    return pickle.loads(data)

def deploy(branch):
    os.system("git checkout " + branch)

def fetch(url):
    return requests.get(url, verify=False)

@app.route("/download")
def download():
    return open(request.args.get("file")).read()

@app.route("/hello")
def hello():
    return render_template_string(request.args.get("name"))

@app.route("/go")
def go():
    nxt = request.args.get("next")
    return redirect(nxt)

reset_token = random.randint(100000, 999999)
scratch = tempfile.mktemp()

if __name__ == "__main__":
    app.run(debug=True)
`,
javascript: `const express = require("express");
const child_process = require("child_process");
const cors = require("cors");
const crypto = require("crypto");
const app = express();

const apiKey = "sk_live_abcdefghijkl1234";
app.use(cors());

app.get("/user", (req, res) => {
  const q = "SELECT * FROM users WHERE id=" + req.query.id;
  db.query(q);
});

app.post("/login", async (req, res) => {
  const user = await Users.findOne(req.body);
  res.cookie("sid", user.sid, { httpOnly: false });
});

app.get("/ls", (req, res) => {
  child_process.exec("ls " + req.query.dir);
});

app.get("/proxy", async (req, res) => {
  const r = await fetch(req.query.url);
  res.send(await r.text());
});

app.get("/search", (req, res) => {
  const term = req.query.q;
  res.send("<h1>Results for " + term + "</h1>");
});

function showName(el, name) {
  el.innerHTML = name;
}

const token = Math.random().toString(36);
const h = crypto.createHash("md5").update("pw").digest("hex");
const API_URL = "http://api.example-bank.com/v1";
`,
php: `<?php
$id = $_GET['id'];
$q = "SELECT * FROM users WHERE id=" . $_GET['id'];
echo $_GET['name'];
$user = $_GET['user'];
echo "Hello " . $user;
$h = md5($pass);
$obj = unserialize($data);
move_uploaded_file($_FILES["file"]["tmp_name"], "/uploads/" . $_FILES["file"]["name"]);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
include($_GET['page']);
header("Location: " . $_GET['next']);
ini_set('display_errors', '1');
chmod("/var/www/uploads", 0777);
`
};
