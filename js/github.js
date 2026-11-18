/* CodeShield — scan a public GitHub repository.
   Files are downloaded straight from GitHub into this browser and scanned here.
   Nothing is uploaded to any CodeShield server (there is none). */
import { langFromPath } from "./engine.js";

const MAX_FILES = 150, MAX_BYTES = 300 * 1024;
const SKIP_DIR = /(^|\/)(node_modules|vendor|dist|build|\.git|\.next|coverage|__pycache__|venv|\.venv|site-packages|bower_components|min)\//i;
const SKIP_FILE = /(\.min\.js|\.map|\.lock|package-lock\.json|yarn\.lock)$/i;

export function parseRepo(input){
  const s = input.trim().replace(/\.git$/, "").replace(/\/+$/, "");
  let m = s.match(/github\.com\/([\w.-]+)\/([\w.-]+)(?:\/tree\/([^/]+)(?:\/(.*))?)?/i);
  if (m) return { owner:m[1], repo:m[2], branch:m[3] || null, sub:m[4] || "" };
  m = s.match(/^([\w.-]+)\/([\w.-]+)$/);
  if (m) return { owner:m[1], repo:m[2], branch:null, sub:"" };
  return null;
}

async function gh(url){
  const r = await fetch(url, { headers:{ Accept:"application/vnd.github+json" } });
  if (r.status === 404) throw new Error("not_found");
  if (r.status === 403 || r.status === 429) throw new Error("rate_limited");
  if (!r.ok) throw new Error("http_" + r.status);
  return r.json();
}

/* onProgress({ phase, done, total, path }) */
export async function fetchRepo(input, onProgress = () => {}){
  const ref = parseRepo(input);
  if (!ref) throw new Error("bad_url");
  onProgress({ phase:"meta" });
  const meta = await gh(`https://api.github.com/repos/${ref.owner}/${ref.repo}`);
  if (meta.private) throw new Error("private");
  const branch = ref.branch || meta.default_branch;
  const tree = await gh(`https://api.github.com/repos/${ref.owner}/${ref.repo}/git/trees/${branch.split("/").map(encodeURIComponent).join("/")}?recursive=1`);
  let files = (tree.tree || []).filter(n => n.type === "blob"
    && (!ref.sub || n.path.startsWith(ref.sub + "/"))
    && !SKIP_DIR.test(n.path + "/") && !SKIP_FILE.test(n.path)
    && langFromPath(n.path) && (n.size || 0) <= MAX_BYTES);
  const totalCandidates = files.length;
  files = files.slice(0, MAX_FILES);
  const out = [];
  let done = 0;
  const queue = [...files];
  const worker = async () => {
    while (queue.length){
      const n = queue.shift();
      try {
        const r = await fetch(`https://raw.githubusercontent.com/${ref.owner}/${ref.repo}/${branch.split("/").map(encodeURIComponent).join("/")}/${n.path.split("/").map(encodeURIComponent).join("/")}`);
        if (r.ok) out.push({ path:n.path, lang:langFromPath(n.path), code:await r.text() });
      } catch (e) { /* skip unreadable file */ }
      done++;
      onProgress({ phase:"files", done, total:files.length, path:n.path });
    }
  };
  await Promise.all(Array.from({ length:6 }, worker));
  out.sort((a, b) => a.path.localeCompare(b.path));
  return { owner:ref.owner, repo:ref.repo, branch, files:out, truncated:totalCandidates > MAX_FILES, totalCandidates,
           url:`https://github.com/${ref.owner}/${ref.repo}` };
}
