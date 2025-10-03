// Minimal Aydsko-compatible gateway for iRacing /data
// Protects with x-api-key (or Bearer) and reuses cookies for ~25m.
import express from "express";
import cors from "cors";
import fetchOrig from "node-fetch";
import tough from "tough-cookie";
import fetchCookie from "fetch-cookie";

const IR_BASE = "https://members-ng.iracing.com";
const {
  PORT = 8787,
  API_KEY = "",                 // <-- set this in env (your secret)
  IRACING_EMAIL = "",           // <-- your iRacing login (has Legacy Read-Only enabled)
  IRACING_PASSWORD = "",
  USER_AGENT_PRODUCT = "ImpactGateway/1.0",
  LOGIN_TTL_MS = 25 * 60 * 1000
} = process.env;

if (!API_KEY) { console.error("Missing API_KEY env."); process.exit(1); }
if (!IRACING_EMAIL || !IRACING_PASSWORD) {
  console.error("Missing IRACING_EMAIL/IRACING_PASSWORD env.");
  process.exit(1);
}

const app = express();
app.use(cors());
app.set("trust proxy", true);

// Cookie-aware fetch
const jar = new tough.CookieJar();
const fetch = fetchCookie(fetchOrig, jar);
let lastLogin = 0;

function irHeaders(extra = {}) {
  return { "accept": "application/json", "user-agent": USER_AGENT_PRODUCT, ...extra };
}

async function irLogin(force = false) {
  if (!force && Date.now() - lastLogin < LOGIN_TTL_MS) return;
  const res = await fetch(`${IR_BASE}/auth`, {
    method: "POST",
    headers: { "content-type": "application/json", ...irHeaders() },
    body: JSON.stringify({ email: IRACING_EMAIL, password: IRACING_PASSWORD }),
    redirect: "follow",
  });
  if (!res.ok) throw new Error(`auth ${res.status}`);
  const doc = await fetch(`${IR_BASE}/data/doc`, { headers: irHeaders() }); // probe
  if (!doc.ok) throw new Error(`/data/doc ${doc.status}`);
  lastLogin = Date.now();
}

async function irFollowJson(url) {
  await irLogin().catch(e => { throw e; });
  let r = await fetch(url, { headers: irHeaders(), redirect: "follow" });
  if (r.status === 401) { await irLogin(true); r = await fetch(url, { headers: irHeaders(), redirect: "follow" }); }
  if (!r.ok) throw new Error(`GET ${url} -> ${r.status}`);
  const body = await r.json();
  if (body?.link) {
    let r2 = await fetch(body.link, { headers: irHeaders() });
    if (!r2.ok) throw new Error(`follow ${body.link} -> ${r2.status}`);
    return r2.json();
  }
  return body;
}

// API-key / Bearer protection
function requireKey(req, res, next) {
  const k = req.get("x-api-key");
  const auth = req.get("authorization");
  const bearer = auth?.startsWith("Bearer ") ? auth.slice(7) : null;
  if (k === API_KEY || bearer === API_KEY) return next();
  res.status(401).json({ error: "Unauthorized" });
}

// Aydsko-compatible routes
app.get("/data/doc", requireKey, async (req, res) => {
  try { await irLogin(); const doc = await irFollowJson(`${IR_BASE}/data/doc`); res.json(doc); }
  catch (e) { res.status(502).json({ error: String(e.message || e) }); }
});

app.get("/data/results/get", requireKey, async (req, res) => {
  try {
    const id = req.query.subsession_id;
    if (!id) return res.status(400).json({ error: "subsession_id required" });
    const j = await irFollowJson(`${IR_BASE}/data/results/get?subsession_id=${id}`);
    res.json(j);
  } catch (e) { res.status(502).json({ error: String(e.message || e) }); }
});

app.get("/data/results/lapchart", requireKey, async (req, res) => {
  try {
    const id = req.query.subsession_id;
    if (!id) return res.status(400).json({ error: "subsession_id required" });
    const j = await irFollowJson(`${IR_BASE}/data/results/lapchart?subsession_id=${id}`);
    res.json(j);
  } catch (e) { res.status(502).json({ error: String(e.message || e) }); }
});

app.listen(PORT, () => console.log(`Gateway listening on :${PORT}`));
