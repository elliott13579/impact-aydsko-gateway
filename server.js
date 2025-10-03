// Impact Aydsko-like Gateway (Node) — minimal proxy for iRacing Data API
// Endpoints:
//   GET /               -> 200 OK (health)
//   GET /data/doc       -> list of implemented endpoints
//   GET /data/results/get?subsession_id=12345
//   GET /data/results/lapchart?subsession_id=12345
//
// Env (Render -> "Environment" tab):
//   IRACING_EMAIL          (required)
//   IRACING_PASSWORD       (required)
//   IR_LOGIN_TTL_MS=1500000    optional (25 min default)
//   USER_AGENT_PRODUCT="ImpactGateway/1.0"
//   GATEWAY_KEY=supersecret      optional (x-api-key to protect the gateway)
//   GATEWAY_TOKEN=anothersecret  optional (Authorization: Bearer ... alternative)
//   PORT=10000 (Render sets this automatically)

import http from "http";
import express from "express";
import fetchFn from "node-fetch";
import tough from "tough-cookie";
import fetchCookie from "fetch-cookie";

const IR_BASE = "https://members-ng.iracing.com";
const EMAIL = process.env.IRACING_EMAIL || "";
const PASS  = process.env.IRACING_PASSWORD || "";
const UA    = process.env.USER_AGENT_PRODUCT || "ImpactGateway/1.0 (+node)";
const TTL   = Number(process.env.IR_LOGIN_TTL_MS || 25 * 60 * 1000);
const KEY   = process.env.GATEWAY_KEY || "";    // if set, require x-api-key to match
const TOK   = process.env.GATEWAY_TOKEN || "";  // if set, allow Authorization: Bearer <TOK>

if (!EMAIL || !PASS) {
  console.error("❌ Set IRACING_EMAIL and IRACING_PASSWORD");
  process.exit(1);
}

// cookie-enabled fetch
const jar = new tough.CookieJar();
const f = fetchCookie(fetchFn, jar);
let lastLogin = 0;

function tokenFromJar() {
  try {
    const cookies = jar.getCookiesSync(IR_BASE);
    const tok = cookies.find(c => c.key.toLowerCase().startsWith("authtoken"));
    return tok?.value || null;
  } catch { return null; }
}

function irHeaders(extra = {}) {
  const tok = tokenFromJar();
  return {
    "accept": "application/json",
    "user-agent": UA,
    ...(tok ? { "authorization": `Bearer ${tok}` } : {}),
    ...extra,
  };
}

async function irLogin(force=false) {
  if (!force && Date.now() - lastLogin < TTL) return;

  const r = await f(`${IR_BASE}/auth`, {
    method: "POST",
    headers: { "content-type": "application/json", ...irHeaders() },
    body: JSON.stringify({ email: EMAIL, password: PASS }),
    redirect: "follow",
  });
  if (!r.ok) {
    const t = await r.text().catch(()=> "");
    const msg = `auth ${r.status}: ${t.slice(0,200)}`;
    const e = new Error(msg); e.status = r.status; throw e;
  }

  // probe /data/doc (WAF/Legacy issues show as 401 here)
  const p = await f(`${IR_BASE}/data/doc`, { headers: irHeaders(), redirect: "follow" });
  if (p.status === 401) {
    const e = new Error("iRacing /data/doc -> 401 (Legacy Read-Only / CAPTCHA / WAF).");
    e.status = 401; throw e;
  }
  lastLogin = Date.now();
}

async function followJson(url) {
  await irLogin().catch(e => { throw e; });

  let r = await f(url, { headers: irHeaders(), redirect: "follow" });
  if (r.status === 401) { await irLogin(true); r = await f(url, { headers: irHeaders(), redirect: "follow" }); }
  if (!r.ok) {
    const e = new Error(`GET ${url}`);
    e.status = r.status; e.body = await r.text().catch(()=> ""); throw e;
  }
  const j = await r.json().catch(()=> ({}));
  if (j?.link) {
    let r2 = await f(j.link, { headers: irHeaders(), redirect: "follow" });
    if (r2.status === 401) { await irLogin(true); r2 = await f(j.link, { headers: irHeaders(), redirect: "follow" }); }
    if (!r2.ok) {
      const e2 = new Error(`follow ${j.link}`);
      e2.status = r2.status; e2.body = await r2.text().catch(()=> ""); throw e2;
    }
    return r2.json();
  }
  return j;
}

function authz(req) {
  if (!KEY && !TOK) return true;
  const k = req.header("x-api-key") || "";
  const b = (req.header("authorization") || "").replace(/^Bearer\s+/i, "");
  if (KEY && k === KEY) return true;
  if (TOK && b === TOK) return true;
  return false;
}

const app = express();

app.get("/", (_req, res) => res.status(200).send("OK"));
app.get("/data/doc", async (req, res) => {
  if (!authz(req)) return res.status(401).json({ error: "unauthorized" });
  res.json({
    endpoints: [
      "/data/results/get?subsession_id=<id>",
      "/data/results/lapchart?subsession_id=<id>",
    ],
    note: "Minimal gateway for Impact bot",
  });
});

app.get("/data/results/get", async (req, res) => {
  if (!authz(req)) return res.status(401).json({ error: "unauthorized" });
  const id = req.query.subsession_id;
  if (!id) return res.status(400).json({ error: "missing subsession_id" });
  try {
    const j = await followJson(`${IR_BASE}/data/results/get?subsession_id=${id}`);
    res.json(j);
  } catch (e) {
    res.status(e.status || 502).json({ error: "upstream", status: e.status || 0, message: (e.message || "").slice(0,300) });
  }
});

app.get("/data/results/lapchart", async (req, res) => {
  if (!authz(req)) return res.status(401).json({ error: "unauthorized" });
  const id = req.query.subsession_id;
  if (!id) return res.status(400).json({ error: "missing subsession_id" });
  try {
    const j = await followJson(`${IR_BASE}/data/results/lapchart?subsession_id=${id}`);
    res.json(j);
  } catch (e) {
    res.status(e.status || 502).json({ error: "upstream", status: e.status || 0, message: (e.message || "").slice(0,300) });
  }
});

const port = Number(process.env.PORT || 10000);
http.createServer(app).listen(port, "0.0.0.0", () => {
  console.log(`Gateway listening on :${port}`);
});
