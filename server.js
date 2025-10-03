// Impact Aydsko-like Gateway (Node) v1.1 — adds /debug/health + sturdier auth
import http from "http";
import express from "express";
import fetchFn from "node-fetch";
import tough from "tough-cookie";
import fetchCookie from "fetch-cookie";

const IR_BASE = "https://members-ng.iracing.com";
const IR_ROOT = `${IR_BASE}/`; // for cookie lookups

const EMAIL = process.env.IRACING_EMAIL || "";
const PASS  = process.env.IRACING_PASSWORD || "";
const UA    = process.env.USER_AGENT_PRODUCT || "ImpactGateway/1.1 (+node)";
const TTL   = Number(process.env.IR_LOGIN_TTL_MS || 25 * 60 * 1000);

const KEY   = process.env.GATEWAY_KEY || "";    // optional (x-api-key)
const TOK   = process.env.GATEWAY_TOKEN || "";  // optional (Authorization: Bearer ...)

if (!EMAIL || !PASS) {
  console.error("❌ Set IRACING_EMAIL and IRACING_PASSWORD");
  process.exit(1);
}

const jar = new tough.CookieJar();
const f = fetchCookie(fetchFn, jar);
let lastLogin = 0;

function getAuthTokenFromJar() {
  try {
    const urls = [`${IR_BASE}/auth`, IR_ROOT, `${IR_BASE}/data/doc`];
    for (const u of urls) {
      const cookies = jar.getCookiesSync(u);
      for (const c of cookies) {
        const k = String(c.key || "").toLowerCase();
        if (k.startsWith("authtoken")) return c.value;
      }
    }
  } catch {}
  return null;
}

function irHeaders(extra = {}) {
  const token = getAuthTokenFromJar();
  return {
    accept: "application/json",
    "user-agent": UA,
    ...(token ? { authorization: `Bearer ${token}` } : {}),
    ...extra,
  };
}

async function irLogin(force = false) {
  if (!force && Date.now() - lastLogin < TTL) return;

  if (force) { try { jar.removeAllCookiesSync(); } catch {} }

  const r = await f(`${IR_BASE}/auth`, {
    method: "POST",
    headers: { "content-type": "application/json", "user-agent": UA },
    body: JSON.stringify({ email: EMAIL, password: PASS }),
    redirect: "follow",
  });
  if (!r.ok) {
    const t = await r.text().catch(()=> "");
    const e = new Error(`auth ${r.status}: ${t.slice(0,200)}`); e.status = r.status; throw e;
  }

  const tokenNow = getAuthTokenFromJar();
  if (!tokenNow) { const e = new Error("login ok but no authtoken cookie found"); e.status = 401; throw e; }

  const p = await f(`${IR_BASE}/data/doc`, { headers: irHeaders(), redirect: "follow" });
  if (p.status === 401) { const e = new Error("iRacing /data/doc -> 401 (Legacy / CAPTCHA / WAF)"); e.status = 401; throw e; }

  lastLogin = Date.now();
}

async function followJson(url) {
  await irLogin().catch(e => { throw e; });

  let r = await f(url, { headers: irHeaders(), redirect: "follow" });
  if (r.status === 401) { await irLogin(true); r = await f(url, { headers: irHeaders(), redirect: "follow" }); }
  if (!r.ok) {
    const e = new Error(`GET ${url}`); e.status = r.status; e.body = await r.text().catch(()=> ""); throw e;
  }
  const j = await r.json().catch(()=> ({}));
  if (j?.link) {
    let r2 = await f(j.link, { headers: irHeaders(), redirect: "follow" });
    if (r2.status === 401) { await irLogin(true); r2 = await f(j.link, { headers: irHeaders(), redirect: "follow" }); }
    if (!r2.ok) { const e2 = new Error(`follow ${j.link}`); e2.status = r2.status; e2.body = await r2.text().catch(()=> ""); throw e2; }
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

app.get("/data/doc", (req, res) => {
  if (!authz(req)) return res.status(401).json({ error: "unauthorized" });
  res.json({
    endpoints: [
      "/data/results/get?subsession_id=<id>",
      "/data/results/lapchart?subsession_id=<id>"
    ],
    note: "Minimal gateway for Impact bot"
  });
});

app.get("/data/results/get", async (req, res) => {
  if (!authz(req)) return res.status(401).json({ error: "unauthorized" });
  const id = req.query.subsession_id;
  if (!id) return res.status(400).json({ error: "missing subsession_id" });
  try { res.json(await followJson(`${IR_BASE}/data/results/get?subsession_id=${id}`)); }
  catch (e) { res.status(e.status || 502).json({ error: "upstream", status: e.status || 0, message: (e.message || "").slice(0,300) }); }
});

app.get("/data/results/lapchart", async (req, res) => {
  if (!authz(req)) return res.status(401).json({ error: "unauthorized" });
  const id = req.query.subsession_id;
  if (!id) return res.status(400).json({ error: "missing subsession_id" });
  try { res.json(await followJson(`${IR_BASE}/data/results/lapchart?subsession_id=${id}`)); }
  catch (e) { res.status(e.status || 502).json({ error: "upstream", status: e.status || 0, message: (e.message || "").slice(0,300) }); }
});

// Diagnostics (safe; no secrets)
app.get("/debug/health", async (req, res) => {
  if (!authz(req)) return res.status(401).json({ error: "unauthorized" });
  const out = { forced: !!req.query.force, tokenPresent: !!getAuthTokenFromJar() };
  try { await irLogin(!!req.query.force); out.loginOk = true; } catch(e) { out.loginOk = false; out.loginErr = `${e.status||0} ${e.message}`; }
  try { const r = await f(`${IR_BASE}/data/doc`, { headers: irHeaders(), redirect: "follow" }); out.docStatus = r.status; }
  catch(e) { out.docStatus = 0; out.docErr = e.message; }
  res.json(out);
});

const port = Number(process.env.PORT || 10000);
http.createServer(app).listen(port, "0.0.0.0", () => console.log(`Gateway listening on :${port}`));
