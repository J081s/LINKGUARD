import express from "express";
import dotenv from "dotenv";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import path from "path";
import { fileURLToPath } from "url";
import { analyseURLLocally } from "./heuristics.js";
import { collectThreatIntelligence, getConnectionStatus } from "./services.js";
import { assessRisk } from "./risk.js";

// The project's .env is the authoritative local configuration. This avoids a
// stale system environment variable silently changing the enabled providers.
dotenv.config({ override: true });
const app = express();
const port = process.env.PORT || 3000;
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "10kb" }));
// Permit local static development servers and file:// to call the backend on :3000.
app.use((req, res, next) => {
  const origin = req.get("origin");
  if (!origin || origin === "null" || /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin === "null" ? "*" : (origin || "*"));
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(express.static(root));

app.use((error, _req, res, next) => {
  if (error instanceof SyntaxError && "body" in error) return res.status(400).json({ error: "Request body must be valid JSON." });
  next(error);
});

const scanLimiter = rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: "draft-7", legacyHeaders: false, message: { error: "Too many scan requests. Please try again later." } });

export async function performUrlScan(rawInput, env = process.env) {
  if (typeof rawInput !== "string" || !rawInput.trim() || rawInput.length > 2048) {
    const err = new Error("Please provide a valid URL under 2048 characters.");
    err.status = 400;
    throw err;
  }
  let raw = rawInput.trim();
  if (!/^https?:\/\//i.test(raw)) {
    raw = "https://" + raw;
  }
  let url;
  try {
    url = new URL(raw);
  } catch {
    const err = new Error("Invalid URL format.");
    err.status = 400;
    throw err;
  }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password) {
    const err = new Error("Only valid HTTP/HTTPS URLs without embedded credentials are supported.");
    err.status = 400;
    throw err;
  }

  const local = analyseURLLocally(url);
  const threatIntelligence = await collectThreatIntelligence(url, env);
  const assessment = assessRisk(local, threatIntelligence);

  return {
    success: true,
    scannedURL: url.href,
    ...assessment,
    localRiskScore: local.score,
    threatIntelligence,
    message: assessment.status === "API NOT CONFIGURED" ? "API NOT CONFIGURED: configure at least one provider in .env, then restart the backend."
      : assessment.status === "Checks Incomplete" ? "Threat-intelligence checks are incomplete; no safety conclusion is available."
      : assessment.status === "No Known Threat Found" ? "No known threat was found by all configured completed checks. This is not a guarantee of safety."
      : assessment.status === "Known Malicious" ? (assessment.findings.some(f => f.source === "Google Safe Browsing" || f.source === "VirusTotal" || f.source === "URLhaus") ? "Threat intelligence identified this URL as malicious." : "High-risk threat indicators and security heuristics identified this URL as malicious.")
      : "Suspicious indicators were identified; further investigation is recommended."
  };
}

app.get(["/api/health", "/health"], (_req, res) => res.json({ success: true, application: "LinkGuard", backend: "Online", providers: getConnectionStatus() }));

app.post(["/api/scan", "/scan"], scanLimiter, async (req, res) => {
  try {
    const result = await performUrlScan(req.body?.url);
    res.json(result);
  } catch (error) {
    if (error.status) return res.status(error.status).json({ error: error.message });
    console.error("LinkGuard scan error:", error.message);
    res.status(500).json({ error: "An internal error occurred while scanning the URL." });
  }
});

const isDirectExecution = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isDirectExecution) {
  app.listen(port, () => console.log(`LinkGuard backend ready at http://localhost:${port}`));
}

export { app };
export default app;
