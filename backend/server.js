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

app.get("/api/health", (_req, res) => res.json({ success: true, application: "LinkGuard", backend: "Online", providers: getConnectionStatus() }));

app.post("/api/scan", scanLimiter, async (req, res) => {
  let raw = req.body?.url;
  if (typeof raw !== "string" || !raw.trim() || raw.length > 2048) return res.status(400).json({ error: "Please provide a valid URL under 2048 characters." });
  raw = raw.trim();
  if (!/^https?:\/\//i.test(raw)) {
    raw = "https://" + raw;
  }
  let url;
  try { url = new URL(raw); } catch { return res.status(400).json({ error: "Invalid URL format." }); }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password) return res.status(400).json({ error: "Only valid HTTP/HTTPS URLs without embedded credentials are supported." });
  try {
    const local = analyseURLLocally(url);
    const threatIntelligence = await collectThreatIntelligence(url);
    const assessment = assessRisk(local, threatIntelligence);
    res.json({ success: true, scannedURL: url.href, ...assessment, localRiskScore: local.score, threatIntelligence,
      message: assessment.status === "API NOT CONFIGURED" ? "API NOT CONFIGURED: configure at least one provider in .env, then restart the backend."
        : assessment.status === "Checks Incomplete" ? "Threat-intelligence checks are incomplete; no safety conclusion is available."
        : assessment.status === "No Known Threat Found" ? "No known threat was found by all configured completed checks. This is not a guarantee of safety."
        : assessment.status === "Known Malicious" ? (assessment.findings.some(f => f.source === "Google Safe Browsing" || f.source === "VirusTotal" || f.source === "URLhaus") ? "Threat intelligence identified this URL as malicious." : "High-risk threat indicators and security heuristics identified this URL as malicious.")
        : "Suspicious indicators were identified; further investigation is recommended." });
  } catch (error) {
    console.error("LinkGuard scan error:", error.message);
    res.status(500).json({ error: "An internal error occurred while scanning the URL." });
  }
});

app.listen(port, () => console.log(`LinkGuard backend ready at http://localhost:${port}`));
