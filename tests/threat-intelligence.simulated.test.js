// Simulated tests: all provider responses below are mocked; no live APIs are contacted.
import test from "node:test";
import assert from "node:assert/strict";
import { checkVirusTotal, checkGoogleSafeBrowsing, checkUrlhaus } from "../backend/services.js";
import { assessRisk } from "../backend/risk.js";

const url = new URL("https://example.test/path");
const response = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => body });

test("SIMULATED: missing credentials are explicitly not configured", async () => {
  const result = await checkVirusTotal(url, {}, () => { throw new Error("must not fetch"); });
  assert.equal(result.state, "not_configured");
  assert.equal(result.detail, "API NOT CONFIGURED");
});

test("SIMULATED: VirusTotal detections create a malicious assessment", async () => {
  const vt = await checkVirusTotal(url, { VIRUSTOTAL_API_KEY: "simulated" }, async () => response({ data: { attributes: { last_analysis_stats: { malicious: 2, suspicious: 0, harmless: 1, undetected: 5 }, reputation: -10 } } }));
  const assessment = assessRisk({ score: 0, findings: [] }, { virusTotal: vt, googleSafeBrowsing: { configured: false }, urlhaus: { configured: false } });
  assert.equal(vt.completed, true); assert.equal(assessment.status, "Known Malicious");
});

test("SIMULATED: Google empty matches are a completed check, not a fake guarantee", async () => {
  const google = await checkGoogleSafeBrowsing(url, { GOOGLE_SAFE_BROWSING_API_KEY: "simulated" }, async () => response({}));
  assert.equal(google.completed, true); assert.deepEqual(google.matches, []);
});

test("SIMULATED: URLhaus offline record is not treated as an active malicious verdict", async () => {
  const urlhaus = await checkUrlhaus(url, { URLHAUS_ENABLED: "true", URLHAUS_API_KEY: "simulated" }, async () => response({ query_status: "ok", url_status: "offline" }));
  assert.equal(urlhaus.knownMalicious, false);
});

test("SIMULATED: disabled optional providers do not invalidate completed configured checks", () => {
  const assessment = assessRisk({ score: 0, findings: [] }, {
    virusTotal: { configured: false, completed: false, state: "not_configured" },
    googleSafeBrowsing: { configured: true, completed: true, state: "completed", matches: [] },
    urlhaus: { configured: false, completed: false, state: "not_configured" }
  });
  assert.equal(assessment.status, "No Known Threat Found");
  assert.equal(assessment.verified, true);
});

test("SIMULATED: suspicious heuristic detection is flagged even when external provider checks are pending", async () => {
  const { analyseURLLocally } = await import("../backend/heuristics.js");
  const local = analyseURLLocally(new URL("https://paypal-security-update.com/verify-account"));
  assert.ok(local.score >= 25, "Expected suspicious score >= 25");

  const assessment = assessRisk(local, {
    virusTotal: { configured: true, completed: false, state: "pending" },
    googleSafeBrowsing: { configured: true, completed: true, state: "completed", matches: [] },
    urlhaus: { configured: false, completed: false, state: "disabled" }
  });

  assert.equal(assessment.status, "Suspicious");
  assert.equal(assessment.verified, true);
  assert.ok(assessment.riskScore >= 25);
  assert.ok(assessment.findings.some(f => f.message.includes("PayPal")));
});

test("SIMULATED: high-risk heuristic detections evaluate to Known Malicious", async () => {
  const { analyseURLLocally } = await import("../backend/heuristics.js");
  const local = analyseURLLocally(new URL("http://itisatrap.org/firefox/its-a-trap.html"));
  assert.ok(local.score >= 70, `Expected score >= 70, got ${local.score}`);

  const assessment = assessRisk(local, {
    virusTotal: { configured: true, completed: true, state: "completed", malicious: 0, suspicious: 0 },
    googleSafeBrowsing: { configured: true, completed: true, state: "completed", matches: [] },
    urlhaus: { configured: false, completed: false, state: "disabled" }
  });

  assert.equal(assessment.status, "Known Malicious");
  assert.equal(assessment.verified, true);
  assert.ok(assessment.riskScore >= 85);
});

test("SIMULATED: executable download on suspicious IP evaluates to Known Malicious", async () => {
  const { analyseURLLocally } = await import("../backend/heuristics.js");
  const local = analyseURLLocally(new URL("http://192.168.1.1:8080/trojan.exe"));
  assert.ok(local.score >= 70, `Expected score >= 70, got ${local.score}`);

  const assessment = assessRisk(local, {
    virusTotal: { configured: false, completed: false, state: "not_configured" },
    googleSafeBrowsing: { configured: false, completed: false, state: "not_configured" },
    urlhaus: { configured: false, completed: false, state: "not_configured" }
  });

  assert.equal(assessment.status, "Known Malicious");
  assert.equal(assessment.verified, true);
  assert.ok(assessment.riskScore >= 85);
});

