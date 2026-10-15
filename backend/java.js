
import express from "express";
import dotenv from "dotenv";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");

app.use(helmet());
app.use(express.json({ limit: "10kb" }));

// Serve your existing frontend without rebuilding it.
app.use(express.static(projectRoot));

// Limit repeated scan requests.
const scanLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: 10,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: {
        error: "Too many scan requests. Please try again later."
    }
});


// --------------------------------------
// 1. LOCAL URL ANALYSIS
// --------------------------------------

function analyseURLLocally(url) {

    let score = 0;
    const findings = [];

    function addFinding(points, message, severity = "warning") {
        score += points;

        findings.push({
            message,
            severity
        });
    }

    const hostname = url.hostname.toLowerCase();
    const fullURL = url.href.toLowerCase();

    if (url.protocol === "http:") {
        addFinding(
            10,
            "Website uses an unencrypted HTTP connection."
        );
    }

    const ipv4Pattern =
        /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;

    if (ipv4Pattern.test(hostname) || hostname.startsWith("[")) {
        addFinding(
            20,
            "Website uses an IP address instead of a conventional domain."
        );
    }

    if (hostname.includes("xn--")) {
        addFinding(
            25,
            "Punycode detected. Investigate possible domain impersonation."
        );
    }

    const shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "cutt.ly",
        "is.gd",
        "ow.ly",
        "tiny.cc"
    ];

    if (shorteners.includes(hostname)) {
        addFinding(
            10,
            "URL uses a shortening service. Its destination is not verified."
        );
    }

    const suspiciousTLDs = [
        "xyz",
        "top",
        "click",
        "work",
        "gq",
        "tk"
    ];

    const tld = hostname.split(".").pop();

    if (suspiciousTLDs.includes(tld)) {
        addFinding(
            10,
            "Domain uses an extension requiring additional investigation."
        );
    }

    const keywords = [
        "free-money",
        "claim-prize",
        "account-suspended",
        "verify-account",
        "password-reset",
        "secure-login",
        "bank-verification",
        "crypto-giveaway"
    ];

    const detected = keywords.filter(keyword =>
        fullURL.includes(keyword)
    );

    if (detected.length > 0) {
        addFinding(
            Math.min(detected.length * 8, 20),
            "Potentially suspicious URL keywords: " + detected.join(", ")
        );
    }

    if (hostname.split(".").length >= 5) {
        addFinding(
            10,
            "Unusually large number of domain subdomains detected."
        );
    }

    if (url.username || url.password) {
        addFinding(
            20,
            "URL contains embedded credentials."
        );
    }

    if (url.port) {
        addFinding(
            10,
            "Website uses a non-default network port."
        );
    }

    if (url.href.length > 150) {
        addFinding(
            5,
            "URL is unusually long."
        );
    }

    score = Math.min(score, 100);

    if (findings.length === 0) {
        findings.push({
            message: "No suspicious patterns identified by local analysis.",
            severity: "info"
        });
    }

    return {
        score,
        findings
    };
}


// --------------------------------------
// 2. COMMON API REQUEST HELPER
// --------------------------------------

async function fetchWithTimeout(resource, options = {}) {

    const controller = new AbortController();

    const timeout = setTimeout(
        () => controller.abort(),
        12000
    );

    try {

        return await fetch(resource, {
            ...options,
            signal: controller.signal
        });

    } finally {

        clearTimeout(timeout);

    }
}


// --------------------------------------
// 3. VIRUSTOTAL INTEGRATION
// --------------------------------------

async function checkVirusTotal(url) {

    const apiKey = process.env.VIRUSTOTAL_API_KEY;

    if (!apiKey) {
        return {
            provider: "VirusTotal",
            available: false,
            error: "VirusTotal API key is not configured."
        };
    }

    const headers = {
        "x-apikey": apiKey,
        "accept": "application/json"
    };

    // VirusTotal accepts an unpadded URL-safe Base64 identifier.
    const urlId = Buffer
        .from(url.href)
        .toString("base64url");

    try {

        // First try to retrieve an existing URL report.
        let response = await fetchWithTimeout(
            `https://www.virustotal.com/api/v3/urls/${urlId}`,
            { headers }
        );

        let data;

        if (response.ok) {

            data = await response.json();

        } else if (response.status === 404) {

            // No existing report: submit URL for analysis.
            const form = new URLSearchParams();
            form.append("url", url.href);

            const submission = await fetchWithTimeout(
                "https://www.virustotal.com/api/v3/urls",
                {
                    method: "POST",
                    headers: {
                        ...headers,
                        "content-type": "application/x-www-form-urlencoded"
                    },
                    body: form
                }
            );

            if (!submission.ok) {
                throw new Error(
                    `VirusTotal submission failed: HTTP ${submission.status}`
                );
            }

            const submittedData = await submission.json();

            const analysisId = submittedData?.data?.id;

            if (!analysisId) {
                throw new Error("VirusTotal did not return an analysis ID.");
            }

            // Allow time for the analysis to finish.
            let analysisData = null;

            for (let attempt = 0; attempt < 5; attempt++) {

                await new Promise(resolve =>
                    setTimeout(resolve, 2000)
                );

                const analysisResponse = await fetchWithTimeout(
                    `https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(analysisId)}`,
                    { headers }
                );

                if (!analysisResponse.ok) {
                    throw new Error(
                        `VirusTotal analysis lookup failed: HTTP ${analysisResponse.status}`
                    );
                }

                const result = await analysisResponse.json();

                analysisData = result?.data?.attributes;

                if (analysisData?.status === "completed") {
                    break;
                }
            }

            if (analysisData?.status !== "completed") {
                return {
                    provider: "VirusTotal",
                    available: true,
                    completed: false,
                    message: "Analysis is still processing. Please scan again later."
                };
            }

            const stats = analysisData.stats || {};

            return {
                provider: "VirusTotal",
                available: true,
                completed: true,
                malicious: stats.malicious || 0,
                suspicious: stats.suspicious || 0,
                harmless: stats.harmless || 0,
                undetected: stats.undetected || 0,
                detections: analysisData.results || {}
            };

        } else {

            throw new Error(
                `VirusTotal report lookup failed: HTTP ${response.status}`
            );

        }

        const attributes = data?.data?.attributes;

        if (!attributes) {
            throw new Error("VirusTotal returned an incomplete report.");
        }

        const stats = attributes.last_analysis_stats || {};

        return {
            provider: "VirusTotal",
            available: true,
            completed: true,
            malicious: stats.malicious || 0,
            suspicious: stats.suspicious || 0,
            harmless: stats.harmless || 0,
            undetected: stats.undetected || 0,
            reputation: attributes.reputation ?? null
        };

    } catch (error) {

        console.error("VirusTotal error:", error.message);

        return {
            provider: "VirusTotal",
            available: false,
            error: error.name === "AbortError"
                ? "VirusTotal request timed out."
                : "VirusTotal could not complete the check."
        };
    }
}


// --------------------------------------
// 4. GOOGLE SAFE BROWSING INTEGRATION
// --------------------------------------

async function checkGoogleSafeBrowsing(url) {

    const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

    if (!apiKey) {
        return {
            provider: "Google Safe Browsing",
            available: false,
            error: "Google Safe Browsing API key is not configured."
        };
    }

    try {

        const endpoint =
            "https://safebrowsing.googleapis.com/v4/threatMatches:find";

        const response = await fetchWithTimeout(
            `${endpoint}?key=${encodeURIComponent(apiKey)}`,
            {
                method: "POST",
                headers: {
                    "content-type": "application/json"
                },
                body: JSON.stringify({
                    client: {
                        clientId: "linkguard",
                        clientVersion: "1.0.0"
                    },
                    threatInfo: {
                        threatTypes: [
                            "MALWARE",
                            "SOCIAL_ENGINEERING"
                        ],
                        platformTypes: [
                            "ANY_PLATFORM"
                        ],
                        threatEntryTypes: [
                            "URL"
                        ],
                        threatEntries: [
                            {
                                url: url.href
                            }
                        ]
                    }
                })
            }
        );

        if (!response.ok) {
            throw new Error(
                `Google Safe Browsing failed: HTTP ${response.status}`
            );
        }

        const data = await response.json();

        const matches = data.matches || [];

        return {
            provider: "Google Safe Browsing",
            available: true,
            completed: true,
            matches: matches.map(match => ({
                threatType: match.threatType,
                platformType: match.platformType,
                threatEntryType: match.threatEntryType,
                url: match.threat?.url
            }))
        };

    } catch (error) {

        console.error("Google Safe Browsing error:", error.message);

        return {
            provider: "Google Safe Browsing",
            available: false,
            error: error.name === "AbortError"
                ? "Google Safe Browsing request timed out."
                : "Google Safe Browsing could not complete the check."
        };
    }
}


// --------------------------------------
// 5. COMBINE DETECTION RESULTS
// --------------------------------------

function generateVerdict(local, providers) {

    const vt = providers.virusTotal;
    const google = providers.googleSafeBrowsing;

    const confirmedMalicious =
        (vt?.completed && vt.malicious > 0) ||
        (google?.completed && google.matches?.length > 0);

    const suspiciousThreat =
        (vt?.completed && vt.suspicious > 0) ||
        local.score >= 25;

    const completedChecks = [
        vt?.completed,
        google?.completed
    ].filter(Boolean).length;

    let status;
    let verified;

    if (confirmedMalicious) {

        status = "Known Malicious";
        verified = true;

    } else if (suspiciousThreat) {

        status = "Suspicious";
        verified = completedChecks > 0;

    } else if (completedChecks > 0) {

        status = "No Known Threat Found";
        verified = true;

    } else {

        status = "Unable to Verify";
        verified = false;

    }

    return {
        status,
        verified,
        localRiskScore: local.score,
        completedThreatChecks: completedChecks
    };
}


// --------------------------------------
// 6. MAIN SCAN ENDPOINT
// --------------------------------------

app.post("/api/scan", scanLimiter, async (req, res) => {

    try {

        const { url: rawURL } = req.body;

        if (typeof rawURL !== "string" || !rawURL.trim()) {
            return res.status(400).json({
                error: "Please provide a valid URL."
            });
        }

        if (rawURL.length > 2048) {
            return res.status(400).json({
                error: "URL exceeds the maximum allowed length."
            });
        }

        let url;

        try {

            url = new URL(rawURL.trim());

        } catch {

            return res.status(400).json({
                error: "Invalid URL format."
            });

        }

        if (!["http:", "https:"].includes(url.protocol)) {
            return res.status(400).json({
                error: "Only HTTP and HTTPS URLs are supported."
            });
        }

        if (!url.hostname || url.username || url.password) {
            return res.status(400).json({
                error: "Invalid URL or embedded credentials detected."
            });
        }

        // Run local analysis and both external checks.
        const local = analyseURLLocally(url);

        const [virusTotal, googleSafeBrowsing] = await Promise.all([
            checkVirusTotal(url),
            checkGoogleSafeBrowsing(url)
        ]);

        const providers = {
            virusTotal,
            googleSafeBrowsing
        };

        const verdict = generateVerdict(local, providers);

        return res.json({

            success: true,

            scannedURL: url.href,

            status: verdict.status,

            verified: verdict.verified,

            localRiskScore: verdict.localRiskScore,

            completedThreatChecks: verdict.completedThreatChecks,

            findings: local.findings,

            threatIntelligence: providers,

            message: verdict.status === "Known Malicious"
                ? "Threat intelligence identified this URL as malicious."
                : verdict.status === "Suspicious"
                    ? "Suspicious indicators were identified. Further investigation is recommended."
                    : verdict.status === "No Known Threat Found"
                        ? "No known threat was found by the completed checks. This does not guarantee safety."
                        : "The threat-intelligence services could not verify this URL."

        });

    } catch (error) {

        console.error("LinkGuard scan error:", error.message);

        return res.status(500).json({
            error: "An internal error occurred while scanning the URL."
        });

    }

});


// --------------------------------------
// 7. HEALTH CHECK
// --------------------------------------

app.get("/api/health", (req, res) => {

    res.json({
        success: true,
        application: "LinkGuard",
        backend: "Online",
        virusTotalConfigured: Boolean(
            process.env.VIRUSTOTAL_API_KEY
        ),
        googleSafeBrowsingConfigured: Boolean(
            process.env.GOOGLE_SAFE_BROWSING_API_KEY
        )
    });

});


// --------------------------------------
// 8. START SERVER
// --------------------------------------

app.listen(PORT, () => {

    console.log("--------------------------------");
    console.log("LINKGUARD BACKEND STARTED");
    console.log(`Server: http://localhost:${PORT}`);
    console.log("--------------------------------");

});
