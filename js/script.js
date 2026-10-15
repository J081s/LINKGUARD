
// When opened through a static editor server (for example Live Server on :5500),
// use the actual LinkGuard API instead of posting to that static server.
const apiBase = ["3000", ""].includes(window.location.port) && window.location.protocol !== "file:"
    ? ""
    : "http://localhost:3000";

async function scanLinkWithThreatIntelligence(rawURL) {

    try {

        const response = await fetch(`${apiBase}/api/scan`, {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: rawURL
            })

        });

        // A proxy, stale dev server, or interrupted connection can return an
        // empty/non-JSON body. Never surface the browser's JSON parser error.
        const body = await response.text();
        let result;
        try {
            result = body ? JSON.parse(body) : null;
        } catch {
            throw new Error(`Scan service returned an invalid response (HTTP ${response.status}). Make sure LinkGuard is running with npm start.`);
        }

        if (!response.ok) {
            throw new Error(
                result?.error || `Unable to scan URL (HTTP ${response.status}).`
            );
        }

        if (!result || result.success !== true) {
            throw new Error("Scan service returned an empty or invalid result. Please try again.");
        }

        return result;

    } catch (error) {

        console.error("LinkGuard frontend error:", error);

        if (error.name === "TypeError" || error.message === "Failed to fetch" || error.message.includes("fetch") || error.message.includes("NetworkError")) {
            throw new Error("Unable to connect to the LinkGuard backend. Please ensure the server is running ('npm start') and accessible at http://localhost:3000.");
        }
        throw error;

    }

}

const form = document.getElementById("scanForm");
const input = document.getElementById("urlInput");
const button = document.getElementById("scanButton");
const loading = document.getElementById("loading");
const resultSection = document.getElementById("resultSection");
const errorMessage = document.getElementById("errorMessage");
const historyBody = document.getElementById("historyBody");
const history = JSON.parse(localStorage.getItem("linkguard-history") || "[]");

function escapeHTML(value) { const e = document.createElement("div"); e.textContent = String(value); return e.innerHTML; }
function badgeClass(status) { return status === "Known Malicious" ? "danger" : status === "Suspicious" || status === "Checks Incomplete" || status === "API NOT CONFIGURED" ? "suspicious" : "safe"; }
function renderProviders(providers) {
    const status = document.getElementById("providerStatus");
    status.innerHTML = Object.values(providers).map(p => {
        const label = p.state === "disabled" ? "OPTIONAL CHECK DISABLED" : p.state === "not_configured" ? "API NOT CONFIGURED" : p.state === "completed" ? "CHECK COMPLETED" : p.state === "pending" ? "CHECK PENDING" : "CHECK UNAVAILABLE";
        const details = p.state === "completed"
            ? (p.provider === "VirusTotal" ? `${p.malicious || 0} malicious, ${p.suspicious || 0} suspicious` : p.provider === "Google Safe Browsing" ? `${p.matches?.length || 0} threat match(es)` : p.knownMalicious ? "Malware-related record" : "No active malicious record returned")
            : p.detail || "No result available";
        return `<article class="provider-card ${p.state}"><div><strong>${escapeHTML(p.provider)}</strong><span>${escapeHTML(label)}</span></div><p>${escapeHTML(details)}</p></article>`;
    }).join("");
}
async function loadConnectionStatus() {
    const target = document.getElementById("apiConnectionStatus");
    try {
        const response = await fetch(`${apiBase}/api/health`);
        if (!response.ok) throw new Error("Backend unavailable");
        const { providers } = await response.json();
        target.innerHTML = Object.values(providers).map(p => `<span class="connection ${p.configured ? "ready" : "missing"}"><i></i>${escapeHTML(p.provider)}: ${p.configured ? "CONFIGURED" : "NOT CONFIGURED"}</span>`).join("");
    } catch {
        target.textContent = "Backend offline — run 'npm start' in terminal";
        target.classList.add("backend-offline");
    }
}
function renderHistory() {
    if (!history.length) { historyBody.innerHTML = '<tr><td colspan="4" class="empty-state">No scans performed yet.</td></tr>'; return; }
    historyBody.innerHTML = history.map(item => `<tr><td>${escapeHTML(item.domain)}</td><td>${item.score}/100</td><td>${escapeHTML(item.status)}</td><td>${escapeHTML(item.time)}</td></tr>`).join("");
}
function addHistory(data) {
    history.unshift({ domain: new URL(data.scannedURL).hostname, score: data.riskScore, status: data.status, time: new Date().toLocaleString() });
    history.splice(8); localStorage.setItem("linkguard-history", JSON.stringify(history)); renderHistory();
}
function renderResult(data) {
    const parsed = new URL(data.scannedURL);
    document.getElementById("resultBadge").textContent = data.status;
    document.getElementById("resultBadge").className = `badge ${badgeClass(data.status)}`;
    document.getElementById("riskScore").textContent = data.riskScore;
    document.getElementById("riskBar").style.width = `${data.riskScore}%`;
    document.getElementById("riskBar").style.background = data.status === "Known Malicious" ? "#fb7185" : data.status === "No Known Threat Found" ? "#20d69b" : "#fbbf24";
    document.getElementById("riskDescription").textContent = `${data.completedThreatChecks}/${data.configuredThreatChecks} configured threat checks completed`;
    document.getElementById("analysedUrl").textContent = data.scannedURL;
    document.getElementById("domainName").textContent = parsed.hostname;
    document.getElementById("protocolName").textContent = parsed.protocol;
    document.getElementById("reportNotice").textContent = data.message;
    document.getElementById("findingsList").innerHTML = data.findings.map(f => `<li class="${f.severity === "info" ? "positive" : ""}"><strong>${escapeHTML(f.source || "Assessment")}:</strong> ${escapeHTML(f.message)}</li>`).join("");
    document.getElementById("recommendation").textContent = data.status === "Known Malicious" ? "Recommendation: do not open this link or enter information on the site." : data.status === "Checks Incomplete" || data.status === "API NOT CONFIGURED" ? "Recommendation: do not treat this URL as safe until provider checks have completed." : data.status === "Suspicious" ? "Recommendation: verify the sender and destination before continuing." : "Recommendation: remain cautious; a completed clean check does not guarantee safety.";
    renderProviders(data.threatIntelligence); resultSection.classList.remove("hidden"); addHistory(data);
}
form.addEventListener("submit", async event => {
    event.preventDefault(); errorMessage.classList.add("hidden"); resultSection.classList.add("hidden"); loading.classList.remove("hidden"); button.disabled = true;
    try { renderResult(await scanLinkWithThreatIntelligence(input.value.trim())); }
    catch (error) { errorMessage.textContent = error.message; errorMessage.classList.remove("hidden"); }
    finally { loading.classList.add("hidden"); button.disabled = false; }
});
document.getElementById("clearHistory").addEventListener("click", () => { history.length = 0; localStorage.removeItem("linkguard-history"); renderHistory(); });
renderHistory();
loadConnectionStatus();
