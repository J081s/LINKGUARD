const REQUEST_TIMEOUT_MS = 12000;
const hasCredential = value => typeof value === "string" && value.trim().length > 0 && !/^(PASTE_|YOUR_|CHANGE_)/i.test(value.trim());
const isUrlhausEnabled = env => String(env.URLHAUS_ENABLED ?? "false").toLowerCase() === "true";

export async function fetchWithTimeout(resource, options = {}, fetchImpl = fetch) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetchImpl(resource, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function notConfigured(provider, detail) {
  return { provider, state: "not_configured", completed: false, configured: false, detail };
}

function disabled(provider, detail) {
  return { provider, state: "disabled", completed: false, configured: false, detail };
}

function failed(provider, error) {
  return { provider, state: "error", completed: false, configured: true, detail: error };
}

export async function checkVirusTotal(url, env, fetchImpl = fetch) {
  const apiKey = env.VIRUSTOTAL_API_KEY;
  if (!hasCredential(apiKey)) return notConfigured("VirusTotal", "API NOT CONFIGURED");
  const headers = { "x-apikey": apiKey, accept: "application/json" };
  try {
    const isIp = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(url.hostname);
    const domainEndpoint = isIp
      ? `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(url.hostname)}`
      : `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(url.hostname)}`;

    // Optional domain lookup in parallel to catch known malicious domains immediately
    const domainCheckPromise = fetchWithTimeout(domainEndpoint, { headers }, fetchImpl)
      .then(r => r.ok ? r.json() : null)
      .catch(() => null);

    const urlId = Buffer.from(url.href).toString("base64url");
    let response = await fetchWithTimeout(`https://www.virustotal.com/api/v3/urls/${urlId}`, { headers }, fetchImpl);

    // If 404, try alternative variant without or with trailing slash
    if (response.status === 404) {
      const altHref = url.href.endsWith("/") ? url.href.slice(0, -1) : url.href + "/";
      const altId = Buffer.from(altHref).toString("base64url");
      const altResp = await fetchWithTimeout(`https://www.virustotal.com/api/v3/urls/${altId}`, { headers }, fetchImpl);
      if (altResp.ok) {
        response = altResp;
      }
    }

    let stats = null;
    let reputation = null;

    if (response.ok) {
      const data = await response.json();
      stats = data?.data?.attributes?.last_analysis_stats || null;
      reputation = data?.data?.attributes?.reputation ?? null;
    } else if (response.status === 404) {
      // Submit URL for scan
      const form = new URLSearchParams({ url: url.href });
      const submitted = await fetchWithTimeout("https://www.virustotal.com/api/v3/urls", {
        method: "POST", headers: { ...headers, "content-type": "application/x-www-form-urlencoded" }, body: form
      }, fetchImpl);

      if (submitted.ok) {
        const subData = await submitted.json().catch(() => null);
        const analysisId = subData?.data?.id;
        if (analysisId) {
          // Poll up to 3 times with 1.2s delay to wait for analysis completion
          for (let attempt = 0; attempt < 3; attempt++) {
            await new Promise(res => setTimeout(res, 1200));
            const analysisResp = await fetchWithTimeout(`https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(analysisId)}`, { headers }, fetchImpl).catch(() => null);
            if (analysisResp?.ok) {
              const aData = await analysisResp.json();
              if (aData?.data?.attributes?.status === "completed") {
                stats = aData.data.attributes.stats || null;
                break;
              }
            }
          }
        }
      }
    } else {
      throw new Error(`HTTP ${response.status}`);
    }

    const domainData = await domainCheckPromise;
    const domainStats = domainData?.data?.attributes?.last_analysis_stats;
    const domainMalicious = domainStats?.malicious || 0;
    const domainSuspicious = domainStats?.suspicious || 0;

    if (stats) {
      const malicious = Math.max(stats.malicious || 0, domainMalicious);
      const suspicious = Math.max(stats.suspicious || 0, domainSuspicious);
      return {
        provider: "VirusTotal",
        state: "completed",
        configured: true,
        completed: true,
        malicious,
        suspicious,
        harmless: stats.harmless || 0,
        undetected: stats.undetected || 0,
        reputation
      };
    }

    // If URL analysis is still pending but domain is flagged as malicious:
    if (domainMalicious > 0 || domainSuspicious > 0) {
      return {
        provider: "VirusTotal",
        state: "completed",
        configured: true,
        completed: true,
        malicious: domainMalicious,
        suspicious: domainSuspicious,
        harmless: domainStats?.harmless || 0,
        undetected: domainStats?.undetected || 0,
        reputation: domainData?.data?.attributes?.reputation ?? null,
        detail: "Domain flagged by VirusTotal threat intelligence."
      };
    }

    return {
      provider: "VirusTotal",
      state: "pending",
      configured: true,
      completed: false,
      detail: "URL submitted; VirusTotal analysis is processing. Scan again in a moment."
    };
  } catch (error) {
    return failed("VirusTotal", error.name === "AbortError" ? "Request timed out." : (error.message || "Could not complete the check."));
  }
}

export async function checkGoogleSafeBrowsing(url, env, fetchImpl = fetch) {
  const apiKey = env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!hasCredential(apiKey)) return notConfigured("Google Safe Browsing", "API NOT CONFIGURED");
  try {
    const candidateUrls = new Set([
      url.href,
      url.href.endsWith("/") ? url.href.slice(0, -1) : url.href + "/",
      url.origin + "/",
      url.href.startsWith("http:") ? url.href.replace(/^http:/, "https:") : url.href.replace(/^https:/, "http:")
    ]);
    const threatEntries = Array.from(candidateUrls).map(u => ({ url: u }));

    const response = await fetchWithTimeout(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ client: { clientId: "linkguard", clientVersion: "1.0.0" }, threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"], threatEntries
      }})
    }, fetchImpl);
    if (!response.ok) {
      if (response.status === 403) throw new Error("Safe Browsing API not enabled in Google Console for this key.");
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    const matches = Array.isArray(data.matches) ? data.matches.map(({ threatType, platformType, threatEntryType }) => ({ threatType, platformType, threatEntryType })) : [];
    return { provider: "Google Safe Browsing", state: "completed", configured: true, completed: true, matches };
  } catch (error) {
    return failed("Google Safe Browsing", error.name === "AbortError" ? "Request timed out." : (error.message || "Could not complete the check."));
  }
}

export async function checkUrlhaus(url, env, fetchImpl = fetch) {
  if (!isUrlhausEnabled(env)) return disabled("URLhaus", "Optional URLhaus check is disabled.");
  if (!hasCredential(env.URLHAUS_API_KEY)) return notConfigured("URLhaus", "URLhaus requires an Auth-Key. Set URLHAUS_API_KEY or leave URLHAUS_ENABLED=false.");
  const headers = { "content-type": "application/x-www-form-urlencoded" };
  headers["Auth-Key"] = env.URLHAUS_API_KEY;
  try {
    const body = new URLSearchParams({ url: url.href });
    const response = await fetchWithTimeout("https://urlhaus-api.abuse.ch/v1/url/", {
      method: "POST", headers, body
    }, fetchImpl);
    if (!response.ok) {
      if (response.status === 401) throw new Error("abuse.ch requires an Auth-Key (set URLHAUS_API_KEY or URLHAUS_ENABLED=false).");
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    const knownMalicious = data.query_status === "ok" && Boolean(data.url_status && data.url_status !== "offline");
    return { provider: "URLhaus", state: "completed", configured: true, completed: true, knownMalicious,
      queryStatus: data.query_status || "unknown", urlStatus: data.url_status || null, threat: data.threat || null };
  } catch (error) {
    return failed("URLhaus", error.name === "AbortError" ? "Request timed out." : (error.message || "Could not complete the check."));
  }
}

export async function collectThreatIntelligence(url, env = process.env, fetchImpl = fetch) {
  const [virusTotal, googleSafeBrowsing, urlhaus] = await Promise.all([
    checkVirusTotal(url, env, fetchImpl), checkGoogleSafeBrowsing(url, env, fetchImpl), checkUrlhaus(url, env, fetchImpl)
  ]);
  return { virusTotal, googleSafeBrowsing, urlhaus };
}

export function getConnectionStatus(env = process.env) {
  return {
    virusTotal: { provider: "VirusTotal", configured: hasCredential(env.VIRUSTOTAL_API_KEY), state: hasCredential(env.VIRUSTOTAL_API_KEY) ? "ready" : "not_configured" },
    googleSafeBrowsing: { provider: "Google Safe Browsing", configured: hasCredential(env.GOOGLE_SAFE_BROWSING_API_KEY), state: hasCredential(env.GOOGLE_SAFE_BROWSING_API_KEY) ? "ready" : "not_configured" },
    urlhaus: { provider: "URLhaus", configured: isUrlhausEnabled(env) && hasCredential(env.URLHAUS_API_KEY), state: isUrlhausEnabled(env) ? (hasCredential(env.URLHAUS_API_KEY) ? "configured" : "not_configured") : "disabled" }
  };
}
