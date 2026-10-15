// Known target brands frequently impersonated in phishing attacks and their legitimate root domains
const BRAND_TARGETS = [
  { name: "PayPal", pattern: /paypal/i, legitimate: ["paypal.com", "paypal.me"] },
  { name: "Apple", pattern: /apple|icloud/i, legitimate: ["apple.com", "icloud.com"] },
  { name: "Google", pattern: /google|gmail/i, legitimate: ["google.com", "gmail.com"] },
  { name: "Microsoft", pattern: /microsoft|office365|live\.com|outlook/i, legitimate: ["microsoft.com", "office.com", "live.com", "office365.com", "outlook.com"] },
  { name: "Netflix", pattern: /netflix/i, legitimate: ["netflix.com"] },
  { name: "Amazon", pattern: /amazon|primevideo/i, legitimate: ["amazon.com"] },
  { name: "Meta / Facebook", pattern: /facebook|meta|fb\.com/i, legitimate: ["facebook.com", "meta.com", "fb.com"] },
  { name: "Instagram", pattern: /instagram/i, legitimate: ["instagram.com"] },
  { name: "WhatsApp", pattern: /whatsapp/i, legitimate: ["whatsapp.com"] },
  { name: "Telegram", pattern: /telegram/i, legitimate: ["telegram.org", "t.me"] },
  { name: "Chase", pattern: /chase/i, legitimate: ["chase.com"] },
  { name: "Wells Fargo", pattern: /wellsfargo/i, legitimate: ["wellsfargo.com"] },
  { name: "Bank of America", pattern: /bankofamerica|bofa/i, legitimate: ["bankofamerica.com"] },
  { name: "Citibank", pattern: /citibank|citi/i, legitimate: ["citibank.com", "citi.com"] },
  { name: "Binance", pattern: /binance/i, legitimate: ["binance.com"] },
  { name: "Coinbase", pattern: /coinbase/i, legitimate: ["coinbase.com"] },
  { name: "MetaMask", pattern: /metamask/i, legitimate: ["metamask.io"] },
  { name: "Steam", pattern: /steam/i, legitimate: ["steamcommunity.com", "steampowered.com"] },
  { name: "Discord", pattern: /discord/i, legitimate: ["discord.com", "discord.gg"] },
  { name: "Roblox", pattern: /roblox/i, legitimate: ["roblox.com"] },
  { name: "eBay", pattern: /ebay/i, legitimate: ["ebay.com"] },
  { name: "Spotify", pattern: /spotify/i, legitimate: ["spotify.com"] },
  { name: "USPS", pattern: /usps/i, legitimate: ["usps.com"] },
  { name: "FedEx", pattern: /fedex/i, legitimate: ["fedex.com"] },
  { name: "DHL", pattern: /dhl/i, legitimate: ["dhl.com"] },
  { name: "UPS", pattern: /ups/i, legitimate: ["ups.com"] }
];

const SECURITY_TEST_SIGNATURES = [
  { pattern: /testsafebrowsing\.appspot\.com/i, name: "Google Safe Browsing test portal" },
  { pattern: /malware\.testing\.google\.test/i, name: "Google Safe Browsing malware test site" },
  { pattern: /itisatrap\.org/i, name: "Mozilla Firefox anti-phishing test suite" },
  { pattern: /wicar\.org/i, name: "WICAR malware test suite" },
  { pattern: /eicar(?:\.org|\.com)/i, name: "EICAR standard anti-virus test signature" }
];

const SUSPICIOUS_TLDS = new Set([
  "xyz", "top", "click", "work", "gq", "tk", "ml", "cf", "ga",
  "buzz", "icu", "monster", "quest", "rest", "cam", "sbs", "cfd",
  "fit", "online", "site", "vip", "support", "link", "live", "info",
  "bid", "loan", "win", "stream", "download", "fun", "pw", "cc", "space", "shop", "club",
  "surf", "beauty", "hair", "skin", "makeup", "center", "agency", "zip", "mov"
]);

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "ow.ly",
  "tiny.cc", "rb.gy", "shorturl.at", "goo.gl", "qr.net", "shorte.st", "trib.al", "v.gd"
]);

const SUSPICIOUS_KEYWORD_PATTERNS = [
  { pattern: /free[-_]?(?:money|crypto|robux|nitro|giftcard|iphone|rewards?)|crypto[-_]?giveaway|claim[-_]?(?:prize|reward|gift|airdrop)|airdrop|lottery[-_]?(?:winner|claim)|congratulations[-_]?winner/i, name: "financial scam / bait" },
  { pattern: /account[-_]?(?:suspended|locked|blocked|disabled|alert|security|verify|update|restricted|compromised)|verify[-_]?(?:account|identity|email|login|device|phone|card|ssn)|urgent[-_]?action/i, name: "account suspension / urgent verification" },
  { pattern: /secure[-_]?login|password[-_]?reset|reset[-_]?password|credential|passcode|confirm[-_]?identity|signin|sign[-_]?in|log[-_]?in|auth[-_]?check|session[-_]?expired/i, name: "credential harvest / fake login" },
  { pattern: /bank[-_]?(?:verification|alert|update|security)|billing[-_]?(?:update|issue|failed|problem)|invoice[-_]?(?:alert|overdue|pending)|payment[-_]?(?:failed|verify|declined|hold)/i, name: "banking / billing impersonation" },
  { pattern: /wallet[-_]?connect|metamask[-_]?(?:validate|sync|restore)|seed[-_]?phrase|private[-_]?key|keystore[-_]?json|phantom[-_]?wallet|trustwallet/i, name: "crypto wallet theft" },
  { pattern: /phish|malware|trojan|exploit|hacked|suspicious|dangerous|ransomware|keylogger|spyware|stealer|payload|backdoor|dropper/i, name: "threat indicator keyword" }
];

export function analyseURLLocally(url) {
  let score = 0;
  const findings = [];
  const add = (points, message, severity = "warning") => {
    score += points;
    findings.push({ message, severity, source: "Local heuristic" });
  };

  const host = url.hostname.toLowerCase();
  const full = url.href.toLowerCase();
  const path = url.pathname.toLowerCase();

  // 0. Security test suite detection (official anti-malware/phishing test links)
  for (const sig of SECURITY_TEST_SIGNATURES) {
    if (sig.pattern.test(full)) {
      add(75, `Industry security test target detected: ${sig.name}.`, "danger");
      break;
    }
  }

  // 1. Unencrypted HTTP
  if (url.protocol === "http:") {
    add(10, "Website uses an unencrypted HTTP connection.");
  }

  // 2. IP Address as host
  if (/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(host) || host.startsWith("[")) {
    add(25, "Website uses an IP address instead of a conventional domain.", "danger");
  }

  // 3. Punycode / Internationalized Domain Name homograph
  if (host.includes("xn--")) {
    add(25, "Punycode detected; investigate possible domain impersonation (homograph attack).", "danger");
  }

  // 4. URL Shortener
  if (SHORTENERS.has(host)) {
    add(15, "URL uses a shortening service; real destination is masked.");
  }

  // 5. Suspicious TLD
  const tld = host.split(".").pop();
  if (SUSPICIOUS_TLDS.has(tld)) {
    add(15, `Domain extension (.${tld}) has a high correlation with spam and phishing activity.`);
  }

  // 6. Brand Impersonation Check (in host or deceptive paths)
  for (const brand of BRAND_TARGETS) {
    const isOfficial = brand.legitimate.some(legit => host === legit || host.endsWith("." + legit));
    if (!isOfficial) {
      if (brand.pattern.test(host)) {
        add(35, `Potential brand impersonation: URL hostname references '${brand.name}' but is not an official ${brand.name} domain.`, "danger");
        break;
      } else if (brand.pattern.test(path) && /(?:login|signin|sign-in|log-in|verify|secure|account|update|auth)/i.test(full)) {
        add(25, `Potential brand impersonation: URL path references '${brand.name}' with login/verification keywords on an unofficial domain.`, "danger");
        break;
      }
    }
  }

  // 7. Deceptive compound domain / embedded TLD in subdomain (e.g., paypal.com.evil.xyz)
  if (/(?:\.com|\.net|\.org|\.gov|\.edu|\.io|\.co)\./.test(host)) {
    add(25, "Deceptive domain structure detected (legitimate TLD embedded in subdomains).", "danger");
  }

  // 8. Multiple hyphens in domain (classic phishing domain generator pattern)
  const domainHyphenCount = (host.match(/-/g) || []).length;
  if (domainHyphenCount >= 2) {
    add(15, `Domain contains ${domainHyphenCount} hyphens, a common pattern in phishing domain generation.`);
  }

  // 9. Suspicious keywords in domain, query, or path
  const matchedKeywords = [];
  for (const kw of SUSPICIOUS_KEYWORD_PATTERNS) {
    if (kw.pattern.test(full)) {
      matchedKeywords.push(kw.name);
    }
  }
  if (matchedKeywords.length) {
    const points = Math.min(matchedKeywords.length * 15, 30);
    add(points, `Suspicious phishing/scam patterns detected: ${matchedKeywords.join(", ")}.`);
  }

  // 10. Dangerous executable or script download
  if (/\.(exe|scr|bat|cmd|vbs|ps1|apk|iso|hta|dll|jar|msi|vbe|wsf|com)$/i.test(path)) {
    add(35, "URL directly links to an executable or script file download.", "danger");
  }

  // 11. Excessive subdomains
  if (host.split(".").length >= 5) {
    add(10, "Unusually large number of domain subdomains detected.");
  }

  // 12. Non-standard network port
  if (url.port && url.port !== "80" && url.port !== "443") {
    add(15, `Website uses an unusual non-standard network port (${url.port}).`);
  }

  // 13. URL contains "@" symbol (credentials / host confusion)
  if (url.username || full.includes("@")) {
    add(25, "URL contains an '@' character which can obscure the actual destination domain.", "danger");
  }

  // 14. Unusually long URL
  if (url.href.length > 120) {
    add(10, "URL is unusually long (potential payload or tracking obfuscation).");
  }

  if (!findings.length) {
    findings.push({ message: "No suspicious patterns identified by local analysis.", severity: "info", source: "Local heuristic" });
  }

  return { score: Math.min(score, 100), findings };
}

