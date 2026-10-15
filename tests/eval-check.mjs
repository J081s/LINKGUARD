import dotenv from 'dotenv';
dotenv.config();

const { collectThreatIntelligence } = await import('./backend/services.js');
const { assessRisk } = await import('./backend/risk.js');
const { analyseURLLocally } = await import('./backend/heuristics.js');

const testUrls = [
  'http://testsafebrowsing.appspot.com/s/malware.html',
  'http://testsafebrowsing.appspot.com',
  'http://itisatrap.org',
  'http://wicar.org/test-malware.html',
  'http://www.eicar.org/download/eicar.com',
  'http://paypal-verification.com',
  'http://paypal-login-alert.xyz',
  'http://free-money-giveaway.top',
  'http://192.168.1.1:8080/payload.exe',
  'https://www.google.com'
];

for (const raw of testUrls) {
  const url = new URL(raw);
  const local = analyseURLLocally(url);
  const intel = await collectThreatIntelligence(url, process.env);
  const risk = assessRisk(local, intel);
  console.log(raw.padEnd(52), '=>', risk.status.padEnd(20), 'RiskScore:', String(risk.riskScore).padEnd(4), 'VT_mal:', intel.virusTotal.malicious, 'GSB:', intel.googleSafeBrowsing.matches?.length || 0, 'Local:', local.score);
}
