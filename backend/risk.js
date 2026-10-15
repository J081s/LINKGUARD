export function assessRisk(local, providers) {
  const all = Object.values(providers);
  const configured = all.filter(p => p.configured);
  const completed = all.filter(p => p.completed);
  const externalMalicious = (providers.virusTotal?.malicious || 0) > 0 || (providers.googleSafeBrowsing?.matches?.length || 0) > 0 || providers.urlhaus?.knownMalicious === true;
  const externalSuspicious = (providers.virusTotal?.suspicious || 0) > 0 || (providers.virusTotal?.reputation || 0) < -5;

  // High-confidence heuristic indicators (such as official test signatures, payload downloads, or multiple danger flags)
  const localMalicious = local.score >= 70;
  const localSuspicious = local.score >= 25;

  const providerFindings = [];

  if ((providers.virusTotal?.malicious || 0) > 0) {
    providerFindings.push({ message: `VirusTotal reported ${providers.virusTotal.malicious} malicious detection(s).`, severity: "danger", source: "VirusTotal" });
  }
  if ((providers.virusTotal?.suspicious || 0) > 0) {
    providerFindings.push({ message: `VirusTotal reported ${providers.virusTotal.suspicious} suspicious detection(s).`, severity: "warning", source: "VirusTotal" });
  }
  if ((providers.googleSafeBrowsing?.matches?.length || 0) > 0) {
    const threats = providers.googleSafeBrowsing.matches.map(m => m.threatType).filter(Boolean);
    const label = threats.length ? ` (${threats.join(", ")})` : "";
    providerFindings.push({ message: `Google Safe Browsing matched this URL to an active threat list${label}.`, severity: "danger", source: "Google Safe Browsing" });
  }
  if (providers.urlhaus?.knownMalicious) {
    providerFindings.push({ message: "URLhaus lists this URL as malware-related.", severity: "danger", source: "URLhaus" });
  }

  let status, verified = false, riskScore = local.score;
  if (externalMalicious || localMalicious) {
    status = "Known Malicious";
    verified = true;
    riskScore = Math.max(riskScore, 85);
  } else if (externalSuspicious || localSuspicious) {
    status = "Suspicious";
    verified = true;
    riskScore = Math.max(riskScore, externalSuspicious ? 65 : local.score);
  } else if (configured.length === 0) {
    status = "API NOT CONFIGURED";
  } else if (completed.length !== configured.length) {
    status = "Checks Incomplete";
  } else {
    status = "No Known Threat Found";
    verified = true;
  }

  return {
    status,
    verified,
    riskScore,
    completedThreatChecks: completed.length,
    configuredThreatChecks: configured.length,
    findings: [...providerFindings, ...local.findings]
  };
}

