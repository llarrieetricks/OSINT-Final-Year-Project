
const SUSPICIOUS_TERMS = [
  "account",
  "auth",
  "bank",
  "confirm",
  "credential",
  "login",
  "password",
  "secure",
  "signin",
  "verify",
];

const LURE_TERMS = [
  "alert",
  "message",
  "invoice",
  "reward",
  "update",
];

const HIGHER_RISK_TLDS = new Set([
  "click",
  "gq",
  "link",
  "monster",
  "rest",
  "shop",
  "top",
  "work",
  "xyz",
]);

function normalizeUrl(input) {
  if (typeof input !== "string" || !input.trim()) {
    throw new Error("A valid URL is required.");
  }

  const candidate = input.trim();

  const url = new URL(
    /^https?:\/\//i.test(candidate)
      ? candidate
      : `https://${candidate}`
  );

  if (!/^https?:$/.test(url.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs can be assessed.");
  }

  [
    "fbclid",
    "gclid",
    "mc_cid",
    "mc_eid",
    "ref",
    "source",
  ].forEach((parameter) => {
    url.searchParams.delete(parameter);
  });

  [...url.searchParams.keys()].forEach((parameter) => {
    if (parameter.toLowerCase().startsWith("utm_")) {
      url.searchParams.delete(parameter);
    }
  });

  url.hash = "";

  return url.toString();
}

function indicator(category, severity, weight, details) {
  return {
    category,
    severity,
    weight,
    details,
  };
}

function assessUrl(input, threatIntelligence = null) {
  const normalizedUrl = normalizeUrl(input);
  const parsed = new URL(normalizedUrl);

  const indicators = [];

  const hostname = parsed.hostname.toLowerCase();
  const pathAndQuery = `${parsed.pathname}${parsed.search}`.toLowerCase();
  const addressText = `${hostname}${pathAndQuery}`;

  const topLevelDomain = hostname.split(".").at(-1);

  // Check HTTPS usage
  if (parsed.protocol !== "https:") {
    indicators.push(
      indicator(
        "Transport security",
        "medium",
        15,
        "The URL does not use HTTPS."
      )
    );
  }

  // Check for Punycode domains
  if (hostname.includes("xn--")) {
    indicators.push(
      indicator(
        "Domain encoding",
        "high",
        25,
        "The domain contains Punycode, which can be used for lookalike domains."
      )
    );
  }

  // Check subdomain structure
  const subdomainCount = hostname.split(".").length - 2;

  if (subdomainCount >= 3) {
    indicators.push(
      indicator(
        "Domain structure",
        "medium",
        12,
        "The domain uses an unusually deep subdomain structure."
      )
    );
  }

  // Check IP-based URLs
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    indicators.push(
      indicator(
        "Host format",
        "high",
        25,
        "The URL uses an IP address instead of a domain name."
      )
    );
  }

  // Check higher-risk top-level domains
  if (HIGHER_RISK_TLDS.has(topLevelDomain)) {
    indicators.push(
      indicator(
        "Domain suffix",
        "medium",
        16,
        `The .${topLevelDomain} top-level domain may warrant additional scrutiny.`
      )
    );
  }

  // Check suspicious URL terms
  const matchedTerms = SUSPICIOUS_TERMS.filter((term) =>
    addressText.includes(term)
  );

  if (matchedTerms.length > 0) {
    indicators.push(
      indicator(
        "URL content",
        "medium",
        Math.min(20, matchedTerms.length * 6),
        `Sensitive-action terms found: ${matchedTerms.join(", ")}.`
      )
    );
  }

  // Check social-engineering wording
  const matchedLures = LURE_TERMS.filter((term) =>
    addressText.includes(term)
  );

  if (matchedLures.length > 0) {
    indicators.push(
      indicator(
        "Social-engineering wording",
        "low",
        Math.min(12, matchedLures.length * 4),
        `Urgency or lure terms found: ${matchedLures.join(", ")}.`
      )
    );
  }

  // Check URL length
  if (normalizedUrl.length > 100) {
    indicators.push(
      indicator(
        "URL length",
        "low",
        8,
        "The URL is unusually long."
      )
    );
  }

  // Check multiple hyphens
  if (hostname.split("-").length - 1 >= 3) {
    indicators.push(
      indicator(
        "Domain structure",
        "low",
        8,
        "The hostname contains multiple hyphens."
      )
    );
  }

  // Check OpenPhish threat intelligence
  const openphish = threatIntelligence?.openphish;

  const confirmedPhishingMatch =
    openphish?.source === "OpenPhish" &&
    openphish?.available === true &&
    openphish?.matched === true &&
    openphish?.queryStatus === "ok";

  if (confirmedPhishingMatch) {
    indicators.push(
      indicator(
        "Phishing intelligence",
        "critical",
        100,
        "OpenPhish has identified this URL as a phishing URL."
      )
    );
  }

  // Check URLhaus threat intelligence
  const urlhaus = threatIntelligence?.urlhaus;

  const maliciousMatch =
    urlhaus?.source === "URLhaus" &&
    urlhaus?.available === true &&
    urlhaus?.matched === true &&
    urlhaus?.queryStatus === "ok";

  if (maliciousMatch) {
    indicators.push(
      indicator(
        "Threat intelligence",
        "critical",
        100,
        `URLhaus has identified this URL as malicious. Threat category: ${
          urlhaus.threat || "unspecified"
        }.`
      )
    );
  }

  // Calculate heuristic score separately
  const heuristicScore = indicators
    .filter(
      (item) =>
        item.category !== "Threat intelligence" &&
        item.category !== "Phishing intelligence"
    )
    .reduce((total, item) => total + item.weight, 0);

  // Calculate final risk score
  const riskScore =
    confirmedPhishingMatch || maliciousMatch
      ? 100
      : Math.min(100, heuristicScore);

  // Determine risk classification
  let riskLevel;

  if (confirmedPhishingMatch) {
    riskLevel = "Confirmed Phishing";
  } else if (maliciousMatch || riskScore > 0) {
    riskLevel = "Suspicious";
  } else {
    riskLevel = "Safe";
  }

  // Generate recommendations
  let recommendation;

  if (confirmedPhishingMatch) {
    recommendation =
      "OpenPhish has identified this URL as a phishing URL. Do not visit it or enter credentials, payment details, or personal information.";
  } else if (maliciousMatch) {
    recommendation =
      `URLhaus has reported this URL as malicious (${
        urlhaus.threat || "unspecified threat"
      }). Avoid visiting it or downloading files from it. This finding does not by itself confirm phishing.`;
  } else if (riskLevel === "Suspicious") {
    recommendation =
      "This URL has suspicious characteristics. Avoid entering credentials or payment details until the domain has been independently verified.";
  } else {
    recommendation =
      "No strong warning signs were detected by the available checks. This assessment is not a guarantee of safety.";
  }

  return {
    normalizedUrl,
    riskScore,
    riskLevel,
    indicators,
    recommendation,
  };
}

module.exports = {
  assessUrl,
  normalizeUrl,
};
