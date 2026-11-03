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
const LURE_TERMS = ["alert", "message", "invoice", "reward", "update"];
const HIGHER_RISK_TLDS = new Set(["click", "gq", "link", "monster", "rest", "shop", "top", "work", "xyz"]);

function normalizeUrl(input) {
  const candidate = input.trim();
  const url = new URL(/^https?:\/\//i.test(candidate) ? candidate : `https://${candidate}`);

  if (!/^https?:$/.test(url.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs can be assessed.");
  }

  ["fbclid", "gclid", "mc_cid", "mc_eid", "ref", "source"].forEach((parameter) => {
    url.searchParams.delete(parameter);
  });
  [...url.searchParams.keys()].forEach((parameter) => {
    if (parameter.toLowerCase().startsWith("utm_")) url.searchParams.delete(parameter);
  });
  url.hash = "";

  return url.toString();
}

function indicator(category, severity, weight, details) {
  return { category, severity, weight, details };
}

function assessUrl(input) {
  const normalizedUrl = normalizeUrl(input);
  const parsed = new URL(normalizedUrl);
  const indicators = [];
  const hostname = parsed.hostname.toLowerCase();
  const pathAndQuery = `${parsed.pathname}${parsed.search}`.toLowerCase();
  const addressText = `${hostname}${pathAndQuery}`;
  const topLevelDomain = hostname.split(".").at(-1);

  if (parsed.protocol !== "https:") {
    indicators.push(indicator("Transport security", "medium", 15, "The URL does not use HTTPS."));
  }

  if (hostname.includes("xn--")) {
    indicators.push(indicator("Domain encoding", "high", 25, "The domain contains Punycode, which can be used for lookalike domains."));
  }

  const subdomainCount = hostname.split(".").length - 2;
  if (subdomainCount >= 3) {
    indicators.push(indicator("Domain structure", "medium", 12, "The domain uses an unusually deep subdomain structure."));
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    indicators.push(indicator("Host format", "high", 25, "The URL uses an IP address instead of a domain name."));
  }

  if (HIGHER_RISK_TLDS.has(topLevelDomain)) {
    indicators.push(indicator("Domain suffix", "medium", 16, `The .${topLevelDomain} top-level domain is commonly abused in phishing campaigns.`));
  }

  const matchedTerms = SUSPICIOUS_TERMS.filter((term) => addressText.includes(term));
  if (matchedTerms.length > 0) {
    indicators.push(indicator("URL content", "medium", Math.min(20, matchedTerms.length * 6), `Sensitive-action terms found: ${matchedTerms.join(", ")}.`));
  }

  const matchedLures = LURE_TERMS.filter((term) => addressText.includes(term));
  if (matchedLures.length > 0) {
    indicators.push(indicator("Social-engineering wording", "low", Math.min(12, matchedLures.length * 4), `Urgency or lure terms found: ${matchedLures.join(", ")}.`));
  }

  if (normalizedUrl.length > 100) {
    indicators.push(indicator("URL length", "low", 8, "The URL is unusually long."));
  }

  if (hostname.split("-").length - 1 >= 3) {
    indicators.push(indicator("Domain structure", "low", 8, "The hostname contains multiple hyphens."));
  }

  const riskScore = Math.min(100, indicators.reduce((total, item) => total + item.weight, 0));
  const riskLevel = riskScore >= 60 ? "Confirmed Phishing" : riskScore >= 25 ? "Suspicious" : "Safe";
  const recommendation = riskLevel === "Safe"
    ? "No strong URL-based warning signs were found. Continue carefully because this assessment is not a guarantee of safety."
    : "Avoid entering credentials or payment details until the domain has been independently verified.";

  return { normalizedUrl, riskScore, riskLevel, indicators, recommendation };
}

module.exports = { assessUrl, normalizeUrl };