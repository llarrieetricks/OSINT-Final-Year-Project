
const Assessment = require("../models/Assessment");

const { assessUrl } = require("../services/riskAssessment");

const {
  getWhoisData,
  getSslData,
} = require("../services/osintClient");

const { getDnsData } = require("../services/dnsService");

const { checkUrlhaus } = require("../services/threatFeedService");

const { checkOpenPhish } = require("../services/openphishService");

async function createAssessment(req, res) {
  try {
    const { url } = req.body;

    if (!url || typeof url !== "string" || !url.trim()) {
      return res.status(400).json({
        error: "A valid 'url' field is required.",
      });
    }

    let initialAnalysis;

    try {
      initialAnalysis = assessUrl(url);
    } catch (error) {
      return res.status(400).json({
        error: error.message || "Enter a valid URL.",
      });
    }

    const normalizedUrl = initialAnalysis.normalizedUrl;
    const hostname = new URL(normalizedUrl).hostname;

    let whois = null;
    let dns = null;
    let ssl = null;
    let urlhaus = null;
    let openphish = null;

    // Collect WHOIS information
    try {
      whois = await getWhoisData(hostname);

      if (whois.error) {
        console.warn("WHOIS lookup warning:", whois.error);
      }

      console.log("WHOIS collection completed for:", hostname);
    } catch (error) {
      console.error("WHOIS service unavailable:", error.message);

      whois = {
        domain: hostname,
        error: "WHOIS service unavailable.",
      };
    }

    // Collect DNS information
    try {
      dns = await getDnsData(hostname);

      console.log("DNS collection completed for:", hostname);
    } catch (error) {
      console.error("DNS collection failed:", error.message);

      dns = {
        hostname,
        error: "DNS collection failed.",
      };
    }

    // Collect SSL certificate information
    try {
      ssl = await getSslData(hostname);

      if (ssl.error) {
        console.warn("SSL lookup warning:", ssl.error);
      }

      console.log("SSL collection completed for:", hostname);
    } catch (error) {
      console.error("SSL service unavailable:", error.message);

      ssl = {
        hostname,
        valid: false,
        error: "SSL collection failed.",
      };
    }

    // Check URLhaus threat intelligence
    try {
      urlhaus = await checkUrlhaus(normalizedUrl);

      console.log(
        "URLhaus lookup completed:",
        urlhaus.queryStatus
      );
    } catch (error) {
      console.error("URLhaus lookup failed:", error.message);

      urlhaus = {
        source: "URLhaus",
        available: false,
        matched: null,
        queryStatus: "error",
        error: "URLhaus lookup failed.",
        checkedAt: new Date(),
      };
    }

    // Check OpenPhish threat intelligence
    try {
      openphish = await checkOpenPhish(normalizedUrl);

      console.log(
        "OpenPhish lookup completed:",
        openphish.queryStatus
      );
    } catch (error) {
      console.error("OpenPhish lookup failed:", error.message);

      openphish = {
        source: "OpenPhish",
        available: false,
        matched: null,
        queryStatus: "error",
        error: "OpenPhish lookup failed.",
        checkedAt: new Date(),
      };
    }

    // Recalculate risk using both threat intelligence sources
    const analysis = assessUrl(normalizedUrl, {
      urlhaus,
      openphish,
    });

    // Save assessment and collected OSINT information
    const assessment = await Assessment.create({
      url: analysis.normalizedUrl,
      riskScore: analysis.riskScore,
      riskLevel: analysis.riskLevel,
      indicators: analysis.indicators,

      whois,
      dns,
      ssl,

      threatIntelligence: {
        urlhaus,
        openphish,
      },

      recommendation: analysis.recommendation,
    });

    return res.status(201).json(assessment);
  } catch (err) {
    console.error("Assessment creation failed:", err);

    return res.status(500).json({
      error: "Failed to create assessment.",
    });
  }
}

async function getAssessmentByUrl(req, res) {
  try {
    const { url } = req.query;

    if (!url) {
      return res.status(400).json({
        error: "A 'url' query parameter is required.",
      });
    }

    const existing = await Assessment.findOne({
      url,
    }).sort({ createdAt: -1 });

    if (!existing) {
      return res.status(404).json({
        message: "No prior assessment found for this URL.",
      });
    }

    return res.json(existing);
  } catch (err) {
    console.error("Assessment lookup failed:", err);

    return res.status(500).json({
      error: "Lookup failed.",
    });
  }
}

module.exports = {
  createAssessment,
  getAssessmentByUrl,
};
