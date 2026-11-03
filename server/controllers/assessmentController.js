const Assessment = require("../models/Assessment");
const { assessUrl } = require("../services/riskAssessment");

async function createAssessment(req, res) {
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ error: "A 'url' field is required." });
    }

    let analysis;
    try {
      analysis = assessUrl(url);
    } catch (error) {
      return res.status(400).json({ error: error.message || "Enter a valid URL." });
    }

    const assessment = await Assessment.create({
      url: analysis.normalizedUrl,
      riskScore: analysis.riskScore,
      riskLevel: analysis.riskLevel,
      indicators: analysis.indicators,
      recommendation: analysis.recommendation,
    });

    res.status(201).json(assessment);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to create assessment." });
  }
}

async function getAssessmentByUrl(req, res) {
  try {
    const { url } = req.query;
    if (!url) {
      return res.status(400).json({ error: "A 'url' query parameter is required." });
    }

    const existing = await Assessment.findOne({ url }).sort({ createdAt: -1 });
    if (!existing) {
      return res.status(404).json({ message: "No prior assessment found for this URL." });
    }

    res.json(existing);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Lookup failed." });
  }
}

module.exports = { createAssessment, getAssessmentByUrl };
