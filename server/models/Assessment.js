const mongoose = require("mongoose");

const indicatorSchema = new mongoose.Schema(
  {
    category: { type: String, required: true },
    severity: { type: String, required: true },
    weight: { type: Number, required: true },
    details: { type: String },
  },
  { _id: false }
);

const assessmentSchema = new mongoose.Schema({
  url: { type: String, required: true },
  riskScore: { type: Number, required: true },
  riskLevel: { type: String, required: true },
  indicators: [indicatorSchema],
  recommendation: { type: String },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Assessment", assessmentSchema);
