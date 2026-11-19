
const mongoose = require("mongoose");

// Risk indicator schema
const indicatorSchema = new mongoose.Schema(
  {
    category: { type: String, required: true },
    severity: { type: String, required: true },
    weight: { type: Number, required: true },
    details: { type: String },
  },
  { _id: false }
);

// WHOIS information schema
const whoisSchema = new mongoose.Schema(
  {
    domain: String,
    registrar: String,
    creationDate: mongoose.Schema.Types.Mixed,
    expirationDate: mongoose.Schema.Types.Mixed,
    updatedDate: mongoose.Schema.Types.Mixed,
    nameServers: [String],
    status: [String],
    emails: [String],
    country: String,
    organization: String,
    collectedAt: Date,
    error: String,
  },
  { _id: false }
);

// DNS record schema
const dnsRecordSchema = new mongoose.Schema(
  {
    records: {
      type: [mongoose.Schema.Types.Mixed],
      default: [],
    },
    error: {
      type: String,
      default: null,
    },
  },
  { _id: false }
);

// DNS information schema
const dnsSchema = new mongoose.Schema(
  {
    hostname: String,
    records: {
      A: dnsRecordSchema,
      AAAA: dnsRecordSchema,
      MX: dnsRecordSchema,
      NS: dnsRecordSchema,
      TXT: dnsRecordSchema,
      CNAME: dnsRecordSchema,
    },
    collectedAt: Date,
  },
  { _id: false }
);

// SSL certificate information schema
const sslSchema = new mongoose.Schema(
  {
    hostname: String,
    subject: mongoose.Schema.Types.Mixed,
    issuer: mongoose.Schema.Types.Mixed,
    subjectAlternativeNames: [String],
    serialNumber: String,
    version: Number,
    notBefore: String,
    notAfter: String,
    expired: Boolean,
    daysUntilExpiry: Number,
    collectedAt: Date,
    valid: Boolean,
    error: String,
  },
  { _id: false }
);

// URLhaus threat intelligence schema
const urlhausSchema = new mongoose.Schema(
  {
    source: String,
    available: Boolean,
    matched: {
      type: Boolean,
      default: null,
    },
    queryStatus: String,
    url: String,
    urlhausId: String,
    urlStatus: String,
    threat: String,
    tags: [String],
    dateAdded: String,
    reporter: String,
    reference: String,
    payloads: [mongoose.Schema.Types.Mixed],
    checkedAt: Date,
    error: String,
  },
  { _id: false }
);

// OpenPhish threat intelligence schema
const openphishSchema = new mongoose.Schema(
  {
    source: String,
    available: Boolean,
    matched: {
      type: Boolean,
      default: null,
    },
    queryStatus: String,
    url: String,
    feedEntries: Number,
    checkedAt: Date,
    error: String,
  },
  { _id: false }
);

// Threat intelligence collection schema
const threatIntelligenceSchema = new mongoose.Schema(
  {
    urlhaus: {
      type: urlhausSchema,
      default: null,
    },
    openphish: {
      type: openphishSchema,
      default: null,
    },
  },
  { _id: false }
);

// Main assessment schema
const assessmentSchema = new mongoose.Schema({
  url: { type: String, required: true },
  riskScore: { type: Number, required: true },
  riskLevel: { type: String, required: true },
  indicators: [indicatorSchema],

  whois: { type: whoisSchema, default: null },
  dns: { type: dnsSchema, default: null },
  ssl: { type: sslSchema, default: null },

  threatIntelligence: {
    type: threatIntelligenceSchema,
    default: null,
  },

  recommendation: { type: String },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Assessment", assessmentSchema);
