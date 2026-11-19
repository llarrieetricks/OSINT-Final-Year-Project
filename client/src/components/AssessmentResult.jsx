
function formatDate(value) {
  if (!value) return "Not available";

  const date = new Date(value);

  return Number.isNaN(date.getTime())
    ? "Not available"
    : date.toLocaleString();
}

function getSeverity(severity) {
  const value = (severity || "info").toLowerCase();

  if (["critical", "high", "medium", "low"].includes(value)) {
    return value;
  }

  return "info";
}

function ThreatFeedCard({ title, data, description, symbol }) {
  const available = data?.available === true;
  const matched = data?.matched === true;

  const status = !available
    ? "Unavailable"
    : matched
      ? "Match detected"
      : "No match detected";

  const statusClass = !available
    ? "unknown"
    : matched
      ? "matched"
      : "clear";

  return (
    <article className={`evidence-feed-card ${statusClass}`}>
      <div className="feed-card-top">
        <div className="feed-source-icon">{symbol}</div>
        <span className={`feed-status ${statusClass}`}>
          {status}
        </span>
      </div>

      <h4>{title}</h4>
      <p className="feed-description">{description}</p>

      <div className="feed-result">
        <span className="feed-result-indicator">
          {matched ? "!" : available ? "✓" : "?"}
        </span>

        <span>
          {!available
            ? "Source could not be checked"
            : matched
              ? "URL found in this intelligence source"
              : "No matching URL found"}
        </span>
      </div>

      {data?.threat && (
        <p className="feed-meta">
          <strong>Threat category:</strong> {data.threat}
        </p>
      )}

      {data?.urlhausId && (
        <p className="feed-meta">
          <strong>URLhaus ID:</strong> {data.urlhausId}
        </p>
      )}

      {data?.feedEntries !== undefined && (
        <p className="feed-meta">
          <strong>Feed entries:</strong> {data.feedEntries}
        </p>
      )}

      <div className="feed-footer">
        <span>Last checked</span>
        <span>{formatDate(data?.checkedAt)}</span>
      </div>
    </article>
  );
}

function EvidenceCard({ item, index }) {
  const severity = getSeverity(item.severity);

  return (
    <article className={`evidence-card severity-${severity}`}>
      <div className="evidence-card-top">
        <div className={`evidence-number ${severity}`}>
          {String(index + 1).padStart(2, "0")}
        </div>

        <span className={`severity-label ${severity}`}>
          {severity}
        </span>
      </div>

      <h4>{item.category || "Security indicator"}</h4>

      <p className="evidence-description">
        {item.details || "No additional explanation is available."}
      </p>

      <div className="evidence-card-footer">
        <span>Risk contribution</span>
        <strong>+{item.weight ?? 0}</strong>
      </div>
    </article>
  );
}

function DetailCard({ title, subtitle, symbol, children }) {
  return (
    <details className="technical-card">
      <summary>
        <div className="technical-card-icon">{symbol}</div>

        <div className="technical-card-heading">
          <h4>{title}</h4>
          <span>{subtitle}</span>
        </div>

        <span className="technical-toggle">+</span>
      </summary>

      <div className="technical-card-content">
        {children}
      </div>
    </details>
  );
}

function DetailRow({ label, value }) {
  return (
    <div className="technical-row">
      <span>{label}</span>
      <strong>{value ?? "Unavailable"}</strong>
    </div>
  );
}

export default function AssessmentResult({ assessment }) {
  if (!assessment) return null;

  const score = Math.max(
    0,
    Math.min(100, Number(assessment.riskScore) || 0)
  );

  const riskLevel = assessment.riskLevel || "Unknown";

  const riskClass = riskLevel
    .toLowerCase()
    .replaceAll(" ", "-");

  const indicators = Array.isArray(assessment.indicators)
    ? assessment.indicators
    : [];

  const intelligence = assessment.threatIntelligence || {};
  const dnsRecords = assessment.dns?.records || {};

  const matchedFeeds = [
    intelligence.openphish,
    intelligence.urlhaus,
  ].filter((feed) => feed?.available === true && feed?.matched === true).length;

  const unavailableFeeds = [
    intelligence.openphish,
    intelligence.urlhaus,
  ].filter((feed) => !feed || feed.available !== true).length;

  const highSeverity = indicators.filter((item) =>
    ["critical", "high"].includes(getSeverity(item.severity))
  ).length;

  const mediumSeverity = indicators.filter(
    (item) => getSeverity(item.severity) === "medium"
  ).length;

  return (
    <section className="assessment-result" aria-live="polite">

      {/* ASSESSMENT HERO */}

      <div className={`evidence-hero ${riskClass}`}>
        <div className="hero-background-glow" />

        <div className="hero-content">
          <div className="hero-topline">
            <span className="hero-live-indicator" />
            SECURITY ANALYSIS COMPLETE
          </div>

          <div className="hero-main">
            <div className="hero-copy">
              <p className="eyebrow">THREAT INTELLIGENCE REPORT</p>
              <h2>Assessment overview</h2>

              <p className="hero-description">
                A detailed analysis of the submitted URL, its security
                indicators and available threat intelligence evidence.
              </p>

              <div className={`hero-risk-status ${riskClass}`}>
                <span className="risk-status-icon">
                  {score >= 70 ? "!" : score >= 30 ? "◆" : "✓"}
                </span>
                <span>{riskLevel}</span>
              </div>
            </div>

            <div
              className="risk-gauge"
              style={{ "--score": `${score * 3.6}deg` }}
              role="img"
              aria-label={`Risk score ${score} out of 100`}
            >
              <div className="risk-gauge-inner">
                <strong>{score}</strong>
                <span>RISK SCORE</span>
                <small>OUT OF 100</small>
              </div>
            </div>
          </div>

          <div className="hero-url">
            <div>
              <span className="hero-url-label">ANALYSED URL</span>
              <p>{assessment.url || "URL unavailable"}</p>
            </div>
            <span className="hero-url-icon">↗</span>
          </div>

          <div className="hero-date">
            <span>◷</span>
            Assessment date: {formatDate(assessment.createdAt)}
          </div>
        </div>
      </div>

      {/* EVIDENCE OVERVIEW */}

      <section className="evidence-overview">
        <div className="section-heading">
          <div>
            <p className="section-kicker">INVESTIGATION SUMMARY</p>
            <h3>Evidence at a glance</h3>
            <p>Key findings collected during this assessment.</p>
          </div>
          <span className="section-heading-icon">⌘</span>
        </div>

        <div className="evidence-stat-grid">
          <article className="evidence-stat">
            <div className="stat-icon purple">◈</div>
            <span>Total indicators</span>
            <strong>{indicators.length}</strong>
            <small>Detected signals</small>
          </article>

          <article className="evidence-stat">
            <div className="stat-icon red">!</div>
            <span>High severity</span>
            <strong>{highSeverity}</strong>
            <small>Critical and high findings</small>
          </article>

          <article className="evidence-stat">
            <div className="stat-icon amber">◇</div>
            <span>Medium severity</span>
            <strong>{mediumSeverity}</strong>
            <small>Moderate risk findings</small>
          </article>

          <article className="evidence-stat">
            <div className="stat-icon green">⌁</div>
            <span>Feed matches</span>
            <strong>{matchedFeeds}</strong>
            <small>
              {unavailableFeeds} source(s) unavailable
            </small>
          </article>
        </div>
      </section>

      {/* SECURITY RECOMMENDATION */}

      <section className="recommendation-panel">
        <div className="recommendation-symbol">✦</div>

        <div>
          <span className="section-kicker">SECURITY GUIDANCE</span>
          <h3>Recommended action</h3>
          <p>
            {assessment.recommendation ||
              "No recommendation is currently available."}
          </p>
        </div>
      </section>

      {/* EVIDENCE INDICATORS */}

      <section className="evidence-section">
        <div className="section-heading">
          <div>
            <p className="section-kicker">DETECTED SECURITY SIGNALS</p>
            <h3>Risk evidence</h3>
            <p>
              Individual findings contributing to the assessment.
            </p>
          </div>

          <span className="evidence-count">
            {indicators.length} FINDINGS
          </span>
        </div>

        {indicators.length > 0 ? (
          <div className="evidence-grid">
            {indicators.map((item, index) => (
              <EvidenceCard
                key={`${item.category || "indicator"}-${index}`}
                item={item}
                index={index}
              />
            ))}
          </div>
        ) : (
          <div className="evidence-empty">
            <div className="empty-icon">✓</div>
            <h4>No warning indicators detected</h4>
            <p>
              No risk indicators were returned by the current
              assessment. This does not guarantee that the URL is safe.
            </p>
          </div>
        )}
      </section>

      {/* THREAT INTELLIGENCE */}

      <section className="evidence-section">
        <div className="section-heading">
          <div>
            <p className="section-kicker">EXTERNAL THREAT SOURCES</p>
            <h3>Threat intelligence</h3>
            <p>
              Results from external URL reputation and threat feeds.
            </p>
          </div>

          <span className="evidence-count">LIVE SOURCES</span>
        </div>

        <div className="threat-feed-grid">
          <ThreatFeedCard
            title="OpenPhish"
            symbol="◉"
            description="Phishing-specific URL intelligence."
            data={intelligence.openphish}
          />

          <ThreatFeedCard
            title="URLhaus"
            symbol="⌁"
            description="Malicious URL intelligence, including malware distribution."
            data={intelligence.urlhaus}
          />
        </div>
      </section>

      {/* TECHNICAL INTELLIGENCE */}

      <section className="evidence-section technical-section">
        <div className="section-heading">
          <div>
            <p className="section-kicker">DEEP TECHNICAL ANALYSIS</p>
            <h3>Technical intelligence</h3>
            <p>
              Expand each category to inspect the collected evidence.
            </p>
          </div>

          <span className="section-heading-icon">⌘</span>
        </div>

        <div className="technical-grid">

          <DetailCard
            title="WHOIS information"
            subtitle="Domain registration"
            symbol="◎"
          >
            <DetailRow
              label="Domain"
              value={assessment.whois?.domain}
            />
            <DetailRow
              label="Registrar"
              value={assessment.whois?.registrar}
            />
            <DetailRow
              label="Creation date"
              value={formatDate(assessment.whois?.creationDate)}
            />
            <DetailRow
              label="Expiration date"
              value={formatDate(assessment.whois?.expirationDate)}
            />
          </DetailCard>

          <DetailCard
            title="DNS records"
            subtitle="Domain resolution"
            symbol="⌘"
          >
            {Object.entries(dnsRecords).length > 0 ? (
              Object.entries(dnsRecords).map(([type, result]) => (
                <DetailRow
                  key={type}
                  label={type}
                  value={
                    result?.records?.length
                      ? result.records.join(", ")
                      : result?.error || "No records found"
                  }
                />
              ))
            ) : (
              <p className="technical-empty">
                No DNS records available.
              </p>
            )}
          </DetailCard>

          <DetailCard
            title="SSL certificate"
            subtitle="Connection security"
            symbol="▣"
          >
            <DetailRow
              label="Hostname"
              value={assessment.ssl?.hostname}
            />
            <DetailRow
              label="Issuer"
              value={
                assessment.ssl?.issuer?.organizationName ||
                assessment.ssl?.issuer?.commonName
              }
            />
            <DetailRow
              label="Certificate valid"
              value={
                assessment.ssl?.valid === true
                  ? "Yes"
                  : assessment.ssl?.valid === false
                    ? "No"
                    : "Unknown"
              }
            />
            <DetailRow
              label="Expired"
              value={
                assessment.ssl?.expired === true
                  ? "Yes"
                  : assessment.ssl?.expired === false
                    ? "No"
                    : "Unknown"
              }
            />
            <DetailRow
              label="Days until expiry"
              value={assessment.ssl?.daysUntilExpiry}
            />
          </DetailCard>

        </div>
      </section>

      <div className="evidence-disclaimer">
        <span>ⓘ</span>
        <p>
          Risk scores and threat intelligence findings are based on
          available evidence at the time of assessment. A low score
          does not guarantee that a URL is harmless.
        </p>
      </div>

    </section>
  );
}
