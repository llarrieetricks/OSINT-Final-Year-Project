
function formatDate(value) {
  if (!value) return "Not available";

  const date = new Date(value);

  return Number.isNaN(date.getTime())
    ? "Not available"
    : date.toLocaleString();
}

function ThreatFeedCard({ title, data }) {
  if (!data) {
    return (
      <article className="threat-feed-card">
        <h4>{title}</h4>
        <p>Data unavailable.</p>
      </article>
    );
  }

  let status = "Unavailable";
  let statusClass = "unknown";

  if (data.available === true) {
    if (data.matched === true) {
      status = "Match found";
      statusClass = "matched";
    } else if (data.matched === false) {
      status = "No match found";
      statusClass = "clear";
    }
  }

  return (
    <article className="threat-feed-card">
      <div className="feed-heading">
        <h4>{title}</h4>
        <span className={`feed-status ${statusClass}`}>
          {status}
        </span>
      </div>

      <p>
        {data.available
          ? data.matched
            ? `This URL appears in the ${title} threat intelligence source.`
            : `No matching URL was found in ${title}.`
          : "The threat intelligence source could not be checked."}
      </p>

      {data.threat && (
        <p><strong>Threat category:</strong> {data.threat}</p>
      )}

      {data.urlhausId && (
        <p><strong>URLhaus ID:</strong> {data.urlhausId}</p>
      )}

      {data.feedEntries !== undefined && (
        <p><strong>Feed entries:</strong> {data.feedEntries}</p>
      )}

      <small>Checked: {formatDate(data.checkedAt)}</small>
    </article>
  );
}

function DetailCard({ title, children }) {
  return (
    <article className="technical-card">
      <h4>{title}</h4>
      {children}
    </article>
  );
}

export default function AssessmentResult({ assessment }) {
  const riskClass = (assessment.riskLevel || "unknown")
    .toLowerCase()
    .replaceAll(" ", "-");

  const intelligence = assessment.threatIntelligence || {};
  const dnsRecords = assessment.dns?.records || {};

  return (
    <section className="assessment-result" aria-live="polite">
      <div className="result-heading">
        <div>
          <p className="eyebrow">Assessment complete</p>
          <h2>Risk assessment</h2>
        </div>

        <span className={`risk-badge ${riskClass}`}>
          {assessment.riskLevel}
        </span>
      </div>

      <div className="score-summary">
        <div
          className="score-value"
          aria-label={`Risk score ${assessment.riskScore} out of 100`}
        >
          <strong>{assessment.riskScore}</strong>
          <span>/100</span>
        </div>

        <div>
          <p className="result-url">{assessment.url}</p>
          <p className="muted">
            Assessed {formatDate(assessment.createdAt)}
          </p>
        </div>
      </div>

      <div className="recommendation">
        <h3>Security recommendation</h3>
        <p>{assessment.recommendation || "No recommendation available."}</p>
      </div>

      <div className="evidence-heading">
        <h3>Risk indicators</h3>
        <span>
          {assessment.indicators?.length || 0} signals
        </span>
      </div>

      {assessment.indicators?.length > 0 ? (
        <ul className="indicator-list">
          {assessment.indicators.map((item, index) => (
            <li key={`${item.category}-${index}`}>
              <span
                className={`severity-dot ${item.severity}`}
                aria-hidden="true"
              />

              <div>
                <strong>{item.category}</strong>
                <p>{item.details}</p>
              </div>

              <span className="weight">+{item.weight}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="empty-evidence">
          No high-confidence URL warning signals were found.
        </p>
      )}

      <section className="threat-intelligence">
        <div className="evidence-heading">
          <h3>Threat intelligence</h3>
        </div>

        <div className="threat-feed-grid">
          <ThreatFeedCard
            title="OpenPhish"
            data={intelligence.openphish}
          />

          <ThreatFeedCard
            title="URLhaus"
            data={intelligence.urlhaus}
          />
        </div>
      </section>

      <section className="technical-details">
        <div className="evidence-heading">
          <h3>Technical intelligence</h3>
        </div>

        <div className="technical-grid">
          <DetailCard title="WHOIS information">
            <p><strong>Domain:</strong> {assessment.whois?.domain || "Unavailable"}</p>
            <p><strong>Registrar:</strong> {assessment.whois?.registrar || "Unavailable"}</p>
            <p><strong>Created:</strong> {formatDate(assessment.whois?.creationDate)}</p>
            <p><strong>Expires:</strong> {formatDate(assessment.whois?.expirationDate)}</p>
          </DetailCard>

          <DetailCard title="DNS records">
            {Object.entries(dnsRecords).map(([type, result]) => (
              <p key={type}>
                <strong>{type}:</strong>{" "}
                {result?.records?.length
                  ? result.records.join(", ")
                  : result?.error || "No records found"}
              </p>
            ))}
          </DetailCard>

          <DetailCard title="SSL certificate">
            <p><strong>Hostname:</strong> {assessment.ssl?.hostname || "Unavailable"}</p>
            <p><strong>Issuer:</strong> {assessment.ssl?.issuer?.organizationName || assessment.ssl?.issuer?.commonName || "Unavailable"}</p>
            <p><strong>Valid:</strong> {assessment.ssl?.valid === true ? "Yes" : assessment.ssl?.valid === false ? "No" : "Unknown"}</p>
            <p><strong>Expired:</strong> {assessment.ssl?.expired === true ? "Yes" : assessment.ssl?.expired === false ? "No" : "Unknown"}</p>
            <p><strong>Days until expiry:</strong> {assessment.ssl?.daysUntilExpiry ?? "Unavailable"}</p>
          </DetailCard>
        </div>
      </section>
    </section>
  );
}

