function formatDate(value) {
  return new Date(value).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export default function AssessmentResult({ assessment }) {
  const riskClass = assessment.riskLevel.toLowerCase().replaceAll(" ", "-");

  return (
    <section className="assessment-result" aria-live="polite">
      <div className="result-heading">
        <div>
          <p className="eyebrow">Assessment complete</p>
          <h2>Risk assessment</h2>
        </div>
        <span className={`risk-badge ${riskClass}`}>{assessment.riskLevel}</span>
      </div>

      <div className="score-summary">
        <div className="score-value" aria-label={`Risk score ${assessment.riskScore} out of 100`}>
          <strong>{assessment.riskScore}</strong><span>/100</span>
        </div>
        <div>
          <p className="result-url">{assessment.url}</p>
          <p className="muted">Assessed {formatDate(assessment.createdAt)}</p>
        </div>
      </div>

      <p className="recommendation">{assessment.recommendation}</p>

      <div className="evidence-heading">
        <h3>Evidence used</h3>
        <span>{assessment.indicators.length} signal{assessment.indicators.length === 1 ? "" : "s"}</span>
      </div>
      {assessment.indicators.length > 0 ? (
        <ul className="indicator-list">
          {assessment.indicators.map((item, index) => (
            <li key={`${item.category}-${index}`}>
              <span className={`severity-dot ${item.severity}`} aria-hidden="true" />
              <div>
                <strong>{item.category}</strong>
                <p>{item.details}</p>
              </div>
              <span className="weight">+{item.weight}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="empty-evidence">No high-confidence URL warning signals were found.</p>
      )}
    </section>
  );
}