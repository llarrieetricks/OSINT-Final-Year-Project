import { useEffect, useRef, useState } from "react";
import { submitUrlForAssessment } from "../api/assessments";

export default function SubmitForm({ onResult }) {
  const [url, setUrl] = useState("");
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [completionMessage, setCompletionMessage] = useState("");
  const startedAt = useRef(null);

  useEffect(() => {
    if (!loading) return undefined;

    const intervalId = window.setInterval(() => {
      setElapsedSeconds((performance.now() - startedAt.current) / 1000);
    }, 100);

    return () => window.clearInterval(intervalId);
  }, [loading]);

  async function handleSubmit(e) {
    e.preventDefault();
    setError(null);
    setCompletionMessage("");
    startedAt.current = performance.now();
    setElapsedSeconds(0);
    setLoading(true);
    try {
      const result = await submitUrlForAssessment(url.trim());
      onResult(result);
      const duration = (performance.now() - startedAt.current) / 1000;
      setElapsedSeconds(duration);
      setCompletionMessage(`Assessment complete in ${duration.toFixed(1)} seconds.`);
    } catch (err) {
      setError(err.response?.data?.error || "Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <form className="assessment-form" onSubmit={handleSubmit} noValidate>
      <label htmlFor="url">Website address</label>
      <div className="url-input-row">
        <input
          id="url"
          type="url"
          inputMode="url"
          placeholder="https://example.com/login"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          aria-describedby="url-help"
          required
        />
        <button type="submit" disabled={loading}>
          {loading ? "Assessing..." : "Assess URL"}
        </button>
      </div>
      <p id="url-help" className="field-help">We analyze the address and public signals. Do not enter passwords or personal data.</p>

      {loading && (
        <p className="assessment-progress" role="status">
          <span className="progress-spinner" aria-hidden="true" />
          Analyzing public signals... {elapsedSeconds.toFixed(1)} seconds elapsed
        </p>
      )}
      {completionMessage && <p className="assessment-complete" role="status">{completionMessage}</p>}

      <details className="alert-options">
        <summary>Email alert option</summary>
        <label htmlFor="email">Alert email <span>(optional)</span></label>
        <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="name@example.com" />
        <p className="field-help">Email delivery requires a configured notification service.</p>
      </details>
      {error && <p className="form-error" role="alert">{error}</p>}
    </form>
  );
}
