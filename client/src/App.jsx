import { useState } from "react";
import SubmitForm from "./components/SubmitForm";
import AssessmentResult from "./components/AssessmentResult";

function App() {
  const [result, setResult] = useState(null);
  const [darkMode, setDarkMode] = useState(false);

  return (
    <main className={`app-shell ${darkMode ? "theme-dark" : "theme-light"}`}>
      <header className="site-header">
        <a className="brand" href="#top">SignalWatch</a>
        <div className="header-actions">
          <span className="header-label">OSINT URL assessment</span>
          <button
            className="theme-toggle"
            type="button"
            onClick={() => setDarkMode((current) => !current)}
            aria-pressed={darkMode}
          >
            {darkMode ? "Light mode" : "Dark mode"}
          </button>
        </div>
      </header>
      <div className="page-shell" id="top">
        <section className="intro">
          <p className="eyebrow">URL intelligence</p>
          <h1>Know the risk before you click.</h1>
          <p>Check suspicious links against transparent URL-risk indicators and get a clear recommendation.</p>
        </section>
        <section className="assessment-panel" aria-labelledby="assessment-title">
          <div>
            <p className="eyebrow">New assessment</p>
            <h2 id="assessment-title">Inspect a URL</h2>
          </div>
          <SubmitForm onResult={setResult} />
        </section>
        {result ? <AssessmentResult assessment={result} /> : (
          <section className="result-placeholder">
            <p className="eyebrow">What you will receive</p>
            <h2>Clear evidence, not a black box.</h2>
            <div className="preview-grid">
              <div><strong>Risk level</strong><span>Safe, Suspicious, or Confirmed Phishing</span></div>
              <div><strong>Score</strong><span>A transparent score from 0 to 100</span></div>
              <div><strong>Evidence</strong><span>Signals that shaped the assessment</span></div>
            </div>
          </section>
        )}
      </div>
    </main>
  );
}

export default App;
