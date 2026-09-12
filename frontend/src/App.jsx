import { useState } from "react";
import { Mail, Upload, ArrowRight } from "lucide-react";
import "./App.css";

function App() {
  const [email, setEmail] = useState("");
  const [showInput, setShowInput] = useState(false);

  const handleAnalyze = () => {
    if (!email.trim()) return;

    alert("Email analysis will be connected to the backend soon.");
  };

  return (
    <div className="page">

      <div className="hero">
        <h1>Email Threat Detection</h1>

        <h2>GeoLocation &amp; Forensic Intelligence</h2>

        <p>
          Detect suspicious emails, trace their infrastructure, analyze
          authentication and generate forensic intelligence.
        </p>
      </div>

      <div className="analysis-card">

        {!showInput ? (
          <button
            className="start-button"
            onClick={() => setShowInput(true)}
          >
            <div className="mail-icon">
              <Mail size={42} />
            </div>

            <h3>Analyze an Email</h3>

            <span className="click-text">
              Click to begin analysis <ArrowRight size={16} />
            </span>
          </button>
        ) : (
          <div className="email-input-area">

            <div className="mail-icon">
              <Mail size={34} />
            </div>

            <h3>Analyze an Email</h3>

            <p>
              Paste the suspicious email content below
            </p>

            <textarea
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Paste email headers or email content here..."
            />

            <div className="button-row">
              <label className="upload-button">
                <Upload size={18} />
                Upload .eml
                <input
                  type="file"
                  accept=".eml"
                  hidden
                />
              </label>

              <button
                className="analyze-button"
                onClick={handleAnalyze}
              >
                Analyze Email
                <ArrowRight size={18} />
              </button>
            </div>

          </div>
        )}

      </div>

      <div className="footer">
        <span>AI-Powered Threat Detection</span>
        <span>•</span>
        <span>Forensic Intelligence System</span>
      </div>

    </div>
  );
}

export default App;