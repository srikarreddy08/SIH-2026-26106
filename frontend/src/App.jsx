import { useEffect, useState } from "react";
import {
  Mail,
  Upload,
  ShieldAlert,
  ShieldCheck,
  Globe,
  Server,
  Link as LinkIcon,
  MapPin,
  FileSearch,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
} from "lucide-react";

import "./App.css";
import HopMap from "./HopMap";

// Change this if your backend runs on a different machine/port.
const API_URL = "http://127.0.0.1:8000";

function mapApiResponseToResult(data) {
  const verdict = data.overall_risk?.verdict ?? "likely_safe";

  const riskLevelMap = {
    high_risk: "HIGH RISK",
    medium_risk: "MEDIUM RISK",
    low_risk: "LOW RISK",
    likely_safe: "LIKELY SAFE",
  };

  const classificationMap = {
    high_risk: "PHISHING",
    medium_risk: "SUSPICIOUS",
    low_risk: "LOW RISK",
    likely_safe: "SAFE",
  };

  const authLabel = (v) =>
    v === "pass" ? "PASSED" : v === "fail" ? "FAILED" : "UNKNOWN";

  const suspiciousDomains = (data.domain_analysis || [])
    .filter((d) => d.flags && d.flags.length > 0)
    .map((d) => d.domain);

  return {
    riskScore: data.overall_risk?.overall_risk_score ?? 0,
    riskLevel: riskLevelMap[verdict] || "UNKNOWN",
    classification: classificationMap[verdict] || "UNKNOWN",

    email: {
      from: data.from,
      to: data.to,
      subject: data.subject,
    },

    authentication: {
      spf: authLabel(data.authentication?.spf),
      dkim: authLabel(data.authentication?.dkim),
      dmarc: authLabel(data.authentication?.dmarc),
    },

    iocs: {
      domains: suspiciousDomains.length
        ? suspiciousDomains
        : data.domains_found || [],
      ips: data.public_ips || [],
      urls: (data.urls_found || []).slice(0, 5),
    },

    location: data.location
      ? {
          country: data.location.country || "Unknown",
          region: data.location.region || "Unknown",
          city: data.location.city || "Unknown",
        }
      : { country: "Unknown", region: "Unknown", city: "Unknown" },

    sendingIp:
      data.public_ips && data.public_ips.length > 0
        ? data.public_ips[data.public_ips.length - 1]
        : "Unknown",

    hopPath: data.hop_path || [],

    indicators:
      data.overall_risk?.reasons && data.overall_risk.reasons.length > 0
        ? data.overall_risk.reasons
        : ["No significant threat indicators detected"],
  };
}

function generateReport(result) {
  const now = new Date().toLocaleString();

  const reportHtml = `
    <html>
      <head>
        <title>Forensic Investigation Report</title>
        <style>
          body { font-family: Arial, sans-serif; padding: 40px; color: #1a1a1a; }
          h1 { font-size: 22px; border-bottom: 2px solid #00a8ff; padding-bottom: 10px; }
          h2 { font-size: 15px; margin-top: 28px; color: #005b82; }
          .meta { color: #666; font-size: 12px; margin-bottom: 20px; }
          table { width: 100%; border-collapse: collapse; margin-top: 8px; }
          td { padding: 6px 8px; border: 1px solid #ddd; font-size: 12px; vertical-align: top; }
          td.label { font-weight: bold; width: 160px; background: #f5f5f5; }
          .risk-badge {
            display: inline-block; padding: 4px 12px; border-radius: 4px;
            font-weight: bold; font-size: 13px; color: white;
          }
          ul { margin: 6px 0; padding-left: 20px; font-size: 12px; }
          li { margin-bottom: 4px; }
        </style>
      </head>
      <body>
        <h1>Email Forensic Investigation Report</h1>
        <div class="meta">Generated: ${now}</div>

        <h2>Overall Risk Assessment</h2>
        <table>
          <tr><td class="label">Risk Score</td><td>${result.riskScore} / 100</td></tr>
          <tr><td class="label">Risk Level</td><td>${result.riskLevel}</td></tr>
          <tr><td class="label">Classification</td><td>${result.classification}</td></tr>
        </table>

        <h2>Email Information</h2>
        <table>
          <tr><td class="label">From</td><td>${result.email.from || "N/A"}</td></tr>
          <tr><td class="label">To</td><td>${result.email.to || "N/A"}</td></tr>
          <tr><td class="label">Subject</td><td>${result.email.subject || "N/A"}</td></tr>
        </table>

        <h2>Email Authentication</h2>
        <table>
          <tr><td class="label">SPF</td><td>${result.authentication.spf}</td></tr>
          <tr><td class="label">DKIM</td><td>${result.authentication.dkim}</td></tr>
          <tr><td class="label">DMARC</td><td>${result.authentication.dmarc}</td></tr>
        </table>

        <h2>Sender Infrastructure / Geolocation</h2>
        <table>
          <tr><td class="label">Country</td><td>${result.location.country}</td></tr>
          <tr><td class="label">Region</td><td>${result.location.region}</td></tr>
          <tr><td class="label">City</td><td>${result.location.city}</td></tr>
          <tr><td class="label">Sending IP</td><td>${result.sendingIp}</td></tr>
        </table>

        <h2>Indicators of Compromise</h2>
        <table>
          <tr><td class="label">Domains</td><td>${result.iocs.domains.join(", ") || "None"}</td></tr>
          <tr><td class="label">IP Addresses</td><td>${result.iocs.ips.join(", ") || "None"}</td></tr>
          <tr><td class="label">URLs</td><td>${result.iocs.urls.join("<br>") || "None"}</td></tr>
        </table>

        <h2>Detection Signals / Reasoning</h2>
        <ul>
          ${result.indicators.map((i) => `<li>${i}</li>`).join("")}
        </ul>
      </body>
    </html>
  `;

  const reportWindow = window.open("", "_blank");
  reportWindow.document.write(reportHtml);
  reportWindow.document.close();
  reportWindow.focus();
  reportWindow.print();
}

function App() {
  const [screen, setScreen] = useState("home");
  const [file, setFile] = useState(null);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const analysisSteps = [
    "Parsing email headers",
    "Checking SPF / DKIM / DMARC",
    "Extracting URLs and IP addresses",
    "Reconstructing relay path",
    "Running threat intelligence analysis",
  ];

  // Plays the step-by-step animation while "analyzing" is showing.
  useEffect(() => {
    if (screen !== "analyzing") return;

    setProgress(0);

    const timer = setInterval(() => {
      setProgress((previous) => {
        if (previous >= analysisSteps.length - 1) {
          clearInterval(timer);
          return previous;
        }
        return previous + 1;
      });
    }, 850);

    return () => clearInterval(timer);
  }, [screen]);

  // Moves to the results screen only once the real backend result has arrived.
  useEffect(() => {
    if (result && screen === "analyzing") {
      setScreen("results");
    }
  }, [result]);

  const handleFile = (event) => {
    const selected = event.target.files[0];

    if (!selected) return;

    if (!selected.name.toLowerCase().endsWith(".eml")) {
      alert("Please select an .eml file.");
      return;
    }

    setFile(selected);
  };

  const startAnalysis = async () => {
    setScreen("analyzing");
    setError(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch(`${API_URL}/analyze-email`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Server responded with ${response.status}`);
      }

      const data = await response.json();
      setResult(mapApiResponseToResult(data));
    } catch (err) {
      console.error("Analysis failed:", err);
      setError(
        "Failed to analyze email. Make sure the backend server is running."
      );
      setScreen("home");
    }
  };

  const resetAnalysis = () => {
    setFile(null);
    setProgress(0);
    setResult(null);
    setError(null);
    setScreen("home");
  };

  return (
    <div className="app">

      {/* ================= HOME ================= */}

      {screen === "home" && (
        <main className="home-page">

          <div className="top-badge">
            <span className="badge-dot"></span>
            AI-POWERED SECURITY ANALYSIS
          </div>

          <section className="hero">
            <h1>Email Threat Detection</h1>

            <h2>
              GeoLocation &amp; Forensic Intelligence
            </h2>

            <p>
              Detect suspicious emails, trace their infrastructure,
              analyze authentication and generate forensic intelligence.
            </p>
          </section>

          <section className="analyze-card">

            <div className="mail-icon-large">
              <Mail size={42} />
            </div>

            <h3>Analyze an Email</h3>

            <p className="card-description">
              Upload an .eml file or provide email headers
            </p>

            <div className="upload-area">

              <label className="choose-button">
                <Upload size={18} />
                {file ? file.name : "Choose Email"}

                <input
                  type="file"
                  accept=".eml,message/rfc822"
                  onChange={handleFile}
                  hidden
                />
              </label>

              <button
                className="analyze-button"
                onClick={startAnalysis}
                disabled={!file}
              >
                Analyze Email
                <ArrowRight size={18} />
              </button>

            </div>

            <div className="supported">
              Supported format: <span>.EML</span>
            </div>

            {error && (
              <p style={{ color: "#ff5d65", marginTop: "20px", fontSize: "13px" }}>
                {error}
              </p>
            )}

          </section>

          <footer>
            <span>AI-Powered Threat Detection</span>
            <span>•</span>
            <span>Forensic Intelligence System</span>
          </footer>

        </main>
      )}

      {/* ================= ANALYZING ================= */}

      {screen === "analyzing" && (
        <main className="analysis-page">

          <div className="analysis-loader">

            <div className="loader-icon">
              <FileSearch size={38} />
            </div>

            <div className="top-badge">
              <span className="badge-dot"></span>
              FORENSIC ANALYSIS
            </div>

            <h1>Analyzing Email...</h1>

            <p>
              Running AI-powered forensic analysis
            </p>

            <div className="progress-container">

              {analysisSteps.map((step, index) => {
                const completed = index < progress;
                const active = index === progress;

                return (
                  <div
                    className={`analysis-step ${
                      completed ? "completed" : ""
                    } ${active ? "active" : ""}`}
                    key={step}
                  >
                    <div className="step-icon">
                      {completed ? (
                        <CheckCircle2 size={18} />
                      ) : active ? (
                        <div className="mini-spinner"></div>
                      ) : (
                        <div className="step-number">
                          {index + 1}
                        </div>
                      )}
                    </div>

                    <span>{step}</span>
                  </div>
                );
              })}

            </div>

          </div>

        </main>
      )}

      {/* ================= RESULTS ================= */}

      {screen === "results" && result && (
        <main className="results-page">

          <header className="results-header">

            <div>
              <div className="top-badge">
                <span className="badge-dot"></span>
                ANALYSIS COMPLETE
              </div>

              <h1>Forensic Intelligence Report</h1>

              <p>
                Comprehensive email threat analysis and forensic evidence
              </p>
            </div>

            <button
              className="new-analysis-button"
              onClick={resetAnalysis}
            >
              <RefreshCw size={17} />
              New Analysis
            </button>

          </header>

          {/* RISK OVERVIEW */}

          <section className="risk-overview">

            <div className="risk-score">

              <div className="score-ring">

                <div className="score-inner">
                  <strong>{result.riskScore}</strong>
                  <span>/100</span>
                </div>

              </div>

              <div className="risk-info">
                <span className="section-label">
                  OVERALL THREAT SCORE
                </span>

                <h2>{result.riskLevel}</h2>

                <div className="risk-bar">
                  <div style={{ width: `${result.riskScore}%` }}></div>
                </div>

                <p>
                  Multiple high-confidence indicators of malicious
                  activity were detected.
                </p>
              </div>

            </div>

            <div className="classification">

              <span className="section-label">
                CLASSIFICATION
              </span>

              <div className="classification-value">
                <ShieldAlert size={28} />
                <strong>{result.classification}</strong>
              </div>

              <span className="confidence">
                Confidence: 94%
              </span>

            </div>

          </section>

          {/* EMAIL INFORMATION */}

          <section className="dashboard-section">

            <div className="section-heading">
              <Mail size={21} />
              <div>
                <span className="section-label">EMAIL</span>
                <h2>Email Information</h2>
              </div>
            </div>

            <div className="info-grid">

              <InfoBox
                label="FROM"
                value={result.email.from}
              />

              <InfoBox
                label="TO"
                value={result.email.to}
              />

              <InfoBox
                label="SUBJECT"
                value={result.email.subject}
                wide
              />

            </div>

          </section>

          {/* AUTHENTICATION */}

          <section className="dashboard-section">

            <div className="section-heading">
              <ShieldCheck size={21} />
              <div>
                <span className="section-label">AUTHENTICATION</span>
                <h2>Email Authentication</h2>
              </div>
            </div>

            <div className="auth-grid">

              <AuthCard
                name="SPF"
                status={result.authentication.spf}
                description="Sending server is not authorized"
              />

              <AuthCard
                name="DKIM"
                status={result.authentication.dkim}
                description="Email signature verification failed"
              />

              <AuthCard
                name="DMARC"
                status={result.authentication.dmarc}
                description="Domain authentication policy failed"
              />

            </div>

          </section>

          {/* GEOLOCATION */}

          <section className="dashboard-section">

            <div className="section-heading">
              <MapPin size={21} />
              <div>
                <span className="section-label">GEOLOCATION</span>
                <h2>Sender Infrastructure</h2>
              </div>
            </div>

            <div className="location-grid">

              <div className="location-card">

                <Globe size={25} />

                <span>COUNTRY</span>
                <strong>{result.location.country}</strong>

                <small>
                  {result.location.region}
                </small>

              </div>

              <div className="location-card">

                <MapPin size={25} />

                <span>CITY</span>
                <strong>{result.location.city}</strong>

                <small>
                  Sender origin estimate
                </small>

              </div>

              <div className="location-card">

                <Server size={25} />

                <span>SENDING IP</span>
                <strong>{result.sendingIp}</strong>

                <small>
                  Public infrastructure
                </small>

              </div>

            </div>

            <div className="hop-map-wrapper">
              <HopMap hopPath={result.hopPath} />
            </div>

          </section>

          {/* IOC */}

          <section className="dashboard-section">

            <div className="section-heading">
              <AlertTriangle size={21} />

              <div>
                <span className="section-label">
                  THREAT INTELLIGENCE
                </span>

                <h2>Indicators of Compromise</h2>
              </div>
            </div>

            <div className="ioc-grid">

              <IOCList
                icon={<Globe size={19} />}
                title="Suspicious Domains"
                items={result.iocs.domains}
              />

              <IOCList
                icon={<Server size={19} />}
                title="IP Addresses"
                items={result.iocs.ips}
              />

              <IOCList
                icon={<LinkIcon size={19} />}
                title="Malicious URLs"
                items={result.iocs.urls}
              />

            </div>

          </section>

          {/* INDICATORS */}

          <section className="dashboard-section">

            <div className="section-heading">
              <ShieldAlert size={21} />

              <div>
                <span className="section-label">
                  DETECTION SIGNALS
                </span>

                <h2>Threat Indicators</h2>
              </div>
            </div>

            <div className="indicator-list">

              {result.indicators.map((indicator) => (
                <div className="indicator" key={indicator}>
                  <AlertTriangle size={17} />
                  <span>{indicator}</span>
                </div>
              ))}

            </div>

          </section>

          {/* REPORT */}

          <section className="report-card">

            <div>
              <FileSearch size={30} />

              <span className="section-label">
                FORENSIC REPORT
              </span>

              <h2>Investigation Report</h2>

              <p>
                Complete threat analysis, authentication results,
                indicators and forensic evidence.
              </p>
            </div>

            <button className="report-button" onClick={() => generateReport(result)}>
              Generate Investigation Report
              <ArrowRight size={18} />
            </button>

          </section>

          <footer>
            <span>AI-Powered Threat Detection</span>
            <span>•</span>
            <span>Forensic Intelligence System</span>
          </footer>

        </main>
      )}

    </div>
  );
}


/* ================= COMPONENTS ================= */

function InfoBox({ label, value, wide }) {
  return (
    <div className={`info-box ${wide ? "wide" : ""}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}


function AuthCard({ name, status, description }) {
  return (
    <div className="auth-card">

      <div className="auth-top">
        <div className="auth-icon">
          <ShieldCheck size={20} />
        </div>

        <span>{name}</span>
      </div>

      <strong className="failed">{status}</strong>

      <p>{description}</p>

    </div>
  );
}


function IOCList({ icon, title, items }) {
  return (
    <div className="ioc-card">

      <div className="ioc-title">
        {icon}
        <h3>{title}</h3>
      </div>

      <div className="ioc-items">
        {items.map((item) => (
          <div className="ioc-item" key={item}>
            {item}
          </div>
        ))}
      </div>

    </div>
  );
}


export default App;