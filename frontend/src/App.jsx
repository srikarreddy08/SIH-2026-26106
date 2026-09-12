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

const fakeResult = {
  riskScore: 91,
  riskLevel: "HIGH RISK",
  classification: "PHISHING",

  email: {
    from: "security-alert@paypa1-support.com",
    to: "user@example.com",
    subject: "Urgent: Your account requires verification",
  },

  authentication: {
    spf: "FAILED",
    dkim: "FAILED",
    dmarc: "FAILED",
  },

  iocs: {
    domains: [
      "paypa1-support.com",
      "secure-account-verification.net",
    ],
    ips: [
      "185.220.101.42",
      "91.108.56.120",
    ],
    urls: [
      "https://paypa1-support.com/verify",
      "https://secure-account-verification.net/login",
    ],
  },

  location: {
    country: "Netherlands",
    region: "North Holland",
    city: "Amsterdam",
  },

  indicators: [
    "Urgent language detected",
    "Suspicious sender domain",
    "Credential harvesting URL",
    "Authentication failures",
    "Domain impersonation detected",
  ],
};

function App() {
  const [screen, setScreen] = useState("home");
  const [file, setFile] = useState(null);
  const [progress, setProgress] = useState(0);

  const analysisSteps = [
    "Parsing email headers",
    "Checking SPF / DKIM / DMARC",
    "Extracting URLs and IP addresses",
    "Reconstructing relay path",
    "Running threat intelligence analysis",
  ];

  useEffect(() => {
    if (screen !== "analyzing") return;

    setProgress(0);

    const timer = setInterval(() => {
      setProgress((previous) => {
        if (previous >= analysisSteps.length) {
          clearInterval(timer);
          return previous;
        }

        return previous + 1;
      });
    }, 850);

    const resultTimer = setTimeout(() => {
      setScreen("results");
    }, analysisSteps.length * 850 + 700);

    return () => {
      clearInterval(timer);
      clearTimeout(resultTimer);
    };
  }, [screen]);

  const handleFile = (event) => {
    const selected = event.target.files[0];

    if (!selected) return;

    if (!selected.name.toLowerCase().endsWith(".eml")) {
      alert("Please select an .eml file.");
      return;
    }

    setFile(selected);
  };

  const startAnalysis = () => {
    setScreen("analyzing");
  };

  const resetAnalysis = () => {
    setFile(null);
    setProgress(0);
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

      {screen === "results" && (
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
                  <strong>{fakeResult.riskScore}</strong>
                  <span>/100</span>
                </div>

              </div>

              <div className="risk-info">
                <span className="section-label">
                  OVERALL THREAT SCORE
                </span>

                <h2>{fakeResult.riskLevel}</h2>

                <div className="risk-bar">
                  <div style={{ width: `${fakeResult.riskScore}%` }}></div>
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
                <strong>{fakeResult.classification}</strong>
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
                value={fakeResult.email.from}
              />

              <InfoBox
                label="TO"
                value={fakeResult.email.to}
              />

              <InfoBox
                label="SUBJECT"
                value={fakeResult.email.subject}
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
                status={fakeResult.authentication.spf}
                description="Sending server is not authorized"
              />

              <AuthCard
                name="DKIM"
                status={fakeResult.authentication.dkim}
                description="Email signature verification failed"
              />

              <AuthCard
                name="DMARC"
                status={fakeResult.authentication.dmarc}
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
                <strong>{fakeResult.location.country}</strong>

                <small>
                  {fakeResult.location.region}
                </small>

              </div>

              <div className="location-card">

                <MapPin size={25} />

                <span>CITY</span>
                <strong>{fakeResult.location.city}</strong>

                <small>
                  Sender origin estimate
                </small>

              </div>

              <div className="location-card">

                <Server size={25} />

                <span>SENDING IP</span>
                <strong>185.220.101.42</strong>

                <small>
                  Public infrastructure
                </small>

              </div>

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
                items={fakeResult.iocs.domains}
              />

              <IOCList
                icon={<Server size={19} />}
                title="IP Addresses"
                items={fakeResult.iocs.ips}
              />

              <IOCList
                icon={<LinkIcon size={19} />}
                title="Malicious URLs"
                items={fakeResult.iocs.urls}
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

              {fakeResult.indicators.map((indicator) => (
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

            <button className="report-button">
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