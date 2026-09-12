const API_URL = "http://127.0.0.1:8000";

const analyzeBtn = document.getElementById("analyzeBtn");
const rawEmailInput = document.getElementById("rawEmail");
const statusDiv = document.getElementById("status");
const inputArea = document.getElementById("inputArea");
const resultBox = document.getElementById("resultBox");

analyzeBtn.addEventListener("click", async () => {
  const rawEmail = rawEmailInput.value;

  if (!rawEmail.trim()) {
    statusDiv.innerText = "Please paste an email first.";
    return;
  }

  analyzeBtn.disabled = true;
  statusDiv.innerText = "Analyzing...";

  try {
    const response = await fetch(`${API_URL}/analyze-email-text`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw_email: rawEmail }),
    });

    if (!response.ok) {
      throw new Error(`Server responded with ${response.status}`);
    }

    const data = await response.json();
    renderResult(data);
  } catch (err) {
    console.error(err);
    statusDiv.innerText = "Error: make sure your backend server is running.";
  } finally {
    analyzeBtn.disabled = false;
  }
});

function verdictInfo(verdict) {
  switch (verdict) {
    case "high_risk":
      return { cls: "high", label: "HIGH RISK" };
    case "medium_risk":
      return { cls: "medium", label: "MEDIUM RISK" };
    case "low_risk":
      return { cls: "low", label: "LOW RISK" };
    default:
      return { cls: "safe", label: "LIKELY SAFE" };
  }
}

function authRow(name, status) {
  const cls = status === "pass" ? "pass" : status === "fail" ? "fail" : "";
  const text = (status || "unknown").toUpperCase();
  return `<div class="row"><span class="k">${name}</span><span class="v ${cls}">${text}</span></div>`;
}

function renderResult(data) {
  const risk = data.overall_risk || {};
  const { cls, label } = verdictInfo(risk.verdict);
  const score = risk.overall_risk_score ?? 0;
  const auth = data.authentication || {};
  const location = data.location;
  const reasons = risk.reasons || [];

  const reasonsHtml =
    reasons.length > 0
      ? `<ul>${reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>`
      : `<div class="none">No suspicious indicators detected.</div>`;

  resultBox.innerHTML = `
    <div class="risk-banner ${cls}">
      <div class="score">${score}/100</div>
      <div class="label">${label}</div>
    </div>

    <div class="section">
      <div class="section-title">EMAIL</div>
      <div class="row"><span class="k">From</span><span class="v">${escapeHtml(truncate(data.from, 60))}</span></div>
      <div class="row"><span class="k">Subject</span><span class="v">${escapeHtml(truncate(data.subject, 80))}</span></div>
    </div>

    <div class="section">
      <div class="section-title">AUTHENTICATION</div>
      ${authRow("SPF", auth.spf)}
      ${authRow("DKIM", auth.dkim)}
      ${authRow("DMARC", auth.dmarc)}
    </div>

    <div class="section">
      <div class="section-title">GEOLOCATION</div>
      <div class="row"><span class="k">Country</span><span class="v">${escapeHtml(location?.country || "Unknown")}</span></div>
      <div class="row"><span class="k">City</span><span class="v">${escapeHtml(location?.city || "Unknown")}</span></div>
      <div class="row"><span class="k">Source Type</span><span class="v">${escapeHtml(data.ip_classification || "unknown")}</span></div>
    </div>

    <div class="section reasons">
      <div class="section-title">WHY THIS VERDICT</div>
      ${reasonsHtml}
    </div>

    <button id="newAnalysisBtn">Analyze Another Email</button>
  `;

  inputArea.style.display = "none";
  resultBox.style.display = "block";

  document.getElementById("newAnalysisBtn").addEventListener("click", () => {
    rawEmailInput.value = "";
    statusDiv.innerText = "";
    resultBox.style.display = "none";
    inputArea.style.display = "block";
  });
}

function truncate(str, n) {
  if (!str) return "N/A";
  return str.length > n ? str.slice(0, n) + "..." : str;
}

function escapeHtml(str) {
  if (!str) return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}