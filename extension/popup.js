const API_URL = "http://127.0.0.1:8000";

document.getElementById("analyzeBtn").addEventListener("click", async () => {
  const rawEmail = document.getElementById("rawEmail").value;
  const resultDiv = document.getElementById("result");

  if (!rawEmail.trim()) {
    resultDiv.innerText = "Please paste an email first.";
    return;
  }

  resultDiv.innerText = "Analyzing...";

  try {
    const response = await fetch(`${API_URL}/analyze-email-text`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw_email: rawEmail }),
    });
    const data = await response.json();
    const verdict = data.overall_risk?.verdict || "unknown";
    const score = data.overall_risk?.overall_risk_score ?? "N/A";

    resultDiv.innerText = `Verdict: ${verdict.toUpperCase()}\nRisk Score: ${score}/100\nReasons:\n${(data.overall_risk?.reasons || []).join("\n")}`;
  } catch (err) {
    resultDiv.innerText = "Error: make sure your backend server is running.";
  }
});