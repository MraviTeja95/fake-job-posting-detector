// SafeRecruit AI - Popup Script
// Requests job data from the content script and sends it to the Flask backend.

const BACKEND_URL = "http://127.0.0.1:5000/api/analyze";

const scanBtn = document.getElementById("scan-btn");
const statusEl = document.getElementById("status");
const errorEl = document.getElementById("error");
const resultBox = document.getElementById("result");
const verdictEl = document.getElementById("verdict");
const confidenceEl = document.getElementById("confidence");
const fraudRiskEl = document.getElementById("fraud-risk");
const trustScoreEl = document.getElementById("trust-score");
const engineEl = document.getElementById("engine");
const reasonsEl = document.getElementById("reasons");

function showStatus(msg) {
  statusEl.textContent = msg;
}

function showError(msg) {
  errorEl.textContent = msg;
  errorEl.classList.add("show");
  resultBox.classList.remove("show");
}

function clearError() {
  errorEl.textContent = "";
  errorEl.classList.remove("show");
}

function displayResult(data) {
  const prediction = (data.prediction || "UNKNOWN").toUpperCase();

  verdictEl.textContent = prediction;
  verdictEl.className = "verdict " + prediction;

  confidenceEl.textContent = (data.confidence || 0) + "%";
  fraudRiskEl.textContent = (data.fraud_risk_score || 0) + "/100";
  
  // Display Trust Score as requested
  trustScoreEl.textContent = (data.trust_score !== undefined) ? `Trust Score: ${data.trust_score}` : "Trust Score: N/A";
  
  engineEl.textContent = data.engine || "N/A";

  reasonsEl.innerHTML = "";
  const reasons = data.reasons || [];
  reasons.forEach(function (r) {
    const li = document.createElement("li");
    li.textContent = r;
    reasonsEl.appendChild(li);
  });

  resultBox.classList.add("show");
}

scanBtn.addEventListener("click", async function () {
  clearError();
  resultBox.classList.remove("show");
  scanBtn.disabled = true;
  showStatus("Extracting job data from page...");

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab || !tab.url || !tab.url.includes("linkedin.com")) {
      showError("Please navigate to a LinkedIn job posting first.");
      scanBtn.disabled = false;
      showStatus("");
      return;
    }

    chrome.tabs.sendMessage(tab.id, { action: "extractJob" }, async function (response) {
      if (chrome.runtime.lastError) {
        showError("Could not connect to LinkedIn page. Try refreshing the page.");
        scanBtn.disabled = false;
        showStatus("");
        return;
      }

      const combinedText = (response && response.text) || "";

      if (!combinedText || combinedText.length < 50) {
        alert("Extraction failed. Scroll and retry");
        scanBtn.disabled = false;
        showStatus("");
        return;
      }

      showStatus("Analyzing with SafeRecruit AI...");

      try {
        const res = await fetch(BACKEND_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text: combinedText })
        });

        if (!res.ok) {
          throw new Error("Backend returned " + res.status);
        }

        const result = await res.json();
        displayResult(result);
        showStatus("Analysis complete.");
      } catch (fetchErr) {
        showError("Could not reach SafeRecruit backend. Is the server running?");
        showStatus("");
      }

      scanBtn.disabled = false;
    });
  } catch (err) {
    showError("Unexpected error: " + err.message);
    scanBtn.disabled = false;
    showStatus("");
  }
});
