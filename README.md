# 🛡️ SafeRecruit AI — Fake Job & Scam Detection System

SafeRecruit AI is an intelligent fraud detection system that analyzes job postings and detects whether they are **Real, Suspicious, or Fake** using a combination of **AI (LLM), rule-based guardrails, and real-world verification APIs**.

---

## 🚀 Key Features

### 🔍 AI-Powered Fraud Detection

* Uses Large Language Models (Llama 3.1) for deep semantic analysis
* Detects scam patterns like:

  * Unrealistic salaries
  * Urgency pressure
  * Task scams
  * Fake recruiter language

---

### 🛡️ Guardrail Security System

* Hard rules prevent AI misclassification
* Examples:

  * Payment unverified → Suspicious
  * Payment + $0 spent → Fake
* Ensures **LLM cannot override critical fraud signals**

---

### 🌐 Real-World Company Verification

* Integrated **Google Custom Search API**
* Checks if company exists online
* If not found → increases fraud risk automatically

> This reduces LLM hallucination and makes the system more reliable by combining AI with real-world verification.

---

### 🌍 Domain Verification (WHOIS)

* Detects newly created domains
* Flags potential phishing/scam domains
* Combines with Google signals for stronger accuracy

---

### 🧠 Multi-Agent LLM Architecture

* **Llama 3.1 8B** → Fast "Scout" scan
* **Llama 3.1 70B** → Deep forensic analysis

---

### 🖼️ OCR Support (Image Input)

* Upload screenshots of job posts
* Extracts and analyzes text automatically

---

### 📊 Explainable Results

* Provides:

  * Risk score
  * Key findings
  * Safety recommendations

---

## ⚙️ Tech Stack

* **Backend**: Python, Flask
* **AI Models**: NVIDIA Llama 3.1 (8B + 70B)
* **APIs**: Google Custom Search API, WHOIS
* **OCR**: Tesseract
* **Frontend**: HTML, CSS, JavaScript

---

## 🧠 System Architecture

```text
Input (Text / Screenshot)
        ↓
OCR Processing
        ↓
Pre-LLM Guardrails
        ↓
Google Verification + WHOIS
        ↓
LLM Analysis (8B + 70B)
        ↓
Final Risk Score + Explanation
```

---

## 🎯 Example Output

* ✅ Real Job → Low Risk
* ⚠️ Suspicious → Medium Risk
* 🚨 Fake Job → High Risk

---

## 🚀 How to Run

```bash
git clone <your-repo>
cd SafeRecruit-AI
pip install -r requirements.txt
python app.py
```

Open:

```
http://127.0.0.1:5000/
```

---

## 🔒 Security Notes

* API keys are stored securely using `.env`
* `.env` is excluded from version control

---

## 🚀 Future Improvements

* LinkedIn company verification
* Trust score system
* Browser extension for real-time detection
* Deployment as SaaS platform

---

## 🎤 Project Highlight

SafeRecruit AI is not just an AI model — it is a **multi-layer fraud detection system** that combines:

* AI reasoning
* Rule-based validation
* Real-world verification

to deliver **accurate and reliable scam detection**.

---

## 👨‍💻 Author


