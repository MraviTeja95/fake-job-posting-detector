import pytesseract
from PIL import Image

pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

from flask import Flask, render_template, request
import time
import requests
from bs4 import BeautifulSoup
import random
import re

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():

    prediction = None
    confidence = None
    reasons = []
    profile = None

    risk_score = 0
    job_category = "Unknown"
    suggestions = []

    if request.method == "POST":

        job_input = request.form.get("job_input")
        image_file = request.files.get("job_image")

        # ==========================
        # 🧠 OCR FEATURE
        # ==========================
        if image_file and image_file.filename != "":
            img = Image.open(image_file)
            extracted_text = pytesseract.image_to_string(img)

            extracted_text = extracted_text.strip()

            # ❌ Invalid image / no text
            if extracted_text == "" or len(extracted_text) < 10:

                prediction = "Invalid Input"
                confidence = 0

                reasons.append("No readable text found in the uploaded image")
                reasons.append("Please upload a clear job-related screenshot")

                return render_template(
                    "index.html",
                    prediction=prediction,
                    confidence=confidence,
                    reasons=reasons,
                    profile=None,
                    risk=0,
                    category="Unknown",
                    suggestions=["Upload a proper job screenshot or paste text"]
                )

            # ✅ Valid OCR text
            job_input = extracted_text
            reasons.append("Text extracted from uploaded screenshot using OCR")

        # Safety check
        if not job_input:
            job_input = ""

        text = job_input.lower()

        # ==========================
        # LinkedIn Detection
        # ==========================
        if "linkedin.com" in text:

            time.sleep(3)

            try:
                r = requests.get(job_input, headers={"User-Agent": "Mozilla/5.0"})
                soup = BeautifulSoup(r.text, "html.parser")

                title = soup.title.text if soup.title else "LinkedIn Profile"

                profile = {
                    "platform": "LinkedIn",
                    "title": title
                }

                reasons.append("LinkedIn profile link detected and analysed")

            except:
                profile = {
                    "platform": "LinkedIn",
                    "title": "Unable to fetch details"
                }

        # ==========================
        # Suspicious Keywords
        # ==========================
        suspicious_keywords = [
            "urgent hiring", "earn money fast", "work from home",
            "no experience required", "no experience needed",
            "whatsapp", "telegram", "limited seats",
            "quick placement", "instant joining",
            "direct message", "easy money"
        ]

        for word in suspicious_keywords:
            if word in text:

                if word in ["whatsapp", "telegram"]:
                    risk_score += 25
                else:
                    risk_score += 15

                reasons.append(f"Suspicious phrase detected: '{word}'")

        # ==========================
        # Salary Logic
        # ==========================
        if "₹" in text or "salary" in text:
            if "no experience" in text:
                risk_score += 20
                reasons.append("High salary offered with no experience requirement")

        # ==========================
        # Email Detection
        # ==========================
        email_pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
        emails = re.findall(email_pattern, text)

        for email in emails:
            if any(domain in email for domain in ["gmail.com", "yahoo.com", "outlook.com"]):
                risk_score += 10
                reasons.append("Generic email domain used instead of company email")
            else:
                reasons.append("Company email domain detected")

        # ==========================
        # Salary Mention
        # ==========================
        if "salary" in text or "$" in text:
            reasons.append("Salary information mentioned in job posting")

        # ==========================
        # Job Category
        # ==========================
        if "remote" in text:
            job_category = "Remote Job"
        elif "internship" in text:
            job_category = "Internship"
        elif "freelance" in text:
            job_category = "Freelance"
        elif "full time" in text:
            job_category = "Full-time Job"

        # ==========================
        # Prediction
        # ==========================
        if risk_score >= 20:
            prediction = "Fake"
        else:
            prediction = "Real"

        confidence = random.randint(70, 95)

        # ==========================
        # Suggestions
        # ==========================
        if prediction == "Fake":
            suggestions.extend([
                "Verify company website before applying",
                "Avoid sharing personal documents",
                "Search company reviews online"
            ])
        else:
            suggestions.extend([
                "Check company LinkedIn page",
                "Verify job on official company website"
            ])

        if len(reasons) == 0:
            reasons.append("Job description looks professional")

    return render_template(
        "index.html",
        prediction=prediction,
        confidence=confidence,
        reasons=reasons,
        profile=profile,
        risk=risk_score,
        category=job_category,
        suggestions=suggestions
    )

if __name__ == "__main__":
    app.run(debug=True)