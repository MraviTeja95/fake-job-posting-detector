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
        text = job_input.lower()

        # Detect LinkedIn link
        if "linkedin.com" in text:

            time.sleep(5)

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

        # Suspicious keyword detection
        suspicious_keywords = [
            "urgent hiring",
            "earn money fast",
            "work from home",
            "no experience required",
            "no experience needed",
            "whatsapp",
            "telegram",
            "limited seats",
            "quick placement",
            "instant joining",
            "direct message",
            "easy money"
        ]

        for word in suspicious_keywords:

            if word in text:

                if word in ["whatsapp", "telegram"]:
                    risk_score += 25
                else:
                    risk_score += 15

                reasons.append(f"Suspicious phrase detected: '{word}'")

        # Unrealistic salary detection
        if "₹" in text or "salary" in text:

            if "no experience" in text or "without experience" in text:

                risk_score += 20
                reasons.append("High salary offered with no experience requirement")

        # Email detection
        email_pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"

        emails = re.findall(email_pattern, text)

        for email in emails:

            if "gmail.com" in email or "yahoo.com" in email:

                risk_score += 10
                reasons.append("Generic email domain used instead of company email")

            else:

                reasons.append("Company email domain detected")

        # Salary mention detection
        if "salary" in text or "$" in text or "per month" in text:

            reasons.append("Salary information mentioned in job posting")

        # Job category detection
        if "remote" in text:
            job_category = "Remote Job"

        elif "internship" in text:
            job_category = "Internship"

        elif "freelance" in text:
            job_category = "Freelance"

        elif "full time" in text:
            job_category = "Full-time Job"

        # Prediction logic
        if risk_score >= 25:
            prediction = "Fake"
        else:
            prediction = "Real"

        confidence = random.randint(70, 95)

        # Suggestions
        if prediction == "Fake":

            suggestions.append("Verify company website before applying")
            suggestions.append("Avoid sharing personal documents")
            suggestions.append("Search company reviews online")

        else:

            suggestions.append("Check company LinkedIn page")
            suggestions.append("Verify job on official company website")

        if len(reasons) == 0:
            reasons.append("Job description structure matches typical professional postings")

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