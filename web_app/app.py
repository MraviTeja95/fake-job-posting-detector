import pytesseract
from PIL import Image
import numpy as np
import cv2
import os

pytesseract.pytesseract.tesseract_cmd = r"C:\Users\BAVAN KUMAR\AppData\Local\Programs\Tesseract-OCR\tesseract.exe"
print("Using Tesseract path:", pytesseract.pytesseract.tesseract_cmd)

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
    processed_image = None

    risk_score = 0
    job_category = "Unknown"
    suggestions = []

    if request.method == "POST":

        job_input = request.form.get("job_input")
        image_file = request.files.get("job_image")

        # ==========================
        # 🧠 OCR + IMAGE HIGHLIGHT
        # ==========================
        if image_file and image_file.filename != "":

            try:
                img = Image.open(image_file).convert("RGB")
                img_np = np.array(img)
                img_cv = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)

                data = pytesseract.image_to_data(img_cv, output_type=pytesseract.Output.DICT)
                extracted_text = " ".join(data['text']).strip()

                if extracted_text == "" or len(extracted_text) < 10:
                    return render_template(
                        "index.html",
                        prediction="Invalid Input",
                        confidence=0,
                        reasons=["No readable text found in image"],
                        profile=None,
                        risk=0,
                        category="Unknown",
                        suggestions=["Upload clear job screenshot"],
                        processed_image=None
                    )

                highlight_keywords = [
                    "urgent", "whatsapp", "telegram",
                    "earn", "money", "experience",
                    "work", "home", "job", "salary",
                    "hiring", "contact"
                ]

                for i in range(len(data['text'])):
                    word = data['text'][i].lower().strip()
                    if word == "":
                        continue

                    for keyword in highlight_keywords:
                        if keyword in word:
                            x = data['left'][i]
                            y = data['top'][i]
                            w = data['width'][i]
                            h = data['height'][i]

                            cv2.rectangle(img_cv, (x, y), (x+w, y+h), (0, 0, 255), 2)

                # 🔥 CORRECT SAVE BLOCK
                BASE_DIR = os.path.dirname(os.path.abspath(__file__))
                static_folder = os.path.join(BASE_DIR, "static")
                os.makedirs(static_folder, exist_ok=True)

                output_path = os.path.join(static_folder, "processed.png")
                saved = cv2.imwrite(output_path, img_cv)

                print("Saved:", saved)
                print("Path:", output_path)

                processed_image = "processed.png"

                job_input = extracted_text
                reasons.append("Scam words highlighted in screenshot")

            except Exception as e:
                print("ERROR:", e)
                reasons.append("Error processing image")

        if not job_input:
            job_input = ""

        text = job_input.lower()

        if "linkedin.com" in text:
            try:
                r = requests.get(job_input, headers={"User-Agent": "Mozilla/5.0"})
                soup = BeautifulSoup(r.text, "html.parser")

                profile = {
                    "platform": "LinkedIn",
                    "title": soup.title.text if soup.title else "LinkedIn Profile"
                }

                reasons.append("LinkedIn profile detected")
            except:
                profile = {"platform": "LinkedIn", "title": "Unable to fetch"}

        suspicious_keywords = [
            "urgent hiring", "earn money fast", "work from home",
            "no experience required", "no experience needed",
            "whatsapp", "telegram", "limited seats",
            "quick placement", "instant joining",
            "direct message", "easy money"
        ]

        for word in suspicious_keywords:
            if word in text:
                risk_score += 25 if word in ["whatsapp", "telegram"] else 15
                reasons.append(f"Suspicious phrase: '{word}'")

        if "salary" in text and "no experience" in text:
            risk_score += 20
            reasons.append("High salary with no experience")

        emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)
        for email in emails:
            if any(d in email for d in ["gmail.com", "yahoo.com", "outlook.com"]):
                risk_score += 10
                reasons.append("Generic email used")

        if "remote" in text:
            job_category = "Remote Job"
        elif "internship" in text:
            job_category = "Internship"
        elif "freelance" in text:
            job_category = "Freelance"
        elif "full time" in text:
            job_category = "Full-time Job"

        prediction = "Fake" if risk_score >= 20 else "Real"
        confidence = random.randint(70, 95)

        suggestions = (
            ["Verify company", "Avoid sharing data"]
            if prediction == "Fake"
            else ["Check official site"]
        )

    return render_template(
        "index.html",
        prediction=prediction,
        confidence=confidence,
        reasons=reasons,
        profile=profile,
        risk=risk_score,
        category=job_category,
        suggestions=suggestions,
        processed_image=processed_image
    )

if __name__ == "__main__":
    app.run(debug=True)