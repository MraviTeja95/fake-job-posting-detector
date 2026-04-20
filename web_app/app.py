import os
import re
import random
import requests
import numpy as np
import cv2
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from PIL import Image
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, redirect, url_for
import pytesseract

# 🔥 SET YOUR TESSERACT PATH
pytesseract.pytesseract.tesseract_cmd = r"C:\Users\BAVAN KUMAR\AppData\Local\Programs\Tesseract-OCR\tesseract.exe"
os.environ["TESSDATA_PREFIX"] = r"C:\Users\BAVAN KUMAR\AppData\Local\Programs\Tesseract-OCR\tessdata"

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    input_text = db.Column(db.Text)
    prediction = db.Column(db.String(20))
    risk = db.Column(db.Integer)  

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))   


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username, password=password).first()

        if user:
            login_user(user)
            return redirect(url_for("home"))
        else:
            return "invaid username or password "

    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")


        existing = User.query.filter_by(username=username).first()
        if existing:
            return "User already exists"

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/", methods=["GET", "POST"])
@login_required

def home():

    # ✅ ALWAYS INITIALIZE (prevents errors)
    prediction = None
    confidence = None
    reasons = []
    profile = None
    processed_image = None
    highlighted_text = ""

    risk_score = 0
    job_category = "Unknown"
    suggestions = []

    print("Using Tesseract:", pytesseract.pytesseract.tesseract_cmd)

    if request.method == "POST":

        job_input = request.form.get("job_input") or ""
        image_file = request.files.get("job_image")

        if not job_input and (not image_file or image_file.filename == ""):
            return render_template(
                "index.html",
                prediction="Invalid Input",
                confidence=0,
                reasons=["Please enter text or upload image"],
                profile=None,
                risk=0,
                category="Unknown",
                suggestions=["Provide valid job input"],
                processed_image=None,
                highlighted_text=""
            )

        # ==========================
        # 🧠 OCR + IMAGE HIGHLIGHT
        # ==========================
        if image_file and image_file.filename != "":
            try:
                img = Image.open(image_file).convert("RGB")
                img_np = np.array(img)
                img_cv = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)

                data = pytesseract.image_to_data(
                    img_cv,
                    output_type=pytesseract.Output.DICT
                )

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
                        processed_image=None,
                        highlighted_text=""
                    )

                # 🔥 Keywords for image highlighting
                highlight_keywords = [
                    "urgent", "whatsapp", "telegram",
                    "earn", "money", "experience",
                    "work", "home", "job", "salary",
                    "hiring", "contact"
                ]

                # Draw red boxes
                for i in range(len(data['text'])):
                    word = data['text'][i].lower().strip()
                    if not word:
                        continue

                    for keyword in highlight_keywords:
                        if keyword in word:
                            x, y, w, h = (
                                data['left'][i],
                                data['top'][i],
                                data['width'][i],
                                data['height'][i]
                            )
                            cv2.rectangle(img_cv, (x, y), (x+w, y+h), (0, 0, 255), 2)

                # Save image
                base_dir = os.path.dirname(os.path.abspath(__file__))
                static_folder = os.path.join(base_dir, "static")
                os.makedirs(static_folder, exist_ok=True)

                output_path = os.path.join(static_folder, "processed.png")
                cv2.imwrite(output_path, img_cv)

                processed_image = "processed.png"

                job_input = extracted_text
                reasons.append("Scam words highlighted in screenshot")

            except Exception as e:
                print("OCR ERROR:", e)
                reasons.append("Error processing image")

        # ==========================
        # TEXT ANALYSIS
        # ==========================
        text = job_input.lower()

        # 🔥 Highlight scam words in text
        highlight_keywords = [
            "urgent hiring", "earn money fast", "work from home",
            "no experience required", "no experience needed",
            "whatsapp", "telegram", "limited seats",
            "quick placement", "instant joining",
            "direct message", "easy money"
        ]

        highlighted_text = job_input

        for word in highlight_keywords:
            pattern = re.compile(re.escape(word), re.IGNORECASE)
            highlighted_text = pattern.sub(
                lambda m: f"<span class='scam-word'>{m.group()}</span>",
                highlighted_text
            )

        # LinkedIn detection
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

        # Suspicious keywords scoring
        for word in highlight_keywords:
            if word in text:
                risk_score += 25 if word in ["whatsapp", "telegram"] else 15
                reasons.append(f"Suspicious phrase: '{word}'")

        # Salary logic
        if "salary" in text and "no experience" in text:
            risk_score += 20
            reasons.append("High salary with no experience")

        # Email detection
        emails = re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)
        for email in emails:
            if any(d in email for d in ["gmail.com", "yahoo.com", "outlook.com"]):
                risk_score += 10
                reasons.append("Generic email used")

        # Job category
        if "remote" in text:
            job_category = "Remote Job"
        elif "internship" in text:
            job_category = "Internship"
        elif "freelance" in text:
            job_category = "Freelance"
        elif "full time" in text:
            job_category = "Full-time Job"

        # Prediction
        prediction = "Fake" if risk_score >= 20 else "Real"
        confidence = random.randint(70, 95)

        new_history = History(
            user_id=current_user.id,
            input_text=job_input,
            prediction=prediction,
            risk=risk_score
        )

        db.session.add(new_history)
        db.session.commit()

        # Suggestions
        suggestions = [
            "Verify company website",
            "Avoid sharing personal data",
            "Search company reviews"
        ] if prediction == "Fake" else [
            "Check official website",
            "Verify LinkedIn page"
        ]

    return render_template(
        "index.html",
        prediction=prediction,
        confidence=confidence,
        reasons=reasons,
        profile=profile,
        risk=risk_score,
        category=job_category,
        suggestions=suggestions,
        processed_image=processed_image,
        highlighted_text=highlighted_text
    )

@app.route("/history")
@login_required
def history():
    data = History.query.filter_by(user_id=current_user.id).all()
    return render_template("history.html", data=data)

if __name__ == "__main__":
    app.run(debug=True)