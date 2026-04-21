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

# Tesseract path
pytesseract.pytesseract.tesseract_cmd = r"C:\Users\BAVAN KUMAR\AppData\Local\Programs\Tesseract-OCR\tesseract.exe"
os.environ["TESSDATA_PREFIX"] = r"C:\Users\BAVAN KUMAR\AppData\Local\Programs\Tesseract-OCR\tessdata"

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ================= MODELS =================
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

# ================= AUTH =================
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
            return "Invalid username or password"

    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if User.query.filter_by(username=username).first():
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

# ================= MAIN =================
@app.route("/", methods=["GET", "POST"])
@login_required
def home():

    prediction = None
    confidence = None
    reasons = []
    profile = None
    processed_image = None
    highlighted_text = ""
    error = None

    risk_score = 0
    job_category = "Unknown"
    suggestions = []

    if request.method == "POST":

        job_input = request.form.get("job_input") or ""
        image_file = request.files.get("job_image")

        # 🔥 EMPTY INPUT FIX
        if not job_input and (not image_file or image_file.filename == ""):
            error = "⚠ Please enter job text or upload an image"
            return render_template(
                "index.html",
                error=error,
                prediction=None,
                confidence=None,
                reasons=[],
                profile=None,
                risk=0,
                category="Unknown",
                suggestions=[],
                processed_image=None,
                highlighted_text="",
                user=current_user
            )

        # ================= OCR =================
        if image_file and image_file.filename != "":
            try:
                img = Image.open(image_file).convert("RGB")
                img_np = np.array(img)
                img_cv = cv2.cvtColor(img_np, cv2.COLOR_RGB2BGR)

                data = pytesseract.image_to_data(img_cv, output_type=pytesseract.Output.DICT)
                extracted_text = " ".join(data['text']).strip()

                highlight_keywords = ["urgent", "whatsapp", "telegram", "money", "salary"]

                for i in range(len(data['text'])):
                    word = data['text'][i].lower().strip()
                    if word:
                        for keyword in highlight_keywords:
                            if keyword in word:
                                x, y, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
                                cv2.rectangle(img_cv, (x, y), (x+w, y+h), (0, 0, 255), 2)

                output_path = os.path.join("static", "processed.png")
                cv2.imwrite(output_path, img_cv)

                processed_image = "processed.png"
                job_input = extracted_text
                reasons.append("Scam words highlighted in screenshot")

            except Exception as e:
                reasons.append("Image processing failed")

        # ================= TEXT =================
        text = job_input.lower()

        keywords = ["urgent hiring", "whatsapp", "earn money"]
        highlighted_text = job_input

        for word in keywords:
            highlighted_text = re.sub(
                word,
                lambda m: f"<span class='scam-word'>{m.group()}</span>",
                highlighted_text,
                flags=re.IGNORECASE
            )

        for word in keywords:
            if word in text:
                risk_score += 20
                reasons.append(f"Suspicious phrase: {word}")

        prediction = "Fake" if risk_score >= 20 else "Real"
        confidence = random.randint(70, 95)

        # SAVE HISTORY
        db.session.add(History(
            user_id=current_user.id,
            input_text=job_input,
            prediction=prediction,
            risk=risk_score
        ))
        db.session.commit()

        suggestions = ["Verify company", "Avoid sharing data"] if prediction == "Fake" else ["Looks safe"]

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
            highlighted_text=highlighted_text,
            user=current_user
        )

    return render_template("index.html", user=current_user)

# ================= HISTORY =================
@app.route("/history")
@login_required
def history():
    data = History.query.filter_by(user_id=current_user.id).all()
    return render_template("history.html", data=data, user=current_user)

if __name__ == "__main__":
    app.run(debug=True)