from flask import Flask, render_template, request, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
import re
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.secret_key = "secret123"
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Dummy user system
class User(UserMixin):
    def __init__(self, id):
        self.id = id
        self.username = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Simple job analysis logic
def analyze_job_description(text):
    """Analyze job description for fraud indicators"""
    if not text or len(text.strip()) < 10:
        return {
            "prediction": "INVALID",
            "confidence": 0,
            "risk": 0,
            "category": "Too Short",
            "reasons": ["Job description is too short to analyze"],
            "suggestions": ["Please provide a detailed job description"]
        }

    text_lower = text.lower()

    # Fraud indicators
    red_flags = {
        "no experience": 0.15,
        "work from home": -0.05,
        "no qualifications": 0.20,
        "guaranteed income": 0.25,
        "quick money": 0.30,
        "easy money": 0.30,
        "upfront payment": 0.25,
        "wire transfer": 0.35,
        "bitcoin": 0.30,
        "western union": 0.35,
        "no interview": 0.20,
        "immediate hire": 0.15,
        "urgent": 0.10,
        "limited time": 0.10,
        "high salary": 0.05,
        "flexible hours": -0.05,
        "remote": -0.05,
    }

    reasons = []
    risk_score = 0.3  # Base score

    for flag, weight in red_flags.items():
        if flag in text_lower:
            risk_score += weight
            if weight > 0.15:
                reasons.append(f"Detected suspicious phrase: '{flag}'")

    # Positive indicators (reduce risk)
    positive_indicators = [
        "apply here", "contact us", "email", "phone",
        "requirements", "qualifications", "experience",
        "company", "location", "benefits"
    ]

    for indicator in positive_indicators:
        if indicator in text_lower:
            risk_score -= 0.05

    # Word count analysis
    word_count = len(text.split())
    if word_count < 50:
        risk_score += 0.15
        reasons.append("Job description is unusually brief")

    # Ensure score is between 0-100
    risk_score = max(0, min(100, risk_score * 100))

    # Determine prediction
    if risk_score > 60:
        prediction = "FAKE"
        confidence = int(min(95, risk_score))
        category = "High Risk"
    elif risk_score > 40:
        prediction = "SUSPICIOUS"
        confidence = int(risk_score / 1.5)
        category = "Medium Risk"
    else:
        prediction = "REAL"
        confidence = int(100 - risk_score)
        category = "Low Risk"

    if not reasons:
        reasons = ["Job description appears legitimate"] if prediction == "REAL" else ["Multiple fraud indicators detected"]

    suggestions = [
        "Verify company information independently",
        "Check official company website",
        "Be cautious of requests for upfront payments",
        "Research the company on Glassdoor or LinkedIn"
    ]

    return {
        "prediction": prediction,
        "confidence": confidence,
        "risk": int(risk_score),
        "category": category,
        "reasons": reasons[:3],
        "suggestions": suggestions
    }

# OCR simulation (basic text extraction)
def extract_text_from_image(image_path):
    """Extract text from image using OCR"""
    try:
        from PIL import Image
        import pytesseract

        img = Image.open(image_path)
        text = pytesseract.image_to_string(img)
        return text
    except:
        return None

# HOME
@app.route("/", methods=["GET", "POST"])
@login_required
def home():
    prediction = None
    confidence = None
    risk = None
    category = None
    reasons = None
    suggestions = None
    highlighted_text = None
    processed_image = False
    error = None

    if request.method == "POST":
        job_input = request.form.get("job_input", "").strip()
        job_image = request.files.get("job_image")

        # Extract text from image if provided
        if job_image and job_image.filename:
            try:
                filename = secure_filename(job_image.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                job_image.save(filepath)

                extracted_text = extract_text_from_image(filepath)
                if extracted_text:
                    job_input = extracted_text
                    processed_image = True
                else:
                    error = "Could not extract text from image. Please paste text instead."
            except Exception as e:
                error = f"Error processing image: {str(e)}"

        if job_input:
            # Analyze the job description
            result = analyze_job_description(job_input)

            prediction = result["prediction"]
            confidence = result["confidence"]
            risk = result["risk"]
            category = result["category"]
            reasons = result["reasons"]
            suggestions = result["suggestions"]

            # Highlight suspicious keywords
            highlighted_text = job_input
            keywords = ["upfront", "bitcoin", "western union", "wire transfer", "urgent", "immediate"]
            for keyword in keywords:
                if keyword.lower() in job_input.lower():
                    highlighted_text = highlighted_text.replace(
                        keyword,
                        f'<mark style="background-color: #ffcccc;">{keyword}</mark>'
                    )

            # Store in history
            if 'history' not in session:
                session['history'] = []

            history_item = {
                "input_text": job_input[:100] + "..." if len(job_input) > 100 else job_input,
                "prediction": prediction,
                "confidence": confidence,
                "risk": risk,
                "category": category,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            session['history'].insert(0, history_item)  # Add to the beginning
            session.modified = True
        else:
            error = "Please enter a job description or upload an image"

    return render_template("index.html",
        prediction=prediction,
        confidence=confidence,
        risk=risk,
        category=category,
        reasons=reasons,
        suggestions=suggestions,
        highlighted_text=highlighted_text,
        processed_image=processed_image,
        error=error
    )

# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        if username:
            user = User(username)
            login_user(user)
            session.clear()  # Clear history on new login
            return redirect(url_for("home"))
    return render_template("login.html")

# LOGOUT
@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("home"))

# HISTORY
@app.route("/history")
@login_required
def history():
    search_history = session.get('history', [])
    return render_template("history.html", data=search_history)

if __name__ == "__main__":
    app.run(debug=True)