from flask import Flask, render_template, request, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import os
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.secret_key = "secret123"
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'uploads'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):
    def __init__(self, id):
        self.id = id
        self.username = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

def analyze_job_description(text):
    if not text or len(text.strip()) < 10:
        return {
            "prediction": "INVALID", "confidence": 0, "risk": 0,
            "category": "Too Short",
            "reasons": ["Job description is too short to analyze"],
            "suggestions": ["Please provide a detailed job description"]
        }

    text_lower = text.lower()
    red_flags = {
        "no experience": 0.15, "work from home": -0.05, "no qualifications": 0.20,
        "guaranteed income": 0.25, "quick money": 0.30, "easy money": 0.30,
        "upfront payment": 0.25, "wire transfer": 0.35, "bitcoin": 0.30,
        "western union": 0.35, "no interview": 0.20, "immediate hire": 0.15,
        "urgent": 0.10, "limited time": 0.10, "high salary": 0.05,
        "flexible hours": -0.05, "remote": -0.05,
    }

    reasons = []
    risk_score = 0.3

    for flag, weight in red_flags.items():
        if flag in text_lower:
            risk_score += weight
            if weight > 0.15:
                reasons.append(f"Detected suspicious phrase: '{flag}'")

    for indicator in ["apply here","contact us","email","phone","requirements","qualifications","experience","company","location","benefits"]:
        if indicator in text_lower:
            risk_score -= 0.05

    if len(text.split()) < 50:
        risk_score += 0.15
        reasons.append("Job description is unusually brief")

    risk_score = max(0, min(100, risk_score * 100))

    if risk_score > 60:
        prediction, confidence, category = "FAKE", int(min(95, risk_score)), "High Risk"
    elif risk_score > 40:
        prediction, confidence, category = "SUSPICIOUS", int(risk_score / 1.5), "Medium Risk"
    else:
        prediction, confidence, category = "REAL", int(100 - risk_score), "Low Risk"

    if not reasons:
        reasons = ["Job description appears legitimate"] if prediction == "REAL" else ["Multiple fraud indicators detected"]

    return {
        "prediction": prediction, "confidence": confidence,
        "risk": int(risk_score), "category": category,
        "reasons": reasons[:3],
        "suggestions": [
            "Verify company information independently",
            "Check official company website",
            "Be cautious of requests for upfront payments",
            "Research the company on Glassdoor or LinkedIn"
        ]
    }

def extract_text_from_image(image_path):
    try:
        from PIL import Image
        import pytesseract
        return pytesseract.image_to_string(Image.open(image_path))
    except:
        return None

@app.route("/", methods=["GET", "POST"])
@login_required
def home():
    prediction = confidence = risk = category = reasons = suggestions = highlighted_text = error = None
    processed_image = False

    if request.method == "POST":
        job_input = request.form.get("job_input", "").strip()
        job_image = request.files.get("job_image")

        if job_image and job_image.filename:
            try:
                filename = secure_filename(job_image.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                job_image.save(filepath)
                extracted = extract_text_from_image(filepath)
                if extracted:
                    job_input = extracted
                    processed_image = True
                else:
                    error = "Could not extract text from image. Please paste text instead."
            except Exception as e:
                error = f"Error processing image: {str(e)}"

        if job_input:
            result = analyze_job_description(job_input)
            prediction  = result["prediction"]
            confidence  = result["confidence"]
            risk        = result["risk"]
            category    = result["category"]
            reasons     = result["reasons"]
            suggestions = result["suggestions"]

            highlighted_text = job_input
            for kw in ["upfront","bitcoin","western union","wire transfer","urgent","immediate"]:
                if kw.lower() in job_input.lower():
                    highlighted_text = highlighted_text.replace(
                        kw, f'<mark style="background-color:#ffcccc;">{kw}</mark>'
                    )

            session.setdefault('history', []).insert(0, {
                "input_text": job_input[:100] + ("..." if len(job_input) > 100 else ""),
                "prediction": prediction, "confidence": confidence,
                "risk": risk, "category": category,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            session.modified = True
        else:
            error = "Please enter a job description or upload an image"

    return render_template("index.html",
        prediction=prediction, confidence=confidence, risk=risk,
        category=category, reasons=reasons, suggestions=suggestions,
        highlighted_text=highlighted_text, processed_image=processed_image, error=error
    )

# ====================================================
# ✅ BUG FIX: session.clear() BEFORE login_user()
#    Old code did it AFTER which wiped the login session
# ====================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        if not username:
            error = "Please enter a username."
        else:
            session.clear()                    # ✅ clear OLD session first
            login_user(User(username), remember=True)  # ✅ then create new login
            return redirect(request.args.get('next') or url_for("home"))

    return render_template("login.html", error=error)

# ✅ BUG FIX: redirect to /login (not /home which needs auth)
@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("login"))

@app.route("/history")
@login_required
def history():
    return render_template("history.html", data=session.get('history', []))

if __name__ == "__main__":
    app.run(debug=True)