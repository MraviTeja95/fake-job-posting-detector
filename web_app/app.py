from flask import Flask, render_template, request, redirect, url_for, session, make_response
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re
import json
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.secret_key = "secret123"
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'uploads'
USERS_FILE = 'users.json'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ===== USER MANAGEMENT FUNCTIONS =====
def load_users():
    """Load users from JSON file."""
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_users(users):
    """Save users to JSON file."""
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def user_exists(username):
    """Check if user exists."""
    users = load_users()
    return username in users

def register_user(username, password):
    """Register a new user with hashed password."""
    if user_exists(username):
        return False
    users = load_users()
    users[username] = generate_password_hash(password)
    save_users(users)
    return True

def verify_user(username, password):
    """Verify username and password."""
    users = load_users()
    if username not in users:
        return False
    return check_password_hash(users[username], password)

class User(UserMixin):
    def __init__(self, id):
        self.id = id
        self.username = id

@login_manager.user_loader
def load_user(user_id):
    if user_exists(user_id):
        return User(user_id)
    return None

def analyze_job_description(text):
    if not text or len(text.strip()) < 10:
        return {
            "prediction": "INVALID", "confidence": 0, "risk": 0,
            "category": "Too Short",
            "reasons": ["Job description is too short to analyze"],
            "suggestions": ["Please provide a detailed job description"]
        }

    text_lower = text.lower()

    # Red flags with severity weights
    red_flags = {
        # Payment-related (highest risk)
        "upfront payment": 0.35, "wire transfer": 0.40, "bitcoin": 0.40,
        "western union": 0.40, "gift card": 0.35, "itunes card": 0.35,

        # Work patterns (medium-high risk)
        "no experience": 0.20, "no qualifications": 0.25, "no cv needed": 0.25,
        "no interview": 0.25, "immediate hire": 0.20, "immediate start": 0.20,

        # Financial promises (high risk)
        "guaranteed income": 0.35, "quick money": 0.35, "easy money": 0.35,
        "guaranteed income": 0.35, "risk-free": 0.30, "work from anywhere": 0.10,

        # Urgency/pressure tactics (medium risk)
        "urgent": 0.15, "limited time": 0.15, "act now": 0.15, "don't delay": 0.15,

        # Unrealistic pay (low-medium risk)
        "high salary": 0.10, "lucrative": 0.05, "earn $": 0.08,
    }

    # Legitimate indicators (reduce risk)
    legitimate_indicators = {
        "apply on indeed": -0.10, "apply on linkedin": -0.10, "job portal": -0.10,
        "contact hr": -0.08, "contact human resources": -0.08, "apply here": -0.08,
        "requirements": -0.05, "qualifications": -0.05, "experience": -0.05,
        "benefits": -0.08, "salary": -0.08, "company": -0.08, "location": -0.05,
        "official website": -0.10, "company website": -0.10,
    }

    reasons = []
    risk_score = 0.3

    # Check for red flags
    for flag, weight in red_flags.items():
        if flag in text_lower:
            risk_score += weight
            if weight > 0.20:
                reasons.append(f"⚠️ Detected: '{flag}'")

    # Check for legitimate indicators
    for indicator, reduction in legitimate_indicators.items():
        if indicator in text_lower:
            risk_score += reduction

    # Length check
    if len(text.split()) < 50:
        risk_score += 0.15
        reasons.append("📏 Job description is unusually brief")
    elif len(text.split()) > 500:
        risk_score -= 0.05  # Detailed descriptions are usually legitimate

    # Normalize risk score
    risk_score = max(0, min(1, risk_score))
    risk_percentage = int(risk_score * 100)

    # Determine prediction
    if risk_percentage > 65:
        prediction = "FAKE"
        confidence = min(95, risk_percentage)
        category = "🚨 High Risk"
    elif risk_percentage > 45:
        prediction = "SUSPICIOUS"
        confidence = min(85, int(risk_percentage / 1.2))
        category = "⚠️ Medium Risk"
    else:
        prediction = "REAL"
        confidence = min(95, 100 - risk_percentage)
        category = "✅ Low Risk"

    if not reasons:
        reasons = ["Job description appears legitimate"] if prediction == "REAL" else ["Multiple fraud indicators detected"]

    return {
        "prediction": prediction, "confidence": confidence,
        "risk": risk_percentage, "category": category,
        "reasons": reasons[:4],
        "suggestions": [
            "✓ Verify company information independently",
            "✓ Check official company website and LinkedIn",
            "✓ Be cautious of requests for upfront payments",
            "✓ Research the company on Glassdoor or Indeed reviews"
        ]
    }

def extract_text_from_image(image_path):
    """Extract text from image using OCR."""
    try:
        from PIL import Image
        import pytesseract

        # Validate file exists
        if not os.path.exists(image_path):
            return None

        # Open and validate image
        img = Image.open(image_path)

        # Check image size (limit to 50MB to prevent processing large files)
        file_size = os.path.getsize(image_path)
        if file_size > 50 * 1024 * 1024:
            return None

        # Extract text
        extracted_text = pytesseract.image_to_string(img)

        # Validate extraction result
        if extracted_text and len(extracted_text.strip()) > 5:
            return extracted_text.strip()

        return None
    except ImportError:
        return None
    except Exception as e:
        return None

def highlight_keywords_in_image(image_path, keywords):
    """Draw red highlights on keywords found in the image."""
    try:
        from PIL import Image, ImageDraw, ImageFont
        import pytesseract

        if not os.path.exists(image_path):
            return False

        # Open image
        img = Image.open(image_path)
        draw = ImageDraw.Draw(img)

        # Get detailed OCR data with bounding boxes
        data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)

        # For each word in the OCR results
        highlighted = False
        for i in range(len(data['text'])):
            word = data['text'][i].lower().strip()

            # Check if word matches any keyword
            for keyword in keywords:
                if keyword.lower() in word:
                    # Get bounding box
                    x = data['left'][i]
                    y = data['top'][i]
                    w = data['width'][i]
                    h = data['height'][i]

                    # Draw red rectangle with border
                    # Coordinates: (left, top, right, bottom)
                    draw.rectangle(
                        [x, y, x + w, y + h],
                        outline='red',
                        width=3
                    )

                    # Add semi-transparent red background
                    # Create a new image for transparency effect
                    overlay = Image.new('RGBA', img.size, (0, 0, 0, 0))
                    overlay_draw = ImageDraw.Draw(overlay)
                    overlay_draw.rectangle(
                        [x, y, x + w, y + h],
                        fill=(255, 0, 0, 80)  # Red with 80/255 transparency
                    )
                    img = Image.alpha_composite(img.convert('RGBA'), overlay).convert('RGB')
                    draw = ImageDraw.Draw(img)

                    highlighted = True
                    break

        # Save the marked image
        processed_path = os.path.join(app.config['UPLOAD_FOLDER'], 'processed.png')
        img.save(processed_path)
        return highlighted

    except Exception as e:
        return False

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

                    # Highlight keywords in the screenshot image
                    keywords_to_highlight = [
                        "upfront", "bitcoin", "western union", "wire transfer", "gift card",
                        "urgent", "immediate", "immediate start", "no interview", "no experience",
                        "guaranteed income", "quick money", "easy money", "risk-free",
                        "itunes card", "no cv needed", "act now", "don't delay", "limited time"
                    ]
                    highlight_keywords_in_image(filepath, keywords_to_highlight)
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
            # Keywords to highlight (matches red flags from analysis)
            keywords_to_highlight = [
                "upfront", "bitcoin", "western union", "wire transfer", "gift card",
                "urgent", "immediate", "immediate start", "no interview", "no experience",
                "guaranteed income", "quick money", "easy money", "risk-free",
                "itunes card", "no cv needed", "act now", "don't delay", "limited time"
            ]

            for kw in keywords_to_highlight:
                if kw.lower() in job_input.lower():
                    # Use red highlighting: #e74c3c (bright red)
                    pattern = re.compile(re.escape(kw), re.IGNORECASE)
                    highlighted_text = pattern.sub(
                        f'<mark style="background-color:#e74c3c; color:white; padding:2px 4px; border-radius:3px; font-weight:bold;">\\g<0></mark>',
                        highlighted_text
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

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            error = "Please enter both username and password."
        elif not user_exists(username):
            error = "User not found. Please sign up first."
        elif not verify_user(username, password):
            error = "Incorrect password. Please try again."
        else:
            session.clear()
            login_user(User(username), remember=True)
            return redirect(request.args.get('next') or url_for("home"))

    return render_template("login.html", error=error)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    error = None
    success = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        # Validation
        if not username or not password:
            error = "Please fill in all fields."
        elif len(username) < 3:
            error = "Username must be at least 3 characters."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif password != confirm_password:
            error = "Passwords do not match."
        elif user_exists(username):
            error = "Username already exists. Please choose another."
        else:
            # Register user
            if register_user(username, password):
                success = "Account created successfully! Please login."
                session.clear()
                login_user(User(username), remember=True)
                return redirect(url_for("home"))
            else:
                error = "Registration failed. Please try again."

    return render_template("signup.html", error=error, success=success)

# ✅ BUG FIX: redirect to /login (not /home which needs auth)
@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    session.modified = True
    response = make_response(redirect(url_for("login")))
    response.delete_cookie('remember_token')
    return response

@app.route("/history")
@login_required
def history():
    return render_template("history.html", data=session.get('history', []))

if __name__ == "__main__":
    app.run(debug=True)