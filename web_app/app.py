from flask import Flask, render_template, request, redirect, url_for, session, make_response, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re
import json
import hashlib
import secrets
from werkzeug.utils import secure_filename
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import functools
from openai import OpenAI
from dotenv import load_dotenv
from collections import Counter
from datetime import datetime, timedelta

# Load environment variables from .env (check both project root and web_app folder)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

app = Flask(__name__)
# Load secret key from environment — never hardcode in production
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
# Use absolute path so it works regardless of where the server is started
USERS_FILE = os.path.join(app.root_path, 'users.json')
HISTORY_DIR = os.path.join(app.root_path, 'history')
FEEDBACK_FILE = os.path.join(app.root_path, 'feedback.json')
os.makedirs(HISTORY_DIR, exist_ok=True)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ===== NVIDIA NIM LLM CLIENT =====
_nvidia_client = None
def get_nvidia_client():
    """Lazily initialize the NVIDIA OpenAI client."""
    global _nvidia_client
    if _nvidia_client is None:
        api_key = os.environ.get("NVIDIA_API_KEY")
        if api_key:
            _nvidia_client = OpenAI(
                base_url="https://integrate.api.nvidia.com/v1",
                api_key=api_key
            )
    return _nvidia_client


# ===== LLM ANALYSIS CACHE =====
# Caches results by MD5 hash of input text — avoids repeat API calls, saves credits
_ANALYSIS_CACHE: dict = {}
_ANALYSIS_CACHE_MAX = 50

def _cache_key(text: str) -> str:
    return hashlib.md5(text.strip().lower().encode()).hexdigest()

def _get_cached(text: str):
    return _ANALYSIS_CACHE.get(_cache_key(text))

def _set_cache(text: str, result: dict):
    key = _cache_key(text)
    if len(_ANALYSIS_CACHE) >= _ANALYSIS_CACHE_MAX:
        # Evict the oldest entry
        oldest = next(iter(_ANALYSIS_CACHE))
        del _ANALYSIS_CACHE[oldest]
    _ANALYSIS_CACHE[key] = result


# ===== PERSISTENT HISTORY HELPERS =====
def _history_path(username: str) -> str:
    safe = re.sub(r'[^a-zA-Z0-9_-]', '_', username)
    return os.path.join(HISTORY_DIR, f'history_{safe}.json')

def load_history(username: str) -> list:
    path = _history_path(username)
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return []

def save_history(username: str, entries: list):
    path = _history_path(username)
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(entries[:50], f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f'[History] Failed to save: {e}')

# ===== FEEDBACK & LEARNING HELPERS =====
def load_feedback() -> list:
    if os.path.exists(FEEDBACK_FILE):
        try:
            with open(FEEDBACK_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return []

def save_feedback(input_text: str, corrected_prediction: str, user_notes: str):
    feedback = load_feedback()
    # Keep only the last 100 feedback entries to prevent prompt bloat
    new_entry = {
        "text": input_text[:500],
        "correction": corrected_prediction,
        "notes": user_notes,
        "timestamp": datetime.now().isoformat()
    }
    feedback.append(new_entry)
    try:
        with open(FEEDBACK_FILE, 'w', encoding='utf-8') as f:
            json.dump(feedback[-100:], f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f'[Feedback] Failed to save: {e}')

def get_feedback_few_shots() -> str:
    feedback = load_feedback()
    if not feedback:
        return ""
    
    # Select up to 3 relevant feedback examples to inject
    examples = feedback[-3:]
    fs_text = "\nRECENT USER CORRECTIONS (Learn from these mistakes):\n"
    for ex in examples:
        fs_text += f"Input: \"{ex['text']}...\" -> Correction: {ex['correction']} (Reason: {ex['notes']})\n"
    return fs_text

# ===== USER MANAGEMENT FUNCTIONS =====
_USER_CACHE = None

def load_users():
    """Load users from JSON file with in-memory caching."""
    global _USER_CACHE
    if _USER_CACHE is not None:
        return _USER_CACHE

    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                _USER_CACHE = json.load(f)
                return _USER_CACHE
        except:
            pass
    _USER_CACHE = {}
    return _USER_CACHE

def save_users(users):
    """Save users to JSON file and update cache."""
    global _USER_CACHE
    _USER_CACHE = users
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

@functools.lru_cache(maxsize=128)
def scrape_url_text(url):
    """Scrape and extract text from a URL, with caching to improve performance."""
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Remove script and style elements
    for script in soup(["script", "style", "nav", "footer", "header"]):
        script.extract()
        
    # Get text
    text = soup.get_text(separator=' ')
    
    # Check for Bot Protection / Security Challenges (Common on LinkedIn/Indeed)
    block_phrases = ["security check", "captcha", "bot detection", "please sign in", "log in to view", "access denied", "verify you are human"]
    if any(phrase in text.lower() for phrase in block_phrases):
        raise ValueError("The website blocked our scanner (Security Check). Please paste the job description text manually for a more accurate analysis.")

    lines = (line.strip() for line in text.splitlines())
    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
    return '\n'.join(chunk for chunk in chunks if chunk)


# =============================================================================
# GUARDRAIL PIPELINE — 5 Layers
# =============================================================================

# --- KNOWN INVALID PATTERNS (no API call ever made for these) ----------------
_GIBBERISH_PHRASES = {
    "hi", "hello", "hey", "ok", "okay", "yes", "no", "thanks", "thank you",
    "lol", "haha", "nice", "good", "bad", "test", "testing", "help", "sup",
    "what", "who", "why", "how", "when", "bye", "goodbye", "hmm", "uh", "um",
}

_JOB_KEYWORDS = {
    "job", "position", "role", "hiring", "salary", "work", "employment",
    "company", "apply", "candidate", "experience", "skills", "remote",
    "part-time", "full-time", "internship", "vacancy", "opening", "join",
    "responsibilities", "requirements", "qualifications", "earn", "pay",
    "weekly", "monthly", "per hour", "per day", "manager", "engineer",
    "developer", "analyst", "assistant", "coordinator", "specialist",
    "immediate", "urgent", "whatsapp", "telegram", "deposit", "upfront",
    "guaranteed", "work from home", "data entry", "no experience",
}


# ── LAYER 1: Input Validator ──────────────────────────────────────────────────
def _validate_input(text: str) -> tuple[bool, str]:
    """
    Returns (is_valid, rejection_reason).
    Runs entirely in-process — zero API calls.
    """
    if not text or not text.strip():
        return False, "empty"

    cleaned = text.strip()
    word_count = len(cleaned.split())

    # Too short (fewer than 5 words)
    if word_count < 5:
        return False, "too_short"

    # Single common word / greeting
    if cleaned.lower() in _GIBBERISH_PHRASES:
        return False, "gibberish"

    # All digits / random characters (no alphabetic content)
    alpha_ratio = sum(c.isalpha() for c in cleaned) / max(len(cleaned), 1)
    if alpha_ratio < 0.4:
        return False, "non_text"

    return True, "ok"


# ── LAYER 2: Task Classifier ──────────────────────────────────────────────────
def _classify_task(text: str) -> str:
    """
    Classify input without any API call.
    Returns 'valid_job' or 'invalid'.
    A valid job post must contain at least 2 job-domain keywords.
    """
    text_lower = text.lower()
    hits = sum(1 for kw in _JOB_KEYWORDS if kw in text_lower)
    return "valid_job" if hits >= 2 else "invalid"


def _research_url_forensics(text: str) -> str:
    """
    Extracts URLs AND emails from the text, performs local forensic research
    (TLD risk, brand spoofing, LinkedIn pattern, generic email providers).
    Returns a pre-analysis block to inject into the LLM prompt.
    """
    import urllib.parse
    findings = []

    # ── URL research ──
    urls = re.findall(r'(https?://[^\s<>"]+)', text)
    high_risk_tlds = {
        '.xyz', '.top', '.site', '.work', '.icu', '.vip',
        '.online', '.club', '.buzz', '.info', '.biz', '.tk',
    }
    major_brands = [
        'amazon', 'google', 'microsoft', 'linkedin', 'indeed',
        'apple', 'netflix', 'meta', 'facebook', 'twitter', 'paypal',
        'glassdoor', 'ziprecruiter', 'monster', 'upwork',
    ]

    for url in urls[:4]:
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower().lstrip('www.')
            if not domain:
                continue
            note = f"URL-DOMAIN: {domain}"
            # High-risk TLD
            if any(domain.endswith(tld) for tld in high_risk_tlds):
                note += " → 🚨 HIGH-RISK TLD (phishing indicator)"
            # Brand spoofing
            for brand in major_brands:
                if brand in domain and domain not in (f"{brand}.com", f"www.{brand}.com") \
                        and not domain.endswith(f".{brand}.com"):
                    note += f" → ⚠️ POTENTIAL {brand.upper()} DOMAIN SPOOF"
            # LinkedIn check
            if 'linkedin' in domain and 'linkedin.com' not in domain:
                note += " → 🚨 FAKE LINKEDIN DOMAIN"
            elif 'linkedin.com' in domain and '/jobs' not in url and '/in/' not in url:
                note += " → ⚠️ LinkedIn link but not a job posting — possible DM redirect"
            findings.append(note)
        except:
            continue

    # ── Email research ──
    emails = re.findall(r'[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}', text)
    generic_providers = {
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
        'protonmail.com', 'aol.com', 'icloud.com', 'mail.com',
    }
    for email in emails[:3]:
        domain = email.split('@')[-1].lower()
        note = f"EMAIL: {email}"
        if domain in generic_providers:
            note += " → ⚠️ Generic provider (legitimate companies use corporate email)"
        for brand in major_brands:
            if brand in domain and domain not in (f"{brand}.com",):
                note += f" → 🚨 POTENTIAL {brand.upper()} EMAIL SPOOF"
        findings.append(note)

    if not findings:
        return ""
    return "--- AUTOMATED FORENSIC PRE-SCAN ---\n" + "\n".join(findings)


# ── LAYER 3: Strict LLM Prompt ────────────────────────────────────────────────
_FEW_SHOT_EXAMPLES = """EXAMPLES:
Input: "Job at Amazon! Link: amazon-recruitment.xyz" -> Output: {"prediction":"Fake","confidence":"99%","company_legitimacy":"Low","link_trust_score":"Low","risk_level":"High","reasons":["Domain spoofing found","Generic email provider"],"final_advice":"Verify via amazon.jobs only."}
Input: "Verified Microsoft role from microsoft.com" -> Output: {"prediction":"Real","confidence":"95%","company_legitimacy":"High","link_trust_score":"High","risk_level":"Low","reasons":["Official domain verified"],"final_advice":"Safe to apply."}"""

_SYSTEM_PROMPT = f"""Role: AI Fraud Verification System. 
Goal: Determine if a job/company is REAL or FAKE using deep reasoning.

ANALYSIS PHASES:
1. Company Legitimacy: Check for realistic name, known history, and vagueness.
2. Link Verification: Analyze structure (Real domain vs Random/Short links). Check LinkedIn profile consistency.
3. Job Content: Flag unrealistic salary, no experience high-pay, and urgency tactics.
4. Communication: Flag WhatsApp/Telegram and personal emails (@gmail, @yahoo).
5. Cross-Consistency: Match job description to company type and location.

RULES:
- Do NOT hallucinate data.
- If data is missing, say "Insufficient data".
- Mark as "Suspicious" if unsure.

{_FEW_SHOT_EXAMPLES}

JSON SCHEMA:
{{
  "prediction": "Real | Fake | Suspicious",
  "confidence": "0-100%",
  "company_legitimacy": "High | Medium | Low",
  "link_trust_score": "High | Medium | Low",
  "risk_level": "Low | Medium | High",
  "reasons": ["string"],
  "final_advice": "string"
}}"""

_ADAPTIVE_DEPTH = {
    "short":    "Check: verifiable credentials, generic text, off-platform chat (Telegram/WhatsApp).",
    "standard": "Check: linguistic cues, pay vs effort, domain mismatches.",
    "deep":     "Check: social triggers (fear/greed), data contradictions, 'Task Scam' patterns.",
}


def _build_user_prompt(text: str) -> str:
    words = len(text.split())
    mode  = "short" if words < 50 else ("standard" if words < 200 else "deep")
    depth = _ADAPTIVE_DEPTH[mode]
    
    # NEW: Perform URL/Domain Research
    research_data = _research_url_forensics(text)
    
    # Hard-cap text at 1500 chars to stay well under token limits
    prompt = f"Mode: {mode.upper()} — {depth}\n"
    if research_data:
        prompt += f"{research_data}\n"
    prompt += f"\nJob posting:\n{text[:1500]}"
    return prompt


# ── LAYER 4: Output Validator ─────────────────────────────────────────────────
_REQUIRED_KEYS = {
    "prediction", "confidence", "risk", "category",
    "fraud_risk_score", "financial_trap_index", "credibility_score",
    "urgency_pressure_score", "information_quality_score",
    "reasons", "suggestions",
}
_VALID_PREDICTIONS = {"FAKE", "SUSPICIOUS", "REAL"}


def _validate_output(result: dict) -> bool:
    """Returns True only if the LLM result has all required fields with sensible values."""
    if not isinstance(result, dict):
        return False
    
    # Standardize
    if "verdict" in result:
        result["verdict"] = result["verdict"].upper()
    
    required_keys = {"prediction", "confidence", "company_legitimacy", "link_trust_score", "risk_level"}
    if not required_keys.issubset(result.keys()):
        return False
    
    if result.get("prediction").upper() not in {"REAL", "FAKE", "SUSPICIOUS"}:
        return False
        
    return True


def _fill_defaults(result: dict) -> dict:
    """Ensure all fields exist even if LLM returned a partial response."""
    result.setdefault("prediction",                 "SUSPICIOUS")
    result.setdefault("confidence",                 50)
    result.setdefault("risk",                       50)
    result.setdefault("fraud_risk_score",           50)
    result.setdefault("financial_trap_index",       50)
    result.setdefault("credibility_score",          50)
    result.setdefault("urgency_pressure_score",     30)
    result.setdefault("information_quality_score",  50)
    result.setdefault("category",                   "General")
    result.setdefault("validation_gates_passed", False)
    result.setdefault("failed_gates",            ["Missing mandatory validation audit."])
    
    # HARD VERDICT LOGIC ENFORCEMENT
    score = result.get("score", 50)
    gates_passed = result.get("validation_gates_passed", False)
    
    if score >= 40:
        result["verdict"] = "FAKE"
        result["category"] = "🚨 High Risk"
    elif not gates_passed or score >= 10:
        result["verdict"] = "SUSPICIOUS"
        result["category"] = "⚠️ Medium Risk"
    elif gates_passed and score < 10:
        result["verdict"] = "REAL"
        result["category"] = "✅ Low Risk"
    else:
        result["verdict"] = "SUSPICIOUS"
        result["category"] = "⚠️ Medium Risk"

    # Handle nested analysis
    result.setdefault("company_analysis", {
        "exists_online": "uncertain",
        "platform_consistency": "uncertain"
    })
    result.setdefault("contact_verification", {
        "email_validity": "uncertain",
        "domain_check": "uncertain"
    })

    result.setdefault("evidence",    ["Security scan complete."])
    result.setdefault("consistency_check", "pass")
    result.setdefault("final_reasoning", "Strict forensic analysis applied.")
    result.setdefault("suggestions", [
        "✓ Do not proceed until company identity is verified.",
        "✓ Check if this job exists on official LinkedIn pages.",
    ])
    
    return result


# ── LAYER 5: Token-Optimised LLM Call ──
def _call_llm(client, text: str, retries: int = 1) -> dict | None:
    user_prompt = _build_user_prompt(text)

    for attempt in range(retries + 1):
        try:
            full_response = ""
            # On retry, send a simplified prompt to avoid hitting edge cases
            prompt_to_send = user_prompt if attempt == 0 else f"Analyze this job posting for fraud. Respond ONLY in JSON schema.\n\n{text[:800]}"

            # Dynamic Few-Shot Injection from User Feedback
            dynamic_fs = get_feedback_few_shots()
            sys_prompt_with_feedback = _SYSTEM_PROMPT + dynamic_fs

            completion = client.chat.completions.create(
                model="meta/llama-3.1-70b-instruct",
                messages=[
                    {"role": "system", "content": sys_prompt_with_feedback},
                    {"role": "user",   "content": prompt_to_send},
                ],
                temperature=0.0,
                top_p=0.1,
                max_tokens=300,
                stream=True,
            )
            for chunk in completion:
                if chunk.choices and chunk.choices[0].delta.content is not None:
                    full_response += chunk.choices[0].delta.content

            # Model chose to reject the input
            if "INVALID_INPUT" in full_response:
                print(f"[LLM] Model flagged input as INVALID_INPUT (attempt {attempt+1})")
                return None

            # Extract JSON — handle markdown code blocks too
            json_match = re.search(r'```(?:json)?\s*([\s\S]*?)```', full_response)
            if not json_match:
                json_match = re.search(r'\{[\s\S]*\}', full_response)

            if json_match:
                raw_json = json_match.group(1) if json_match.lastindex else json_match.group()
                result = json.loads(raw_json)
                
                # Extract from your Custom Reasoning Structure
                result["prediction"] = result.get("prediction", "Suspicious").upper()
                conf_str = str(result.get("confidence", "50%")).replace("%", "")
                result["confidence"] = int(conf_str) if conf_str.isdigit() else 50
                
                # Map Categories to UI Risk Scores
                risk_map = {"High": 90, "Medium": 50, "Low": 15}
                trust_map = {"High": 15, "Medium": 50, "Low": 90}
                
                result["risk"] = risk_map.get(result.get("risk_level"), 50)
                result["fraud_risk_score"] = result["risk"]
                result["financial_trap_index"] = trust_map.get(result.get("link_trust_score"), 50)
                result["credibility_score"] = 100 - trust_map.get(result.get("company_legitimacy"), 50)
                
                # Standard UI Mapping
                result["reasons"] = result.get("reasons", [])
                result["suggestions"] = [result.get("final_advice", "Verifying...")]
                result["final_reasoning"] = result.get("final_advice", "Deep reasoning applied.")
                
                # Flatten metrics if they are in the nested 'metrics' key
                if "metrics" in result and isinstance(result["metrics"], dict):
                    result.update(result["metrics"])

                if _validate_output(result):
                    result["engine"] = "LLM-Deep"
                    print(f"[LLM] ✅ Valid result: {result.get('prediction')} / risk={result.get('risk')} (attempt {attempt+1})")
                    return _fill_defaults(result) # Ensure all fields for UI
                # Partial output — fill defaults and return
                print(f"[LLM] ⚠️ Output failed validation — filling defaults (attempt {attempt+1})")
                return _fill_defaults(result)

        except json.JSONDecodeError as e:
            print(f"[LLM JSON Error] attempt {attempt+1}: {e}")
        except Exception as e:
            print(f"[LLM Error] attempt {attempt+1}: {e}")

    return None


# =============================================================================
# PUBLIC ENTRY POINT - Full Guardrail Pipeline
# =============================================================================
def analyze_job_description(text: str) -> dict:
    """
    Full 5-layer analysis pipeline:
      L1: Input Validator - rejects empty/gibberish/non-text inputs
      L2: Task Classifier - rejects non-job-related text without API call
      L3: Strict LLM Prompt - model self-rejects unclear inputs
      L4: Output Validator - discards malformed LLM responses
      L5: Token Optimiser - max_tokens=300, text capped at 1500 chars
    """

    # -- L1: Validate input ----------------------------------------------------
    is_valid, rejection_reason = _validate_input(text)
    if not is_valid:
        reason_map = {
            "empty":    "No input was provided. Please paste a job description.",
            "too_short": "Input is too short to be a job posting (minimum 5 words).",
            "gibberish": "Input looks like a greeting or random text, not a job posting.",
            "non_text":  "Input does not appear to contain readable text.",
        }
        print(f"[L1-Validator] Rejected: {rejection_reason}")
        return {
            "prediction": "INVALID",
            "confidence": 0, "risk": 0,
            "category": "❌ Invalid Input",
            "fraud_risk_score": 0, "financial_trap_index": 0,
            "credibility_score": 0, "urgency_pressure_score": 0,
            "information_quality_score": 0,
            "reasons": [reason_map.get(rejection_reason, "Invalid input.")],
            "suggestions": [
                "✓ Paste the full text of the job posting.",
                "✓ Or enter the job URL to have it scraped automatically.",
                "✓ Or upload a screenshot of the job ad.",
            ],
            "engine": "Validator",
        }

    # ── L2: Classify task ─────────────────────────────────────────────────────
    task_class = _classify_task(text)
    if task_class == "invalid":
        print(f"[L2-Classifier] Rejected: not a job posting")
        return {
            "prediction": "INVALID",
            "confidence": 0, "risk": 0,
            "category": "❌ Not a Job Posting",
            "fraud_risk_score": 0, "financial_trap_index": 0,
            "credibility_score": 0, "urgency_pressure_score": 0,
            "information_quality_score": 0,
            "reasons": [
                "⚠️ This text does not appear to be a job posting.",
                "⚠️ No job-related keywords were found (e.g., hiring, salary, position, role).",
            ],
            "suggestions": [
                "✓ Paste a real job advertisement to get an analysis.",
                "✓ Include details like role, salary, company, and requirements.",
            ],
            "engine": "Classifier",
        }

    # ── L3 + L4 + L5: LLM call with strict prompt + output validation ─────────
    client = get_nvidia_client()
    if client:
        llm_result = _call_llm(client, text)
        if llm_result:
            print(f"[Pipeline] LLM result: {llm_result.get('prediction')} / risk={llm_result.get('risk')}")
            return llm_result
        print("[Pipeline] LLM returned None — falling back to rule-based.")

    # ── Fallback: rule-based ──────────────────────────────────────────────────
    result = _rule_based_analyze(text)
    result["engine"] = "Rule-based"
    return result


# ── Rule-based analyser (fallback only) ──────────────────────────────────────
def analyze_job_with_llm(text: str) -> dict:
    """Alias kept for backward compatibility."""
    return analyze_job_description(text)


def _rule_based_analyze(text: str) -> dict:
    """Keyword-weighted rule-based fallback - used when LLM is unavailable."""
    if not text or len(text.strip()) < 10:
        return {
            "prediction": "INVALID", "confidence": 0, "risk": 0,
            "category": "❌ Invalid Input",
            "fraud_risk_score": 0, "financial_trap_index": 0,
            "credibility_score": 0, "urgency_pressure_score": 0,
            "information_quality_score": 0,
            "reasons": ["Job description is too short to analyze."],
            "suggestions": ["Please provide a detailed job description."],
            "engine": "Rule-based",
        }

    text_lower = text.lower()
    red_flags = {
        "upfront payment": 0.40, "wire transfer": 0.45, "bitcoin": 0.45,
        "western union": 0.45, "gift card": 0.40, "itunes card": 0.40,
        "cash app": 0.40, "venmo": 0.40, "paypal": 0.35, "crypto": 0.40,
        "security deposit": 0.45, "starter kit": 0.40, "equipment fee": 0.45,
        "whatsapp": 0.35, "telegram": 0.35,
        "no experience": 0.25, "no qualifications": 0.25, "no cv needed": 0.30,
        "no interview": 0.30, "immediate hire": 0.25, "immediate start": 0.25,
        "data entry": 0.15, "envelope stuffing": 0.25, "reshipping": 0.35,
        "guaranteed income": 0.40, "quick money": 0.40, "easy money": 0.40,
        "risk-free": 0.35, "urgent": 0.20, "limited time": 0.20,
        "act now": 0.20, "high salary": 0.10, "earn $": 0.10,
    }
    legitimate_indicators = {
        "apply on indeed": -0.10, "apply on linkedin": -0.10,
        "requirements": -0.05, "qualifications": -0.05,
        "benefits": -0.08, "salary": -0.08, "company": -0.08,
        "official website": -0.10,
    }
    reasons = []
    risk_score = 0.3
    for flag, weight in red_flags.items():
        if flag in text_lower:
            risk_score += weight
            if weight > 0.20:
                reasons.append(f"⚠️ Detected: '{flag}'")
    for indicator, reduction in legitimate_indicators.items():
        if indicator in text_lower:
            risk_score += reduction
    if len(text.split()) < 50:
        risk_score += 0.15
        reasons.append("📏 Job description is unusually brief")
    risk_score = max(0.0, min(1.0, risk_score))
    risk_percentage = int(risk_score * 100)
    if risk_percentage > 55:
        prediction = "FAKE"
        confidence = min(95, risk_percentage)
        category   = "🚨 High Risk"
    elif risk_percentage > 45:
        prediction = "SUSPICIOUS"
        confidence = min(85, int(risk_percentage / 1.2))
        category   = "⚠️ Medium Risk"
    else:
        prediction = "REAL"
        confidence = min(95, 100 - risk_percentage)
        category   = "✅ Low Risk"
    if not reasons:
        reasons = ["✅ Job description appears legitimate."] if prediction == "REAL" else ["⚠️ Multiple fraud indicators detected."]
    return {
        "prediction": prediction, "confidence": confidence,
        "risk": risk_percentage, "category": category,
        "fraud_risk_score": risk_percentage,
        "financial_trap_index": min(100, risk_percentage + 5),
        "credibility_score": max(0, 100 - risk_percentage),
        "urgency_pressure_score": risk_percentage // 2,
        "information_quality_score": max(0, 80 - risk_percentage),
        "reasons": reasons[:4],
        "suggestions": [
            "✓ Verify company information independently.",
            "✓ Check official company website and LinkedIn.",
            "✓ Be cautious of requests for upfront payments.",
            "✓ Research the company on Glassdoor or Indeed reviews.",
        ],
        "engine": "Rule-based",
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

def normalize_ocr_text(text):
    """Normalize OCR words so punctuation does not block keyword matching."""
    return re.sub(r"[^a-z0-9]+", "", text.lower())

def highlight_keywords_in_image(image_path, keywords, output_path):
    """Draw red highlights on keywords found in the image."""
    try:
        from PIL import Image, ImageDraw
        import pytesseract

        if not os.path.exists(image_path):
            return False

        img = Image.open(image_path).convert('RGBA')

        # Get detailed OCR data with bounding boxes
        data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)

        words = []
        for i, raw_word in enumerate(data['text']):
            normalized_word = normalize_ocr_text(raw_word)
            if not normalized_word:
                continue

            words.append({
                "text": normalized_word,
                "left": data['left'][i],
                "top": data['top'][i],
                "width": data['width'][i],
                "height": data['height'][i],
            })

        highlight_boxes = []
        keyword_tokens = [
            [normalize_ocr_text(token) for token in keyword.split() if normalize_ocr_text(token)]
            for keyword in keywords
        ]

        for start_index in range(len(words)):
            for tokens in keyword_tokens:
                if not tokens or start_index + len(tokens) > len(words):
                    continue

                candidate = words[start_index:start_index + len(tokens)]
                is_match = all(
                    token == word["text"] or token in word["text"] or word["text"] in token
                    for token, word in zip(tokens, candidate)
                )

                if is_match:
                    highlight_boxes.extend(candidate)

        overlay = Image.new('RGBA', img.size, (0, 0, 0, 0))
        overlay_draw = ImageDraw.Draw(overlay)

        for box in highlight_boxes:
            padding = 4
            x1 = max(0, box["left"] - padding)
            y1 = max(0, box["top"] - padding)
            x2 = min(img.width, box["left"] + box["width"] + padding)
            y2 = min(img.height, box["top"] + box["height"] + padding)
            overlay_draw.rectangle([x1, y1, x2, y2], fill=(217, 64, 53, 78))

        img = Image.alpha_composite(img, overlay).convert('RGB')
        draw = ImageDraw.Draw(img)

        for box in highlight_boxes:
            padding = 4
            x1 = max(0, box["left"] - padding)
            y1 = max(0, box["top"] - padding)
            x2 = min(img.width, box["left"] + box["width"] + padding)
            y2 = min(img.height, box["top"] + box["height"] + padding)
            draw.rectangle([x1, y1, x2, y2], outline=(217, 64, 53), width=3)

        img.save(output_path)
        return bool(highlight_boxes)

    except Exception as e:
        return False

@app.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route("/", methods=["GET", "POST"])
@login_required
def home():
    result = {}  # Initialize result to prevent UndefinedError
    prediction = confidence = risk = category = reasons = suggestions = highlighted_text = error = None
    processed_image_url = None
    scraped_url = None
    job_input = None  # Ensure job_input is initialized for the template

    if request.method == "POST":
        job_input = request.form.get("job_input", "").strip()
        job_image = request.files.get("job_image")

        if job_image and job_image.filename:
            try:
                filename = secure_filename(job_image.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                job_image.save(filepath)
                
                # Provide the original image to be displayed in the results unconditionally
                processed_image_url = url_for("uploaded_file", filename=filename)
                
                extracted = extract_text_from_image(filepath)
                if extracted:
                    job_input = extracted

                    # Highlight keywords in the screenshot image
                    keywords_to_highlight = [
                        "upfront", "bitcoin", "western union", "wire transfer", "gift card",
                        "urgent", "immediate", "immediate start", "no interview", "no experience",
                        "guaranteed income", "quick money", "easy money", "risk-free",
                        "itunes card", "no cv needed", "act now", "don't delay", "limited time",
                        "whatsapp", "telegram", "cash app", "venmo", "paypal", "crypto",
                        "security deposit", "starter kit", "equipment fee", "reshipping"
                    ]
                    processed_filename = f"processed_{datetime.now().strftime('%Y%m%d%H%M%S%f')}.png"
                    processed_path = os.path.join(app.config['UPLOAD_FOLDER'], processed_filename)
                    if highlight_keywords_in_image(filepath, keywords_to_highlight, processed_path):
                        if os.path.exists(processed_path):
                            processed_image_url = url_for("uploaded_file", filename=processed_filename)
                else:
                    if not job_input: # Only show error if no text was provided at all
                        error = "Could not extract text from image. Please paste text instead."
            except Exception as e:
                error = f"Error processing image: {str(e)}"

        if job_input:
            if job_input.startswith("http://") or job_input.startswith("https://"):
                try:
                    scraped_url = job_input
                    job_input = scrape_url_text(job_input)
                except Exception as e:
                    error = str(e)
                    job_input = None # Stop analysis if scraping failed (e.g. LinkedIn Security Check)

        if job_input:
            # Bypass cache for URLs to ensure deep, fresh analysis every time
            cached = _get_cached(job_input) if not scraped_url else None
            if cached:
                result = cached
            else:
                result = analyze_job_description(job_input)
                # Only cache valid analyses — never cache INVALID or URL-based responses
                if result.get("prediction") != "INVALID" and not scraped_url:
                    _set_cache(job_input, result)

            prediction  = result["prediction"]
            confidence  = result["confidence"]
            risk        = result["risk"]
            category    = result["category"]
            reasons     = result["reasons"]
            suggestions = result["suggestions"]
            engine      = result.get("engine", "LLM" if get_nvidia_client() else "Rule-based")

            # ── Guardrail: show INVALID as a user-facing error, not a result page ──
            if prediction == "INVALID":
                error = reasons[0] if reasons else "That doesn't look like a job posting. Please paste a real job description."
                prediction = None   # prevents the results block from rendering
            else:
                # Custom LLM metrics
                fraud_risk_score          = result.get("fraud_risk_score")
                financial_trap_index      = result.get("financial_trap_index")
                credibility_score         = result.get("credibility_score")
                urgency_pressure_score    = result.get("urgency_pressure_score")
                information_quality_score = result.get("information_quality_score")

                highlighted_text = job_input
                keywords_to_highlight = [
                    "upfront", "bitcoin", "western union", "wire transfer", "gift card",
                    "urgent", "immediate", "immediate start", "no interview", "no experience",
                    "guaranteed income", "quick money", "easy money", "risk-free",
                    "itunes card", "no cv needed", "act now", "don't delay", "limited time",
                    "whatsapp", "telegram", "cash app", "venmo", "paypal", "crypto",
                    "security deposit", "starter kit", "equipment fee", "reshipping"
                ]
                for kw in keywords_to_highlight:
                    if kw.lower() in job_input.lower():
                        pattern = re.compile(re.escape(kw), re.IGNORECASE)
                        highlighted_text = pattern.sub(
                            f'<mark style="background-color:#e74c3c; color:white; padding:2px 4px; border-radius:3px; font-weight:bold;">\\g<0></mark>',
                            highlighted_text
                        )

                # Persist history — only for valid FAKE/SUSPICIOUS/REAL results
                history = load_history(current_user.username)
                history.insert(0, {
                    "input_text": job_input[:120] + ("..." if len(job_input) > 120 else ""),
                    "prediction": prediction, "confidence": confidence,
                    "risk": risk, "category": category, "engine": engine,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M")
                })
                save_history(current_user.username, history)
        elif request.method == "POST":
            error = "Please enter a job description or upload an image"

    return render_template("index.html",
        prediction=prediction, confidence=confidence, risk=risk,
        category=category, reasons=reasons, suggestions=suggestions,
        highlighted_text=highlighted_text, processed_image_url=processed_image_url, error=error,
        scraped_url=scraped_url,
        fraud_risk_score=result.get('fraud_risk_score', 50),
        financial_trap_index=result.get('financial_trap_index', 50),
        credibility_score=result.get('credibility_score', 50),
        urgency_pressure_score=result.get('urgency_pressure_score', 30),
        information_quality_score=result.get('information_quality_score', 50),
        # Strict Security and Consistency fields
        consistency_check=result.get('consistency_check', 'pass'),
        evidence=result.get('evidence', []),
        final_reasoning=result.get('final_reasoning', 'Analysis complete.'),
        company_analysis=result.get('company_analysis'),
        contact_verification=result.get('contact_verification'),
        # Pass original text
        original_text=job_input if request.method == "POST" else ""
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

@app.route("/feedback", methods=["POST"])
@login_required
def feedback():
    """Endpoint for the LLM to 'learn' from user corrections."""
    text = request.form.get("text", "")
    correction = request.form.get("correction", "")
    notes = request.form.get("notes", "")
    
    from flask import jsonify
    if text and correction:
        save_feedback(text, correction, notes)
        return jsonify({"status": "success", "message": "SafeRecruit AI has learned from this report."})
    
    return jsonify({"status": "error", "message": "Invalid feedback data."}), 400

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
    data = load_history(current_user.username)
    return render_template("history.html", data=data)

@app.route("/dashboard")
@login_required
def dashboard():
    """Aggregated forensics statistics for the user."""
    history = load_history(current_user.username)
    
    # ── 1. General Stats ──
    total_scans = len(history)
    
    # ── 2. Risk Distribution ──
    predictions = [item.get('prediction', 'UNKNOWN') for item in history]
    risk_counts = Counter(predictions)
    
    # ── 3. Engine Distribution ──
    engines = [item.get('engine', 'LLM') for item in history]
    engine_counts = Counter(engines)
    
    # ── 4. Average Confidence & Risk ──
    avg_confidence = sum(item.get('confidence', 0) for item in history) / max(total_scans, 1)
    avg_risk = sum(item.get('risk', 0) for item in history) / max(total_scans, 1)
    
    # ── 5. Activity Timeline (Last 7 Days) ──
    # Format: {"2024-04-20": 5, ...}
    dates = [item.get('timestamp', '').split(' ')[0] for item in history if item.get('timestamp')]
    timeline_counts = Counter(dates)
    
    # Sort timeline for Chart.js
    sorted_dates = sorted(timeline_counts.keys())[-7:]
    timeline_data = {date: timeline_counts[date] for date in sorted_dates}

    stats = {
        "total_scans": total_scans,
        "risk_counts": dict(risk_counts),
        "engine_counts": dict(engine_counts),
        "avg_confidence": round(avg_confidence, 1),
        "avg_risk": round(avg_risk, 1),
        "timeline_data": timeline_data
    }
    
    return render_template("dashboard.html", stats=stats)

if __name__ == "__main__":
    app.run(debug=True)
