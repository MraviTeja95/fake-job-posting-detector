from flask import Flask, render_template, request, redirect, url_for, session, make_response, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import os
import re
import json
import hashlib
import secrets
import whois
import sqlite3
from datetime import datetime
import requests
from openai import OpenAI
from dotenv import load_dotenv
from collections import Counter
from datetime import datetime, timedelta

from auth import (
    User,
    configure_auth_storage,
    register_user,
    user_exists,
    verify_user,
)
from analysis import polish_analysis_result
from ocr import extract_text_from_image, highlight_keywords_in_image
from scraping import scrape_url_text
from utils import (
    configure_limiter,
    sanitize_highlighted_text,
    startup_validation,
    validate_image_upload,
)

# Load environment variables from .env (check both project root and web_app folder)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

app = Flask(__name__)
# Load secret key from environment â€” never hardcode in production
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
app.config['TEMPLATES_AUTO_RELOAD'] = True
# Use absolute path so it works regardless of where the server is started
USERS_FILE = os.path.join(app.root_path, 'users.json')
HISTORY_DIR = os.path.join(app.root_path, 'history')
FEEDBACK_FILE = os.path.join(app.root_path, 'feedback.json')
DATABASE_FILE = os.path.join(app.root_path, 'instance', 'database.db')
os.makedirs(HISTORY_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DATABASE_FILE), exist_ok=True)
configure_auth_storage(USERS_FILE)
startup_validation(app)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
limiter = configure_limiter(app)

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


# ===== MULTI-AGENT PIPELINE =====

def _agent_fast_scan(client, text: str, metadata: dict = None) -> dict:
    """Agent 1 (Llama-3.1-8B): The 'Scout' performs initial forensic scanning."""
    try:
        dynamic_fs = get_feedback_few_shots()
        completion = client.chat.completions.create(
            model="meta/llama-3.1-8b-instruct",
            messages=[
                {"role": "system", "content": f"Role: Senior Cybersecurity Forensic Scout. Identify immediate fraud patterns, social engineering triggers, and infrastructure anomalies. Respond ONLY with a JSON object containing: 'initial_risk' (0-100), 'red_flags' (list of specific patterns), and 'scout_summary' (concise forensic overview). {dynamic_fs}"},
                {"role": "user", "content": f"Analyze this Job: {text[:1000]}\nMetadata: {metadata}"}
            ],
            temperature=0.1,
            max_tokens=400,
            response_format={"type": "json_object"}
        )
        return json.loads(completion.choices[0].message.content)
    except Exception as e:
        print(f"[Agent Fast Scan Error] {e}")
        return {"initial_risk": 50, "red_flags": ["Scan failed - fallback applied."]}

def _agent_forensic_analysis(client, text: str, scout_report: dict, metadata: dict = None) -> dict:
    """Agent 2 (Llama-3.1-70B): Optimized version"""

    # ðŸ”¥ Reduce input size
    text = text[:800] if text else ""

    user_prompt = _build_user_prompt(text, metadata)
    
    user_prompt += """
IMPORTANT RULES:
- Payment unverified = HIGH RISK
- $0 spent = LOW TRUST
- Missing company info = SUSPICIOUS

STRICT INSTRUCTION:
If payment is unverified OR client has $0 spent,
DO NOT classify as LOW RISK under any condition.
"""

    # Restore full scout report inclusion
    user_prompt += f"\n\n--- SCOUT REPORT (Initial Findings) ---\n{json.dumps(scout_report)}"

    # ðŸš¨ Inject MASTER COMPANY VERIFICATION DATA
    if metadata and "verification" in metadata:
        v = metadata["verification"]
        user_prompt += f"""
--- MASTER COMPANY VERIFICATION ---
- Domain: {v.get('domain_status')}
- WHOIS: {v.get('whois_status')}
- Google Presence: {v.get('google_presence')}
- LinkedIn: {v.get('linkedin_status')}
- Social Media: {v.get('social_presence')}

RULE:
If company has no online presence (Google/Social/LinkedIn) â†’ increase risk significantly.
"""

    # ðŸš¨ Inject VERIFICATION DATA (Scores)
    if metadata:
        user_prompt += f"""
--- VERIFICATION DATA (Forensic Scores) ---
- Trust Score: {metadata.get('trust_score', 50)}/100
- Recruiter Risk: {metadata.get('recruiter_risk', 0)}/100
- Final Calculated Score: {metadata.get('final_score', 50)}/100
- Behavioral Signals: {metadata.get('signals', {})}

IMPORTANT INSTRUCTION:
Use these scores to justify your final verdict.
Do NOT contradict these signals (e.g., if Recruiter Risk is high, do not mark as Low Risk).
"""

    dynamic_fs = get_feedback_few_shots()
    sys_prompt_with_feedback = _SYSTEM_PROMPT + dynamic_fs

    try:
        full_response = ""

        completion = client.chat.completions.create(
            model="meta/llama-3.1-70b-instruct",
            messages=[
                {"role": "system", "content": sys_prompt_with_feedback},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.1,
            top_p=0.1,
            max_tokens=600,   # ðŸ”¥ reduced
            stream=True,
        )

        for chunk in completion:
            if chunk.choices and chunk.choices[0].delta.content:
                full_response += chunk.choices[0].delta.content

        # Extract JSON
        json_match = re.search(r'```(?:json)?\s*([\s\S]*?)```', full_response)
        if not json_match:
            json_match = re.search(r'\{[\s\S]*\}', full_response)

        if json_match:
            raw_json = json_match.group(1) if json_match.lastindex else json_match.group()
            result = json.loads(raw_json)
            result["engine"] = "Multi-Agent (Optimized 8B+70B)"
            return result

    except Exception as e:
        print(f"[Agent Forensic Lead Error] {e}")

    return None


# ===== LLM ANALYSIS CACHE =====
# Caches results by MD5 hash of input text â€” avoids repeat API calls, saves credits
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


# ===== OCR NORMALIZATION HELPERS =====
def _normalize_ocr_text(text: str) -> str:
    """Clean OCR noise: lowercase, remove spaces and non-alphanumeric chars."""
    if not text: return ""
    # Standardize common OCR errors
    text = text.lower()
    text = text.replace("$o", "$0").replace("o spent", "0 spent")
    # Strict alphanumeric cleaning
    return re.sub(r'[^a-z0-9]', '', text)


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

def _db_connect():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_scan_db():
    with _db_connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(100) UNIQUE,
                password VARCHAR(100)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                input_text TEXT,
                prediction VARCHAR(20),
                risk INTEGER
            )
        """)
        existing = {row["name"] for row in conn.execute("PRAGMA table_info(history)").fetchall()}
        for column, definition in {
            "confidence": "INTEGER DEFAULT 0",
            "category": "TEXT DEFAULT ''",
            "engine": "TEXT DEFAULT ''",
            "source": "TEXT DEFAULT 'text'",
            "created_at": "TEXT",
        }.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE history ADD COLUMN {column} {definition}")
        conn.commit()

def _db_user_id(username: str):
    with _db_connect() as conn:
        row = conn.execute("SELECT id FROM user WHERE lower(username) = lower(?)", (username,)).fetchone()
        if row:
            return row["id"]
        cur = conn.execute("INSERT INTO user (username, password) VALUES (?, ?)", (username, "flask-login-json-user"))
        conn.commit()
        return cur.lastrowid

def save_scan_to_db(username: str, entry: dict):
    try:
        init_scan_db()
        user_id = _db_user_id(username)
        with _db_connect() as conn:
            conn.execute("""
                INSERT INTO history
                    (user_id, input_text, prediction, risk, confidence, category, engine, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id,
                entry.get("input_text", ""),
                entry.get("prediction", "UNKNOWN"),
                int(entry.get("risk") or 0),
                int(entry.get("confidence") or 0),
                entry.get("category", ""),
                entry.get("engine", ""),
                entry.get("source", "text"),
                entry.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M"),
            ))
            conn.commit()
    except Exception as e:
        print(f"[SQLite History] Failed to save scan: {e}")

def migrate_json_history_to_db(username: str):
    """Backfill legacy JSON history into SQLite so dashboard analytics use real scans."""
    try:
        init_scan_db()
        user_id = _db_user_id(username)
        for item in load_history(username):
            timestamp = item.get("timestamp") or ""
            input_text = item.get("input_text", "")
            if not input_text or not timestamp:
                continue
            source = item.get("source")
            if not source:
                lowered = input_text.lower()
                source = "url" if lowered.startswith("protected platform url:") or "http" in lowered else "text"
            with _db_connect() as conn:
                exists = conn.execute("""
                    SELECT 1 FROM history
                    WHERE user_id = ? AND input_text = ? AND COALESCE(created_at, '') = ?
                    LIMIT 1
                """, (user_id, input_text, timestamp)).fetchone()
                if exists:
                    continue
                conn.execute("""
                    INSERT INTO history
                        (user_id, input_text, prediction, risk, confidence, category, engine, source, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user_id,
                    input_text,
                    item.get("prediction", "UNKNOWN"),
                    int(item.get("risk") or 0),
                    int(item.get("confidence") or 0),
                    item.get("category", ""),
                    item.get("engine", ""),
                    source,
                    timestamp,
                ))
                conn.commit()
    except Exception as e:
        print(f"[SQLite History] Legacy migration skipped: {e}")

def load_dashboard_stats(username: str) -> dict:
    init_scan_db()
    migrate_json_history_to_db(username)
    user_id = _db_user_id(username)
    with _db_connect() as conn:
        rows = conn.execute("""
            SELECT
                prediction,
                COALESCE(risk, 0) AS risk,
                COALESCE(confidence, 0) AS confidence,
                COALESCE(category, '') AS category,
                COALESCE(engine, '') AS engine,
                COALESCE(source, 'text') AS source,
                COALESCE(created_at, '') AS created_at,
                COALESCE(input_text, '') AS input_text
            FROM history
            WHERE user_id = ?
            ORDER BY datetime(created_at) DESC, id DESC
        """, (user_id,)).fetchall()

        scans_this_week = conn.execute("""
            SELECT COUNT(*) AS count
            FROM history
            WHERE user_id = ?
              AND date(COALESCE(created_at, 'now')) >= date('now', '-6 days')
        """, (user_id,)).fetchone()["count"]

        recent_detections = conn.execute("""
            SELECT COUNT(*) AS count
            FROM history
            WHERE user_id = ?
              AND upper(COALESCE(prediction, '')) IN ('FAKE', 'SUSPICIOUS')
              AND date(COALESCE(created_at, 'now')) >= date('now', '-6 days')
        """, (user_id,)).fetchone()["count"]

    total_scans = len(rows)
    predictions = [str(row["prediction"] or "UNKNOWN").upper() for row in rows]
    risks = [int(row["risk"] or 0) for row in rows]
    confidences = [int(row["confidence"] or 0) for row in rows if int(row["confidence"] or 0) > 0]
    dates = [(row["created_at"] or "").split(" ")[0] for row in rows if row["created_at"]]
    categories = [row["category"] or "Uncategorized" for row in rows]
    sources = [row["source"] or "text" for row in rows]

    risk_bands = {
        "Low (0-39)": sum(1 for r in risks if r < 40),
        "Medium (40-69)": sum(1 for r in risks if 40 <= r < 70),
        "High (70-100)": sum(1 for r in risks if r >= 70),
    }
    timeline_counts = Counter(dates)
    sorted_dates = sorted(timeline_counts.keys())[-14:]
    timeline_data = {date: timeline_counts[date] for date in sorted_dates}
    avg_risk_by_day = {
        date: round(sum(int(row["risk"] or 0) for row in rows if (row["created_at"] or "").startswith(date)) /
                    max(sum(1 for row in rows if (row["created_at"] or "").startswith(date)), 1), 1)
        for date in sorted_dates
    }

    return {
        "total_scans": total_scans,
        "safe_jobs": predictions.count("REAL"),
        "suspicious_jobs": predictions.count("SUSPICIOUS"),
        "fake_jobs": predictions.count("FAKE"),
        "avg_risk": round(sum(risks) / max(total_scans, 1), 1),
        "avg_confidence": round(sum(confidences) / max(len(confidences), 1), 1),
        "ocr_scans": sources.count("ocr"),
        "url_scans": sources.count("url") + sources.count("linkedin"),
        "scans_this_week": scans_this_week,
        "recent_detections": recent_detections,
        "risk_counts": dict(Counter(predictions)),
        "risk_bands": risk_bands,
        "category_counts": dict(Counter(categories).most_common(6)),
        "engine_counts": dict(Counter(row["engine"] or "Unknown" for row in rows)),
        "timeline_data": timeline_data,
        "avg_risk_by_day": avg_risk_by_day,
        "recent_activity": [
            {
                "prediction": row["prediction"],
                "risk": row["risk"],
                "source": row["source"],
                "created_at": row["created_at"],
                "input_text": (row["input_text"] or "")[:90],
            }
            for row in rows[:5]
        ],
    }

init_scan_db()

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

@login_manager.user_loader
def load_user(user_id):
    if user_exists(user_id):
        return User(user_id)
    return None


# =============================================================================
# GUARDRAIL PIPELINE â€” 5 Layers
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


# â”€â”€ LAYER 1: Input Validator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def _validate_input(text: str) -> tuple[bool, str]:
    """
    Returns (is_valid, rejection_reason).
    Runs entirely in-process â€” zero API calls.
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


# â”€â”€ LAYER 2: Task Classifier â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

    # â”€â”€ URL research â”€â”€
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
                note += " â†’ ðŸš¨ HIGH-RISK TLD (phishing indicator)"
            # Brand spoofing
            for brand in major_brands:
                if brand in domain and domain not in (f"{brand}.com", f"www.{brand}.com") \
                        and not domain.endswith(f".{brand}.com"):
                    note += f" â†’ âš ï¸ POTENTIAL {brand.upper()} DOMAIN SPOOF"
            # LinkedIn check
            if 'linkedin' in domain and 'linkedin.com' not in domain:
                note += " â†’ ðŸš¨ FAKE LINKEDIN DOMAIN"
            elif 'linkedin.com' in domain and '/jobs' not in url and '/in/' not in url:
                note += " â†’ âš ï¸ LinkedIn link but not a job posting â€” possible DM redirect"
            findings.append(note)
        except:
            continue

    # â”€â”€ Email research â”€â”€
    emails = re.findall(r'[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}', text)
    generic_providers = {
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
        'protonmail.com', 'aol.com', 'icloud.com', 'mail.com',
    }
    for email in emails[:3]:
        domain = email.split('@')[-1].lower()
        note = f"EMAIL: {email}"
        if domain in generic_providers:
            note += " â†’ âš ï¸ Generic provider (legitimate companies use corporate email)"
        for brand in major_brands:
            if brand in domain and domain not in (f"{brand}.com",):
                note += f" â†’ ðŸš¨ POTENTIAL {brand.upper()} EMAIL SPOOF"
        findings.append(note)

    if not findings:
        return ""
    return "--- AUTOMATED FORENSIC PRE-SCAN ---\n" + "\n".join(findings)


def check_domain(domain):
    """Perform a live check to see if a domain is active and reachable."""
    try:
        # Try https first
        response = requests.get(f"https://{domain}", timeout=5)
        if response.status_code == 200:
            return "valid"
    except:
        try:
            # Fallback to http
            response = requests.get(f"http://{domain}", timeout=5)
            if response.status_code == 200:
                return "valid"
        except:
            return "invalid"
    return "unknown"


def check_whois(domain):
    """Verify domain registration status via WHOIS."""
    try:
        data = whois.whois(domain)
        if data.creation_date:
            return "valid"
        return "suspicious"
    except:
        return "invalid"


def check_linkedin_company(text):
    """Simple check for a LinkedIn company profile presence in the text."""
    if "linkedin.com/company/" in text.lower():
        return "valid"
    return "missing"


def extract_company(text):
    """Attempt to extract a candidate company name from the text using robust patterns."""
    if not text: return "unknown"
    
    patterns = [
        r'(?:at|from)\s+([A-Z][a-zA-Z0-9& ]+)',
        r'([A-Z][a-zA-Z0-9& ]+)\s+(?:is hiring)'
    ]

    for p in patterns:
        match = re.search(p, text)
        if match:
            return match.group(1).strip()

    # fallback: email domain or URL domain
    email_match = re.search(r'[\w.+-]+@([\w.-]+\.[a-zA-Z]{2,})', text)
    if email_match:
        return email_match.group(1).split('.')[0]
        
    url_match = re.search(r'https?://(?:www\.)?([^/\s]+)', text)
    if url_match:
        return url_match.group(1).split('.')[0]

    return "unknown"


def google_search_company(company):
    """Use Google Custom Search API to verify company existence."""
    api_key = os.environ.get("GOOGLE_API_KEY")
    cx = os.environ.get("GOOGLE_CX")
    if not api_key or not cx:
        return "unknown"

    try:
        url = "https://www.googleapis.com/customsearch/v1"
        params = {
            "key": api_key,
            "cx": cx,
            "q": company,
            "num": 1
        }
        response = requests.get(url, params=params, timeout=5)
        data = response.json()
        
        if "items" in data:
            return "found"
        return "not_found"
    except Exception as e:
        print(f"[Google API Error] {e}")
        return "unknown"

def check_google_presence(company):
    """Bridge to the API-based Google search."""
    return google_search_company(company)


def _extract_domain(text):
    """Extract domain from URLs or Emails in the job text."""
    # Try URL first
    url_match = re.search(r'https?://(?:www\.)?([^/\s]+)', text)
    if url_match:
        return url_match.group(1).lower()
    
    # Try Email
    email_match = re.search(r'[\w.+-]+@([\w.-]+\.[a-zA-Z]{2,})', text)
    if email_match:
        return email_match.group(1).lower()
    
    return None


def check_domain_age(domain):
    """Fetch WHOIS data and compute domain age in days."""
    try:
        # Use a timeout if possible, but python-whois doesn't have a direct timeout param in some versions
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        if not creation_date:
            return "unknown"
        
        # creation_date can be a list or a single datetime object
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if not isinstance(creation_date, datetime):
            return "unknown"
            
        age_days = (datetime.now() - creation_date).days
        
        if age_days < 180:
            return "new"
        elif age_days <= 365:
            return "medium"
        else:
            return "old"
            
    except Exception as e:
        print(f"[WHOIS Error] {domain}: {e}")
        return "unknown"


def check_social_presence(text):
    """Scan for multiple social media footprints to gauge company establishment."""
    platforms = ["facebook.com", "twitter.com", "instagram.com", "linkedin.com"]
    
    found = []
    for p in platforms:
        if p in text.lower():
            found.append(p)

    if len(found) >= 2:
        return "strong"
    elif len(found) == 1:
        return "weak"
    return "none"


def verify_company_full(text):
    """MASTER COMPANY VERIFICATION ENGINE: Aggregates all forensic signals."""
    result = {
        "domain_status": "unknown",
        "whois_status": "unknown",
        "google_presence": "unknown",
        "linkedin_status": "missing",
        "social_presence": "none",
        "company_name": None,
        "domain_age": "unknown"
    }

    # Extract domain
    domain = _extract_domain(text)
    if domain:
        result["domain_status"] = check_domain(domain)
        result["whois_status"] = check_whois(domain)
        result["domain_age"] = check_domain_age(domain)

    # Identify company name
    company = extract_company(text)
    result["company_name"] = company

    if company and company != "unknown":
        result["google_presence"] = check_google_presence(company)

    result["linkedin_status"] = check_linkedin_company(text)
    result["social_presence"] = check_social_presence(text)

    return result


def calculate_trust_score(verification, text):
    """Calculate a weighted trust score (0-100) based on forensic evidence."""
    trust = 50

    if verification.get("google_presence") == "found":
        trust += 20
    elif verification.get("google_presence") == "not_found":
        trust -= 30

    domain_age = verification.get("domain_age", "unknown")
    if domain_age == "old":
        trust += 15
    elif domain_age == "new":
        trust -= 25

    # platform trusted
    if verification.get("linkedin_status") == "valid" or verification.get("social_presence") in ["strong", "weak"]:
        trust += 10
    
    # scam keywords
    text_lower = text.lower()
    scam_keywords = ["payment", "deposit", "urgent", "whatsapp", "telegram"]
    if any(k in text_lower for k in scam_keywords):
        trust -= 30

    return max(0, min(100, trust))


def analyze_recruiter_behavior(text):
    """Scan for behavioral red flags and social engineering tactics."""
    text_lower = text.lower()

    signals = {
        "uses_whatsapp": "whatsapp" in text_lower,
        "asks_payment": any(x in text_lower for x in ["payment", "fee", "deposit", "money", "registration"]),
        "urgent_language": any(x in text_lower for x in ["urgent", "immediate", "act now", "limited time"]),
        "no_company": "company" not in text_lower,
    }

    risk_boost = 0

    if signals["uses_whatsapp"]:
        risk_boost += 25
    if signals["asks_payment"]:
        risk_boost += 30
    if signals["urgent_language"]:
        risk_boost += 10
    if signals["no_company"]:
        risk_boost += 15

    return risk_boost, signals


def build_final_verdict(text, verification):
    """Combine trust scoring and behavioral analysis into a final verdict."""
    trust_score = calculate_trust_score(verification, text)
    recruiter_risk, signals = analyze_recruiter_behavior(text)
    detected_patterns = [k for k, v in signals.items() if v]
    
    # Adjust trust score based on behavioral risk
    final_trust = max(0, trust_score - recruiter_risk)
    
    reasons = [f"Detected known scam pattern: {p}" for p in detected_patterns]

    if final_trust < 30:
        prediction = "FAKE"
        category = "ðŸš¨ High Risk (Verified Scam Pattern)"
    elif final_trust <= 60:
        prediction = "SUSPICIOUS"
        category = "âš ï¸ Medium Risk (Suspicious Behavior)"
    else:
        prediction = "REAL"
        category = "âœ… Low Risk (Verified Employer)"

    # Generate a why_risky explanation based on signals
    why_risky_parts = []
    if recruiter_risk > 30:
        why_risky_parts.append(f"Multiple behavioral red flags were detected (Score: {recruiter_risk}). This indicates a pattern common in automated or low-effort scam campaigns.")
    if signals.get("off_platform"):
        why_risky_parts.append("The use of off-platform communication (Telegram/WhatsApp) is a critical indicator of identity theft and recruitment fraud, as it bypasses platform security monitors.")
    if signals.get("payment_request"):
        why_risky_parts.append("Requests for upfront payments, fees, or cryptocurrency are definitive markers of financial fraud. Legitimate employers never require payment for job applications or equipment.")
    if signals.get("urgency"):
        why_risky_parts.append("Artificial urgency ('Limited slots', 'Immediate hiring') is a social engineering tactic designed to rush victims into making mistakes.")
    
    why_risky_text = " ".join(why_risky_parts) if why_risky_parts else "No immediate behavioral scam patterns were definitively detected, but platform trust remains a key factor."

    return {
        "prediction": prediction,
        "trust_score": final_trust,
        "recruiter_risk": recruiter_risk,
        "final_score": final_trust,
        "signals": signals,
        "category": category,
        "fraud_risk_score": 100 - final_trust,
        "behavioral_reasons": reasons,
        "why_risky": why_risky_text
    }


def linkedin_like_verification(text):
    """Simulate professional trust signals typically found on LinkedIn-verified companies."""
    text_lower = text.lower()

    score = 0

    if "linkedin.com/company" in text_lower:
        score += 30

    if "verified company" in text_lower:
        score += 20

    if "employees" in text_lower:
        score += 10

    return score


# â”€â”€ LAYER 3: Strict LLM Prompt â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_FEW_SHOT_EXAMPLES = """--- FORENSIC EXAMPLES ---
Example 1 (High Risk):
Input: "Urgent hiring! No interview needed. Contact on Telegram @job_offer. Payment $50 for background check."
Output: {
  "prediction": "Fake",
  "confidence": "100%",
  "risk": 95,
  "category": "ðŸš¨ High Risk (Task Scam & Fee Fraud)",
  "reasons": ["Detected known scam pattern: Upfront payment request", "Detected known scam pattern: Off-platform contact (Telegram)", "Detected known scam pattern: Artificial urgency"],
  "why_risky": "This posting exhibits multiple high-confidence indicators of a 'Task Scam'. The request for an upfront fee for a background check is a classic financial fraud tactic, as legitimate employers cover these costs. Use of Telegram bypasses corporate communication standards to avoid traceability.",
  "final_advice": "DO NOT send money or share personal data. Block the contact immediately.",
  "fraud_risk_score": 95, "financial_trap_index": 90, "credibility_score": 5, "urgency_pressure_score": 85, "information_quality_score": 10
}

Example 2 (Low Risk):
Input: "Software Engineer at Google. Apply on google.jobs/careers. Requirements: CS degree, 3 years experience."
Output: {
  "prediction": "Real",
  "confidence": "95%",
  "risk": 10,
  "category": "âœ… Low Risk (Verified Corporate)",
  "reasons": ["Official career portal detected", "Standard professional requirements", "No social engineering triggers found"],
  "why_risky": "The posting links to an official, verified corporate domain and follows standard recruitment protocols without any pressure tactics or financial red flags.",
  "final_advice": "Safe to proceed through the official link provided.",
  "fraud_risk_score": 10, "financial_trap_index": 5, "credibility_score": 95, "urgency_pressure_score": 10, "information_quality_score": 90
}
"""

_SYSTEM_PROMPT = """Role: You are a Lead Fraud Detection Analyst specializing in job scams and recruitment fraud.

Your task is to analyze job postings deeply, identify scam patterns, and provide clear, forensic reasoning.

INSTRUCTIONS:
1.  **Analyze Content Deeply**: Look beyond the surface level. Check for linguistic anomalies, social engineering triggers, and infrastructure mismatches.
2.  **Identify Scam Patterns**: Look for 'Task Scams', 'Fee Fraud', 'Identity Harvesting', 'Ghost Companies', 'Payment Mismatches', etc.
3.  **Explain Reasoning Clearly**: Do not use generic statements. Explain *exactly why* a signal is suspicious.
4.  **Avoid Hallucination**: Do not invent company details. If a company is unknown, state it is 'Not found in official records'.
5.  **Highlight Suspicious Phrases**: Mention specific phrases from the text that triggered the flags.

--------------------------------------------------
STRICT PLATFORM RULES:
- If 'Payment unverified' or '$0 spent' is detected -> Minimum verdict = SUSPICIOUS.
- If off-platform chat (Telegram/WhatsApp) is found -> High Risk / FAKE.

--------------------------------------------------
OUTPUT FORMAT (STRICT JSON):
{{
  "prediction": "Real | Fake | Suspicious",
  "confidence": "0-100%",
  "risk": 0-100,
  "category": "Specific Risk Category",
  "reasons": ["Bullet points of key findings using format: 'Detected known scam pattern: <pattern>'"],
  "why_risky": "Deep, forensic explanation of the underlying risks. Link specific phrases to known scam types.",
  "final_advice": "Clear, actionable safety advice.",
  "fraud_risk_score": 0-100,
  "financial_trap_index": 0-100,
  "credibility_score": 0-100,
  "urgency_pressure_score": 0-100,
  "information_quality_score": 0-100,
  "consistency_check": "pass | fail",
  "evidence": ["List of forensic signals detected"]
}}"""

_ADAPTIVE_DEPTH = {
    "short":    "Rapid forensic triage: check for obvious red flags like off-platform chat and generic text.",
    "standard": "Linguistic and infrastructure analysis: evaluate pay/effort ratio and domain credibility.",
    "deep":     "Full behavioral forensic audit: analyze social engineering triggers, data contradictions, and 'Task Scam' markers.",
}


def _build_user_prompt(text: str, metadata: dict = None) -> str:
    words = len(text.split())
    mode  = "short" if words < 50 else ("standard" if words < 200 else "deep")
    depth = _ADAPTIVE_DEPTH[mode]
    
    # NEW: Perform URL/Domain Research
    research_data = _research_url_forensics(text)
    
    prompt = f"Mode: {mode.upper()} â€” {depth}\n"
    if research_data:
        prompt += f"{research_data}\n"
    
    if metadata:
        prompt += f"Context: Industry: {metadata.get('industry')}, Level: {metadata.get('level')}, Location: {metadata.get('location')}\n"
        if metadata.get("platform_risk_boost", 0) > 0:
            prompt += f"CRITICAL ALERT: Automated Pre-Scan detected Platform Metadata Risk: +{metadata.get('platform_risk_boost')} risk factor. Be extremely skeptical of company legitimacy.\n"
        if metadata.get("google_status") == "not_found":
            prompt += "CRITICAL: Company not found on Google. Treat as suspicious.\n"
        if metadata.get("domain_age") == "new":
            prompt += "CRITICAL: new domain -> high risk\n"

    prompt += f"\nJob posting:\n{text[:1500]}"
    
    return prompt


# â”€â”€ LAYER 4: Output Validator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
    
    required_keys = {"prediction", "confidence", "risk_level"}
    missing = required_keys - set(result.keys())
    if missing:
        print(f"[Validator] Missing keys: {missing}")
        return False
    
    if result.get("prediction").upper() not in {"REAL", "FAKE", "SUSPICIOUS"}:
        print(f"[Validator] Invalid prediction: {result.get('prediction')}")
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
    result.setdefault("why_risky",                  "Analysis complete. No critical behavioral anomalies definitively flagged, but exercise standard caution.")
    result.setdefault("category",                   "General")
    result.setdefault("validation_gates_passed", False)
    result.setdefault("failed_gates",            ["Missing mandatory validation audit."])
    
    # Resume Match Defaults
    result.setdefault("match_score", 0)
    result.setdefault("match_confidence", "Low")
    result.setdefault("key_matches", [])
    result.setdefault("key_gaps", [])
    result.setdefault("optimized_resume", None)
    result.setdefault("recommendations", [])

    # HARD VERDICT LOGIC ENFORCEMENT
    # Use fraud_risk_score if available, else fallback to risk
    score = result.get("fraud_risk_score", result.get("risk", 50))
    gates_passed = result.get("validation_gates_passed", False)
    
    # Harmonize prediction with the score
    if score >= 75:
        result["prediction"] = "FAKE"
    elif score >= 40:
        result["prediction"] = "SUSPICIOUS"
    elif score < 25 and gates_passed:
        result["prediction"] = "REAL"
    
    # Update verdict and category based on final prediction
    prediction = result["prediction"].upper()
    if prediction == "FAKE":
        result["verdict"] = "FAKE"
        result["category"] = "ðŸš¨ High Risk"
        result["risk"] = max(score, 75)
        result["optimized_resume"] = None # Never optimize for fake jobs
    elif prediction == "SUSPICIOUS":
        result["verdict"] = "SUSPICIOUS"
        result["category"] = "âš ï¸ Medium Risk"
        result["risk"] = max(score, 40)
    else:
        result["verdict"] = "REAL"
        result["category"] = "âœ… Low Risk"
        result["risk"] = min(score, 25)

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
        "âœ“ Do not proceed until company identity is verified.",
        "âœ“ Check if this job exists on official LinkedIn pages.",
    ])
    
    return result


# â”€â”€ LAYER 5: Multi-Agent Collaborative Call â”€â”€
def _call_llm(client, text: str, metadata: dict = None, retries: int = 1) -> dict | None:
    for attempt in range(retries + 1):
        try:
            # Rate Limit Protection
            import time
            time.sleep(1)
            
            # Step 1: Agent 1 (8B) performs Scout Scan
            scout_report = _agent_fast_scan(client, text, metadata)
            
            # Step 2: Agent 2 (70B) performs Lead Analysis ONLY if risk is not already clear
            if scout_report.get("initial_risk", 50) < 70:
                final_result = _agent_forensic_analysis(client, text, scout_report, metadata)
            else:
                # ðŸ”¥ Skip 70B (high risk already clear)
                print("[Pipeline] Short-circuiting to 8B decision (High Risk detected).")
                final_result = {
                    "prediction": "FAKE",
                    "confidence": 90,
                    "fraud_risk_score": scout_report.get("initial_risk", 80),
                    "reasons": scout_report.get("red_flags", []),
                    "engine": "8B-fast-decision",
                    "final_advice": "Immediate security risk detected. Avoid all contact.",
                    "match_score": 0,
                    "optimized_resume": None
                }
            
            if final_result:
                # Merge Scout report for UI display
                final_result["scout_summary"] = scout_report.get("scout_summary", "High risk scout scan.")
                final_result["initial_risk"] = scout_report.get("initial_risk", 70)
                final_result["initial_match"] = scout_report.get("initial_match", 0)

                # Merge logic: if Scout found massive risk but Lead missed it, flag it
                if scout_report.get("initial_risk", 0) > 80 and final_result.get("fraud_risk_score", 0) < 50:
                    final_result["fraud_risk_score"] = max(final_result.get("fraud_risk_score", 0), 60)
                    if "reasons" in final_result:
                        final_result["reasons"].append("ðŸš¨ Discrepancy Alert: Scout Agent detected high immediate risk.")
                
                # Standardize Metrics
                for metric in ["fraud_risk_score", "financial_trap_index", "credibility_score", "urgency_pressure_score", "information_quality_score", "confidence", "match_score"]:
                    if metric in final_result:
                        try:
                            val = str(final_result[metric]).replace("%", "")
                            final_result[metric] = int(float(val))
                        except:
                            final_result[metric] = 50
                
                return _fill_defaults(final_result)
        except Exception as e:
            print(f"[Multi-Agent Logic Error] attempt {attempt+1}: {e}")

    return None


# =============================================================================
# PUBLIC ENTRY POINT - Full Guardrail Pipeline
# =============================================================================
def analyze_job_description(text: str, metadata: dict = None) -> dict:
    """
    Full 5-layer analysis pipeline:
      L1: Input Validator - rejects empty/gibberish/non-text inputs
      L2: Task Classifier - rejects non-job-related text without API call
      L3: Strict LLM Prompt - model self-rejects unclear inputs
      L4: Output Validator - discards malformed LLM responses
      L5: Token Optimiser - max_tokens=1500, text capped at 1500 chars
    """

    # â”€â”€ L1: Validate input ----------------------------------------------------
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
            "category": "âŒ Invalid Input",
            "fraud_risk_score": 0, "financial_trap_index": 0,
            "credibility_score": 0, "urgency_pressure_score": 0,
            "information_quality_score": 0,
            "reasons": [reason_map.get(rejection_reason, "Invalid input.")],
            "suggestions": [
                "âœ“ Paste the full text of the job posting.",
                "âœ“ Or enter the job URL to have it scraped automatically.",
                "âœ“ Or upload a screenshot of the job ad.",
            ],
            "engine": "Validator",
        }

    # -- Cache Check (Temporarily Disabled for Debugging & Guardrail Enforcement) ---
    # if len(text) < 500:
    #     cached = _get_cached(text)
    #     if cached:
    #         print("[Cache] Returning cached result for short description.")
    #         return cached
    # else:
    #     cached = None
    cached = None

    # -- OCR NORMALIZATION & DEBUG LOGGING --
    text_clean = _normalize_ocr_text(text)
    print(f"\n[DEBUG] Original Text (first 100 chars): {text[:100]}")
    print(f"[DEBUG] Normalized Text (first 100 chars): {text_clean[:100]}")

    # â”€â”€ Instant Kill Rule (High Certainty Scams) â”€â”€
    text_lower = text.lower()
    
    # â”€â”€ MANDATORY PRE-LLM GUARDRAIL (HARD ENFORCEMENT) â”€â”€
    if "paymentunverified" in text_clean or "0spent" in text_clean or "paymentunveritied" in text_clean:
        print("[Guardrail] Instant Kill: Platform Trust Failure detected in Normalized Text.")
        
        # Default to SUSPICIOUS
        prediction = "SUSPICIOUS"
        category = "âš ï¸ Medium Risk (Platform Trust Failure)"
        risk_score = 75
        confidence = 85
        
        # ðŸ”¥ CRITICAL: Double Failure = FAKE
        if ("paymentunverified" in text_clean or "paymentunveritied" in text_clean) and "0spent" in text_clean:
            prediction = "FAKE"
            category = "ðŸš¨ High Risk (Verified Scam Pattern)"
            risk_score = 90
            confidence = 95

        return {
            "prediction": prediction,
            "confidence": confidence,
            "risk": risk_score,
            "category": category,
            "fraud_risk_score": risk_score,
            "financial_trap_index": 70 if prediction == "SUSPICIOUS" else 85,
            "credibility_score": 30 if prediction == "SUSPICIOUS" else 10,
            "urgency_pressure_score": 40 if prediction == "SUSPICIOUS" else 70,
            "information_quality_score": 40 if prediction == "SUSPICIOUS" else 20,
            "reasons": [
                "Payment unverified detected",
                "Client has no spending history",
                "Platform trust is low"
            ],
            "suggestions": [
                "Avoid applying without verifying client",
                "Check if company exists on LinkedIn",
                "Do not share personal or financial details",
                "Proceed only with verified clients"
            ],
            "engine": "Pre-Guardrail"
        }

    # â”€â”€ COMPANY VERIFICATION GUARDRAIL (FULL FORENSICS) â”€â”€
    verification = verify_company_full(text)
    
    # ðŸš¨ FAKE DOMAIN (WHOIS INVALID)
    if verification["whois_status"] == "invalid":
        print(f"[Guardrail] WHOIS Check Failed: {verification['whois_status']}")
        return {
            "prediction": "FAKE",
            "confidence": 95,
            "risk": 90,
            "category": "ðŸš¨ Fake Domain",
            "fraud_risk_score": 90,
            "financial_trap_index": 85,
            "credibility_score": 5,
            "reasons": ["ðŸš¨ High-risk signal: The domain does not have a valid WHOIS registration or is invalid."],
            "suggestions": ["Avoid applying immediately. This domain appears to be spoofed or a burner site."],
            "engine": "WHOIS-Guardrail"
        }

    # === GOOGLE SEARCH INTEGRATION ===
    if metadata is None: metadata = {}
    google_status = verification.get("google_presence", "unknown")
    
    # Guardrail: If company name is too short, treat a 'found' result as unknown
    # (prevents false positives for generic single-letter/short strings)
    company_name = verification.get("company_name", "")
    if google_status == "found" and company_name and len(str(company_name)) < 3:
        google_status = "unknown"

    metadata["google_status"] = google_status
    print("Google Status:", google_status)

    # === DOMAIN FORENSICS (Requirement 4 & 8) ===
    domain = _extract_domain(text)
    print("Domain:", domain)
    domain_age = "unknown"
    if domain:
        domain_age = check_domain_age(domain)
    
    metadata["domain_age"] = domain_age
    print("Domain Age:", domain_age)

    reasons = []
    suggestions = []

    if google_status == "not_found":
        # Requirement 3: Increase fraud_risk_score by +30 (max 100)
        risk_boost_val = 30
        reasons.append("Company not found on Google (low legitimacy)")
        # Note: prediction downgrade and risk boost applied in common flow below
    elif google_status == "found":
        # Requirement 3: Increase credibility_score by +20 (max 100)
        metadata["credibility_boost"] = 20

    # ðŸš¨ NO SOCIAL SIGNAL
    if verification["social_presence"] == "none":
        print("âš ï¸ No social media presence detected in job text.")

    if verification["linkedin_status"] == "missing":
        print("âš ï¸ No LinkedIn company profile found in job text.")

    # â”€â”€ CALCULATE FINAL TRUST METRICS â”€â”€
    final_verdict_data = build_final_verdict(text, verification)

    if "whatsapp" in text_lower and ("payment" in text_lower or "money" in text_lower or "registration" in text_lower):
        print("[Guardrail] Instant Kill: Found WhatsApp + Payment/Money signal.")
        return {
            "prediction": "FAKE",
            "confidence": 100,
            "fraud_risk_score": 100,
            "reasons": ["ðŸš¨ High-certainty scam pattern: Found off-platform contact (WhatsApp) combined with financial requests."],
            "verdict": "FAKE",
            "category": "ðŸš¨ Critical Risk",
            "risk": 100,
            "engine": "Static-Guardrail",
            "final_advice": "CRITICAL: This is a verified scam pattern. Do not share any data.",
            "match_score": 0,
            "optimized_resume": None
        }

    # â”€â”€ Platform Metadata Risk Boost â”€â”€
    risk_boost = 0
    if "payment unverified" in text_lower: risk_boost += 30
    if "$0 spent" in text_lower: risk_boost += 25
    if "no reviews" in text_lower: risk_boost += 15
    if google_status == "not_found": 
        risk_boost += 30
        if "company" in text_lower:
            risk_boost += 10
    
    if metadata is None: metadata = {}
    metadata["platform_risk_boost"] = risk_boost
    metadata["trust_score"] = final_verdict_data["trust_score"]
    metadata["recruiter_risk"] = final_verdict_data["recruiter_risk"]
    metadata["final_score"] = final_verdict_data["final_score"]
    metadata["signals"] = final_verdict_data["signals"]
    
    if risk_boost > 0:
        print(f"[Guardrail] Risk Boost applied: +{risk_boost} based on platform metadata.")

    # â”€â”€ L2: Classify task â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    task_class = _classify_task(text)
    if task_class == "invalid":
        print(f"[L2-Classifier] Rejected: not a job posting")
        return {
            "prediction": "INVALID",
            "confidence": 0, "risk": 0,
            "category": "âŒ Not a Job Posting",
            "fraud_risk_score": 0, "financial_trap_index": 0,
            "credibility_score": 0, "urgency_pressure_score": 0,
            "information_quality_score": 0,
            "reasons": [
                "âš ï¸ This text does not appear to be a job posting.",
                "âš ï¸ No job-related keywords were found (e.g., hiring, salary, position, role).",
            ],
            "suggestions": [
                "âœ“ Paste a real job advertisement to get an analysis.",
                "âœ“ Include details like role, salary, company, and requirements.",
            ],
            "engine": "Classifier",
        }

    # â”€â”€ L3 + L4 + L5: LLM call with strict prompt + output validation â”€â”€â”€â”€â”€â”€â”€â”€â”€
    client = get_nvidia_client()
    if client:
        # Pass verification data inside metadata
        if metadata is None: metadata = {}
        metadata["verification"] = verification
        
        llm_result = _call_llm(client, text, metadata)
        if llm_result:
            # â”€â”€ Post-LLM Hard Guardrail â”€â”€
            # If LLM says REAL but text has massive red flags, downgrade to SUSPICIOUS
            prediction = llm_result.get("prediction", "SUSPICIOUS").upper()
            text_lower = text.lower()
            critical_flags = ["whatsapp", "telegram", "no interview", "no experience", "immediate start", "registration fee"]
            if prediction == "REAL" and any(flag in text_lower for flag in critical_flags):
                print(f"[Guardrail] Downgrading REAL to SUSPICIOUS due to red flags in text.")
                llm_result["prediction"] = "SUSPICIOUS"
                llm_result["verdict"] = "SUSPICIOUS"
                llm_result["category"] = "âš ï¸ Medium Risk (Flagged by Guardrail)"
                llm_result["risk"] = max(llm_result.get("risk", 0), 45)
                llm_result["reasons"].append("âš ï¸ Automatic Guardrail: Found high-risk phrases in a 'Real' prediction.")
            
            # â”€â”€ HARD PLATFORM ENFORCEMENT (CRITICAL FIX) â”€â”€
            text_lower = text.lower()
            if "payment unverified" in text_lower or "$0 spent" in text_lower:
                print("[CRITICAL GUARDRAIL] Enforcing HIGH RISK due to platform signals")

                # Default to SUSPICIOUS for single failure
                llm_result["prediction"] = "SUSPICIOUS"
                llm_result["verdict"] = "SUSPICIOUS"
                llm_result["category"] = "âš ï¸ Medium Risk (Platform Trust Failure)"
                llm_result["fraud_risk_score"] = max(llm_result.get("fraud_risk_score", 50), 70)

                # ðŸ”¥ CRITICAL: Double Failure = FAKE
                if ("payment unverified" in text_lower and "$0 spent" in text_lower) or \
                   ("paymentunverified" in text_clean and "0spent" in text_clean):
                    llm_result["prediction"] = "FAKE"
                    llm_result["category"] = "ðŸš¨ High Risk (Verified Scam Pattern)"
                    llm_result["fraud_risk_score"] = 85

                llm_result["risk"] = llm_result["fraud_risk_score"]

                # Add reason if missing
                reason_text = "âš ï¸ Platform Risk: Payment unverified / $0 spent detected"
                if "reasons" in llm_result:
                    llm_result["reasons"].append(reason_text)
                else:
                    llm_result["reasons"] = [reason_text]
            
            print(f"[Pipeline] LLM result: {llm_result.get('prediction')} / match_score={llm_result.get('match_score')}")
            
            # Cache the result if short
            if len(text) < 500:
                _set_cache(text, llm_result)
                
            return llm_result
        print("[Pipeline] LLM returned None â€” falling back to rule-based.")

    # â”€â”€ Fallback: rule-based â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    result = _rule_based_analyze(text)
    result["engine"] = "Rule-based"
    
    # Cache the result if short
    if len(text) < 500:
        _set_cache(text, result)

    # â”€â”€ Apply Google-based Enhancements to Final Result â”€â”€
    final_result = llm_result if llm_result else result
    
    # Apply Reasons and Suggestions
    if reasons:
        final_result.setdefault("reasons", []).extend(reasons)
    if suggestions:
        final_result.setdefault("suggestions", []).extend(suggestions)
        
    # Apply Google-specific logic (Requirement 3)
    if google_status == "not_found":
        boost = 30
        # stronger penalty if company explicitly mentioned
        if "company" in text.lower():
            boost += 10

        final_result["fraud_risk_score"] = min(final_result.get("fraud_risk_score", 50) + boost, 100)
        final_result["risk"] = final_result["fraud_risk_score"]
        
        # Downgrade REAL to SUSPICIOUS if company not found
        if final_result.get("prediction") == "REAL" and verification.get("company_name"):
            final_result["prediction"] = "SUSPICIOUS"
            final_result["category"] = "âš ï¸ Medium Risk (Unverified Company)"
            
        final_result.setdefault("reasons", []).append("Company could not be verified online despite normal job description")
            
    elif google_status == "found":
        final_result["credibility_score"] = min(final_result.get("credibility_score", 50) + 20, 100)
        
    elif google_status == "unknown":
        print("[Google] Skipping scoring due to API failure or indeterminate search result.")

    # === Apply WHOIS scoring (Requirement 5) ===
    domain_age = metadata.get("domain_age", "unknown")
    if domain_age == "new":
        final_result["fraud_risk_score"] = min(final_result.get("fraud_risk_score", 50) + 25, 100)
        final_result["risk"] = final_result["fraud_risk_score"]
        final_result.setdefault("reasons", []).append("âš ï¸ New domain detected (possible scam)")
        final_result["urgency_pressure_score"] = min(final_result.get("urgency_pressure_score", 30) + 10, 100)
        
    elif domain_age == "medium":
        final_result["fraud_risk_score"] = min(final_result.get("fraud_risk_score", 50) + 10, 100)
        final_result["risk"] = final_result["fraud_risk_score"]
        
    elif domain_age == "old":
        final_result["credibility_score"] = min(final_result.get("credibility_score", 50) + 15, 100)

    # === Stronger Multi-Signal Logic (Requirement 6) ===
    if domain_age == "new" and google_status == "not_found":
        final_result["prediction"] = "FAKE"
        final_result["category"] = "ðŸš¨ High Risk (Verified Scam Pattern)"
        final_result["fraud_risk_score"] = max(final_result.get("fraud_risk_score", 0), 92)
        final_result["risk"] = final_result["fraud_risk_score"]
        final_result.setdefault("reasons", []).append("ðŸš¨ Critical signal: New domain + no Google presence (high scam probability)")

    final_result["trust_score"] = metadata.get("trust_score", 50)
    final_result["domain_age"] = metadata.get("domain_age", "unknown")

    if metadata.get("source") == "linkedin":
        final_result.setdefault("reasons", []).append("Source verified: LinkedIn job platform")
        # Only boost if no strong scam signals
        if final_result.get("fraud_risk_score", 50) < 50:
            final_result["credibility_score"] = min(final_result.get("credibility_score", 50) + 10, 100)
        else:
            # Reduce blind trust if risk already high
            final_result["credibility_score"] = min(final_result.get("credibility_score", 50) + 3, 100)

    def dedupe_list(items):
        seen = set()
        return [x for x in items if not (x in seen or seen.add(x))]

    if "reasons" in final_result and isinstance(final_result["reasons"], list):
        final_result["reasons"] = dedupe_list(final_result["reasons"])

    return final_result


# â”€â”€ Rule-based analyser (fallback only) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def analyze_job_with_llm(text: str) -> dict:
    """Alias kept for backward compatibility."""
    return analyze_job_description(text)


def _rule_based_analyze(text: str) -> dict:
    """Keyword-weighted rule-based fallback - used when LLM is unavailable."""
    if not text or len(text.strip()) < 10:
        return {
            "prediction": "INVALID", "confidence": 0, "risk": 0,
            "category": "âŒ Invalid Input",
            "fraud_risk_score": 0, "financial_trap_index": 0,
            "credibility_score": 0, "urgency_pressure_score": 0,
            "information_quality_score": 0,
            "reasons": ["Job description is too short to analyze."],
            "suggestions": ["Please provide a detailed job description."],
            "engine": "Rule-based",
        }

    risk_boost, signals = analyze_recruiter_behavior(text)
    detected_patterns = [k for k, v in signals.items() if v]
    
    # Calculate base risk from length and content
    base_risk = 30
    if len(text.split()) < 50:
        base_risk += 15
        
    final_risk = min(100, base_risk + risk_boost)
    reasons = [f"Detected known scam pattern: {p}" for p in detected_patterns]
    
    if final_risk > 65:
        prediction = "FAKE"
        category = "ðŸš¨ High Risk"
    elif final_risk > 40:
        prediction = "SUSPICIOUS"
        category = "âš ï¸ Medium Risk"
    else:
        prediction = "REAL"
        category = "âœ… Low Risk"

    return {
        "prediction": prediction, 
        "confidence": 85 if len(detected_patterns) >= 2 else 60,
        "risk": final_risk, 
        "category": category,
        "fraud_risk_score": final_risk,
        "reasons": reasons if reasons else ["âœ“ No obvious fraud patterns detected."],
        "suggestions": [
            "âœ“ Verify company information independently.",
            "âœ“ Check official company website and LinkedIn.",
            "âœ“ Be cautious of requests for upfront payments.",
        ],
        "engine": "Rule-based",
    }

def is_valid_job_text(text):
    text_lower = text.lower()

    # Reject blocked pages
    blocked = ["captcha", "login", "sign in", "security check"]
    if any(b in text_lower for b in blocked):
        return False

    # Must contain job-related words
    keywords = [
        "job", "role", "salary", "experience",
        "requirements", "responsibilities", "apply"
    ]

    hits = sum(1 for k in keywords if k in text_lower)

    return hits >= 2 and len(text) > 300




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
        print("="*60)
        print("[POST] Form submitted")
        print(f"[POST] FILES: {request.files}")
        print(f"[POST] FORM KEYS: {list(request.form.keys())}")
        job_input = request.form.get("job_input", "").strip()
        print(f"[POST] job_input length: {len(job_input)}")
        
        # Optional Metadata
        metadata = {
            "industry": request.form.get("industry", "").strip(),
            "level": request.form.get("level", "").strip(),
            "location": request.form.get("location", "").strip(),
        }

        job_image = request.files.get("job_image")
        scan_source = "text"
        print(f"[POST] job_image: {job_image}")
        print(f"[POST] job_image.filename: {job_image.filename if job_image else 'None'}")

        if job_image and job_image.filename:
            try:
                filename, upload_error = validate_image_upload(job_image)
                if upload_error:
                    raise ValueError(upload_error)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                print(f"[IMAGE] Saving to: {filepath}")
                job_image.save(filepath)
                print(f"[IMAGE] Saved successfully. File size: {os.path.getsize(filepath)} bytes")
                
                # Provide the original image to be displayed in the results unconditionally
                processed_image_url = url_for("uploaded_file", filename=filename)
                
                print("[IMAGE] Starting OCR extraction...")
                extracted = extract_text_from_image(filepath)
                print(f"[IMAGE] OCR result: {'SUCCESS - ' + str(len(extracted)) + ' chars' if extracted else 'FAILED (None)'}")
                if extracted:
                    job_input = extracted
                    scan_source = "ocr"
                    print(f"[IMAGE] Using extracted text as job_input ({len(job_input)} chars)")

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
                    print("[IMAGE] OCR returned no text")
                    if not job_input: # Only show error if no text was provided at all
                        error = "Could not extract text from image. Please paste text instead."
                        print(f"[IMAGE] Setting error: {error}")
            except ValueError as e:
                error = str(e)
                print(f"[IMAGE] VALIDATION ERROR: {error}")
            except Exception as e:
                error = f"Error processing image: {str(e)}"
                print(f"[IMAGE] EXCEPTION: {error}")

        is_protected_url = False
        if job_input:
            if job_input.startswith("http://") or job_input.startswith("https://"):
                url_lower = job_input.lower()
                protected_platforms = ["linkedin.com", "indeed.com", "glassdoor.com"]
                if any(plat in url_lower for plat in protected_platforms):
                    print("Protected Platform Detected:", job_input)
                    
                    fallback_result = {
                        "prediction": "SUSPICIOUS",
                        "confidence": 60,
                        "risk": 30,
                        "category": "âš ï¸ Limited Analysis (Protected Platform)",
                        "fraud_risk_score": 30,
                        "reasons": [
                            "This platform blocks automated scraping",
                            "Unable to extract full job content"
                        ],
                        "suggestions": [
                            "Copy and paste the full job description for accurate analysis",
                            "Avoid relying only on URL-based scans"
                        ],
                        "engine": "Platform-Guard"
                    }

                    if "linkedin.com" in url_lower:
                        try:
                            scraped_url = job_input
                            text = scrape_url_text(job_input)
                            if is_valid_job_text(text):
                                print("[LinkedIn] Valid job content extracted")
                                job_input = text
                                metadata["source"] = "linkedin"
                                scan_source = "linkedin"
                            else:
                                raise Exception("Invalid LinkedIn content")
                        except Exception as e:
                            is_protected_url = True
                            scraped_url = job_input
                            job_input = "Protected Platform URL: " + job_input
                            scan_source = "linkedin"
                            result = fallback_result
                    else:
                        is_protected_url = True
                        scraped_url = job_input
                        job_input = "Protected Platform URL: " + job_input
                        scan_source = "url"
                        result = fallback_result
                else:
                    try:
                        scraped_url = job_input
                        job_input = scrape_url_text(job_input)
                        scan_source = "url"
                    except Exception as e:
                        error = str(e)
                        job_input = None # Stop analysis if scraping failed (e.g. LinkedIn Security Check)

        if job_input:
            if is_protected_url:
                pass # result is already populated with the protected platform response
            else:
                # Bypass cache for URLs to ensure deep, fresh analysis every time
                cached = _get_cached(job_input) if not scraped_url else None
                if cached:
                    result = cached
                else:
                    result = analyze_job_description(job_input, metadata)
                    # Only cache valid analyses â€” never cache INVALID or URL-based responses
                    if result.get("prediction") != "INVALID" and not scraped_url:
                        _set_cache(job_input, result)
                result = polish_analysis_result(result)

            prediction  = result.get("prediction")
            confidence  = result.get("confidence", 50)
            risk        = result.get("risk", 50)
            category    = result.get("category", "Unknown")
            reasons     = result.get("reasons", [])
            suggestions = result.get("suggestions", [])
            engine      = result.get("engine", "LLM" if get_nvidia_client() else "Rule-based")

            # â”€â”€ Guardrail: show INVALID as a user-facing error, not a result page â”€â”€
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

                keywords_to_highlight = [
                    "upfront", "bitcoin", "western union", "wire transfer", "gift card",
                    "urgent", "immediate", "immediate start", "no interview", "no experience",
                    "guaranteed income", "quick money", "easy money", "risk-free",
                    "itunes card", "no cv needed", "act now", "don't delay", "limited time",
                    "whatsapp", "telegram", "cash app", "venmo", "paypal", "crypto",
                    "security deposit", "starter kit", "equipment fee", "reshipping"
                ]
                highlighted_text = sanitize_highlighted_text(job_input, keywords_to_highlight)

                # Persist history â€” only for valid FAKE/SUSPICIOUS/REAL results
                history = load_history(current_user.username)
                history_entry = {
                    "input_text": job_input[:120] + ("..." if len(job_input) > 120 else ""),
                    "prediction": prediction, "confidence": confidence,
                    "risk": risk, "category": category, "engine": engine,
                    "source": scan_source,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M")
                }
                history.insert(0, history_entry)
                save_history(current_user.username, history)
                save_scan_to_db(current_user.username, history_entry)
        elif request.method == "POST" and not error:
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
        why_risky=result.get('why_risky', ''),
        company_analysis=result.get('company_analysis'),
        contact_verification=result.get('contact_verification'),
        # Original input text
        original_text=job_input if request.method == "POST" else "",
        # Multi-Agent Visibility
        scout_summary=result.get('scout_summary'),
        initial_risk=result.get('initial_risk'),
        final_advice=result.get('final_advice', ''),
        validation_gates_passed=result.get('validation_gates_passed'),
        failed_gates=result.get('failed_gates', []),
        trust_score=result.get('trust_score', 50)
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

# âœ… BUG FIX: redirect to /login (not /home which needs auth)
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
    """Aggregated forensics statistics from SQLite scan history."""
    stats = load_dashboard_stats(current_user.username)
    return render_template("dashboard.html", stats=stats)


# ===== CHROME EXTENSION API ENDPOINT =====
@app.route("/api/analyze", methods=["POST"])
@limiter.limit("20 per minute")
def api_analyze():
    """API endpoint for the Chrome extension to submit job text for analysis."""
    from flask import jsonify

    try:
        data = request.get_json() or {}
        text = data.get("text", "").strip()
        
        if not text:
            return jsonify({"error": "No job text provided. Please try again."}), 400

        metadata = {"source": "linkedin_extension"}

        result = polish_analysis_result(analyze_job_description(text, metadata=metadata))
        
        # Override engine for clarity
        result["engine"] = "Extension + AI Pipeline"
        
        return jsonify(result)

    except Exception as e:
        print(f"[API Error] {e}")
        return jsonify({"error": "Analysis failed", "details": str(e)}), 500


# ===== NEXT.JS FRONTEND JSON API ENDPOINTS =====

@app.route("/api/history", methods=["GET"])
@login_required
def api_history():
    """Return current user's scan history as JSON for the Next.js frontend."""
    from flask import jsonify
    data = load_history(current_user.username)
    return jsonify(data)


@app.route("/api/stats", methods=["GET"])
@login_required
def api_stats():
    """Return aggregated stats as JSON from SQLite scan history."""
    from flask import jsonify
    return jsonify(load_dashboard_stats(current_user.username))



if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
