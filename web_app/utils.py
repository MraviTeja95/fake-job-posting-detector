import importlib.util
import os
import re
from uuid import uuid4

from markupsafe import Markup, escape
from werkzeug.utils import secure_filename


ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
ALLOWED_IMAGE_MIMES = {"image/png", "image/jpeg", "image/webp"}
MAX_IMAGE_BYTES = 8 * 1024 * 1024


class NoopLimiter:
    def limit(self, _rule):
        def decorator(func):
            return func

        return decorator


def configure_limiter(app):
    try:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address

        return Limiter(key_func=get_remote_address, app=app, default_limits=[])
    except Exception as exc:
        app.logger.warning("Flask-Limiter unavailable; /api/analyze rate limiting disabled: %s", exc)
        return NoopLimiter()


def startup_validation(app):
    optional = ["easyocr", "PIL", "pytesseract", "flask_limiter"]
    missing = [pkg for pkg in optional if importlib.util.find_spec(pkg) is None]
    if missing:
        app.logger.warning("Optional dependency check: missing %s", ", ".join(missing))
    return missing


def validate_image_upload(file_storage):
    if not file_storage or not file_storage.filename:
        return None, None

    raw_name = secure_filename(file_storage.filename)
    ext = raw_name.rsplit(".", 1)[-1].lower() if "." in raw_name else ""
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        return None, "Only PNG, JPG, JPEG, and WEBP screenshots are supported."

    mime = (file_storage.mimetype or "").lower()
    if mime and mime not in ALLOWED_IMAGE_MIMES:
        return None, "Uploaded file does not look like a supported image."

    stream = file_storage.stream
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    stream.seek(0)
    if size <= 0:
        return None, "Uploaded image is empty."
    if size > MAX_IMAGE_BYTES:
        return None, "Image is too large. Please upload a screenshot under 8 MB."

    return f"{uuid4().hex}.{ext}", None


def sanitize_highlighted_text(text, keywords):
    safe_text = escape(text or "")
    for keyword in keywords:
        pattern = re.compile(re.escape(keyword), re.IGNORECASE)
        safe_text = Markup(
            pattern.sub(
                lambda match: (
                    '<mark class="highlight danger">'
                    f"{escape(match.group(0))}"
                    "</mark>"
                ),
                str(safe_text),
            )
        )
    return safe_text
