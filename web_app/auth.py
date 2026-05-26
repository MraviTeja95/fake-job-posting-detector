import json
import os

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash


USERS_FILE = None
_USER_CACHE = None


def configure_auth_storage(users_file: str):
    global USERS_FILE
    USERS_FILE = users_file


def load_users():
    global _USER_CACHE
    if _USER_CACHE is not None:
        return _USER_CACHE

    if USERS_FILE and os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                _USER_CACHE = json.load(f)
                return _USER_CACHE
        except Exception:
            pass
    _USER_CACHE = {}
    return _USER_CACHE


def save_users(users):
    global _USER_CACHE
    _USER_CACHE = users
    if not USERS_FILE:
        raise RuntimeError("Auth storage is not configured.")
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


def user_exists(username):
    return username in load_users()


def register_user(username, password):
    if user_exists(username):
        return False
    users = load_users()
    users[username] = generate_password_hash(password)
    save_users(users)
    return True


def verify_user(username, password):
    users = load_users()
    if username not in users:
        return False
    return check_password_hash(users[username], password)


class User(UserMixin):
    def __init__(self, id):
        self.id = id
        self.username = id
