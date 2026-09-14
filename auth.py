import os
from datetime import datetime, timedelta, timezone
from functools import wraps

from dotenv import load_dotenv
from flask import jsonify, request
from jose import JWTError, jwt
from werkzeug.security import check_password_hash, generate_password_hash

from database import create_user, get_user_by_email, get_user_by_id

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET", "")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))


def _require_secret():
    if not JWT_SECRET:
        raise RuntimeError(
            "JWT_SECRET is not configured. Add a strong JWT_SECRET to your .env file."
        )


def create_access_token(user_id):
    _require_secret()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": expires,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


def decode_access_token(token):
    _require_secret()
    payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    user_id = payload.get("sub")
    if not user_id:
        raise JWTError("Missing subject")
    return int(user_id)


def register_user(email, password):
    email = email.strip().lower()
    password_hash = generate_password_hash(password)
    return create_user(email, password_hash)


def authenticate_user(email, password):
    user = get_user_by_email(email.strip().lower())
    if not user:
        return None
    if not check_password_hash(user["password_hash"], password):
        return None
    return user


def token_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({
                "success": False,
                "error": "Authentication required. Use Authorization: Bearer <token>.",
            }), 401

        token = header.split(" ", 1)[1].strip()
        if not token:
            return jsonify({
                "success": False,
                "error": "Bearer token is missing.",
            }), 401

        try:
            user_id = decode_access_token(token)
            user = get_user_by_id(user_id)
            if not user:
                raise JWTError("User not found")
        except (JWTError, ValueError, TypeError, RuntimeError):
            return jsonify({
                "success": False,
                "error": "Invalid or expired authentication token.",
            }), 401

        request.current_user = user
        return view(*args, **kwargs)

    return wrapped
