import hmac
import os
import secrets
from functools import wraps
from pathlib import Path

from flask import g, jsonify, request, session

from .extensions import db
from .models import User


def configure_hmac_key(app):
    configured_key = app.config.get("AUDIT_HMAC_KEY") or os.getenv("AUDIT_HMAC_KEY")
    if configured_key:
        if app.config["APP_ENV"] == "production" and len(configured_key) < 32:
            raise RuntimeError("AUDIT_HMAC_KEY deve ter pelo menos 32 caracteres em produção.")
        app.config["AUDIT_HMAC_KEY_BYTES"] = configured_key.encode("utf-8")
        return

    if app.config["APP_ENV"] == "production":
        raise RuntimeError("A variável AUDIT_HMAC_KEY é obrigatória em produção.")

    key_path = Path(app.instance_path) / "audit_hmac.key"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        key = key_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        key = secrets.token_urlsafe(48)
        try:
            with key_path.open("x", encoding="utf-8") as key_file:
                key_file.write(key)
        except FileExistsError:
            key = key_path.read_text(encoding="utf-8").strip()
        if os.name != "nt":
            key_path.chmod(0o600)

    if not key:
        raise RuntimeError("A chave local de integridade está vazia.")
    app.config["AUDIT_HMAC_KEY_BYTES"] = key.encode("utf-8")


def public_user(user):
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role,
    }


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    user = db.session.get(User, user_id)
    if user is None or not user.is_active:
        session.clear()
        return None
    return user


def require_auth(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return jsonify(erro="Faça login para acessar este recurso."), 401
        g.current_user = user
        return view(*args, **kwargs)
    return wrapped


def require_role(role):
    def decorator(view):
        @wraps(view)
        @require_auth
        def wrapped(*args, **kwargs):
            if g.current_user.role != role:
                return jsonify(erro="Você não tem permissão para acessar este recurso."), 403
            return view(*args, **kwargs)
        return wrapped
    return decorator


def csrf_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        expected = session.get("csrf_token", "")
        supplied = request.headers.get("X-CSRF-Token", "")
        if not expected or not supplied or not hmac.compare_digest(expected, supplied):
            return jsonify(erro="Token CSRF ausente ou inválido. Atualize a página."), 403
        return view(*args, **kwargs)
    return wrapped


def register_security_headers(app):
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        )
        return response
