import os
import secrets

from flask import Blueprint, current_app, jsonify, render_template, session
from sqlalchemy import select

from ..extensions import db
from ..security import current_user, public_user

bp = Blueprint("web", __name__)


@bp.get("/")
def index():
    demo_credentials = None
    if current_app.config.get("DEMO_SEED_DATA", False):
        demo_credentials = {
            "admin_email": os.getenv("DEMO_ADMIN_EMAIL", ""),
            "admin_password": os.getenv("DEMO_ADMIN_PASSWORD", ""),
            "operator_email": os.getenv("DEMO_OPERATOR_EMAIL", ""),
            "operator_password": os.getenv("DEMO_OPERATOR_PASSWORD", ""),
        }
    return render_template("index.html", demo_credentials=demo_credentials)


@bp.get("/api/health")
def health():
    try:
        db.session.execute(select(1))
        return jsonify(status="ok"), 200
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Falha na verificação de saúde do Sentinela.")
        return jsonify(status="unavailable"), 503


@bp.get("/api/status")
def status():
    user = current_user()
    csrf_token = session.get("csrf_token")
    if not csrf_token:
        csrf_token = secrets.token_urlsafe(32)
        session["csrf_token"] = csrf_token
    return jsonify({
        "authenticated": user is not None,
        "csrf_token": csrf_token,
        "user": public_user(user) if user else None,
    })
