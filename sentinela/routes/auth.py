import time
import secrets

from flask import Blueprint, current_app, g, jsonify, request, session
from sqlalchemy import func, select
from werkzeug.security import check_password_hash

from ..audit import append_event
from ..config import MAX_LOGIN_ATTEMPTS, LOCKOUT_SECONDS
from ..extensions import db
from ..models import User
from ..security import csrf_required, public_user, require_auth

bp = Blueprint("auth", __name__)


@bp.post("/api/login")
@csrf_required
def login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    email_value = data.get("email", "")
    email = email_value.strip().lower() if isinstance(email_value, str) else ""
    password = data.get("password", "")

    if not email or not isinstance(password, str) or not password:
        return jsonify(erro="Informe e-mail e senha."), 400

    user = db.session.scalar(select(User).where(func.lower(User.email) == email))
    if user is None:
        try:
            append_event(
                None,
                email[:80] or "Desconhecido",
                email[:254] or "unknown",
                "LOGIN",
                "FALHA",
                "Tentativa de autenticação com credenciais inválidas.",
                source="authentication",
            )
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Falha ao registrar tentativa de login inválida.")
        return jsonify(erro="E-mail ou senha inválidos."), 401

    now = int(time.time())
    if user.locked_until and user.locked_until > now:
        try:
            append_event(
                None,
                user.name,
                user.email,
                "LOGIN",
                "FALHA",
                "Tentativa durante bloqueio temporário da conta.",
                source="authentication",
            )
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Falha ao registrar tentativa durante bloqueio.")
        return jsonify(
            erro="Conta temporariamente bloqueada.",
            retry_after=user.locked_until - now,
        ), 429

    if user.locked_until and user.locked_until <= now:
        user.failed_attempts = 0
        user.locked_until = None

    if not user.is_active or not check_password_hash(user.password_hash, password):
        if user.is_active:
            user.failed_attempts += 1
            if user.failed_attempts >= MAX_LOGIN_ATTEMPTS:
                user.locked_until = now + LOCKOUT_SECONDS
                db.session.commit()
                try:
                    append_event(
                        None,
                        user.name,
                        user.email,
                        "LOGIN",
                        "FALHA",
                        "Conta bloqueada após várias tentativas de autenticação.",
                        source="authentication",
                    )
                except Exception:
                    db.session.rollback()
                    current_app.logger.exception("Falha ao registrar bloqueio da conta.")
                return jsonify(
                    erro="Conta temporariamente bloqueada após várias tentativas."
                ), 429
            db.session.commit()
        try:
            append_event(
                None,
                user.name,
                user.email,
                "LOGIN",
                "FALHA",
                "Tentativa de autenticação inválida.",
                source="authentication",
            )
        except Exception:
            db.session.rollback()
            current_app.logger.exception("Falha ao registrar tentativa de login inválida.")
        return jsonify(erro="E-mail ou senha inválidos."), 401

    user.failed_attempts = 0
    user.locked_until = None
    db.session.commit()
    try:
        append_event(
            user.id,
            user.name,
            user.email,
            "LOGIN",
            "SUCESSO",
            "Autenticação realizada.",
            source="authentication",
        )
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Falha ao registrar autenticação bem-sucedida.")
        return jsonify(erro="Não foi possível registrar o acesso com segurança."), 503

    session.clear()
    session.permanent = True
    session["user_id"] = user.id
    session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify(
        mensagem="Login realizado com sucesso.",
        csrf_token=session["csrf_token"],
        user=public_user(user),
    )


@bp.post("/api/logout")
@require_auth
@csrf_required
def logout():
    try:
        append_event(
            g.current_user.id,
            g.current_user.name,
            g.current_user.email,
            "LOGOUT",
            "SUCESSO",
            "Sessão encerrada.",
            source="authentication",
        )
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Falha ao registrar encerramento da sessão.")
    session.clear()
    session["csrf_token"] = secrets.token_urlsafe(32)
    return jsonify(mensagem="Sessão encerrada.", csrf_token=session["csrf_token"])


@bp.get("/api/me")
@require_auth
def me():
    return jsonify(user=public_user(g.current_user))
