from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
import click
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time

from flask import Flask, g, jsonify, render_template, request, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
GENESIS_HASH = "0" * 64
ACOES_PERMITIDAS = {
    "LOGIN", "LOGOUT", "SAQUE", "DEPOSITO",
    "EXCLUSAO", "EDICAO", "CONSULTA"
}
STATUS_PERMITIDOS = {"SUCESSO", "FALHA"}
PAPEIS_PERMITIDOS = {"operator", "admin"}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60
WRITE_LOCK = threading.RLock()

PADRAO_EVENTO_LEGADO = re.compile(
    r"^\[(?P<data_hora>\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})\]\s*"
    r"Usuário:\s*(?P<usuario>.*?)\s*\|\s*"
    r"Ação:\s*(?P<acao>.*?)\s*\|\s*"
    r"Status:\s*(?P<status>SUCESSO|FALHA)\s*$",
    re.IGNORECASE
)

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"
    __table_args__ = (
        db.CheckConstraint("role IN ('operator', 'admin')", name="ck_users_role"),
        db.CheckConstraint("is_active IN (0, 1)", name="ck_users_active"),
    )

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(254), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False, default="operator")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    failed_attempts = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.String(32), nullable=False)


class AuditEvent(db.Model):
    __tablename__ = "audit_events"
    __table_args__ = (
        db.CheckConstraint(
            "action IN ('LOGIN', 'LOGOUT', 'SAQUE', 'DEPOSITO', 'EXCLUSAO', 'EDICAO', 'CONSULTA')",
            name="ck_audit_action"
        ),
        db.CheckConstraint("status IN ('SUCESSO', 'FALHA')", name="ck_audit_status"),
    )

    id = db.Column(db.Integer, primary_key=True)
    occurred_at = db.Column(db.String(32), nullable=False, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="RESTRICT"), nullable=True)
    actor_name = db.Column(db.String(80), nullable=False)
    actor_email = db.Column(db.String(254), nullable=False)
    action = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(10), nullable=False)
    details = db.Column(db.String(500), nullable=False, default="")
    source = db.Column(db.String(20), nullable=False, default="application")
    previous_hash = db.Column(db.String(64), nullable=False)
    record_hash = db.Column(db.String(64), nullable=False)


class AuditChainState(db.Model):
    __tablename__ = "audit_chain_state"

    id = db.Column(db.Integer, primary_key=True)
    head_hash = db.Column(db.String(64), nullable=False)
    event_count = db.Column(db.Integer, nullable=False)
    signature = db.Column(db.String(64), nullable=False)
    updated_at = db.Column(db.String(32), nullable=False)


class LegacyImport(db.Model):
    __tablename__ = "legacy_imports"

    id = db.Column(db.Integer, primary_key=True)
    source_sha256 = db.Column(db.String(64), nullable=False, unique=True)
    imported_at = db.Column(db.String(32), nullable=False)
    imported_count = db.Column(db.Integer, nullable=False)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize_database_url(database_url):
    if database_url.startswith("postgres://"):
        return "postgresql+psycopg://" + database_url[len("postgres://"):]
    if database_url.startswith("postgresql://"):
        return "postgresql+psycopg://" + database_url[len("postgresql://"):]
    return database_url


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


def event_payload(event):
    return {
        "id": event.id,
        "occurred_at": event.occurred_at,
        "actor_id": event.actor_id,
        "actor_name": event.actor_name,
        "actor_email": event.actor_email,
        "action": event.action,
        "status": event.status,
        "details": event.details,
        "source": event.source,
        "previous_hash": event.previous_hash,
    }


def sign_event(app, event):
    canonical = json.dumps(
        event_payload(event),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(
        app.config["AUDIT_HMAC_KEY_BYTES"],
        canonical,
        hashlib.sha256,
    ).hexdigest()


def sign_chain_state(app, event_count, head_hash):
    payload = f"{event_count}:{head_hash}".encode("utf-8")
    return hmac.new(
        app.config["AUDIT_HMAC_KEY_BYTES"],
        payload,
        hashlib.sha256,
    ).hexdigest()


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app_env = os.getenv("APP_ENV", "development").strip().lower()
    secret_key = os.getenv("SECRET_KEY")

    if not secret_key and app_env == "production":
        raise RuntimeError("A variável SECRET_KEY é obrigatória em produção.")
    if not secret_key:
        secret_key = secrets.token_urlsafe(48)

    database_url = os.getenv("DATABASE_URL")
    if database_url:
        database_uri = normalize_database_url(database_url)
    else:
        database_path = Path(app.instance_path) / "sentinela.db"
        database_path.parent.mkdir(parents=True, exist_ok=True)
        database_uri = "sqlite:///" + database_path.as_posix()

    app.config.update(
        SECRET_KEY=secret_key,
        APP_ENV=app_env,
        SQLALCHEMY_DATABASE_URI=database_uri,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=(app_env == "production"),
        PERMANENT_SESSION_LIFETIME=1800,
        MAX_CONTENT_LENGTH=16 * 1024,
        LEGACY_LOG_PATH=str(BASE_DIR / "auditoria_sistema.log"),
    )
    if test_config:
        app.config.update(test_config)

    if app.config["APP_ENV"] == "production":
        if len(app.config["SECRET_KEY"]) < 32:
            raise RuntimeError("SECRET_KEY deve ter pelo menos 32 caracteres em produção.")

    configure_hmac_key(app)
    db.init_app(app)

    with app.app_context():
        db.create_all()
        state = db.session.get(AuditChainState, 1)
        if state is None:
            state = AuditChainState(
                id=1,
                head_hash=GENESIS_HASH,
                event_count=0,
                signature=sign_chain_state(app, 0, GENESIS_HASH),
                updated_at=utc_now(),
            )
            db.session.add(state)
            db.session.commit()

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

    def append_event(
        actor_id,
        actor_name,
        actor_email,
        action,
        status,
        details="",
        source="application",
        occurred_at=None,
        commit=True,
    ):
        with WRITE_LOCK:
            state = db.session.execute(
                select(AuditChainState)
                .where(AuditChainState.id == 1)
                .with_for_update()
            ).scalar_one()

            event = AuditEvent(
                occurred_at=occurred_at or utc_now(),
                actor_id=actor_id,
                actor_name=actor_name,
                actor_email=actor_email,
                action=action,
                status=status,
                details=details,
                source=source,
                previous_hash=state.head_hash,
                record_hash="",
            )
            db.session.add(event)
            db.session.flush()
            event.record_hash = sign_event(app, event)
            state.head_hash = event.record_hash
            state.event_count += 1
            state.signature = sign_chain_state(app, state.event_count, state.head_hash)
            state.updated_at = utc_now()
            db.session.flush()
            if commit:
                db.session.commit()
            return event

    def verify_integrity():
        state = db.session.get(AuditChainState, 1)
        if state is None:
            return {"valid": False, "checked": 0, "erro": "Checkpoint da cadeia ausente."}

        events = db.session.scalars(
            select(AuditEvent).order_by(AuditEvent.id.asc())
        ).all()
        previous_hash = GENESIS_HASH
        checked = 0

        for event in events:
            checked += 1
            if not hmac.compare_digest(event.previous_hash, previous_hash):
                return {
                    "valid": False,
                    "checked": checked,
                    "erro": f"Quebra na sequência de integridade do evento {event.id}.",
                }
            expected_hash = sign_event(app, event)
            if not hmac.compare_digest(event.record_hash, expected_hash):
                return {
                    "valid": False,
                    "checked": checked,
                    "erro": f"Assinatura inválida no evento {event.id}.",
                }
            previous_hash = event.record_hash

        if checked != state.event_count or previous_hash != state.head_hash:
            return {
                "valid": False,
                "checked": checked,
                "erro": "O total de registros ou o último hash diverge do checkpoint assinado.",
            }

        expected_signature = sign_chain_state(app, state.event_count, state.head_hash)
        if not hmac.compare_digest(state.signature, expected_signature):
            return {
                "valid": False,
                "checked": checked,
                "erro": "A assinatura do checkpoint da cadeia é inválida.",
            }

        return {
            "valid": True,
            "checked": checked,
            "head_hash": state.head_hash,
            "message": "Cadeia de auditoria íntegra.",
        }

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

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/status")
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

    @app.post("/api/login")
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
                append_event(None, email[:80] or "Desconhecido", email[:254] or "unknown",
                             "LOGIN", "FALHA", "Tentativa de autenticação com credenciais inválidas.",
                             source="authentication")
            except Exception:
                db.session.rollback()
                app.logger.exception("Falha ao registrar tentativa de login inválida.")
            return jsonify(erro="E-mail ou senha inválidos."), 401

        now = int(time.time())
        if user.locked_until and user.locked_until > now:
            return jsonify(erro="Conta temporariamente bloqueada.", retry_after=user.locked_until - now), 429

        if user.locked_until and user.locked_until <= now:
            user.failed_attempts = 0
            user.locked_until = None

        if not user.is_active or not check_password_hash(user.password_hash, password):
            if user.is_active:
                user.failed_attempts += 1
                if user.failed_attempts >= MAX_LOGIN_ATTEMPTS:
                    user.locked_until = now + LOCKOUT_SECONDS
                    db.session.commit()
                    return jsonify(erro="Conta temporariamente bloqueada após várias tentativas."), 429
                db.session.commit()
            try:
                append_event(None, user.name, user.email, "LOGIN", "FALHA",
                             "Tentativa de autenticação inválida.", source="authentication")
            except Exception:
                db.session.rollback()
                app.logger.exception("Falha ao registrar tentativa de login inválida.")
            return jsonify(erro="E-mail ou senha inválidos."), 401

        user.failed_attempts = 0
        user.locked_until = None
        db.session.commit()
        try:
            append_event(user.id, user.name, user.email, "LOGIN", "SUCESSO",
                         "Autenticação realizada.", source="authentication")
        except Exception:
            db.session.rollback()
            app.logger.exception("Falha ao registrar autenticação bem-sucedida.")
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

    @app.post("/api/logout")
    @require_auth
    @csrf_required
    def logout():
        try:
            append_event(g.current_user.id, g.current_user.name, g.current_user.email,
                         "LOGOUT", "SUCESSO", "Sessão encerrada.", source="authentication")
        except Exception:
            db.session.rollback()
            app.logger.exception("Falha ao registrar encerramento da sessão.")
        session.clear()
        session["csrf_token"] = secrets.token_urlsafe(32)
        return jsonify(mensagem="Sessão encerrada.", csrf_token=session["csrf_token"])

    @app.get("/api/me")
    @require_auth
    def me():
        return jsonify(user=public_user(g.current_user))

    @app.get("/api/eventos")
    @require_auth
    def listar_eventos():
        limit = request.args.get("limit", default=200, type=int)
        limit = max(1, min(limit or 200, 500))
        events = db.session.scalars(
            select(AuditEvent).order_by(AuditEvent.id.desc()).limit(limit)
        ).all()
        return jsonify(eventos=[{
            "id": event.id,
            "data_hora": event.occurred_at,
            "actor_id": event.actor_id,
            "usuario": event.actor_name,
            "email": event.actor_email,
            "acao": event.action,
            "status": event.status,
            "detalhes": event.details,
            "origem": event.source,
            "hash": event.record_hash,
        } for event in events])

    @app.post("/api/eventos")
    @require_auth
    @csrf_required
    def criar_evento():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            data = {}
        action = data.get("acao", "")
        status_value = data.get("status", "")
        details = data.get("detalhes", "")

        action = action.strip().upper() if isinstance(action, str) else ""
        status_value = status_value.strip().upper() if isinstance(status_value, str) else ""
        details = details.strip() if isinstance(details, str) else None

        if action not in ACOES_PERMITIDAS:
            return jsonify(erro="Selecione uma ação válida."), 400
        if status_value not in STATUS_PERMITIDOS:
            return jsonify(erro="Selecione um status válido."), 400
        if details is None or len(details) > 500:
            return jsonify(erro="Os detalhes devem ter até 500 caracteres."), 400

        try:
            event = append_event(
                actor_id=g.current_user.id,
                actor_name=g.current_user.name,
                actor_email=g.current_user.email,
                action=action,
                status=status_value,
                details=details,
            )
        except Exception:
            db.session.rollback()
            app.logger.exception("Falha ao gravar evento de auditoria.")
            return jsonify(erro="Não foi possível registrar o evento."), 500

        return jsonify(
            mensagem="Evento registrado e encadeado com sucesso.",
            evento_id=event.id,
            hash=event.record_hash,
        ), 201

    @app.get("/api/integridade")
    @require_role("admin")
    def integridade():
        resultado = verify_integrity()
        return jsonify(resultado), 200 if resultado["valid"] else 409

    @app.get("/api/admin/users")
    @require_role("admin")
    def listar_usuarios():
        users = db.session.scalars(select(User).order_by(User.id)).all()
        return jsonify(usuarios=[{
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
            "is_active": user.is_active,
            "created_at": user.created_at,
        } for user in users])

    def create_cli_user(role):
        name = click.prompt("Nome").strip()
        email = click.prompt("E-mail").strip().lower()
        password = click.prompt(
            "Senha (mínimo de 10 caracteres)",
            hide_input=True,
            confirmation_prompt=True,
        )
        if not 2 <= len(name) <= 80:
            raise click.ClickException("O nome deve ter entre 2 e 80 caracteres.")
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
            raise click.ClickException("Informe um e-mail válido.")
        if not 10 <= len(password) <= 128:
            raise click.ClickException("A senha deve ter entre 10 e 128 caracteres.")

        db.session.add(User(
            name=name,
            email=email,
            password_hash=generate_password_hash(password),
            role=role,
            is_active=True,
            failed_attempts=0,
            created_at=utc_now(),
        ))
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            raise click.ClickException("Já existe uma conta com este e-mail.")
        click.echo(f"Conta {role} criada com sucesso.")

    @app.cli.command("create-admin")
    def create_admin():
        """Cria uma conta administrativa."""
        create_cli_user("admin")

    @app.cli.command("create-operator")
    def create_operator():
        """Cria uma conta de operador."""
        create_cli_user("operator")

    @app.cli.command("import-legacy-log")
    def import_legacy_log():
        """Importa uma única vez o arquivo de auditoria legado para o banco."""
        legacy_path = Path(app.config["LEGACY_LOG_PATH"])
        if not legacy_path.exists():
            raise click.ClickException("Arquivo auditoria_sistema.log não encontrado.")

        content = legacy_path.read_text(encoding="utf-8", errors="replace")
        source_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if db.session.scalar(
            select(LegacyImport).where(LegacyImport.source_sha256 == source_digest)
        ):
            raise click.ClickException("Este arquivo já foi importado anteriormente.")

        normalized = content.replace("\\n", "\n").replace("\r\n", "\n")
        parsed_events = []
        for line in normalized.splitlines():
            match = PADRAO_EVENTO_LEGADO.fullmatch(line.strip())
            if not match:
                continue
            action = match.group("acao").strip().upper()
            status_value = match.group("status").strip().upper()
            if action not in ACOES_PERMITIDAS or status_value not in STATUS_PERMITIDOS:
                continue
            try:
                old_date = datetime.strptime(match.group("data_hora"), "%d/%m/%Y %H:%M:%S")
            except ValueError:
                continue
            parsed_events.append((
                old_date.isoformat(timespec="seconds"),
                match.group("usuario").strip()[:80],
                action,
                status_value,
            ))

        if not parsed_events:
            raise click.ClickException("Nenhum registro legado válido foi encontrado.")

        try:
            with WRITE_LOCK:
                for old_date, old_user, action, status_value in parsed_events:
                    append_event(
                        actor_id=None,
                        actor_name=old_user or "Usuário legado",
                        actor_email="legacy-import",
                        action=action,
                        status=status_value,
                        details="Registro importado do arquivo de auditoria legado.",
                        source="legacy_import",
                        occurred_at=old_date,
                        commit=False,
                    )
                db.session.add(LegacyImport(
                    source_sha256=source_digest,
                    imported_at=utc_now(),
                    imported_count=len(parsed_events),
                ))
                db.session.commit()
        except Exception:
            db.session.rollback()
            raise click.ClickException("Falha ao importar o histórico legado; nenhuma alteração foi confirmada.")

        click.echo(f"{len(parsed_events)} registro(s) importado(s) para o banco de dados.")

    return app


app = create_app()

if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "5000")),
        debug=(
            app.config["APP_ENV"] != "production"
            and os.getenv("FLASK_DEBUG", "false").strip().lower() in {"1", "true", "yes", "on"}
        ),
    )
        try:
            append_event(g.current_user.id, g.current_user.name, g.current_user.email,
                         "LOGOUT", "SUCESSO", "Sessão encerrada.", source="authentication")
        except Exception:
            db.session.rollback()
            app.logger.exception("Falha ao registrar encerramento da sessão.")
