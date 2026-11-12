import os
import secrets
from pathlib import Path

from flask import Flask

from .audit import GENESIS_HASH, seed_demo_data, sign_chain_state
from .config import BASE_DIR, normalize_database_url
from .extensions import db
from .models import AuditChainState
from .security import configure_hmac_key, register_security_headers
from .routes import register_blueprints
from .cli import register_cli_commands
from .utils import utc_now


def create_app(test_config=None):
    """Cria e configura uma instância da aplicação Sentinela."""
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
        DEMO_SEED_DATA=False,
    )
    if test_config:
        app.config.update(test_config)

    # Só habilita o seed em produção; testes podem habilitá-lo explicitamente.
    app.config["DEMO_SEED_DATA"] = bool(
        (
            app.config["APP_ENV"] == "production"
            and os.getenv("DEMO_SEED_DATA", "").strip().lower()
            in {"1", "true", "yes", "on"}
        )
        or (test_config and test_config.get("DEMO_SEED_DATA", False))
    )

    if app.config["APP_ENV"] == "production":
        if len(app.config["SECRET_KEY"]) < 32:
            raise RuntimeError("SECRET_KEY deve ter pelo menos 32 caracteres em produção.")

    configure_hmac_key(app)
    db.init_app(app)

    register_security_headers(app)
    register_blueprints(app)
    register_cli_commands(app)

    with app.app_context():
        db.create_all()
        state = db.session.get(AuditChainState, 1)
        if state is None:
            state = AuditChainState(
                id=1,
                head_hash=GENESIS_HASH,
                event_count=0,
                signature=sign_chain_state(0, GENESIS_HASH),
                updated_at=utc_now(),
            )
            db.session.add(state)
            db.session.commit()

        seed_demo_data()

    return app


__all__ = ["create_app", "db"]
