"""Ponto de entrada compatível com Render, Flask CLI e imports legados."""

import os

from sentinela import create_app
from sentinela.audit import (
    append_event,
    event_payload,
    sign_chain_state,
    sign_event,
    verify_integrity,
)
from sentinela.config import (
    ACOES_PERMITIDAS,
    BASE_DIR,
    LOCKOUT_SECONDS,
    MAX_LOGIN_ATTEMPTS,
    PADRAO_EVENTO_LEGADO,
    PAPEIS_PERMITIDOS,
    STATUS_PERMITIDOS,
    normalize_database_url,
)
from sentinela.extensions import WRITE_LOCK, db
from sentinela.models import AuditChainState, AuditEvent, LegacyImport, User
from sentinela.security import (
    configure_hmac_key,
    csrf_required,
    current_user,
    public_user,
    require_auth,
    require_role,
)
from sentinela.utils import utc_now

app = create_app()

__all__ = [
    "app",
    "create_app",
    "db",
    "User",
    "AuditEvent",
    "AuditChainState",
    "LegacyImport",
    "append_event",
    "event_payload",
    "sign_event",
    "sign_chain_state",
    "verify_integrity",
    "utc_now",
]

if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "5000")),
        debug=(
            app.config["APP_ENV"] != "production"
            and os.getenv("FLASK_DEBUG", "false").strip().lower()
            in {"1", "true", "yes", "on"}
        ),
    )
