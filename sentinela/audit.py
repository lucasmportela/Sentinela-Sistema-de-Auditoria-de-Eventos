import hashlib
import hmac
import json
import os

from flask import current_app
from sqlalchemy import func, select
from werkzeug.security import generate_password_hash

from .extensions import db, WRITE_LOCK
from .models import AuditChainState, AuditEvent, User
from .utils import utc_now

GENESIS_HASH = "0" * 64


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


def sign_event(event):
    canonical = json.dumps(
        event_payload(event),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(
        current_app.config["AUDIT_HMAC_KEY_BYTES"],
        canonical,
        hashlib.sha256,
    ).hexdigest()


def sign_chain_state(event_count, head_hash):
    payload = f"{event_count}:{head_hash}".encode("utf-8")
    return hmac.new(
        current_app.config["AUDIT_HMAC_KEY_BYTES"],
        payload,
        hashlib.sha256,
    ).hexdigest()


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
        event.record_hash = sign_event(event)
        state.head_hash = event.record_hash
        state.event_count += 1
        state.signature = sign_chain_state(state.event_count, state.head_hash)
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
        expected_hash = sign_event(event)
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

    expected_signature = sign_chain_state(state.event_count, state.head_hash)
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


def seed_demo_data():
    if not current_app.config.get("DEMO_SEED_DATA", False):
        return

    demo_accounts = [
        {
            "name": "Administrador de demonstração",
            "email": os.getenv("DEMO_ADMIN_EMAIL", "").strip().lower(),
            "password": os.getenv("DEMO_ADMIN_PASSWORD", ""),
            "role": "admin",
        },
        {
            "name": "Operador de demonstração",
            "email": os.getenv("DEMO_OPERATOR_EMAIL", "").strip().lower(),
            "password": os.getenv("DEMO_OPERATOR_PASSWORD", ""),
            "role": "operator",
        },
    ]

    for account in demo_accounts:
        if not account["email"] or len(account["password"]) < 10:
            raise RuntimeError(
                "Configure os e-mails e senhas de demonstração; as senhas devem ter pelo menos 10 caracteres."
            )

        existing_user = db.session.scalar(
            select(User).where(func.lower(User.email) == account["email"])
        )
        if existing_user is None:
            db.session.add(User(
                name=account["name"],
                email=account["email"],
                password_hash=generate_password_hash(account["password"]),
                role=account["role"],
                is_active=True,
                failed_attempts=0,
                created_at=utc_now(),
            ))
        elif existing_user.role != account["role"]:
            raise RuntimeError("Uma conta de demonstração já existe com um papel incompatível.")

    db.session.commit()

    # Os exemplos são inseridos apenas em um banco vazio e nunca substituem eventos existentes.
    if db.session.scalar(select(AuditEvent.id).limit(1)) is None:
        admin = db.session.scalar(
            select(User).where(User.email == demo_accounts[0]["email"])
        )
        operator = db.session.scalar(
            select(User).where(User.email == demo_accounts[1]["email"])
        )
        examples = [
            (admin, "LOGIN", "SUCESSO", "Acesso administrativo de demonstração."),
            (operator, "DEPOSITO", "SUCESSO", "Exemplo de registro de operação concluída."),
            (operator, "CONSULTA", "SUCESSO", "Exemplo de consulta registrada na trilha."),
            (operator, "SAQUE", "FALHA", "Exemplo de operação recusada para fins de demonstração."),
        ]
        for actor, action, status, details in examples:
            append_event(
                actor_id=actor.id,
                actor_name=actor.name,
                actor_email=actor.email,
                action=action,
                status=status,
                details=details,
                source="demo_seed",
            )
