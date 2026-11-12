from flask import Blueprint, current_app, g, jsonify, request
from sqlalchemy import select

from ..audit import append_event
from ..config import ACOES_PERMITIDAS, STATUS_PERMITIDOS
from ..extensions import db
from ..models import AuditEvent
from ..security import csrf_required, require_auth

bp = Blueprint("events", __name__)


@bp.get("/api/eventos")
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


@bp.post("/api/eventos")
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
        current_app.logger.exception("Falha ao gravar evento de auditoria.")
        return jsonify(erro="Não foi possível registrar o evento."), 500

    return jsonify(
        mensagem="Evento registrado e encadeado com sucesso.",
        evento_id=event.id,
        hash=event.record_hash,
    ), 201
