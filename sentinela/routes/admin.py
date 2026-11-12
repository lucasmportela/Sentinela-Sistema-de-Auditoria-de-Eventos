from flask import Blueprint, jsonify
from sqlalchemy import select

from ..audit import verify_integrity
from ..extensions import db
from ..models import User
from ..security import require_role

bp = Blueprint("admin", __name__)


@bp.get("/api/integridade")
@require_role("admin")
def integridade():
    resultado = verify_integrity()
    return jsonify(resultado), 200 if resultado["valid"] else 409


@bp.get("/api/admin/users")
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
