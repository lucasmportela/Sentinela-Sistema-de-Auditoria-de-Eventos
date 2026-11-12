from .extensions import db


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
            name="ck_audit_action",
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
