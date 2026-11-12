import hashlib
import re
from datetime import datetime
from pathlib import Path

import click
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash

from .audit import append_event
from .config import ACOES_PERMITIDAS, PADRAO_EVENTO_LEGADO, STATUS_PERMITIDOS
from .extensions import db, WRITE_LOCK
from .models import LegacyImport, User
from .utils import utc_now


def register_cli_commands(app):
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
                old_date = datetime.strptime(
                    match.group("data_hora"), "%d/%m/%Y %H:%M:%S"
                )
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
            raise click.ClickException(
                "Falha ao importar o histórico legado; nenhuma alteração foi confirmada."
            )

        click.echo(f"{len(parsed_events)} registro(s) importado(s) para o banco de dados.")
