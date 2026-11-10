"""Testes de autenticação, persistência e integridade do Sentinela."""
import tempfile
import unittest
from pathlib import Path

from werkzeug.security import generate_password_hash

import app as app_module
from app import AuditChainState, AuditEvent, User, create_app, db


class TestSentinelaSecurity(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="sentinela-tests-")
        self.database_path = Path(self.temp_dir.name) / "sentinela-test.db"
        self.app = create_app({
            "TESTING": True,
            "APP_ENV": "testing",
            "SECRET_KEY": "test-secret-key-with-enough-entropy-123456",
            "AUDIT_HMAC_KEY": "test-audit-hmac-key-with-enough-entropy-123456",
            "SQLALCHEMY_DATABASE_URI": "sqlite:///" + self.database_path.as_posix(),
            "SESSION_COOKIE_SECURE": False,
            "LEGACY_LOG_PATH": str(Path(self.temp_dir.name) / "auditoria_sistema.log"),
        })
        self.client = self.app.test_client()

        with self.app.app_context():
            db.session.add_all([
                User(
                    name="Administrador",
                    email="admin@example.com",
                    password_hash=generate_password_hash("AdminPassword123"),
                    role="admin",
                    is_active=True,
                    failed_attempts=0,
                    created_at="2026-11-10T10:00:00Z",
                ),
                User(
                    name="Operador",
                    email="operador@example.com",
                    password_hash=generate_password_hash("OperatorPassword123"),
                    role="operator",
                    is_active=True,
                    failed_attempts=0,
                    created_at="2026-11-10T10:00:00Z",
                ),
            ])
            db.session.commit()

        self.csrf = self.client.get("/api/status").get_json()["csrf_token"]

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
        self.temp_dir.cleanup()

    def request_json(self, method, path, data=None, csrf=None):
        headers = {}
        if csrf is not None:
            headers["X-CSRF-Token"] = csrf
        return self.client.open(path, method=method, json=data, headers=headers)

    def login(self, email="operador@example.com", password="OperatorPassword123"):
        response = self.request_json(
            "POST", "/api/login",
            {"email": email, "password": password},
            self.csrf,
        )
        if response.status_code == 200:
            self.csrf = response.get_json()["csrf_token"]
        return response

    def create_event(self, action="LOGIN", status="SUCESSO", details="Teste de auditoria"):
        return self.request_json(
            "POST",
            "/api/eventos",
            {"acao": action, "status": status, "detalhes": details},
            self.csrf,
        )

    def test_home_page_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.content_type)

    def test_status_issues_csrf_token_and_reports_anonymous_session(self):
        response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["authenticated"])
        self.assertTrue(response.get_json()["csrf_token"])

    def test_event_routes_require_authentication(self):
        self.assertEqual(self.client.get("/api/eventos").status_code, 401)
        response = self.request_json(
            "POST", "/api/eventos",
            {"acao": "LOGIN", "status": "SUCESSO", "detalhes": ""},
            self.csrf,
        )
        self.assertEqual(response.status_code, 401)

    def test_login_requires_csrf_token(self):
        response = self.request_json(
            "POST", "/api/login",
            {"email": "operador@example.com", "password": "OperatorPassword123"},
        )
        self.assertEqual(response.status_code, 403)

    def test_successful_login_creates_authenticated_session(self):
        response = self.login()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["user"]["role"], "operator")
        me = self.client.get("/api/me")
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.get_json()["user"]["email"], "operador@example.com")

    def test_invalid_login_does_not_create_session(self):
        response = self.login(password="senha-incorreta")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.client.get("/api/me").status_code, 401)

    def test_five_failed_logins_lock_account_temporarily(self):
        for _ in range(4):
            self.assertEqual(self.login(password="senha-incorreta").status_code, 401)
        self.assertEqual(self.login(password="senha-incorreta").status_code, 429)
        self.assertEqual(self.login().status_code, 429)

    def test_csrf_is_required_to_create_events(self):
        self.login()
        response = self.request_json(
            "POST", "/api/eventos",
            {"acao": "LOGIN", "status": "SUCESSO", "detalhes": ""},
        )
        self.assertEqual(response.status_code, 403)

    def test_event_actor_is_taken_from_authenticated_session_not_request_body(self):
        self.login()
        response = self.request_json(
            "POST", "/api/eventos",
            {
                "usuario": "Administrador falsificado",
                "acao": "SAQUE",
                "status": "SUCESSO",
                "detalhes": "Operação de teste",
            },
            self.csrf,
        )
        self.assertEqual(response.status_code, 201)
        events = self.client.get("/api/eventos").get_json()["eventos"]
        self.assertEqual(events[0]["usuario"], "Operador")
        self.assertEqual(events[0]["email"], "operador@example.com")
        self.assertNotEqual(events[0]["usuario"], "Administrador falsificado")

    def test_invalid_action_status_and_details_are_rejected(self):
        self.login()
        cases = [
            {"acao": "EXECUTAR", "status": "SUCESSO", "detalhes": ""},
            {"acao": "LOGIN", "status": "PENDENTE", "detalhes": ""},
            {"acao": "LOGIN", "status": "SUCESSO", "detalhes": "x" * 501},
        ]
        for data in cases:
            response = self.request_json("POST", "/api/eventos", data, self.csrf)
            self.assertEqual(response.status_code, 400)
        with self.app.app_context():
            self.assertEqual(db.session.scalar(select_count_events()), 0)

    def test_events_are_persisted_in_relational_database(self):
        self.login()
        self.assertEqual(self.create_event().status_code, 201)
        second_app = create_app({
            "TESTING": True,
            "APP_ENV": "testing",
            "SECRET_KEY": "another-test-secret-key-with-enough-entropy",
            "AUDIT_HMAC_KEY": "test-audit-hmac-key-with-enough-entropy-123456",
            "SQLALCHEMY_DATABASE_URI": "sqlite:///" + self.database_path.as_posix(),
            "SESSION_COOKIE_SECURE": False,
        })
        with second_app.app_context():
            self.assertEqual(db.session.query(AuditEvent).count(), 1)

    def test_events_are_returned_newest_first(self):
        self.login()
        self.create_event("LOGIN", "SUCESSO", "Primeiro")
        self.create_event("LOGOUT", "FALHA", "Segundo")
        events = self.client.get("/api/eventos").get_json()["eventos"]
        self.assertEqual([event["detalhes"] for event in events], ["Segundo", "Primeiro"])

    def test_operator_cannot_verify_integrity_or_list_users(self):
        self.login()
        self.assertEqual(self.client.get("/api/integridade").status_code, 403)
        self.assertEqual(self.client.get("/api/admin/users").status_code, 403)

    def test_admin_can_verify_integrity_and_list_users(self):
        self.login("admin@example.com", "AdminPassword123")
        self.assertEqual(self.client.get("/api/integridade").status_code, 200)
        result = self.client.get("/api/integridade").get_json()
        self.assertTrue(result["valid"])
        self.assertEqual(self.client.get("/api/admin/users").status_code, 200)

    def test_hash_chain_detects_event_content_tampering(self):
        self.login()
        self.create_event()
        with self.app.app_context():
            event = db.session.query(AuditEvent).one()
            event.status = "FALHA"
            db.session.commit()
        self.login("admin@example.com", "AdminPassword123")
        response = self.client.get("/api/integridade")
        self.assertEqual(response.status_code, 409)
        self.assertFalse(response.get_json()["valid"])

    def test_signed_checkpoint_detects_deletion_of_last_event(self):
        self.login()
        self.create_event()
        with self.app.app_context():
            event = db.session.query(AuditEvent).one()
            db.session.delete(event)
            db.session.commit()
        self.login("admin@example.com", "AdminPassword123")
        response = self.client.get("/api/integridade")
        self.assertEqual(response.status_code, 409)
        self.assertFalse(response.get_json()["valid"])

    def test_signed_checkpoint_detects_checkpoint_tampering(self):
        with self.app.app_context():
            state = db.session.get(AuditChainState, 1)
            state.event_count = 10
            db.session.commit()
        self.login("admin@example.com", "AdminPassword123")
        self.assertEqual(self.client.get("/api/integridade").status_code, 409)

    def test_logout_ends_session(self):
        self.login()
        response = self.request_json("POST", "/api/logout", {}, self.csrf)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get("/api/me").status_code, 401)

    def test_inactive_user_cannot_continue_using_session(self):
        self.login()
        with self.app.app_context():
            user = db.session.query(User).filter_by(email="operador@example.com").one()
            user.is_active = False
            db.session.commit()
        self.assertEqual(self.client.get("/api/eventos").status_code, 401)

    def test_legacy_log_is_imported_once_and_added_to_hash_chain(self):
        legacy_path = Path(self.app.config["LEGACY_LOG_PATH"])
        legacy_path.write_text(
            "[09/11/2026 10:30:00] Usuário: Usuário antigo | Ação: LOGIN | Status: SUCESSO\n",
            encoding="utf-8",
        )
        runner = self.app.test_cli_runner()
        result = runner.invoke(args=["import-legacy-log"])
        self.assertEqual(result.exit_code, 0, result.output)
        duplicate = runner.invoke(args=["import-legacy-log"])
        self.assertNotEqual(duplicate.exit_code, 0)
        with self.app.app_context():
            imported = db.session.query(AuditEvent).one()
            self.assertEqual(imported.source, "legacy_import")
            self.assertIsNone(imported.actor_id)
            self.assertEqual(imported.actor_name, "Usuário antigo")
            self.assertEqual(db.session.query(AuditChainState).one().event_count, 1)


def select_count_events():
    from sqlalchemy import func, select
    return select(func.count(AuditEvent.id))


if __name__ == "__main__":
    unittest.main()
