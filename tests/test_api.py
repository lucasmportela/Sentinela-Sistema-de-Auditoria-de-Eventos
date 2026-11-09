"""Testes de integração da API Flask e do arquivo de auditoria."""
import tempfile
import unittest
from pathlib import Path

import app as app_module


class TestAuditoriaAPI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="sentinela-tests-")
        app_module.ARQUIVO_LOG = Path(self.temp_dir.name) / "auditoria_teste.log"
        app_module.app.config.update(TESTING=True)
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_debug_desativado_por_padrao(self):
        self.assertFalse(app_module.app.debug)

    def test_pagina_inicial(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.content_type)

    def test_lista_vazia_quando_log_nao_existe(self):
        response = self.client.get("/api/eventos")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), [])

    def test_registra_evento_e_persiste_no_arquivo(self):
        response = self.client.post(
            "/api/eventos",
            json={"usuario": "Lucas", "acao": "LOGIN", "status": "SUCESSO"},
        )
        self.assertEqual(response.status_code, 201)
        self.assertIn("Evento registrado", response.get_json()["mensagem"])
        self.assertTrue(app_module.ARQUIVO_LOG.exists())

        conteudo = app_module.ARQUIVO_LOG.read_text(encoding="utf-8")
        self.assertIn("Usuário: Lucas", conteudo)
        self.assertIn("Ação: LOGIN", conteudo)
        self.assertIn("Status: SUCESSO", conteudo)

        eventos = self.client.get("/api/eventos").get_json()
        self.assertEqual(len(eventos), 1)
        self.assertEqual(eventos[0]["usuario"], "Lucas")
        self.assertEqual(eventos[0]["acao"], "LOGIN")
        self.assertEqual(eventos[0]["status"], "SUCESSO")

    def test_eventos_sao_listados_do_mais_recente_para_o_mais_antigo(self):
        for usuario, acao in (("Lucas", "LOGIN"), ("Marina", "LOGOUT")):
            response = self.client.post(
                "/api/eventos",
                json={"usuario": usuario, "acao": acao, "status": "SUCESSO"},
            )
            self.assertEqual(response.status_code, 201)

        eventos = self.client.get("/api/eventos").get_json()
        self.assertEqual([evento["usuario"] for evento in eventos], ["Marina", "Lucas"])

    def test_rejeita_usuario_vazio_acao_e_status_invalidos(self):
        casos = [
            {"usuario": "", "acao": "LOGIN", "status": "SUCESSO"},
            {"usuario": "Lucas", "acao": "EXECUCAO", "status": "SUCESSO"},
            {"usuario": "Lucas", "acao": "LOGIN", "status": "PENDENTE"},
        ]
        for dados in casos:
            with self.subTest(dados=dados):
                response = self.client.post("/api/eventos", json=dados)
                self.assertEqual(response.status_code, 400)
                self.assertIn("erro", response.get_json())

        self.assertFalse(app_module.ARQUIVO_LOG.exists())

    def test_rejeita_usuario_com_delimitador_ou_quebra_de_linha(self):
        for usuario in ("Lucas|admin", "Lucas\nadmin", "x" * 101):
            with self.subTest(usuario=usuario):
                response = self.client.post(
                    "/api/eventos",
                    json={"usuario": usuario, "acao": "LOGIN", "status": "SUCESSO"},
                )
                self.assertEqual(response.status_code, 400)

    def test_nao_sobrescreve_eventos_anteriores(self):
        for usuario in ("Lucas", "Marina"):
            response = self.client.post(
                "/api/eventos",
                json={"usuario": usuario, "acao": "CONSULTA", "status": "SUCESSO"},
            )
            self.assertEqual(response.status_code, 201)

        linhas = app_module.ARQUIVO_LOG.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(linhas), 2)
        self.assertIn("Lucas", linhas[0])
        self.assertIn("Marina", linhas[1])


if __name__ == "__main__":
    unittest.main()
