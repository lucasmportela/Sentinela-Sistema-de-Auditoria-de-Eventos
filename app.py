from datetime import datetime
from pathlib import Path
import os
import re
import threading

from flask import Flask, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent
ARQUIVO_LOG = BASE_DIR / "auditoria_sistema.log"
LOCK_LOG = threading.Lock()

app = Flask(__name__)

APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
DEBUG = (
    APP_ENV != "production"
    and os.getenv("FLASK_DEBUG", "false").strip().lower()
    in {"1", "true", "yes", "on"}
)
app.config["DEBUG"] = DEBUG

ACOES_PERMITIDAS = {
    "LOGIN", "LOGOUT", "SAQUE", "DEPOSITO",
    "EXCLUSAO", "EDICAO", "CONSULTA"
}
STATUS_PERMITIDOS = {"SUCESSO", "FALHA"}

# Reconhece um registro completo do arquivo de auditoria.
PADRAO_EVENTO = re.compile(
    r"\[(?P<data_hora>[^\]]+)\]\s*"
    r"Usuário:\s*(?P<usuario>.*?)\s*\|\s*"
    r"Ação:\s*(?P<acao>.*?)\s*\|\s*"
    r"Status:\s*(?P<status>SUCESSO|FALHA)",
    re.IGNORECASE
)


def registrar_evento(usuario, acao, status):
    """Acrescenta um evento ao log sem sobrescrever registros anteriores."""
    data_hora = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    linha = (
        f"[{data_hora}] Usuário: {usuario} | "
        f"Ação: {acao} | Status: {status}"
    )

    with LOCK_LOG:
        # Garante a codificação UTF-8 ao gravar
        with ARQUIVO_LOG.open("a", encoding="utf-8", newline="\n") as arquivo:
            arquivo.write(linha + "\n")

    return linha


def ler_eventos():
    """Lê os eventos mais recentes primeiro, corrigindo problemas de encoding antigos."""
    if not ARQUIVO_LOG.exists():
        return []

    with LOCK_LOG:
        # O parâmetro errors="replace" evita que o Flask quebre se houver caracteres corrompidos no arquivo antigo
        conteudo = ARQUIVO_LOG.read_text(encoding="utf-8", errors="replace")

    # Corrige problemas de encoding comuns (Mojibake) no arquivo legado
    conteudo = conteudo.replace("UsuĂĄrio", "Usuário").replace("AĂ§ĂŁo", "Ação")
    
    # Corrige registros antigos que foram gravados com os dois caracteres literais \ e n
    conteudo = conteudo.replace("\\n", "\n").replace("\r\n", "\n")

    eventos = []
    for linha in conteudo.splitlines():
        encontrados = list(PADRAO_EVENTO.finditer(linha))

        if encontrados:
            for match in encontrados:
                evento = {
                    "data_hora": match.group("data_hora").strip(),
                    "usuario": match.group("usuario").strip(),
                    "acao": match.group("acao").strip().upper(),
                    "status": match.group("status").strip().upper(),
                }
                eventos.append(evento)
        elif linha.strip():
            eventos.append({
                "data_hora": "",
                "usuario": "",
                "acao": "",
                "status": "",
                "linha": linha.strip()
            })

    return list(reversed(eventos))


@app.get("/")
def inicio():
    return render_template("index.html")


@app.get("/api/eventos")
def listar_eventos():
    return jsonify(ler_eventos())


@app.post("/api/eventos")
def criar_evento():
    dados = request.get_json(silent=True) or {}

    usuario = str(dados.get("usuario", "")).strip()
    acao = str(dados.get("acao", "")).strip().upper()
    status = str(dados.get("status", "")).strip().upper()

    if not usuario:
        return jsonify(erro="Informe o nome do usuário."), 400

    if len(usuario) > 100 or any(c in usuario for c in "\r\n|"):
        return jsonify(
            erro="Nome inválido: limite de 100 caracteres e sem quebras de linha ou |."
        ), 400

    if acao not in ACOES_PERMITIDAS:
        return jsonify(erro="Selecione uma ação válida."), 400

    if status not in STATUS_PERMITIDOS:
        return jsonify(erro="Selecione um status válido."), 400

    registro = registrar_evento(usuario, acao, status)
    return jsonify(
        mensagem="Evento registrado com sucesso.",
        registro=registro
    ), 201


if __name__ == "__main__":
    app.run(
        host=os.getenv("FLASK_HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "5000")),
        debug=DEBUG,
    )