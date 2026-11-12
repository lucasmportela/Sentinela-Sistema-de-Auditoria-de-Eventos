from pathlib import Path
import re

BASE_DIR = Path(__file__).resolve().parent.parent

ACOES_PERMITIDAS = {
    "LOGIN", "LOGOUT", "SAQUE", "DEPOSITO",
    "EXCLUSAO", "EDICAO", "CONSULTA",
}
STATUS_PERMITIDOS = {"SUCESSO", "FALHA"}
PAPEIS_PERMITIDOS = {"operator", "admin"}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60

PADRAO_EVENTO_LEGADO = re.compile(
    r"^\[(?P<data_hora>\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})\]\s*"
    r"Usuário:\s*(?P<usuario>.*?)\s*\|\s*"
    r"Ação:\s*(?P<acao>.*?)\s*\|\s*"
    r"Status:\s*(?P<status>SUCESSO|FALHA)\s*$",
    re.IGNORECASE,
)


def normalize_database_url(database_url):
    if database_url.startswith("postgres://"):
        return "postgresql+psycopg://" + database_url[len("postgres://"):]
    if database_url.startswith("postgresql://"):
        return "postgresql+psycopg://" + database_url[len("postgresql://"):]
    return database_url
