# Sentinela — Sistema de Auditoria de Eventos

Aplicação web de auditoria com autenticação individual, armazenamento relacional centralizado e trilha de integridade criptográfica. O servidor identifica o autor pela sessão autenticada; o cliente não pode atribuir um evento a outro usuário.

## Funcionalidades
- Login e logout com contas provisionadas por administrador.
- Papéis `operator` e `admin`, com autorização verificada no backend.
- Tentativas de login bem-sucedidas e malsucedidas também são registradas na trilha de auditoria.
- Senhas armazenadas com hash seguro do Werkzeug.
- Proteção CSRF, cookies de sessão `HttpOnly` e `SameSite`, expiração e cookies `Secure` em produção.
- Bloqueio temporário após cinco tentativas de login incorretas.
- Registro e consulta de eventos somente por usuários autenticados.
- Identidade do autor obtida no servidor, sem confiar no nome enviado pelo navegador.
- Persistência relacional via SQLAlchemy, com SQLite para desenvolvimento e PostgreSQL para armazenamento centralizado.
- Encadeamento de eventos com HMAC-SHA256, hash anterior e checkpoint assinado.
- Verificação administrativa que detecta alteração, inserção, reordenação e exclusão de registros, inclusive no final da cadeia.
- Importação única do arquivo legado `auditoria_sistema.log` para o banco relacional.

## Demonstração visual

As capturas de tela antigas representam a versão anterior, sem autenticação. Atualize os arquivos em `docs/screenshots/` após executar a versão atual.

## Tecnologias
- Backend: Python 3.10+, Flask e Flask-SQLAlchemy.
- Banco de dados: SQLite local ou PostgreSQL centralizado.
- Driver PostgreSQL: Psycopg 3.
- Segurança: Werkzeug, sessões Flask, CSRF e HMAC-SHA256.
- Frontend: HTML5, CSS3 e JavaScript.
- Testes: unittest e Flask test client.

## Estrutura
```text
Sentinela-Sistema-de-Auditoria-de-Eventos/
├── app.py
├── requirements.txt
├── .env.example
├── README.md
├── tests/test_api.py
├── templates/index.html
├── static/css/style.css
├── static/js/app.js
└── docs/screenshots/
```

## Como executar no Windows (PowerShell)

```powershell
git clone https://github.com/lucasmportela/Sentinela-Sistema-de-Auditoria-de-Eventos.git
cd Sentinela-Sistema-de-Auditoria-de-Eventos
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Na primeira execução em desenvolvimento, o Sentinela cria automaticamente o banco `instance/sentinela.db` e uma chave HMAC local em `instance/audit_hmac.key`. Ambos são ignorados pelo Git. Preserve a chave HMAC: se ela for perdida ou substituída, os registros existentes não poderão ser validados.

Abra http://127.0.0.1:5000.

## Criar contas

O cadastro público foi desativado intencionalmente. Contas são provisionadas por um operador confiável no terminal.

Crie o primeiro administrador:
```powershell
.\.venv\Scripts\flask.exe --app app create-admin
```

Crie uma conta de operador:
```powershell
.\.venv\Scripts\flask.exe --app app create-operator
```

Os comandos solicitam nome, e-mail e senha de forma interativa. Use pelo menos 10 caracteres para a senha. Administradores podem consultar usuários e verificar a integridade; operadores podem registrar e consultar eventos.

## Banco de dados centralizado

SQLite é o padrão para desenvolvimento local. Para compartilhar a mesma trilha de auditoria entre instâncias e usuários, configure PostgreSQL e defina `DATABASE_URL` antes de iniciar a aplicação. Exemplo no PowerShell:

```powershell
$env:DATABASE_URL = "postgresql+psycopg://usuario:senha@localhost:5432/sentinela"
$env:APP_ENV = "production"
$env:SECRET_KEY = "gere-uma-chave-aleatoria-com-pelo-menos-32-caracteres"
$env:AUDIT_HMAC_KEY = "gere-outra-chave-aleatoria-com-pelo-menos-32-caracteres"
.\.venv\Scripts\flask.exe --app app create-admin
.\.venv\Scripts\python.exe app.py
```

Em produção, configure `SECRET_KEY` e `AUDIT_HMAC_KEY` por um gerenciador de segredos, não as grave no repositório e use o mesmo valor de `AUDIT_HMAC_KEY` em todas as instâncias autorizadas. A chave HMAC deve ficar fora do banco de dados e ter pelo menos 32 caracteres.

## Importar o histórico antigo

Se o arquivo `auditoria_sistema.log` da versão anterior ainda existir na pasta do projeto, execute uma vez:
```powershell
.\.venv\Scripts\flask.exe --app app import-legacy-log
```

O comando importa os registros reconhecidos, preserva o nome histórico do autor e encadeia cada linha na nova trilha. O hash SHA-256 do arquivo de origem é registrado para impedir que o mesmo arquivo seja importado novamente.

## API

| Método | Rota | Acesso | Descrição |
|---|---|---|---|
| GET | `/api/status` | Público | Estado da sessão e token CSRF |
| POST | `/api/login` | Público + CSRF | Autenticação |
| POST | `/api/logout` | Autenticado + CSRF | Encerramento da sessão |
| GET | `/api/me` | Autenticado | Identidade da sessão |
| GET | `/api/eventos` | Autenticado | Consulta os eventos mais recentes |
| POST | `/api/eventos` | Autenticado + CSRF | Registra evento com autor identificado no servidor |
| GET | `/api/integridade` | Administrador | Verifica toda a cadeia e o checkpoint assinado |
| GET | `/api/admin/users` | Administrador | Lista contas e papéis |

POST e PATCH exigem o token CSRF recebido em `/api/status` ou no retorno de login, enviado no cabeçalho `X-CSRF-Token`.

## Proteção contra adulteração

Cada evento contém o hash do registro anterior e um HMAC-SHA256 calculado sobre os campos canônicos do evento. O banco também mantém um checkpoint com quantidade de registros, hash final e assinatura HMAC. A verificação administrativa percorre a cadeia inteira e compara o resultado com esse checkpoint.

Esse mecanismo detecta alteração de conteúdo, inserção, reordenação e exclusão de eventos, inclusive do último registro, desde que a chave HMAC permaneça protegida. Ele não torna o banco absolutamente inviolável: um invasor que obtenha a chave HMAC ou restaure simultaneamente um backup antigo do banco pode comprometer a trilha. Para auditoria de produção, mantenha a chave fora do servidor de banco, faça backups imutáveis/off-site e exporte checkpoints para um destino independente.

## Testes automatizados

```powershell
python -m unittest discover -s tests -v
```

A suíte cobre autenticação, CSRF, bloqueio de login, autorização, identidade do autor, persistência relacional, importação do log legado, encadeamento HMAC e detecção de adulteração.

## Segurança e operação

- Em produção, use PostgreSQL, HTTPS, `APP_ENV=production`, `SECRET_KEY` e `AUDIT_HMAC_KEY` fortes.
- Configure backups imutáveis e controle de acesso restrito ao banco.
- A chave HMAC deve ser armazenada separadamente do banco e ter cópias de segurança protegidas.
- O projeto é educacional e não substitui um SIEM ou serviço de log imutável gerenciado.
- Para mudanças futuras no esquema do banco, adote migrações versionadas (por exemplo, Alembic).

## Autor

Projeto de portfólio para praticar Python, Flask, autenticação, autorização, SQLAlchemy, PostgreSQL, segurança web e integridade de trilhas de auditoria.
