const byId = (id) => document.getElementById(id);
const loginPanel = byId("loginPanel");
const dashboard = byId("dashboard");
const loginForm = byId("loginForm");
const loginFeedback = byId("loginFeedback");
const eventForm = byId("formEvento");
const eventList = byId("eventList");
const feedback = byId("feedback");
const filtroStatus = byId("filtroStatus");

let eventos = [];
let csrfToken = "";
let currentUser = null;

function escaparHtml(valor) {
  return String(valor ?? "").replace(/[&<>"']/g, (caractere) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[caractere]));
}

function normalizarStatus(status) {
  return String(status || "").trim().toUpperCase();
}

function setFeedback(elemento, mensagem, erro = false) {
  elemento.textContent = mensagem;
  elemento.className = erro ? "feedback error" : "feedback";
}

function mostrarLogin(mensagem = "") {
  currentUser = null;
  dashboard.hidden = true;
  loginPanel.hidden = false;
  setFeedback(loginFeedback, mensagem, Boolean(mensagem));
  byId("loginPassword").value = "";
}

function mostrarDashboard(user) {
  currentUser = user;
  loginPanel.hidden = true;
  dashboard.hidden = false;
  byId("currentUser").textContent = user.name + " · " + user.email;
  byId("currentRole").textContent = user.role === "admin" ? "ADMINISTRADOR" : "OPERADOR";
  byId("verifyButton").hidden = user.role !== "admin";
  carregarEventos();
}

async function api(url, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = Object.assign({}, options.headers || {});
  if (options.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  if (["POST", "PATCH", "PUT", "DELETE"].includes(method) && csrfToken) {
    headers["X-CSRF-Token"] = csrfToken;
  }

  const response = await fetch(url, Object.assign({}, options, {
    method,
    headers,
    credentials: "same-origin",
    cache: "no-store"
  }));
  const result = await response.json().catch(() => ({}));

  if (response.status === 401 && currentUser) {
    mostrarLogin("Sua sessão expirou. Entre novamente.");
  }
  if (!response.ok) {
    throw new Error(result.erro || "Não foi possível concluir a operação.");
  }
  return result;
}

function atualizarIndicadores() {
  byId("totalEventos").textContent = eventos.length;
  byId("totalSucesso").textContent = eventos.filter(
    (evento) => normalizarStatus(evento.status) === "SUCESSO"
  ).length;
  byId("totalFalha").textContent = eventos.filter(
    (evento) => normalizarStatus(evento.status) === "FALHA"
  ).length;
}

function renderizarEventos() {
  const filtrados = eventos.filter((evento) => {
    const status = normalizarStatus(evento.status);
    return filtroStatus.value === "TODOS" || status === normalizarStatus(filtroStatus.value);
  });

  if (!filtrados.length) {
    eventList.innerHTML = '<div class="empty-state">Nenhum evento encontrado para este filtro.</div>';
    return;
  }

  eventList.innerHTML = filtrados.map((evento) => {
    const status = normalizarStatus(evento.status);
    const falha = status === "FALHA";
    const titulo = evento.acao + " · " + evento.usuario;
    const detalhes = [
      evento.data_hora,
      evento.email,
      evento.detalhes,
      "Hash: " + String(evento.hash || "").slice(0, 16) + "…"
    ].filter(Boolean).join(" | ");

    return '<article class="event-item">' +
      '<span class="event-indicator ' + (falha ? "failure" : "") + '"></span>' +
      '<div class="event-main"><div class="event-title">' + escaparHtml(titulo) + '</div>' +
      '<div class="event-meta">' + escaparHtml(detalhes) + '</div></div>' +
      '<span class="event-status ' + (falha ? "failure" : "") + '">' +
      escaparHtml(status) + '</span></article>';
  }).join("");
}

async function carregarEventos() {
  eventList.innerHTML = '<div class="empty-state">Consultando banco de auditoria...</div>';
  try {
    const result = await api("/api/eventos");
    eventos = Array.isArray(result.eventos) ? result.eventos : [];
    atualizarIndicadores();
    renderizarEventos();
  } catch (error) {
    eventList.innerHTML = '<div class="empty-state">' + escaparHtml(error.message) + '</div>';
  }
}

async function verificarIntegridade() {
  const status = byId("integrityFeedback");
  status.textContent = "Verificando cadeia criptográfica...";
  status.className = "integrity-feedback";
  try {
    const result = await api("/api/integridade");
    status.textContent = "✓ Integridade válida · " + result.checked + " registros verificados.";
    status.className = "integrity-feedback valid";
  } catch (error) {
    status.textContent = "⚠ " + error.message;
    status.className = "integrity-feedback invalid";
  }
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setFeedback(loginFeedback, "Autenticando...");
  try {
    const result = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({
        email: byId("loginEmail").value.trim(),
        password: byId("loginPassword").value
      })
    });
    csrfToken = result.csrf_token;
    loginForm.reset();
    mostrarDashboard(result.user);
  } catch (error) {
    setFeedback(loginFeedback, error.message, true);
  }
});

eventForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setFeedback(feedback, "");
  const selectedStatus = eventForm.querySelector('input[name="status"]:checked');
  if (!selectedStatus) {
    setFeedback(feedback, "Selecione o status da operação.", true);
    return;
  }

  try {
    const result = await api("/api/eventos", {
      method: "POST",
      body: JSON.stringify({
        acao: byId("acao").value,
        status: selectedStatus.value,
        detalhes: byId("detalhes").value.trim()
      })
    });
    setFeedback(feedback, "✓ Evento registrado. Hash: " + result.hash.slice(0, 16) + "…");
    eventForm.reset();
    await carregarEventos();
  } catch (error) {
    setFeedback(feedback, error.message, true);
  }
});

byId("logoutButton").addEventListener("click", async () => {
  try {
    const result = await api("/api/logout", { method: "POST", body: "{}" });
    csrfToken = result.csrf_token;
    mostrarLogin("Sessão encerrada com sucesso.");
  } catch (error) {
    mostrarLogin(error.message);
  }
});

byId("refreshButton").addEventListener("click", carregarEventos);
byId("verifyButton").addEventListener("click", verificarIntegridade);
filtroStatus.addEventListener("change", renderizarEventos);

async function inicializar() {
  try {
    const response = await fetch("/api/status", {
      credentials: "same-origin",
      cache: "no-store"
    });
    const status = await response.json();
    csrfToken = status.csrf_token || "";
    if (status.authenticated && status.user) {
      mostrarDashboard(status.user);
    } else {
      mostrarLogin();
    }
  } catch (error) {
    mostrarLogin("Não foi possível conectar ao serviço de autenticação.");
  }
}

inicializar();
