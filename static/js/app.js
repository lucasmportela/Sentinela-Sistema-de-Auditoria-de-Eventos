const form = document.getElementById("formEvento");
const eventList = document.getElementById("eventList");
const feedback = document.getElementById("feedback");
const filtroStatus = document.getElementById("filtroStatus");

let eventos = [];

function escaparHtml(valor) {
  return String(valor).replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[c]));
}

function normalizarStatus(status) {
  return String(status || "").trim().toUpperCase();
}

function atualizarIndicadores() {
  const total = eventos.length;

  const sucessos = eventos.filter(
    evento => normalizarStatus(evento.status) === "SUCESSO"
  ).length;

  const falhas = eventos.filter(
    evento => normalizarStatus(evento.status) === "FALHA"
  ).length;

  document.getElementById("totalEventos").textContent = total;
  document.getElementById("totalSucesso").textContent = sucessos;
  document.getElementById("totalFalha").textContent = falhas;
}

function renderizarEventos() {
  const filtrados = eventos.filter(evento => {
    const status = normalizarStatus(evento.status);
    return filtroStatus.value === "TODOS" ||
      status === normalizarStatus(filtroStatus.value);
  });

  if (!filtrados.length) {
    eventList.innerHTML =
      '<div class="empty-state">Nenhum evento encontrado para este filtro.</div>';
    return;
  }

  eventList.innerHTML = filtrados.map(evento => {
    const status = normalizarStatus(evento.status);
    const falha = status === "FALHA";
    const titulo = evento.acao
      ? `${evento.acao} · ${evento.usuario || ""}`
      : "REGISTRO";

    const detalhes = [
      evento.data_hora,
      evento.usuario ? `Usuário: ${evento.usuario}` : "",
      evento.acao ? `Ação: ${evento.acao}` : "",
      status ? `Status: ${status}` : "",
      evento.linha || ""
    ].filter(Boolean).join(" | ");

    return `
      <article class="event-item">
        <span class="event-indicator ${falha ? "failure" : ""}"></span>
        <div class="event-main">
          <div class="event-title">${escaparHtml(titulo)}</div>
          <div class="event-meta">${escaparHtml(detalhes)}</div>
        </div>
        <span class="event-status ${falha ? "failure" : ""}">
          ${escaparHtml(status || "LOG")}
        </span>
      </article>
    `;
  }).join("");
}

async function carregarEventos() {
  eventList.innerHTML =
    '<div class="empty-state">Consultando arquivo de auditoria...</div>';

  try {
    const resposta = await fetch("/api/eventos", { cache: "no-store" });

    if (!resposta.ok) {
      throw new Error("Não foi possível consultar o histórico.");
    }

    const dados = await resposta.json();
    eventos = Array.isArray(dados) ? dados : [];

    atualizarIndicadores();
    renderizarEventos();
  } catch (erro) {
    eventList.innerHTML =
      `<div class="empty-state">${escaparHtml(erro.message)}</div>`;
  }
}

form.addEventListener("submit", async evento => {
  evento.preventDefault();
  feedback.textContent = "";
  feedback.className = "feedback";

  const campoStatus = form.querySelector('input[name="status"]:checked');

  if (!campoStatus) {
    feedback.textContent = "Selecione o status da operação.";
    feedback.classList.add("error");
    return;
  }

  const dados = {
    usuario: document.getElementById("usuario").value.trim(),
    acao: document.getElementById("acao").value,
    status: campoStatus.value
  };

  try {
    const resposta = await fetch("/api/eventos", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(dados)
    });

    const resultado = await resposta.json();

    if (!resposta.ok) {
      throw new Error(resultado.erro || "Erro ao registrar evento.");
    }

    feedback.textContent = "✓ Evento gravado no arquivo de auditoria.";
    form.reset();
    await carregarEventos();
  } catch (erro) {
    feedback.textContent = erro.message;
    feedback.classList.add("error");
  }
});

filtroStatus.addEventListener("change", renderizarEventos);
document.getElementById("refreshButton").addEventListener("click", carregarEventos);

carregarEventos();
