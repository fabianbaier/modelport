const state = {
  team: null,
  teams: [],
  services: [],
  sessions: [],
  audit: []
};

const userInput = document.querySelector("#user-email");
const teamsEl = document.querySelector("#teams");
const servicesEl = document.querySelector("#services");
const sessionsEl = document.querySelector("#sessions");
const auditEl = document.querySelector("#audit");
const metrics = {
  services: document.querySelector("#metric-services"),
  sessions: document.querySelector("#metric-sessions"),
  models: document.querySelector("#metric-models")
};

function authHeaders() {
  return {
    "content-type": "application/json",
    authorization: `Bearer dev:${userInput.value.trim() || "owner@modelport.dev"}`
  };
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { ...authHeaders(), ...(options.headers || {}) }
  });
  const body = await response.json();
  if (!response.ok) {
    throw new Error(body.error?.message || `request failed: ${response.status}`);
  }
  return body;
}

function empty(message) {
  const div = document.createElement("div");
  div.className = "empty";
  div.textContent = message;
  return div;
}

function renderTeams() {
  teamsEl.replaceChildren();
  if (state.teams.length === 0) {
    teamsEl.append(empty("No teams yet."));
    return;
  }
  for (const team of state.teams) {
    const button = document.createElement("button");
    button.className = `team-row secondary${state.team?.team_id === team.team_id ? " active" : ""}`;
    button.type = "button";
    button.innerHTML = `<strong>${team.display_name}</strong><br /><small>${team.slug}</small>`;
    button.addEventListener("click", () => {
      state.team = team;
      refreshTeamData();
    });
    teamsEl.append(button);
  }
}

function renderServices() {
  servicesEl.replaceChildren();
  metrics.services.textContent = String(state.services.length);
  metrics.models.textContent = String(state.services.reduce((sum, service) => sum + service.models.length, 0));
  if (!state.team) {
    servicesEl.append(empty("Select a team."));
    return;
  }
  if (state.services.length === 0) {
    servicesEl.append(empty("No services registered. Run modelport serve to add one."));
    return;
  }
  for (const service of state.services) {
    const article = document.createElement("article");
    article.className = "service-card";
    const statusClass = service.status === "online" ? "" : " offline";
    article.innerHTML = `
      <header>
        <div>
          <h3>${service.name}</h3>
          <small>${service.kind}</small>
        </div>
        <span class="pill${statusClass}">${service.status}</span>
      </header>
      <dl>
        <dt>Upstream</dt><dd>${service.upstream_hint}</dd>
        <dt>Hub bind</dt><dd>${service.current_hub_bind || "not connected"}</dd>
        <dt>Models</dt><dd>${service.models.map((model) => model.id).join(", ") || "none"}</dd>
      </dl>
    `;
    servicesEl.append(article);
  }
}

function renderSessions() {
  sessionsEl.replaceChildren();
  metrics.sessions.textContent = String(state.sessions.length);
  if (!state.team) {
    sessionsEl.append(empty("Select a team."));
    return;
  }
  if (state.sessions.length === 0) {
    sessionsEl.append(empty("No tunnel sessions yet."));
    return;
  }
  const table = document.createElement("table");
  table.innerHTML = `
    <thead>
      <tr><th>Direction</th><th>Service</th><th>Hub bind</th><th>Local bind</th><th>Started</th><th>Status</th></tr>
    </thead>
    <tbody>
      ${state.sessions
        .map((session) => {
          const service = state.services.find((item) => item.service_id === session.service_id);
          return `<tr>
            <td>${session.direction}</td>
            <td>${service?.name || session.service_id}</td>
            <td>${session.hub_bind || ""}</td>
            <td>${session.local_bind || ""}</td>
            <td>${new Date(session.started_at).toLocaleString()}</td>
            <td>${session.closed_at ? session.close_reason : "active"}</td>
          </tr>`;
        })
        .join("")}
    </tbody>
  `;
  sessionsEl.append(table);
}

function renderAudit() {
  auditEl.replaceChildren();
  if (!state.team) {
    auditEl.append(empty("Select a team."));
    return;
  }
  if (state.audit.length === 0) {
    auditEl.append(empty("No audit events yet."));
    return;
  }
  for (const event of state.audit.slice().reverse().slice(0, 20)) {
    const row = document.createElement("div");
    row.className = "audit-row";
    row.innerHTML = `<strong>${event.kind}</strong><br /><small>${new Date(event.created_at).toLocaleString()}</small><p>${event.message}</p>`;
    auditEl.append(row);
  }
}

function render() {
  renderTeams();
  renderServices();
  renderSessions();
  renderAudit();
}

async function refreshTeams() {
  const data = await api("/api/v1/teams");
  state.teams = data.teams;
  if (!state.team && state.teams.length > 0) {
    state.team = state.teams[0];
  }
}

async function refreshTeamData() {
  render();
  if (!state.team) {
    return;
  }
  const teamParam = encodeURIComponent(state.team.team_id);
  const [services, sessions, audit] = await Promise.all([
    api(`/api/v1/tunnel/services?team_id=${teamParam}`),
    api(`/api/v1/tunnel/sessions?team_id=${teamParam}`),
    api(`/api/v1/audit?team_id=${teamParam}`)
  ]);
  state.services = services.services;
  state.sessions = sessions.sessions;
  state.audit = audit.audit;
  render();
}

async function refreshAll() {
  await refreshTeams();
  await refreshTeamData();
}

document.querySelector("#team-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const result = await api("/api/v1/teams", {
    method: "POST",
    body: JSON.stringify({
      slug: form.get("slug"),
      display_name: form.get("display_name")
    })
  });
  state.team = result.team;
  await refreshAll();
});

document.querySelector("#refresh").addEventListener("click", refreshAll);
userInput.addEventListener("change", () => {
  state.team = null;
  state.teams = [];
  state.services = [];
  state.sessions = [];
  state.audit = [];
  refreshAll().catch((error) => alert(error.message));
});

refreshAll().catch((error) => {
  servicesEl.replaceChildren(empty(error.message));
});
