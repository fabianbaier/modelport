const state = {
  actor: null,
  team: null,
  teams: [],
  services: [],
  sessions: [],
  audit: [],
  pendingInvite: new URLSearchParams(window.location.search).get("invite")
};

const authPanel = document.querySelector("#auth-panel");
const authForm = document.querySelector("#auth-form");
const authMessage = document.querySelector("#auth-message");
const workspace = document.querySelector("#workspace");
const userSummary = document.querySelector("#user-summary");
const signOut = document.querySelector("#sign-out");
const teamsEl = document.querySelector("#teams");
const servicesEl = document.querySelector("#services");
const sessionsEl = document.querySelector("#sessions");
const auditEl = document.querySelector("#audit");
const inviteForm = document.querySelector("#invite-form");
const inviteResult = document.querySelector("#invite-result");
const metrics = {
  services: document.querySelector("#metric-services"),
  sessions: document.querySelector("#metric-sessions"),
  models: document.querySelector("#metric-models")
};

function html(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    credentials: "same-origin",
    headers: { "content-type": "application/json", ...(options.headers || {}) }
  });
  const body = response.status === 204 ? null : await response.json();
  if (!response.ok) {
    throw new Error(body?.error?.message || `request failed: ${response.status}`);
  }
  return body;
}

function empty(message) {
  const div = document.createElement("div");
  div.className = "empty";
  div.textContent = message;
  return div;
}

function setSignedIn(actor) {
  state.actor = actor;
  authPanel.hidden = true;
  workspace.hidden = false;
  signOut.hidden = false;
  userSummary.textContent = actor.email;
}

function setSignedOut(message = "") {
  state.actor = null;
  state.team = null;
  state.teams = [];
  state.services = [];
  state.sessions = [];
  state.audit = [];
  authPanel.hidden = false;
  workspace.hidden = true;
  signOut.hidden = true;
  userSummary.textContent = "Signed out";
  authMessage.textContent = message || (state.pendingInvite ? "Sign in with the invited email to join the team." : "");
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
    button.innerHTML = `<strong>${html(team.display_name)}</strong><br /><small>${html(team.slug)}</small>`;
    button.addEventListener("click", () => {
      state.team = team;
      refreshTeamData().catch((error) => alert(error.message));
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
          <h3>${html(service.name)}</h3>
          <small>${html(service.kind)}</small>
        </div>
        <span class="pill${statusClass}">${html(service.status)}</span>
      </header>
      <dl>
        <dt>Upstream</dt><dd>${html(service.upstream_hint)}</dd>
        <dt>Hub bind</dt><dd>${html(service.current_hub_bind || "not connected")}</dd>
        <dt>Models</dt><dd>${service.models.map((model) => html(model.id)).join(", ") || "none"}</dd>
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
            <td>${html(session.direction)}</td>
            <td>${html(service?.name || session.service_id)}</td>
            <td>${html(session.hub_bind || "")}</td>
            <td>${html(session.local_bind || "")}</td>
            <td>${html(new Date(session.started_at).toLocaleString())}</td>
            <td>${html(session.closed_at ? session.close_reason : "active")}</td>
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
    row.innerHTML = `<strong>${html(event.kind)}</strong><br /><small>${html(
      new Date(event.created_at).toLocaleString()
    )}</small><p>${html(event.message)}</p>`;
    auditEl.append(row);
  }
}

function render() {
  renderTeams();
  renderServices();
  renderSessions();
  renderAudit();
  inviteForm.hidden = !state.team;
}

async function acceptPendingInvite() {
  if (!state.pendingInvite) {
    return;
  }
  const data = await api("/api/v1/invites/accept", {
    method: "POST",
    body: JSON.stringify({ token: state.pendingInvite })
  });
  state.pendingInvite = null;
  window.history.replaceState({}, "", window.location.pathname);
  state.team = data.team;
  authMessage.textContent = "";
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

authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    const data = await api("/api/v1/auth/signup", {
      method: "POST",
      body: JSON.stringify({ email: form.get("email") })
    });
    setSignedIn(data.user);
    await acceptPendingInvite();
    await refreshAll();
  } catch (error) {
    authMessage.textContent = error.message;
  }
});

signOut.addEventListener("click", async () => {
  await api("/api/v1/auth/logout", { method: "POST" });
  setSignedOut();
});

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

inviteForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.team) {
    return;
  }
  const form = new FormData(event.currentTarget);
  const data = await api(`/api/v1/teams/${encodeURIComponent(state.team.team_id)}/invites`, {
    method: "POST",
    body: JSON.stringify({ email: form.get("email"), role: form.get("role") })
  });
  inviteResult.textContent = data.accept_url;
});

document.querySelector("#refresh").addEventListener("click", () => refreshAll().catch((error) => alert(error.message)));

api("/api/v1/me")
  .then(async (data) => {
    setSignedIn(data.actor);
    await acceptPendingInvite();
    await refreshAll();
  })
  .catch(() => setSignedOut());
