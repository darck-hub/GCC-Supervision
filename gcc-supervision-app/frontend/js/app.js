import { apiRequest, setUnauthorizedHandler } from "./api.js";
import { clearSession, getUser, isAuthenticated, setSession } from "./auth.js";
import { showToast } from "./dom.js";
import { renderDashboard } from "./dashboard.js";
import { renderRouting } from "./routing.js";
import { renderIncidents } from "./incidents.js";
import { renderTicketSheet } from "./sheet.js";
import { renderAdmin } from "./admin.js";
import { renderCompliance } from "./compliance.js";

const loginView = document.getElementById("login-view");
const appShell = document.getElementById("app-shell");
const mainContent = document.getElementById("main-content");
const viewTitle = document.getElementById("view-title");
const loginForm = document.getElementById("login-form");
const loginError = document.getElementById("login-error");
const userBadge = document.getElementById("user-badge");
const rgpdBanner = document.getElementById("rgpd-banner");

let currentView = "dashboard";
let selectedTicketId = null;

const VIEW_TITLES = {
  dashboard: "Tableau de bord temps réel (Supervision)",
  routing: "Matrice de routage & Dispatching opérationnel",
  incidents: "Registre général des incidents distribués",
  sheet: "Fiche d'exploitation certifiée GCC",
  admin: "Administration — Comptes RBAC & Collecteurs",
  compliance: "Conformité CNIL, Sécurité ANSSI & PCA",
};

function handleForceLogout(reason) {
  clearSession();
  appShell.classList.add("hidden");
  loginView.classList.remove("hidden");
  if (reason) {
    loginError.textContent = reason;
    loginError.classList.remove("hidden");
  }
}

setUnauthorizedHandler(handleForceLogout);

function setActiveNav(view) {
  currentView = view;
  viewTitle.textContent = VIEW_TITLES[view] || "Supervision GCC";
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.view === view);
  });
}

async function navigate(view) {
  if (!isAuthenticated()) {
    handleForceLogout("Veuillez vous authentifier.");
    return;
  }
  setActiveNav(view);
  const helpers = {
    openTicket: (id) => {
      selectedTicketId = id;
      navigate("sheet");
    },
    backToIncidents: () => navigate("incidents"),
  };

  try {
    if (view === "dashboard") await renderDashboard(mainContent, helpers);
    else if (view === "routing") await renderRouting(mainContent, helpers);
    else if (view === "incidents") await renderIncidents(mainContent, helpers);
    else if (view === "sheet") await renderTicketSheet(mainContent, selectedTicketId, helpers);
    else if (view === "admin") await renderAdmin(mainContent);
    else if (view === "compliance") await renderCompliance(mainContent);
  } catch (err) {
    showToast(err.message, true);
  }
}

loginForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  loginError.classList.add("hidden");
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;

  try {
    const res = await apiRequest("/api/auth/login", {
      method: "POST",
      body: { username, password },
    });
    setSession(res, handleForceLogout);
    document.getElementById("login-password").value = "";

    const u = getUser();
    userBadge.textContent = `${u.full_name} [${u.role.toUpperCase()} • ${u.plateau}]`;
    loginView.classList.add("hidden");
    appShell.classList.remove("hidden");
    showToast(`Bienvenue ${u.full_name}. Session JWT volatile (15 min) active.`);
    await navigate("dashboard");
  } catch (err) {
    loginError.textContent = err.message;
    loginError.classList.remove("hidden");
  }
});

document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => navigate(btn.dataset.view));
});

document.getElementById("refresh-btn").addEventListener("click", () => navigate(currentView));

document.getElementById("logout-btn").addEventListener("click", async () => {
  try {
    await apiRequest("/api/auth/logout", { method: "POST" });
  } catch (_) {
    // Nettoyage RAM garanti même si le jeton vient d'expirer
  }
  handleForceLogout();
  showToast("Déconnexion effectuée : jeton révoqué et RAM purgée.");
});

// Horloge UTC temps réel
function updateClock() {
  const now = new Date();
  const clock = document.getElementById("live-clock");
  if (clock) {
    clock.textContent = `UTC ${now.toISOString().slice(11, 19)}`;
  }
}
updateClock();
setInterval(updateClock, 1000);

// Bandeau d'information RGPD (mémorisation non sensible en sessionStorage)
if (!sessionStorage.getItem("gcc_rgpd_ack")) {
  rgpdBanner.classList.remove("hidden");
}
document.getElementById("rgpd-accept-btn").addEventListener("click", () => {
  sessionStorage.setItem("gcc_rgpd_ack", "1");
  rgpdBanner.classList.add("hidden");
});
