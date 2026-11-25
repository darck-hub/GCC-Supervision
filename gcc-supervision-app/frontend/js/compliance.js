import { apiRequest } from "./api.js";
import { hasRole } from "./auth.js";
import { badge, clear, el } from "./dom.js";

export async function renderCompliance(container) {
  clear(container);
  const status = await apiRequest("/api/compliance/status");
  const ind = status.cnil_indicators;
  const pca = status.pca;

  container.appendChild(
    el("div", { class: "kpi-grid" }, [
      tile("Plan de Continuité (PCA)", pca.status, `${pca.active_p1_incidents} P1 actif(s) • RTO ${pca.rto_target_minutes}m`, pca.status),
      tile("Stockage JWT", "RAM Uniquement", `Auto-logout ${ind.session_timeout_minutes} min (anti-XSS)`, "ACTIF"),
      tile("Base de données", `SQLite ${ind.sqlite_journal_mode}`, "Requêtes 100% paramétrées", "ACTIF"),
      tile("Traçabilité Audit", `${ind.audit_events_recorded} événements`, `Rétention ${ind.audit_retention_days} jours`, "ACTIF"),
    ])
  );

  // Tableau des 7 couches de sécurité
  const layerRows = status.security_layers.map((l) =>
    el("tr", {}, [
      el("td", {}, el("strong", {}, l.layer)),
      el("td", {}, l.control),
      el("td", {}, el("code", {}, l.ref)),
      el("td", {}, badge(l.status, l.status === "ACTIF" ? "ACTIF" : "WARNING")),
    ])
  );

  container.appendChild(
    el("div", { class: "panel" }, [
      el("div", { class: "panel-header" }, el("div", { class: "panel-title" }, "Architecture de défense en profondeur (7 couches ANSSI / CNIL)")),
      el(
        "div",
        { class: "table-wrap" },
        el("table", {}, [
          el("thead", {}, el("tr", {}, [
            el("th", {}, "Couche"),
            el("th", {}, "Mécanisme implémenté"),
            el("th", {}, "Référentiel"),
            el("th", {}, "État"),
          ])),
          el("tbody", {}, layerRows),
        ])
      ),
    ])
  );

  // Journal d'audit immuable (Admin / Auditeur)
  if (hasRole("admin", "auditeur")) {
    const logsRes = await apiRequest("/api/compliance/audit-logs?limit=40");
    const logRows = logsRes.audit_logs.map((a) =>
      el("tr", {}, [
        el("td", {}, el("code", {}, a.timestamp)),
        el("td", {}, `${a.username} (${a.role})`),
        el("td", {}, el("code", {}, a.action)),
        el("td", {}, a.target),
        el("td", {}, a.ip_address),
        el("td", {}, badge(a.status, a.status)),
        el("td", {}, a.details || "—"),
      ])
    );

    container.appendChild(
      el("div", { class: "panel" }, [
        el("div", { class: "panel-header" }, el("div", { class: "panel-title" }, "Journal d'audit sécurité & exploitation (CNIL / RCA)")),
        el(
          "div",
          { class: "table-wrap" },
          el("table", {}, [
            el("thead", {}, el("tr", {}, [
              el("th", {}, "Horodatage UTC"),
              el("th", {}, "Opérateur"),
              el("th", {}, "Action"),
              el("th", {}, "Cible"),
              el("th", {}, "IP"),
              el("th", {}, "Statut"),
              el("th", {}, "Détails"),
            ])),
            el("tbody", {}, logRows),
          ])
        ),
      ])
    );
  }
}

function tile(label, value, sub, variant) {
  return el("div", { class: "kpi-card" }, [
    el("div", { class: "kpi-label" }, label),
    el("div", { class: "mt-1" }, badge(value, variant)),
    el("div", { class: "kpi-sub mt-1" }, sub),
  ]);
}
