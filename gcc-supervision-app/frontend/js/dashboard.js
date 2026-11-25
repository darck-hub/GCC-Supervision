import { apiRequest } from "./api.js";
import { hasRole } from "./auth.js";
import { badge, clear, el, formatSla, showToast } from "./dom.js";

export async function renderDashboard(container, { openTicket }) {
  clear(container);
  const data = await apiRequest("/api/dashboard/overview");

  // Mise à jour bandeau shift 3/8
  const shiftName = document.getElementById("shift-name");
  const shiftSlot = document.getElementById("shift-slot");
  if (shiftName) shiftName.textContent = data.shift.name;
  if (shiftSlot) shiftSlot.textContent = `${data.shift.slot} • ${data.shift.mode}`;

  const k = data.kpis;
  const kpiGrid = el("div", { class: "kpi-grid" }, [
    kpiCard("Tickets ouverts", k.open_tickets, "Incidents en cours de pilotage"),
    kpiCard("Critiques P1 / P2", k.critical_p1_p2, "Mobilisation immédiate / RCA"),
    kpiCard("Conformité SLA", `${k.sla_compliance_pct}%`, `${k.sla_at_risk} ticket(s) à risque`),
    kpiCard("Services opérationnels", `${k.active_services_ok}/${k.active_services_total}`, "Multi-Client & Plateau Banque"),
    kpiCard("Bruit dédupliqué (HAL)", k.alerts_deduplicated, "Événements corrélés automatiquement"),
  ]);
  container.appendChild(kpiGrid);

  // Barre d'action rapide (Simulation d'alerte sonde)
  if (hasRole("admin", "pilote")) {
    const presetSel = el("select", { id: "sim-preset" }, [
      el("option", { value: "zos_rc0016" }, "Mainframe z/OS — Abend COBOL RC-0016 (P1)"),
      el("option", { value: "zos_b37" }, "Mainframe z/OS — Saturation Disque B37 (P1)"),
      el("option", { value: "db2_deadlock" }, "HAL/Netcool — DB2 Deadlock -911 (P2)"),
      el("option", { value: "net_link" }, "Centreon — Perte lien Backbone LINK_DOWN (P1)"),
      el("option", { value: "cpu_spike" }, "Zabbix — Pic CPU Serveur > 94% (P3)"),
    ]);

    const simBtn = el(
      "button",
      {
        class: "btn btn-primary btn-sm",
        onClick: async () => {
          try {
            const res = await apiRequest("/api/webhooks/simulate", {
              method: "POST",
              body: { preset: presetSel.value },
            });
            const msg = res.deduplicated
              ? `Alerte dédupliquée par HAL (x${res.occurrence_count} occurrences).`
              : `Nouvelle alerte ${res.severity} ingérée${res.ticket_reference ? ` -> Ticket ${res.ticket_reference} ouvert` : ""}.`;
            showToast(msg);
            await renderDashboard(container, { openTicket });
          } catch (err) {
            showToast(err.message, true);
          }
        },
      },
      "Simuler réception sonde"
    );

    container.appendChild(
      el("div", { class: "panel" }, [
        el("div", { class: "panel-header" }, [
          el("div", { class: "panel-title" }, "Simulateur de flux supervision (HAL / z/OS / Centreon / Zabbix)"),
          el("div", { class: "btn-row" }, [presetSel, simBtn]),
        ]),
      ])
    );
  }

  // Grille 2 colonnes : État des services + Tickets prioritaires SLA
  const servicesTable = el("table", {}, [
    el("thead", {}, el("tr", {}, [
      el("th", {}, "Service"),
      el("th", {}, "Plateau"),
      el("th", {}, "État"),
      el("th", {}, "Latence"),
      el("th", {}, "Dispo."),
    ])),
    el(
      "tbody",
      {},
      data.services.map((s) =>
        el("tr", {}, [
          el("td", {}, [el("strong", {}, s.name), el("div", { class: "kpi-sub" }, s.tool)]),
          el("td", {}, badge(s.plateau, "neutral")),
          el("td", {}, badge(s.status, s.status)),
          el("td", {}, `${s.latency_ms} ms`),
          el("td", {}, `${s.uptime_pct}%`),
        ])
      )
    ),
  ]);

  const prioTable = el("table", {}, [
    el("thead", {}, el("tr", {}, [
      el("th", {}, "Réf."),
      el("th", {}, "Prio."),
      el("th", {}, "Incident"),
      el("th", {}, "SLA"),
      el("th", {}, "Fiche"),
    ])),
    el(
      "tbody",
      {},
      data.priority_tickets.map((t) =>
        el("tr", {}, [
          el("td", {}, el("code", {}, t.reference)),
          el("td", {}, badge(t.priority, t.priority)),
          el("td", {}, [el("div", {}, t.title), el("div", { class: "kpi-sub" }, `${t.host} • ${t.assigned_group}`)]),
          el("td", {}, formatSla(t.sla_remaining_sec, t.sla_state)),
          el(
            "td",
            {},
            el(
              "button",
              { class: "btn btn-secondary btn-sm", onClick: () => openTicket(t.id) },
              "Ouvrir"
            )
          ),
        ])
      )
    ),
  ]);

  container.appendChild(
    el("div", { class: "grid-2" }, [
      el("div", { class: "panel" }, [
        el("div", { class: "panel-header" }, el("div", { class: "panel-title" }, "État des services critiques")),
        el("div", { class: "table-wrap" }, servicesTable),
      ]),
      el("div", { class: "panel" }, [
        el("div", { class: "panel-header" }, el("div", { class: "panel-title" }, "Incidents prioritaires & Surveillance SLA")),
        el("div", { class: "table-wrap" }, prioTable),
      ]),
    ])
  );
}

function kpiCard(label, value, sub) {
  return el("div", { class: "kpi-card" }, [
    el("div", { class: "kpi-label" }, label),
    el("div", { class: "kpi-value" }, value),
    el("div", { class: "kpi-sub" }, sub),
  ]);
}
