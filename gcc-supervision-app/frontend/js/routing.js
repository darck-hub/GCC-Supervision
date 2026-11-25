import { apiRequest } from "./api.js";
import { hasRole } from "./auth.js";
import { badge, clear, el, showToast } from "./dom.js";

export async function renderRouting(container, { openTicket }) {
  clear(container);
  const [alertsRes, rulesRes, procsRes] = await Promise.all([
    apiRequest("/api/routing/alerts"),
    apiRequest("/api/routing/rules"),
    apiRequest("/api/procedures"),
  ]);

  // 1. File des alertes corrélées (Dispatching N1)
  const alertRows = alertsRes.alerts.map((a) => {
    const actions = [];
    if (a.ticket_id) {
      actions.push(
        el(
          "button",
          { class: "btn btn-secondary btn-sm", onClick: () => openTicket(a.ticket_id) },
          `Ticket #${a.ticket_id}`
        )
      );
    } else if (a.status === "ACTIVE" && hasRole("admin", "pilote", "n2")) {
      actions.push(
        el(
          "button",
          {
            class: "btn btn-primary btn-sm",
            onClick: async () => {
              try {
                const res = await apiRequest(`/api/routing/alerts/${a.id}/dispatch`, {
                  method: "POST",
                  body: {
                    action: "qualify",
                    priority: a.severity,
                    target_group: a.plateau === "Banque" ? "Équipe Mainframe z/OS N2" : "Équipe Réseau N2",
                    procedure_code: a.plateau === "Banque" ? "PROC-ZOS-016" : "PROC-NET-001",
                  },
                });
                showToast(`Ticket ${res.reference} ouvert et dispatché.`);
                await renderRouting(container, { openTicket });
              } catch (err) {
                showToast(err.message, true);
              }
            },
          },
          "Qualifier & Dispatcher"
        ),
        el(
          "button",
          {
            class: "btn btn-secondary btn-sm",
            onClick: async () => {
              try {
                await apiRequest(`/api/routing/alerts/${a.id}/dispatch`, {
                  method: "POST",
                  body: { action: "ack" },
                });
                showToast("Alerte acquittée (faux positif).");
                await renderRouting(container, { openTicket });
              } catch (err) {
                showToast(err.message, true);
              }
            },
          },
          "Acquitter"
        )
      );
    } else {
      actions.push(badge(a.status, "neutral"));
    }

    return el("tr", {}, [
      el("td", {}, badge(a.severity, a.severity)),
      el("td", {}, [el("strong", {}, a.host), el("div", { class: "kpi-sub" }, `${a.source_tool} • ${a.plateau}`)]),
      el("td", {}, el("code", {}, a.error_code)),
      el("td", {}, a.message),
      el("td", {}, badge(`x${a.occurrence_count}`, a.occurrence_count > 1 ? "WARNING" : "neutral")),
      el("td", {}, badge(a.status, a.status)),
      el("td", {}, el("div", { class: "btn-row" }, actions)),
    ]);
  });

  container.appendChild(
    el("div", { class: "panel" }, [
      el("div", { class: "panel-header" }, [
        el("div", { class: "panel-title" }, "File de corrélation & Dispatching opérationnel (HAL / Centreon / Zabbix)"),
      ]),
      el(
        "div",
        { class: "table-wrap" },
        el("table", {}, [
          el("thead", {}, el("tr", {}, [
            el("th", {}, "Sév."),
            el("th", {}, "Hôte / Outil"),
            el("th", {}, "Code"),
            el("th", {}, "Message"),
            el("th", {}, "Dédup."),
            el("th", {}, "État"),
            el("th", {}, "Action"),
          ])),
          el("tbody", {}, alertRows),
        ])
      ),
    ])
  );

  // 2. Matrice de règles automatiques
  const ruleRows = rulesRes.rules.map((r) => {
    const delBtn = hasRole("admin")
      ? el(
          "button",
          {
            class: "btn btn-danger btn-sm",
            onClick: async () => {
              try {
                await apiRequest(`/api/routing/rules/${r.id}`, { method: "DELETE" });
                showToast("Règle supprimée.");
                await renderRouting(container, { openTicket });
              } catch (err) {
                showToast(err.message, true);
              }
            },
          },
          "Supprimer"
        )
      : el("span", { class: "kpi-sub" }, "—");

    return el("tr", {}, [
      el("td", {}, r.name),
      el("td", {}, el("code", {}, r.keyword)),
      el("td", {}, r.source_tool),
      el("td", {}, badge(r.priority, r.priority)),
      el("td", {}, r.target_group),
      el("td", {}, r.procedure_code ? el("code", {}, r.procedure_code) : "—"),
      el("td", {}, r.auto_create_ticket ? badge("AUTO-TICKET", "OK") : badge("MANUEL", "neutral")),
      el("td", {}, delBtn),
    ]);
  });

  const rulesPanelChildren = [
    el("div", { class: "panel-header" }, el("div", { class: "panel-title" }, "Matrice de routage automatique (P1–P4 -> Groupes N1/N2/N3)")),
    el(
      "div",
      { class: "table-wrap" },
      el("table", {}, [
        el("thead", {}, el("tr", {}, [
          el("th", {}, "Règle"),
          el("th", {}, "Mot-clé / Code"),
          el("th", {}, "Outil"),
          el("th", {}, "Priorité"),
          el("th", {}, "Groupe cible"),
          el("th", {}, "Procédure"),
          el("th", {}, "Mode"),
          el("th", {}, "Admin"),
        ])),
        el("tbody", {}, ruleRows),
      ])
    ),
  ];

  if (hasRole("admin", "pilote")) {
    const nameIn = el("input", { placeholder: "Ex: Erreur Batch S0C7", required: "true" });
    const kwIn = el("input", { placeholder: "Ex: S0C7", required: "true" });
    const toolIn = el("input", { value: "Mainframe z/OS" });
    const prioSel = el("select", {}, ["P1", "P2", "P3", "P4"].map((p) => el("option", { value: p }, p)));
    const groupIn = el("input", { value: "Équipe Mainframe z/OS N2" });
    const procSel = el("select", {}, [
      el("option", { value: "" }, "Aucune procédure"),
      ...procsRes.procedures.map((p) => el("option", { value: p.code }, `${p.code} — ${p.title}`)),
    ]);

    const addForm = el(
      "form",
      {
        class: "form-stack",
        onSubmit: async (ev) => {
          ev.preventDefault();
          try {
            await apiRequest("/api/routing/rules", {
              method: "POST",
              body: {
                name: nameIn.value,
                keyword: kwIn.value,
                source_tool: toolIn.value,
                plateau: "Banque",
                priority: prioSel.value,
                target_group: groupIn.value,
                procedure_code: procSel.value || null,
                auto_create_ticket: true,
              },
            });
            showToast("Règle ajoutée à la matrice de routage.");
            await renderRouting(container, { openTicket });
          } catch (err) {
            showToast(err.message, true);
          }
        },
      },
      [
        el("div", { class: "form-grid" }, [
          el("div", { class: "field" }, [el("label", {}, "Nom de la règle"), nameIn]),
          el("div", { class: "field" }, [el("label", {}, "Mot-clé / Code erreur"), kwIn]),
          el("div", { class: "field" }, [el("label", {}, "Outil source"), toolIn]),
          el("div", { class: "field" }, [el("label", {}, "Priorité"), prioSel]),
          el("div", { class: "field" }, [el("label", {}, "Groupe support cible"), groupIn]),
          el("div", { class: "field" }, [el("label", {}, "Procédure certifiée"), procSel]),
        ]),
        el("div", {}, el("button", { type: "submit", class: "btn btn-primary btn-sm" }, "Ajouter la règle")),
      ]
    );

    rulesPanelChildren.push(el("hr", { class: "hidden" }), el("div", { class: "panel-header" }, el("div", { class: "panel-title" }, "Nouvelle règle de routage")), addForm);
  }

  container.appendChild(el("div", { class: "panel" }, rulesPanelChildren));
}
