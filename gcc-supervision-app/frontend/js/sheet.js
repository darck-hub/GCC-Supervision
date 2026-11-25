import { apiRequest } from "./api.js";
import { hasRole } from "./auth.js";
import { badge, clear, el, formatSla, showToast } from "./dom.js";

export async function renderTicketSheet(container, ticketId, { backToIncidents }) {
  clear(container);
  if (!ticketId) {
    const list = await apiRequest("/api/tickets");
    if (list.tickets.length > 0) {
      return renderTicketSheet(container, list.tickets[0].id, { backToIncidents });
    }
    container.appendChild(el("div", { class: "panel" }, "Aucun ticket sélectionné."));
    return;
  }

  const { ticket, procedure, comments } = await apiRequest(`/api/tickets/${ticketId}`);

  // En-tête fiche certifiée
  container.appendChild(
    el("div", { class: "panel" }, [
      el("div", { class: "panel-header" }, [
        el("div", {}, [
          el("div", { class: "btn-row" }, [
            el("code", {}, ticket.reference),
            badge(ticket.priority, ticket.priority),
            badge(ticket.status, ticket.status),
            formatSla(ticket.sla_remaining_sec, ticket.sla_state),
            ticket.rca_required ? badge("RCA REQUIS", "WARNING") : null,
          ]),
          el("h3", { class: "mt-1" }, ticket.title),
        ]),
        el("button", { class: "btn btn-secondary btn-sm", onClick: backToIncidents }, "Retour registre"),
      ]),
      el("p", { class: "desc-text" }, ticket.description),
      el("div", { class: "kpi-grid" }, [
        metaTile("Hôte / CI", ticket.host),
        metaTile("Source / Plateau", `${ticket.source_tool} (${ticket.plateau})`),
        metaTile("Code erreur", ticket.error_code || "N/A"),
        metaTile("Groupe affecté", ticket.assigned_group),
        metaTile("Échéance SLA (UTC)", ticket.sla_deadline),
      ]),
    ])
  );

  // Procédure officielle certifiée GCC (ex: PROC-NET-001, PROC-ZOS-016)
  const procPanel = el("div", { class: "panel" }, [
    el("div", { class: "panel-header" }, [
      el(
        "div",
        { class: "panel-title" },
        procedure ? `Procédure Certifiée GCC — ${procedure.code} : ${procedure.title}` : "Procédure Certifiée GCC"
      ),
      procedure && procedure.rundeck_job ? badge(`Rundeck: ${procedure.rundeck_job}`, "OK") : null,
    ]),
    procedure
      ? el("div", { class: "procedure-box" }, procedure.steps)
      : el("p", { class: "kpi-sub" }, "Aucune procédure spécifique rattachée à ce ticket."),
  ]);

  // Pilotage / Escalade N1 -> N2 -> N3
  const rightPanels = [procPanel];
  if (hasRole("admin", "pilote", "n2")) {
    const statusSel = el(
      "select",
      {},
      ["NOUVEAU", "EN_COURS", "ESCALADE_N2", "ESCALADE_N3", "RESOLU", "CLOTURE"].map((s) =>
        el("option", { value: s, selected: s === ticket.status ? "selected" : null }, s)
      )
    );
    const groupIn = el("input", { value: ticket.assigned_group });
    const notesIn = el("textarea", {
      rows: "3",
      placeholder: "Synthèse des actions, diagnostic ou notes de clôture (RCA)...",
    }, ticket.resolution_notes || "");

    const updateForm = el(
      "form",
      {
        class: "form-stack",
        onSubmit: async (ev) => {
          ev.preventDefault();
          try {
            await apiRequest(`/api/tickets/${ticketId}`, {
              method: "PATCH",
              body: {
                status: statusSel.value,
                assigned_group: groupIn.value,
                resolution_notes: notesIn.value,
              },
            });
            showToast("Fiche d'exploitation mise à jour.");
            await renderTicketSheet(container, ticketId, { backToIncidents });
          } catch (err) {
            showToast(err.message, true);
          }
        },
      },
      [
        el("div", { class: "form-grid" }, [
          el("div", { class: "field" }, [el("label", {}, "Cycle de vie / Escalade"), statusSel]),
          el("div", { class: "field" }, [el("label", {}, "Groupe support"), groupIn]),
        ]),
        el("div", { class: "field" }, [el("label", {}, "Notes de résolution / RCA"), notesIn]),
        el("button", { type: "submit", class: "btn btn-primary btn-sm" }, "Enregistrer l'avancement"),
      ]
    );

    rightPanels.push(
      el("div", { class: "panel" }, [
        el("div", { class: "panel-header" }, el("div", { class: "panel-title" }, "Actions d'exploitation & Escalade")),
        updateForm,
      ])
    );
  }

  // Fil de discussion horodaté
  const commentNodes = comments.map((c) =>
    el("div", { class: "comment-item" }, [
      el("div", { class: "comment-meta" }, [
        el("span", {}, [el("strong", {}, c.author), ` (${c.author_role})`]),
        el("span", {}, c.created_at),
      ]),
      el("div", {}, c.content),
    ])
  );

  const threadChildren = [
    el("div", { class: "panel-header" }, el("div", { class: "panel-title" }, "Fil de discussion & Traçabilité d'exploitation")),
    el("div", { class: "comment-list" }, commentNodes),
  ];

  if (hasRole("admin", "pilote", "n2")) {
    const commentIn = el("textarea", {
      rows: "2",
      required: "true",
      placeholder: "Consigne de passation 3/8, résultat job Rundeck, retour d'astreinte...",
    });
    threadChildren.push(
      el(
        "form",
        {
          class: "form-stack",
          onSubmit: async (ev) => {
            ev.preventDefault();
            try {
              await apiRequest(`/api/tickets/${ticketId}/comments`, {
                method: "POST",
                body: { content: commentIn.value },
              });
              showToast("Commentaire horodaté enregistré.");
              await renderTicketSheet(container, ticketId, { backToIncidents });
            } catch (err) {
              showToast(err.message, true);
            }
          },
        },
        [commentIn, el("button", { type: "submit", class: "btn btn-primary btn-sm" }, "Publier dans le fil")]
      )
    );
  }

  container.appendChild(
    el("div", { class: "grid-2" }, [
      el("div", { class: "form-stack" }, rightPanels),
      el("div", { class: "panel" }, threadChildren),
    ])
  );
}

function metaTile(label, value) {
  return el("div", { class: "kpi-card" }, [
    el("div", { class: "kpi-label" }, label),
    el("div", { class: "meta-val" }, value),
  ]);
}
