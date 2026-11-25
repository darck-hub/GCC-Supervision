import { apiRequest } from "./api.js";
import { hasRole } from "./auth.js";
import { badge, clear, el, formatSla, showToast } from "./dom.js";

export async function renderIncidents(container, { openTicket }) {
  clear(container);

  const filterPrio = el("select", {}, [
    el("option", { value: "" }, "Toutes priorités"),
    ...["P1", "P2", "P3", "P4"].map((p) => el("option", { value: p }, p)),
  ]);
  const filterStatus = el("select", {}, [
    el("option", { value: "" }, "Tous statuts"),
    ...["NOUVEAU", "EN_COURS", "ESCALADE_N2", "ESCALADE_N3", "RESOLU", "CLOTURE"].map((s) =>
      el("option", { value: s }, s)
    ),
  ]);
  const filterSearch = el("input", { placeholder: "Rechercher réf, hôte, code..." });
  const tbody = el("tbody");

  async function loadList() {
    const qs = new URLSearchParams();
    if (filterPrio.value) qs.set("priority", filterPrio.value);
    if (filterStatus.value) qs.set("status", filterStatus.value);
    if (filterSearch.value.trim()) qs.set("search", filterSearch.value.trim());

    const data = await apiRequest(`/api/tickets?${qs.toString()}`);
    clear(tbody);
    for (const t of data.tickets) {
      tbody.appendChild(
        el("tr", {}, [
          el("td", {}, el("code", {}, t.reference)),
          el("td", {}, badge(t.priority, t.priority)),
          el("td", {}, badge(t.status, t.status)),
          el("td", {}, [el("strong", {}, t.title), el("div", { class: "kpi-sub" }, `${t.host} • ${t.source_tool}`)]),
          el("td", {}, badge(t.plateau, "neutral")),
          el("td", {}, t.assigned_group),
          el("td", {}, formatSla(t.sla_remaining_sec, t.sla_state)),
          el(
            "td",
            {},
            el("button", { class: "btn btn-primary btn-sm", onClick: () => openTicket(t.id) }, "Fiche GCC")
          ),
        ])
      );
    }
  }

  filterPrio.addEventListener("change", loadList);
  filterStatus.addEventListener("change", loadList);
  filterSearch.addEventListener("input", loadList);

  container.appendChild(
    el("div", { class: "panel" }, [
      el("div", { class: "panel-header" }, [
        el("div", { class: "panel-title" }, "Registre Général des Incidents Distribués"),
        el("div", { class: "btn-row" }, [filterPrio, filterStatus, filterSearch]),
      ]),
      el(
        "div",
        { class: "table-wrap" },
        el("table", {}, [
          el("thead", {}, el("tr", {}, [
            el("th", {}, "Réf."),
            el("th", {}, "Prio."),
            el("th", {}, "Statut"),
            el("th", {}, "Incident / Hôte"),
            el("th", {}, "Plateau"),
            el("th", {}, "Groupe"),
            el("th", {}, "SLA"),
            el("th", {}, "Exploitation"),
          ])),
          tbody,
        ])
      ),
    ])
  );

  if (hasRole("admin", "pilote", "n2")) {
    const procs = (await apiRequest("/api/procedures")).procedures;
    const titleIn = el("input", { required: "true", placeholder: "Titre synthétique de l'incident" });
    const hostIn = el("input", { required: "true", placeholder: "Ex: ZOS-PRD-AF01 ou RTR-WAN-01" });
    const codeIn = el("input", { placeholder: "Ex: RC-0016, DB2 -911, LINK_DOWN" });
    const prioSel = el("select", {}, ["P1", "P2", "P3", "P4"].map((p) => el("option", { value: p }, p)));
    const plateauSel = el("select", {}, ["Banque", "Multi-Client"].map((p) => el("option", { value: p }, p)));
    const groupIn = el("input", { value: "Équipe Réseau N2" });
    const procSel = el("select", {}, [
      el("option", { value: "" }, "Procédure standard"),
      ...procs.map((p) => el("option", { value: p.code }, `${p.code} — ${p.title}`)),
    ]);
    const descIn = el("textarea", { rows: "3", required: "true", placeholder: "Contexte technique, logs relevés, impact service..." });

    const form = el(
      "form",
      {
        class: "form-stack",
        onSubmit: async (ev) => {
          ev.preventDefault();
          try {
            const res = await apiRequest("/api/tickets", {
              method: "POST",
              body: {
                title: titleIn.value,
                description: descIn.value,
                priority: prioSel.value,
                plateau: plateauSel.value,
                host: hostIn.value,
                error_code: codeIn.value,
                assigned_group: groupIn.value,
                procedure_code: procSel.value || null,
              },
            });
            showToast(`Ticket ${res.ticket.reference} créé avec succès.`);
            titleIn.value = "";
            descIn.value = "";
            codeIn.value = "";
            await loadList();
          } catch (err) {
            showToast(err.message, true);
          }
        },
      },
      [
        el("div", { class: "form-grid" }, [
          el("div", { class: "field" }, [el("label", {}, "Titre"), titleIn]),
          el("div", { class: "field" }, [el("label", {}, "Hôte / CI impacté"), hostIn]),
          el("div", { class: "field" }, [el("label", {}, "Code erreur"), codeIn]),
          el("div", { class: "field" }, [el("label", {}, "Priorité (SLA auto)"), prioSel]),
          el("div", { class: "field" }, [el("label", {}, "Plateau"), plateauSel]),
          el("div", { class: "field" }, [el("label", {}, "Groupe d'affectation"), groupIn]),
          el("div", { class: "field" }, [el("label", {}, "Procédure GCC"), procSel]),
        ]),
        el("div", { class: "field" }, [el("label", {}, "Description détaillée"), descIn]),
        el("div", {}, el("button", { type: "submit", class: "btn btn-primary" }, "Ouvrir le ticket")),
      ]
    );

    container.appendChild(
      el("div", { class: "panel" }, [
        el("div", { class: "panel-header" }, el("div", { class: "panel-title" }, "Déclarer un nouvel incident")),
        form,
      ])
    );
  }

  await loadList();
}
