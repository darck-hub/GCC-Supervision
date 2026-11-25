import { apiRequest } from "./api.js";
import { hasRole } from "./auth.js";
import { badge, clear, el, showToast } from "./dom.js";

export async function renderAdmin(container) {
  clear(container);

  const collectorsRes = await apiRequest("/api/admin/collectors");
  const collectorRows = collectorsRes.collectors.map((c) => {
    const toggleBtn = hasRole("admin")
      ? el(
          "button",
          {
            class: `btn btn-sm ${c.enabled ? "btn-danger" : "btn-primary"}`,
            onClick: async () => {
              try {
                await apiRequest(`/api/admin/collectors/${c.id}`, {
                  method: "PATCH",
                  body: { enabled: !c.enabled },
                });
                showToast(`Collecteur ${c.name} ${c.enabled ? "désactivé" : "activé"}.`);
                await renderAdmin(container);
              } catch (err) {
                showToast(err.message, true);
              }
            },
          },
          c.enabled ? "Désactiver" : "Activer"
        )
      : badge("Lecture seule", "neutral");

    return el("tr", {}, [
      el("td", {}, el("strong", {}, c.name)),
      el("td", {}, c.type),
      el("td", {}, badge(c.plateau, "neutral")),
      el("td", {}, el("code", {}, c.endpoint_hint)),
      el("td", {}, String(c.events_ingested)),
      el("td", {}, badge(c.enabled ? "ACTIF" : "INACTIF", c.enabled ? "ACTIF" : "neutral")),
      el("td", {}, toggleBtn),
    ]);
  });

  container.appendChild(
    el("div", { class: "panel" }, [
      el("div", { class: "panel-header" }, el("div", { class: "panel-title" }, "Collecteurs d'alertes & Passerelles Webhooks (HMAC-SHA256)")),
      el(
        "div",
        { class: "table-wrap" },
        el("table", {}, [
          el("thead", {}, el("tr", {}, [
            el("th", {}, "Collecteur"),
            el("th", {}, "Type"),
            el("th", {}, "Plateau"),
            el("th", {}, "Endpoint / Protocole"),
            el("th", {}, "Événements"),
            el("th", {}, "État"),
            el("th", {}, "Action"),
          ])),
          el("tbody", {}, collectorRows),
        ])
      ),
    ])
  );

  if (!hasRole("admin")) {
    container.appendChild(
      el("div", { class: "panel" }, "La gestion des comptes utilisateurs et habilitations RBAC est réservée au rôle Administrateur (@exiger_role('admin')).")
    );
    return;
  }

  const usersRes = await apiRequest("/api/admin/users");
  const userRows = usersRes.users.map((u) =>
    el("tr", {}, [
      el("td", {}, el("code", {}, u.username)),
      el("td", {}, u.full_name),
      el("td", {}, badge(u.role.toUpperCase(), u.role === "admin" ? "P1" : "P4")),
      el("td", {}, badge(u.plateau, "neutral")),
      el("td", {}, badge(u.is_active ? "ACTIF" : "DÉSACTIVÉ", u.is_active ? "OK" : "DENIED")),
      el("td", {}, u.created_at),
      el(
        "td",
        {},
        el(
          "button",
          {
            class: "btn btn-secondary btn-sm",
            onClick: async () => {
              try {
                await apiRequest(`/api/admin/users/${u.id}`, {
                  method: "PATCH",
                  body: { is_active: !u.is_active },
                });
                showToast(`Statut du compte ${u.username} mis à jour.`);
                await renderAdmin(container);
              } catch (err) {
                showToast(err.message, true);
              }
            },
          },
          u.is_active ? "Désactiver" : "Réactiver"
        )
      ),
    ])
  );

  const unameIn = el("input", { required: "true", placeholder: "ex: pilote_nuit" });
  const fnameIn = el("input", { required: "true", placeholder: "Prénom Nom" });
  const pwdIn = el("input", { type: "password", required: "true", placeholder: "Min 12 car. (Maj/min/chiffre/spécial)" });
  const roleSel = el("select", {}, ["pilote", "n2", "auditeur", "admin"].map((r) => el("option", { value: r }, r)));
  const platSel = el("select", {}, ["Banque", "Multi-Client"].map((p) => el("option", { value: p }, p)));

  const createUserForm = el(
    "form",
    {
      class: "form-stack",
      onSubmit: async (ev) => {
        ev.preventDefault();
        try {
          await apiRequest("/api/admin/users", {
            method: "POST",
            body: {
              username: unameIn.value,
              full_name: fnameIn.value,
              password: pwdIn.value,
              role: roleSel.value,
              plateau: platSel.value,
            },
          });
          showToast(`Compte ${unameIn.value} créé avec hachage Scrypt.`);
          await renderAdmin(container);
        } catch (err) {
          showToast(err.message, true);
        }
      },
    },
    [
      el("div", { class: "form-grid" }, [
        el("div", { class: "field" }, [el("label", {}, "Identifiant"), unameIn]),
        el("div", { class: "field" }, [el("label", {}, "Nom complet"), fnameIn]),
        el("div", { class: "field" }, [el("label", {}, "Mot de passe (ANSSI >= 12 car.)"), pwdIn]),
        el("div", { class: "field" }, [el("label", {}, "Rôle RBAC"), roleSel]),
        el("div", { class: "field" }, [el("label", {}, "Plateau"), platSel]),
      ]),
      el("div", {}, el("button", { type: "submit", class: "btn btn-primary btn-sm" }, "Créer le compte")),
    ]
  );

  container.appendChild(
    el("div", { class: "panel" }, [
      el("div", { class: "panel-header" }, el("div", { class: "panel-title" }, "Gestion des comptes & Habilitations RBAC")),
      el(
        "div",
        { class: "table-wrap" },
        el("table", {}, [
          el("thead", {}, el("tr", {}, [
            el("th", {}, "Identifiant"),
            el("th", {}, "Nom"),
            el("th", {}, "Rôle"),
            el("th", {}, "Plateau"),
            el("th", {}, "Statut"),
            el("th", {}, "Créé le"),
            el("th", {}, "Action"),
          ])),
          el("tbody", {}, userRows),
        ])
      ),
      el("div", { class: "panel-header mt-3" }, el("div", { class: "panel-title" }, "Créer un opérateur")),
      createUserForm,
    ])
  );
}
