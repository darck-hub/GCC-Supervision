"""Registre Général des Incidents Distribués & Fiche d'Exploitation Certifiée GCC."""

from __future__ import annotations

from flask import Blueprint, current_app, g, jsonify, request

from backend.database import get_db, log_audit, utc_now_iso
from backend.routing_engine import (
    compute_sla_deadline,
    enrich_ticket_sla,
    next_ticket_reference,
)
from backend.security import exiger_role

tickets_bp = Blueprint("tickets", __name__, url_prefix="/api")


@tickets_bp.get("/procedures")
@exiger_role("admin", "pilote", "n2", "auditeur")
def list_procedures():
    """Liste les procédures d'exploitation certifiées (ex: PROC-NET-001, PROC-ZOS-016)."""
    cfg = current_app.config["GCC_CONFIG"]
    with get_db(cfg.DB_PATH) as conn:
        rows = [
            dict(r)
            for r in conn.execute("SELECT * FROM procedures ORDER BY code ASC").fetchall()
        ]
    return jsonify({"procedures": rows})


@tickets_bp.get("/tickets")
@exiger_role("admin", "pilote", "n2", "auditeur")
def list_tickets():
    """Retourne la liste filtrable des tickets avec calcul temps réel des SLA."""
    cfg = current_app.config["GCC_CONFIG"]
    priority = request.args.get("priority", "").strip()
    status = request.args.get("status", "").strip()
    plateau = request.args.get("plateau", "").strip()
    search = request.args.get("search", "").strip()

    clauses = []
    params = []
    if priority in cfg.VALID_PRIORITIES:
        clauses.append("priority = ?")
        params.append(priority)
    if status in cfg.VALID_STATUSES:
        clauses.append("status = ?")
        params.append(status)
    if plateau in cfg.VALID_PLATEAUS:
        clauses.append("plateau = ?")
        params.append(plateau)
    if search:
        clauses.append("(reference LIKE ? OR title LIKE ? OR host LIKE ? OR error_code LIKE ?)")
        like = f"%{search[:80]}%"
        params.extend([like, like, like, like])

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    query = f"SELECT * FROM tickets {where} ORDER BY CASE status WHEN 'CLOTURE' THEN 1 ELSE 0 END, priority ASC, id DESC"

    with get_db(cfg.DB_PATH) as conn:
        rows = [dict(r) for r in conn.execute(query, params).fetchall()]

    return jsonify({"tickets": [enrich_ticket_sla(r, cfg) for r in rows]})


@tickets_bp.post("/tickets")
@exiger_role("admin", "pilote", "n2")
def create_ticket():
    """Crée un ticket d'incident avec calcul SLA automatique et traçabilité d'audit."""
    cfg = current_app.config["GCC_CONFIG"]
    data = request.get_json(silent=True) or {}

    title = str(data.get("title", "")).strip()
    description = str(data.get("description", "")).strip()
    priority = str(data.get("priority", "P3")).strip().upper()
    plateau = str(data.get("plateau", g.current_user["plateau"])).strip()
    source_tool = str(data.get("source_tool", "ServiceNow")).strip()[:64]
    host = str(data.get("host", "SRV-INCONNU")).strip()[:64]
    error_code = str(data.get("error_code", "")).strip()[:40] or None
    assigned_group = str(data.get("assigned_group", "Pilote N1")).strip()[:64]
    procedure_code = str(data.get("procedure_code", "")).strip() or None

    if not title or len(title) < 4 or len(title) > 180:
        return jsonify({"error": "Le titre doit contenir entre 4 et 180 caractères."}), 400
    if not description or len(description) > 2000:
        return jsonify({"error": "La description est obligatoire (max 2000 caractères)."}), 400
    if priority not in cfg.VALID_PRIORITIES:
        return jsonify({"error": "Priorité invalide (P1 à P4 attendu)."}), 400
    if plateau not in cfg.VALID_PLATEAUS:
        return jsonify({"error": "Plateau invalide (Multi-Client ou Banque)."}), 400

    now_iso = utc_now_iso()
    sla_deadline = compute_sla_deadline(priority, cfg)
    rca_required = 1 if priority in ("P1", "P2") else 0

    with get_db(cfg.DB_PATH) as conn:
        if procedure_code:
            exists = conn.execute(
                "SELECT 1 FROM procedures WHERE code = ?", (procedure_code,)
            ).fetchone()
            if not exists:
                return jsonify({"error": f"Procédure inconnue : {procedure_code}"}), 400

        ref = next_ticket_reference(conn)
        cur = conn.execute(
            """
            INSERT INTO tickets
                (reference, title, description, priority, status, plateau, source_tool, host,
                 error_code, assigned_group, assigned_to, procedure_code, sla_deadline,
                 rca_required, created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'NOUVEAU', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ref,
                title,
                description,
                priority,
                plateau,
                source_tool,
                host,
                error_code,
                assigned_group,
                g.current_user["username"],
                procedure_code,
                sla_deadline,
                rca_required,
                g.current_user["username"],
                now_iso,
                now_iso,
            ),
        )
        ticket_id = cur.lastrowid
        conn.execute(
            """
            INSERT INTO ticket_comments (ticket_id, author, author_role, content, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                ticket_id,
                g.current_user["username"],
                g.current_user["role"],
                f"Ouverture du ticket {ref} (Priorité {priority}, Groupe {assigned_group}).",
                now_iso,
            ),
        )
        ticket = dict(
            conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        )

    log_audit(
        cfg.DB_PATH,
        username=g.current_user["username"],
        role=g.current_user["role"],
        action="TICKET_CREATE",
        target=ref,
        ip_address=request.remote_addr or "unknown",
        status="SUCCESS",
        details=f"Priorité={priority}, Plateau={plateau}, Groupe={assigned_group}",
    )
    return jsonify({"ticket": enrich_ticket_sla(ticket, cfg)}), 201


@tickets_bp.get("/tickets/<int:ticket_id>")
@exiger_role("admin", "pilote", "n2", "auditeur")
def get_ticket_sheet(ticket_id: int):
    """Retourne la Fiche d'Exploitation Certifiée GCC (ticket + procédure + fil de discussion)."""
    cfg = current_app.config["GCC_CONFIG"]
    with get_db(cfg.DB_PATH) as conn:
        row = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        if not row:
            return jsonify({"error": "Ticket introuvable."}), 404
        ticket = dict(row)

        procedure = None
        if ticket["procedure_code"]:
            proc_row = conn.execute(
                "SELECT * FROM procedures WHERE code = ?", (ticket["procedure_code"],)
            ).fetchone()
            if proc_row:
                procedure = dict(proc_row)

        comments = [
            dict(c)
            for c in conn.execute(
                "SELECT * FROM ticket_comments WHERE ticket_id = ? ORDER BY id ASC",
                (ticket_id,),
            ).fetchall()
        ]
        linked_alerts = [
            dict(a)
            for a in conn.execute(
                "SELECT * FROM alerts WHERE ticket_id = ? ORDER BY last_seen DESC",
                (ticket_id,),
            ).fetchall()
        ]

    return jsonify(
        {
            "ticket": enrich_ticket_sla(ticket, cfg),
            "procedure": procedure,
            "comments": comments,
            "linked_alerts": linked_alerts,
        }
    )


@tickets_bp.patch("/tickets/<int:ticket_id>")
@exiger_role("admin", "pilote", "n2")
def update_ticket(ticket_id: int):
    """Met à jour le cycle de vie, l'escalade N2/N3 ou les notes de résolution d'un ticket."""
    cfg = current_app.config["GCC_CONFIG"]
    data = request.get_json(silent=True) or {}

    with get_db(cfg.DB_PATH) as conn:
        existing = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        if not existing:
            return jsonify({"error": "Ticket introuvable."}), 404

        new_status = str(data.get("status", existing["status"])).strip().upper()
        new_priority = str(data.get("priority", existing["priority"])).strip().upper()
        new_group = str(data.get("assigned_group", existing["assigned_group"])).strip()[:64]
        new_assigned = data.get("assigned_to", existing["assigned_to"])
        new_notes = data.get("resolution_notes", existing["resolution_notes"])
        new_proc = data.get("procedure_code", existing["procedure_code"])

        if new_status not in cfg.VALID_STATUSES:
            return jsonify({"error": "Statut de ticket non valide."}), 400
        if new_priority not in cfg.VALID_PRIORITIES:
            return jsonify({"error": "Priorité non valide."}), 400
        if new_proc:
            if not conn.execute("SELECT 1 FROM procedures WHERE code = ?", (new_proc,)).fetchone():
                return jsonify({"error": f"Procédure inconnue : {new_proc}"}), 400

        now_iso = utc_now_iso()
        rca_flag = 1 if (new_priority in ("P1", "P2") or existing["rca_required"]) else 0

        conn.execute(
            """
            UPDATE tickets
            SET status = ?, priority = ?, assigned_group = ?, assigned_to = ?,
                resolution_notes = ?, procedure_code = ?, rca_required = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                new_status,
                new_priority,
                new_group,
                str(new_assigned).strip()[:64] if new_assigned else None,
                str(new_notes).strip()[:2000] if new_notes else None,
                new_proc or None,
                rca_flag,
                now_iso,
                ticket_id,
            ),
        )

        # Journalisation automatique dans le fil de discussion lors d'un changement d'état
        changes = []
        if new_status != existing["status"]:
            changes.append(f"Statut : {existing['status']} -> {new_status}")
        if new_priority != existing["priority"]:
            changes.append(f"Priorité : {existing['priority']} -> {new_priority}")
        if new_group != existing["assigned_group"]:
            changes.append(f"Escalade/Routage : {existing['assigned_group']} -> {new_group}")

        if changes:
            conn.execute(
                """
                INSERT INTO ticket_comments (ticket_id, author, author_role, content, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    ticket_id,
                    g.current_user["username"],
                    g.current_user["role"],
                    "Mise à jour d'exploitation — " + " | ".join(changes),
                    now_iso,
                ),
            )

        updated = dict(
            conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        )

    log_audit(
        cfg.DB_PATH,
        username=g.current_user["username"],
        role=g.current_user["role"],
        action="TICKET_UPDATE",
        target=updated["reference"],
        ip_address=request.remote_addr or "unknown",
        status="SUCCESS",
        details=" | ".join(changes) if changes else "Notes / assignation modifiées",
    )
    return jsonify({"ticket": enrich_ticket_sla(updated, cfg)})


@tickets_bp.post("/tickets/<int:ticket_id>/comments")
@exiger_role("admin", "pilote", "n2")
def add_comment(ticket_id: int):
    """Ajoute une entrée horodatée au fil de discussion de la fiche d'exploitation."""
    cfg = current_app.config["GCC_CONFIG"]
    data = request.get_json(silent=True) or {}
    content = str(data.get("content", "")).strip()
    if not content or len(content) > 1500:
        return jsonify({"error": "Le commentaire doit contenir entre 1 et 1500 caractères."}), 400

    now_iso = utc_now_iso()
    with get_db(cfg.DB_PATH) as conn:
        ticket = conn.execute("SELECT reference FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        if not ticket:
            return jsonify({"error": "Ticket introuvable."}), 404

        cur = conn.execute(
            """
            INSERT INTO ticket_comments (ticket_id, author, author_role, content, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (ticket_id, g.current_user["username"], g.current_user["role"], content, now_iso),
        )
        conn.execute("UPDATE tickets SET updated_at = ? WHERE id = ?", (now_iso, ticket_id))
        comment = dict(
            conn.execute("SELECT * FROM ticket_comments WHERE id = ?", (cur.lastrowid,)).fetchone()
        )

    log_audit(
        cfg.DB_PATH,
        username=g.current_user["username"],
        role=g.current_user["role"],
        action="TICKET_COMMENT",
        target=ticket["reference"],
        ip_address=request.remote_addr or "unknown",
        status="SUCCESS",
        details="Ajout d'une consigne / note d'exploitation",
    )
    return jsonify({"comment": comment}), 201
