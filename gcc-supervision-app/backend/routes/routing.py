"""Matrice de Routage et de Dispatching Opérationnel du GCC."""

from __future__ import annotations

from flask import Blueprint, current_app, g, jsonify, request

from backend.database import get_db, log_audit, utc_now_iso
from backend.routing_engine import compute_sla_deadline, next_ticket_reference
from backend.security import exiger_role

routing_bp = Blueprint("routing", __name__, url_prefix="/api/routing")


@routing_bp.get("/rules")
@exiger_role("admin", "pilote", "n2", "auditeur")
def list_rules():
    """Retourne les règles de la matrice de routage GCC."""
    cfg = current_app.config["GCC_CONFIG"]
    with get_db(cfg.DB_PATH) as conn:
        rows = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM routing_rules ORDER BY priority ASC, id ASC"
            ).fetchall()
        ]
    return jsonify({"rules": rows})


@routing_bp.post("/rules")
@exiger_role("admin", "pilote")
def create_rule():
    """Ajoute une règle de qualification/routage automatique."""
    cfg = current_app.config["GCC_CONFIG"]
    data = request.get_json(silent=True) or {}

    name = str(data.get("name", "")).strip()[:100]
    keyword = str(data.get("keyword", "")).strip()[:40]
    source_tool = str(data.get("source_tool", "HAL/Netcool")).strip()[:64]
    plateau = str(data.get("plateau", "Banque")).strip()
    priority = str(data.get("priority", "P2")).strip().upper()
    target_group = str(data.get("target_group", "Pilote N1")).strip()[:64]
    procedure_code = str(data.get("procedure_code", "")).strip() or None
    auto_create = 1 if data.get("auto_create_ticket", True) else 0

    if not name or not keyword:
        return jsonify({"error": "Nom et mot-clé de détection obligatoires."}), 400
    if priority not in cfg.VALID_PRIORITIES:
        return jsonify({"error": "Priorité invalide (P1 à P4)."}), 400
    if plateau not in cfg.VALID_PLATEAUS:
        return jsonify({"error": "Plateau invalide."}), 400

    with get_db(cfg.DB_PATH) as conn:
        if procedure_code and not conn.execute(
            "SELECT 1 FROM procedures WHERE code = ?", (procedure_code,)
        ).fetchone():
            return jsonify({"error": f"Procédure inconnue : {procedure_code}"}), 400

        cur = conn.execute(
            """
            INSERT INTO routing_rules
                (name, keyword, source_tool, plateau, priority, target_group,
                 procedure_code, auto_create_ticket, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (name, keyword, source_tool, plateau, priority, target_group, procedure_code, auto_create),
        )
        rule = dict(
            conn.execute("SELECT * FROM routing_rules WHERE id = ?", (cur.lastrowid,)).fetchone()
        )

    log_audit(
        cfg.DB_PATH,
        username=g.current_user["username"],
        role=g.current_user["role"],
        action="ROUTING_RULE_CREATE",
        target=name,
        ip_address=request.remote_addr or "unknown",
        status="SUCCESS",
        details=f"Keyword={keyword}, Prio={priority}, Groupe={target_group}",
    )
    return jsonify({"rule": rule}), 201


@routing_bp.delete("/rules/<int:rule_id>")
@exiger_role("admin")
def delete_rule(rule_id: int):
    """Supprime une règle de la matrice de routage (Administrateur uniquement)."""
    cfg = current_app.config["GCC_CONFIG"]
    with get_db(cfg.DB_PATH) as conn:
        existing = conn.execute("SELECT name FROM routing_rules WHERE id = ?", (rule_id,)).fetchone()
        if not existing:
            return jsonify({"error": "Règle introuvable."}), 404
        conn.execute("DELETE FROM routing_rules WHERE id = ?", (rule_id,))

    log_audit(
        cfg.DB_PATH,
        username=g.current_user["username"],
        role=g.current_user["role"],
        action="ROUTING_RULE_DELETE",
        target=existing["name"],
        ip_address=request.remote_addr or "unknown",
        status="SUCCESS",
        details=f"rule_id={rule_id}",
    )
    return jsonify({"deleted": True})


@routing_bp.get("/alerts")
@exiger_role("admin", "pilote", "n2", "auditeur")
def list_alerts():
    """Liste les alertes actives et corrélées (avec compteur de déduplication HAL)."""
    cfg = current_app.config["GCC_CONFIG"]
    with get_db(cfg.DB_PATH) as conn:
        alerts = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM alerts ORDER BY CASE status WHEN 'ACTIVE' THEN 0 ELSE 1 END, severity ASC, last_seen DESC"
            ).fetchall()
        ]
    return jsonify({"alerts": alerts})


@routing_bp.post("/alerts/<int:alert_id>/dispatch")
@exiger_role("admin", "pilote", "n2")
def dispatch_alert(alert_id: int):
    """Qualifie une alerte en direct et ouvre le ticket associé (ou acquitte un faux positif)."""
    cfg = current_app.config["GCC_CONFIG"]
    data = request.get_json(silent=True) or {}
    action = str(data.get("action", "qualify")).strip().lower()

    with get_db(cfg.DB_PATH) as conn:
        alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not alert:
            return jsonify({"error": "Alerte introuvable."}), 404

        if action == "ack":
            conn.execute("UPDATE alerts SET status = 'ACK' WHERE id = ?", (alert_id,))
            log_audit(
                cfg.DB_PATH,
                g.current_user["username"],
                g.current_user["role"],
                "ALERT_ACK",
                f"ALERT-{alert_id}",
                request.remote_addr or "unknown",
                "SUCCESS",
                "Acquittement manuel (faux positif ou bruit traité)",
            )
            return jsonify({"alert_id": alert_id, "status": "ACK"})

        if alert["ticket_id"]:
            return jsonify({"error": "Cette alerte est déjà associée à un ticket."}), 409

        priority = str(data.get("priority", alert["severity"])).strip().upper()
        if priority not in cfg.VALID_PRIORITIES:
            return jsonify({"error": "Priorité invalide."}), 400

        target_group = str(data.get("target_group", "Équipe Réseau N2")).strip()[:64]
        procedure_code = str(data.get("procedure_code", "")).strip() or None
        if procedure_code and not conn.execute(
            "SELECT 1 FROM procedures WHERE code = ?", (procedure_code,)
        ).fetchone():
            return jsonify({"error": "Procédure inconnue."}), 400

        now_iso = utc_now_iso()
        ref = next_ticket_reference(conn)
        sla_deadline = compute_sla_deadline(priority, cfg)
        rca_flag = 1 if priority in ("P1", "P2") else 0

        cur = conn.execute(
            """
            INSERT INTO tickets
                (reference, title, description, priority, status, plateau, source_tool, host,
                 error_code, assigned_group, assigned_to, procedure_code, sla_deadline,
                 rca_required, created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'EN_COURS', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ref,
                f"[{alert['error_code']}] {alert['host']} — {alert['message'][:90]}",
                f"Ticket ouvert depuis la matrice de dispatching GCC.\n"
                f"Occurrences dédupliquées : {alert['occurrence_count']}\n"
                f"Message brut : {alert['message']}",
                priority,
                alert["plateau"],
                alert["source_tool"],
                alert["host"],
                alert["error_code"],
                target_group,
                g.current_user["username"],
                procedure_code,
                sla_deadline,
                rca_flag,
                g.current_user["username"],
                now_iso,
                now_iso,
            ),
        )
        ticket_id = cur.lastrowid
        conn.execute(
            "UPDATE alerts SET status = 'QUALIFIED', ticket_id = ?, severity = ? WHERE id = ?",
            (ticket_id, priority, alert_id),
        )
        conn.execute(
            """
            INSERT INTO ticket_comments (ticket_id, author, author_role, content, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                ticket_id,
                g.current_user["username"],
                g.current_user["role"],
                f"Qualification manuelle {priority} depuis l'alerte #{alert_id} (x{alert['occurrence_count']} occurrences) -> {target_group}.",
                now_iso,
            ),
        )

    log_audit(
        cfg.DB_PATH,
        g.current_user["username"],
        g.current_user["role"],
        "ALERT_DISPATCH",
        ref,
        request.remote_addr or "unknown",
        "SUCCESS",
        f"Alerte #{alert_id} qualifiée en {priority} vers {target_group}",
    )
    return jsonify({"alert_id": alert_id, "ticket_id": ticket_id, "reference": ref}), 201
