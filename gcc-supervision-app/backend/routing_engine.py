"""Moteur métier GCC : Déduplication HAL, qualification P1-P4, routage et calcul SLA."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from backend.config import Config
from backend.database import get_db, utc_now_iso


def compute_sla_deadline(priority: str, cfg: Config, from_dt: Optional[datetime] = None) -> str:
    """Calcule la date limite SLA UTC en fonction de la criticité P1-P4."""
    base = from_dt or datetime.now(timezone.utc)
    minutes = cfg.SLA_MINUTES.get(priority, 240)
    return (base + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def enrich_ticket_sla(ticket: Dict[str, Any], cfg: Config) -> Dict[str, Any]:
    """Ajoute les métriques temps réel de respect SLA (secondes restantes, statut)."""
    now = datetime.now(timezone.utc)
    deadline_str = ticket.get("sla_deadline", "")
    status = ticket.get("status", "NOUVEAU")
    priority = ticket.get("priority", "P3")
    total_sec = cfg.SLA_MINUTES.get(priority, 240) * 60

    try:
        deadline = datetime.strptime(deadline_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        deadline = now

    remaining = int((deadline - now).total_seconds())

    if status in ("RESOLU", "CLOTURE"):
        sla_state = "MET"
    elif remaining <= 0:
        sla_state = "BREACHED"
    elif remaining <= int(total_sec * 0.25):
        sla_state = "WARNING"
    else:
        sla_state = "OK"

    enriched = dict(ticket)
    enriched["sla_remaining_sec"] = remaining
    enriched["sla_total_sec"] = total_sec
    enriched["sla_state"] = sla_state
    return enriched


def next_ticket_reference(conn: sqlite3.Connection) -> str:
    """Génère une référence séquentielle INC-YYYY-NNNN."""
    year = datetime.now(timezone.utc).year
    row = conn.execute("SELECT COALESCE(MAX(id), 0) AS max_id FROM tickets").fetchone()
    seq = int(row["max_id"]) + 1
    return f"INC-{year}-{seq:04d}"


def match_routing_rule(
    conn: sqlite3.Connection, source_tool: str, error_code: str, message: str
) -> Optional[sqlite3.Row]:
    """Cherche la règle de routage active la plus pertinente (inspiré Bot Marvin & matrice GCC)."""
    rules = conn.execute(
        "SELECT * FROM routing_rules WHERE enabled = 1 ORDER BY priority ASC, id ASC"
    ).fetchall()
    haystack = f"{error_code} {message}".upper()
    for rule in rules:
        kw = rule["keyword"].upper()
        tool_match = rule["source_tool"].lower() in (source_tool.lower(), "all", "*")
        if kw in haystack and (tool_match or kw == error_code.upper()):
            return rule
    return None


def ingest_alert(
    cfg: Config,
    source_tool: str,
    plateau: str,
    host: str,
    error_code: str,
    message: str,
    severity: Optional[str] = None,
    actor: str = "Webhook Industriel",
) -> Dict[str, Any]:
    """Ingère une alerte avec déduplication (style HAL/Netcool) et qualification auto."""
    now = datetime.now(timezone.utc)
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    window_start = (now - timedelta(seconds=cfg.DEDUP_WINDOW_SECONDS)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    if plateau not in cfg.VALID_PLATEAUS:
        plateau = "Banque"

    with get_db(cfg.DB_PATH) as conn:
        # 1. Corrélation / Déduplication HAL : même outil + hôte + code erreur dans la fenêtre
        existing = conn.execute(
            """
            SELECT * FROM alerts
            WHERE source_tool = ? AND host = ? AND error_code = ?
              AND status IN ('ACTIVE', 'QUALIFIED')
              AND last_seen >= ?
            ORDER BY id DESC LIMIT 1
            """,
            (source_tool, host, error_code, window_start),
        ).fetchone()

        # Incrémente les stats du collecteur correspondant si présent
        conn.execute(
            """
            UPDATE collectors
            SET events_ingested = events_ingested + 1, last_heartbeat = ?
            WHERE LOWER(name) LIKE ? OR LOWER(type) LIKE ?
            """,
            (now_iso, f"%{source_tool.lower()[:6]}%", f"%{source_tool.lower()[:6]}%"),
        )

        if existing:
            new_count = int(existing["occurrence_count"]) + 1
            conn.execute(
                "UPDATE alerts SET occurrence_count = ?, last_seen = ?, message = ? WHERE id = ?",
                (new_count, now_iso, message, existing["id"]),
            )
            return {
                "deduplicated": True,
                "alert_id": existing["id"],
                "occurrence_count": new_count,
                "severity": existing["severity"],
                "ticket_id": existing["ticket_id"],
                "matched_rule": existing["matched_rule"],
            }

        # 2. Qualification via la matrice de routage
        rule = match_routing_rule(conn, source_tool, error_code, message)
        resolved_prio = (
            rule["priority"]
            if rule
            else (severity if severity in cfg.VALID_PRIORITIES else "P3")
        )
        matched_rule_name = rule["name"] if rule else None
        ticket_id = None
        ticket_ref = None
        alert_status = "ACTIVE"

        if rule and int(rule["auto_create_ticket"]) == 1:
            ticket_ref = next_ticket_reference(conn)
            sla_deadline = compute_sla_deadline(resolved_prio, cfg, now)
            rca_flag = 1 if resolved_prio in ("P1", "P2") else 0
            cur = conn.execute(
                """
                INSERT INTO tickets
                    (reference, title, description, priority, status, plateau, source_tool, host,
                     error_code, assigned_group, assigned_to, procedure_code, sla_deadline,
                     rca_required, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'NOUVEAU', ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ticket_ref,
                    f"[{error_code}] {host} — {message[:100]}",
                    f"Ticket généré automatiquement par la matrice de routage ({matched_rule_name}).\n"
                    f"Source : {source_tool} | Hôte : {host}\nPayload : {message}",
                    resolved_prio,
                    rule["plateau"],
                    source_tool,
                    host,
                    error_code,
                    rule["target_group"],
                    rule["procedure_code"],
                    sla_deadline,
                    rca_flag,
                    actor,
                    now_iso,
                    now_iso,
                ),
            )
            ticket_id = cur.lastrowid
            alert_status = "QUALIFIED"
            conn.execute(
                """
                INSERT INTO ticket_comments (ticket_id, author, author_role, content, created_at)
                VALUES (?, ?, 'pilote', ?, ?)
                """,
                (
                    ticket_id,
                    actor,
                    f"Qualification automatique {resolved_prio} -> {rule['target_group']} "
                    f"(Procédure : {rule['procedure_code'] or 'Standard'}).",
                    now_iso,
                ),
            )

        cur_a = conn.execute(
            """
            INSERT INTO alerts
                (source_tool, plateau, host, error_code, message, severity, status,
                 occurrence_count, matched_rule, ticket_id, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
            """,
            (
                source_tool,
                plateau,
                host,
                error_code,
                message,
                resolved_prio,
                alert_status,
                matched_rule_name,
                ticket_id,
                now_iso,
                now_iso,
            ),
        )
        return {
            "deduplicated": False,
            "alert_id": cur_a.lastrowid,
            "occurrence_count": 1,
            "severity": resolved_prio,
            "ticket_id": ticket_id,
            "ticket_reference": ticket_ref,
            "matched_rule": matched_rule_name,
        }


def get_current_shift() -> Dict[str, str]:
    """Détermine l'équipe 3/8 active en fonction de l'heure locale/UTC."""
    hour = datetime.now().hour
    if 6 <= hour < 14:
        return {"name": "Matinée", "slot": "06h00 - 14h00", "mode": "3/8 — Pic d'activité"}
    if 14 <= hour < 22:
        return {"name": "Descendante", "slot": "14h00 - 22h00", "mode": "3/8 — Suivi & Changements"}
    return {"name": "Nocturne (HNO)", "slot": "22h00 - 06h00", "mode": "3/8 — Batchs & Astreintes"}
