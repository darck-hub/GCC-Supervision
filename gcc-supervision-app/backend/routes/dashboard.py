"""Routes du tableau de bord temps réel (Supervision Zabbix / HAL Netcool)."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify

from backend.database import get_db
from backend.routing_engine import enrich_ticket_sla, get_current_shift
from backend.security import exiger_role

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")


@dashboard_bp.get("/overview")
@exiger_role("admin", "pilote", "n2", "auditeur")
def overview():
    """Retourne les KPIs, l'état des services, le shift 3/8 et les alertes corrélées."""
    cfg = current_app.config["GCC_CONFIG"]
    with get_db(cfg.DB_PATH) as conn:
        services = [
            dict(r)
            for r in conn.execute("SELECT * FROM services ORDER BY plateau ASC, name ASC").fetchall()
        ]
        tickets_raw = [
            dict(r)
            for r in conn.execute("SELECT * FROM tickets ORDER BY created_at DESC").fetchall()
        ]
        alerts = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM alerts ORDER BY last_seen DESC LIMIT 12"
            ).fetchall()
        ]

    tickets = [enrich_ticket_sla(t, cfg) for t in tickets_raw]
    open_tickets = [t for t in tickets if t["status"] not in ("RESOLU", "CLOTURE")]
    critical_open = [t for t in open_tickets if t["priority"] in ("P1", "P2")]
    sla_at_risk = [t for t in open_tickets if t["sla_state"] in ("WARNING", "BREACHED")]

    total_tickets = len(tickets)
    breached_count = sum(1 for t in tickets if t["sla_state"] == "BREACHED")
    sla_compliance = (
        round(((total_tickets - breached_count) / total_tickets) * 100.0, 1)
        if total_tickets > 0
        else 100.0
    )

    deduplicated_events = sum(max(0, int(a["occurrence_count"]) - 1) for a in alerts)
    services_ok = sum(1 for s in services if s["status"] == "OK")

    return jsonify(
        {
            "shift": get_current_shift(),
            "kpis": {
                "open_tickets": len(open_tickets),
                "critical_p1_p2": len(critical_open),
                "sla_compliance_pct": sla_compliance,
                "sla_at_risk": len(sla_at_risk),
                "alerts_deduplicated": deduplicated_events,
                "active_services_ok": services_ok,
                "active_services_total": len(services),
            },
            "services": services,
            "recent_alerts": alerts,
            "priority_tickets": open_tickets[:6],
        }
    )
