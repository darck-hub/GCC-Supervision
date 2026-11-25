"""Webhooks industriels isolés (Centreon, Zabbix, HAL/Netcool, JES2 z/OS).

Exemptés de CSRF navigateur par conception, protégés par Rate Limiting dédié
et signature cryptographique HMAC-SHA256 (en-tête X-GCC-Signature).
"""

from __future__ import annotations

from flask import Blueprint, current_app, g, jsonify, request

from backend.database import log_audit
from backend.routing_engine import ingest_alert
from backend.security import exiger_role, verify_webhook_signature

webhooks_bp = Blueprint("webhooks", __name__, url_prefix="/api/webhooks")


@webhooks_bp.post("/alerts")
def receive_webhook_alert():
    """Point d'entrée sécurisé HMAC-SHA256 pour les sondes de supervision."""
    cfg = current_app.config["GCC_CONFIG"]
    limiter = current_app.config["GCC_RATE_LIMITER"]
    ip = request.remote_addr or "unknown"

    allowed, retry_after = limiter.check_and_record(
        f"webhook:{ip}", cfg.WEBHOOK_MAX_RPM, 60
    )
    if not allowed:
        log_audit(
            cfg.DB_PATH, "webhook", "system", "WEBHOOK_RATE_LIMITED",
            "/api/webhooks/alerts", ip, "BLOCKED", f"retry_after={retry_after}s"
        )
        return jsonify({"error": "Limite de débit webhook dépassée."}), 429

    raw_body = request.get_data(cache=True)
    sig_header = request.headers.get("X-GCC-Signature", "")
    if not verify_webhook_signature(raw_body, sig_header, cfg.WEBHOOK_SECRET):
        log_audit(
            cfg.DB_PATH, "webhook", "system", "WEBHOOK_BAD_SIGNATURE",
            "/api/webhooks/alerts", ip, "DENIED", "Signature HMAC-SHA256 absente ou invalide"
        )
        return jsonify({"error": "Signature HMAC-SHA256 invalide (X-GCC-Signature)."}), 401

    data = request.get_json(silent=True) or {}
    source_tool = str(data.get("source_tool", "")).strip()[:64]
    plateau = str(data.get("plateau", "Banque")).strip()
    host = str(data.get("host", "")).strip()[:64]
    error_code = str(data.get("error_code", "")).strip()[:40]
    message = str(data.get("message", "")).strip()[:500]
    severity = str(data.get("severity", "")).strip().upper() or None

    if not source_tool or not host or not error_code or not message:
        return jsonify({"error": "Champs requis : source_tool, host, error_code, message."}), 400

    result = ingest_alert(
        cfg=cfg,
        source_tool=source_tool,
        plateau=plateau,
        host=host,
        error_code=error_code,
        message=message,
        severity=severity,
        actor=f"Webhook ({source_tool})",
    )
    log_audit(
        cfg.DB_PATH, "webhook", "system", "WEBHOOK_INGEST", f"{host}:{error_code}", ip,
        "SUCCESS",
        f"deduplicated={result['deduplicated']}, occ={result['occurrence_count']}, prio={result['severity']}"
    )
    return jsonify(result), (200 if result["deduplicated"] else 201)


@webhooks_bp.post("/simulate")
@exiger_role("admin", "pilote")
def simulate_alert():
    """Déclenche une alerte de test interne depuis l'interface d'administration/supervision."""
    cfg = current_app.config["GCC_CONFIG"]
    data = request.get_json(silent=True) or {}
    preset = str(data.get("preset", "zos_rc0016")).strip().lower()

    presets = {
        "zos_rc0016": (
            "Mainframe z/OS", "Banque", "ZOS-PRD-AF01", "RC-0016",
            "JOB CH7GZBM1 ABENDED AT STEP040 — CRITICAL RC-0016 BATCH COBOL", "P1"
        ),
        "zos_b37": (
            "Mainframe z/OS", "Banque", "ZOS-PRD-AF02", "B37",
            "ABEND SB37-04 SATURATION ESPACE DISQUE SUR VOL=PRD014", "P1"
        ),
        "db2_deadlock": (
            "HAL/Netcool", "Banque", "DB2-BNQ-02", "DB2 -911",
            "SQLCODE -911 DEADLOCK/TIMEOUT ON TRANSACTION TABLE TS_COMP01", "P2"
        ),
        "net_link": (
            "Centreon", "Multi-Client", "RTR-CORE-TLS01", "LINK_DOWN",
            "INTERFACE Gi0/0/1 DOWN — PERTE CONNECTIVITÉ BACKBONE", "P1"
        ),
        "cpu_spike": (
            "Zabbix", "Multi-Client", "SRV-WEB-09", "CPU_HIGH",
            "CPU LOAD > 94% PENDANT 5 MIN SUR SERVEUR FRONTAL", "P3"
        ),
    }

    if preset not in presets:
        return jsonify({"error": "Scénario de simulation inconnu."}), 400

    source_tool, plateau, host, error_code, message, severity = presets[preset]
    result = ingest_alert(
        cfg=cfg,
        source_tool=source_tool,
        plateau=plateau,
        host=host,
        error_code=error_code,
        message=message,
        severity=severity,
        actor=f"Simulation ({g.current_user['username']})",
    )
    log_audit(
        cfg.DB_PATH,
        g.current_user["username"],
        g.current_user["role"],
        "ALERT_SIMULATED",
        f"{host}:{error_code}",
        request.remote_addr or "unknown",
        "SUCCESS",
        f"preset={preset}, deduplicated={result['deduplicated']}",
    )
    return jsonify(result), 201
