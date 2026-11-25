"""Couche de persistance SQLite durcie en mode WAL (Write-Ahead Logging).

Toutes les requêtes SQL sont strictement paramétrées (?) pour éliminer tout risque
d'injection SQL.
"""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from backend.security import hash_password


def utc_now_iso() -> str:
    """Retourne l'horodatage UTC au format ISO-8601 strict."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@contextmanager
def get_db(db_path: str) -> Iterator[sqlite3.Connection]:
    """Ouvre une connexion SQLite configurée en mode WAL avec intégrité référentielle."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA busy_timeout=5000;")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'pilote', 'n2', 'auditeur')),
    plateau TEXT NOT NULL CHECK(plateau IN ('Multi-Client', 'Banque')),
    is_active INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT DEFAULT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    revoked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    tool TEXT NOT NULL,
    plateau TEXT NOT NULL CHECK(plateau IN ('Multi-Client', 'Banque')),
    environment TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('OK', 'DEGRADED', 'CRITICAL')),
    latency_ms INTEGER NOT NULL DEFAULT 12,
    uptime_pct REAL NOT NULL DEFAULT 99.95,
    last_check TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS procedures (
    code TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    steps TEXT NOT NULL,
    rundeck_job TEXT DEFAULT NULL,
    escalation_group TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS routing_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    keyword TEXT NOT NULL,
    source_tool TEXT NOT NULL,
    plateau TEXT NOT NULL CHECK(plateau IN ('Multi-Client', 'Banque')),
    priority TEXT NOT NULL CHECK(priority IN ('P1', 'P2', 'P3', 'P4')),
    target_group TEXT NOT NULL,
    procedure_code TEXT DEFAULT NULL REFERENCES procedures(code),
    auto_create_ticket INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_tool TEXT NOT NULL,
    plateau TEXT NOT NULL CHECK(plateau IN ('Multi-Client', 'Banque')),
    host TEXT NOT NULL,
    error_code TEXT NOT NULL,
    message TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('P1', 'P2', 'P3', 'P4')),
    status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'QUALIFIED', 'ACK')),
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    matched_rule TEXT DEFAULT NULL,
    ticket_id INTEGER DEFAULT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reference TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    priority TEXT NOT NULL CHECK(priority IN ('P1', 'P2', 'P3', 'P4')),
    status TEXT NOT NULL CHECK(status IN ('NOUVEAU', 'EN_COURS', 'ESCALADE_N2', 'ESCALADE_N3', 'RESOLU', 'CLOTURE')),
    plateau TEXT NOT NULL CHECK(plateau IN ('Multi-Client', 'Banque')),
    source_tool TEXT NOT NULL,
    host TEXT NOT NULL,
    error_code TEXT DEFAULT NULL,
    assigned_group TEXT NOT NULL,
    assigned_to TEXT DEFAULT NULL,
    procedure_code TEXT DEFAULT NULL REFERENCES procedures(code),
    sla_deadline TEXT NOT NULL,
    rca_required INTEGER NOT NULL DEFAULT 0,
    resolution_notes TEXT DEFAULT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ticket_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    author TEXT NOT NULL,
    author_role TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS collectors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    plateau TEXT NOT NULL CHECK(plateau IN ('Multi-Client', 'Banque')),
    endpoint_hint TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    events_ingested INTEGER NOT NULL DEFAULT 0,
    last_heartbeat TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    status TEXT NOT NULL,
    details TEXT DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(source_tool, host, error_code, status);
CREATE INDEX IF NOT EXISTS idx_tickets_status_prio ON tickets(status, priority);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(timestamp DESC);
"""


def init_db(db_path: str, seed_demo: bool = True, env_mode: str = "development") -> None:
    """Initialise le schéma SQLite WAL et insère un jeu de données GCC réaliste en mode dev."""
    with get_db(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
        # Purge des jetons révoqués déjà expirés
        now_epoch = int(datetime.now(timezone.utc).timestamp())
        conn.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (now_epoch,))

        if seed_demo and env_mode != "production":
            existing = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
            if existing == 0:
                _seed_demo_data(conn)


def _seed_demo_data(conn: sqlite3.Connection) -> None:
    """Peuple la base de démonstration avec des scénarios inspirés du GCC Capgemini."""
    now = datetime.now(timezone.utc)
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Mots de passe lus depuis l'environnement ou valeurs de démonstration conformes ANSSI (>=12 car.)
    demo_users = [
        (
            "admin",
            "Responsable GCC (Admin)",
            os.environ.get("GCC_DEMO_ADMIN_PASS", "AdminGcc!2026#Sec"),
            "admin",
            "Banque",
        ),
        (
            "pilote",
            "Pilote N1 — Shift 3/8",
            os.environ.get("GCC_DEMO_PILOTE_PASS", "PiloteN1!2026#Gcc"),
            "pilote",
            "Banque",
        ),
        (
            "tech_n2",
            "Ingénieur Support N2",
            os.environ.get("GCC_DEMO_N2_PASS", "SupportN2!2026#Op"),
            "n2",
            "Multi-Client",
        ),
        (
            "auditeur",
            "Auditeur Sécurité / CNIL",
            os.environ.get("GCC_DEMO_AUDIT_PASS", "AuditCnil!2026#Ok"),
            "auditeur",
            "Banque",
        ),
    ]
    for username, full_name, pwd, role, plateau in demo_users:
        conn.execute(
            """
            INSERT INTO users (username, full_name, password_hash, role, plateau, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, 1, ?)
            """,
            (username, full_name, hash_password(pwd), role, plateau, now_iso),
        )

    procedures = [
        (
            "PROC-NET-001",
            "Perte de lien backbone / Alerte critique réseau",
            "Réseau",
            "1. Vérifier la corrélation dans HAL (IBM Netcool) pour écarter un faux positif.\n"
            "2. Contrôler les interfaces actives et la latence via Centreon / Zabbix.\n"
            "3. Ouvrir un ticket P1 dans ServiceNow et déclencher la cellule d'astreinte Réseau N2/N3 en HNO.\n"
            "4. Documenter chaque étape dans le fil d'exploitation pour le RCA post-incident.",
            "net-diag-bgp-check",
            "Équipe Réseau N2",
        ),
        (
            "PROC-ZOS-016",
            "Abend Batch COBOL JES2 — Code retour RC-0016 / B37-E37",
            "Mainframe z/OS",
            "1. Ouvrir le JES2 JOB LOG du traitement batch (ex. CH7GZBM1) et relever l'étape en échec.\n"
            "2. Vérifier si l'arrêt provient d'une saturation espace disque (Abend B37/E37) ou d'un RC-0016.\n"
            "3. Si éligible N1, exécuter le job de nettoyage/relance certifié via Rundeck (sans accès direct z/OS).\n"
            "4. En cas de récidive, escalader immédiatement au groupe Mainframe z/OS N2 (Air France).",
            "rundeck-zos-batch-restart",
            "Équipe Mainframe z/OS N2",
        ),
        (
            "PROC-DB2-911",
            "Contention base DB2 — Codes -904 (indisponible) / -911 (Deadlock)",
            "Base de données",
            "1. Identifier la ressource verrouillée ou indisponible dans les journaux HAL/DB2.\n"
            "2. Contrôler le nombre d'occurrences dédupliquées sur les 15 dernières minutes.\n"
            "3. Lancer la vérification de verrous via Rundeck puis notifier le DBA N2 si le timeout persiste.\n"
            "4. Préparer l'export d'historique pour le processus RCA.",
            "rundeck-db2-lock-check",
            "Équipe DBA N2",
        ),
        (
            "PROC-SRV-002",
            "Saturation CPU / Mémoire sur serveur Linux ou Windows",
            "Système",
            "1. Vérifier s'il s'agit d'une sauvegarde planifiée (faux positif connu).\n"
            "2. Contrôler les tendances Zabbix sur 30 minutes.\n"
            "3. Appliquer la fiche réflexe de nettoyage des espaces temporaires via Rundeck.\n"
            "4. Transférer au support Système N2 si le seuil critique > 95% persiste au-delà de 15 minutes.",
            "rundeck-sys-tmp-cleanup",
            "Équipe Système N2",
        ),
        (
            "PROC-SEC-004",
            "Tentative d'intrusion / Pic brute-force détecté",
            "Cybersécurité",
            "1. Isoler l'adresse IP source et vérifier le volume d'échecs dans les journaux d'audit.\n"
            "2. Confirmer le déclenchement automatique du Rate Limiting applicatif.\n"
            "3. Escalader immédiatement au SOC / Équipe Sécurité N3 avec les preuves horodatées (UTC).\n"
            "4. Activer les mesures du PCA en cas de menace sur un service critique.",
            None,
            "SOC / Cybersécurité N3",
        ),
    ]
    conn.executemany(
        """
        INSERT INTO procedures (code, title, category, steps, rundeck_job, escalation_group)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        procedures,
    )

    services = [
        ("HAL — Hyperviseur IBM Netcool", "HAL/Netcool", "Banque", "Production", "OK", 18, 99.98, now_iso),
        ("Mainframe z/OS JES2 (Air France)", "Mainframe z/OS", "Banque", "Production", "CRITICAL", 240, 99.91, now_iso),
        ("Cluster DB2 Transactions", "HAL/Netcool", "Banque", "Production", "DEGRADED", 145, 99.94, now_iso),
        ("Rundeck — Remédiation Automatisée", "Rundeck", "Banque", "Production", "OK", 24, 99.99, now_iso),
        ("Centreon — Supervision Multi-Client", "Centreon", "Multi-Client", "Production", "OK", 15, 99.97, now_iso),
        ("Zabbix — Sondes Infrastructures", "Zabbix", "Multi-Client", "Production", "OK", 22, 99.95, now_iso),
        ("Passerelle ITSM ServiceNow", "ServiceNow", "Multi-Client", "Production", "OK", 38, 99.99, now_iso),
        ("Backbone WAN Agences", "Centreon", "Multi-Client", "Production", "DEGRADED", 189, 99.89, now_iso),
    ]
    conn.executemany(
        """
        INSERT INTO services (name, tool, plateau, environment, status, latency_ms, uptime_pct, last_check)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        services,
    )

    rules = [
        ("Mainframe RC-0016 Critique", "RC-0016", "Mainframe z/OS", "Banque", "P1", "Équipe Mainframe z/OS N2", "PROC-ZOS-016", 1, 1),
        ("Mainframe Saturation Disque B37/E37", "B37", "Mainframe z/OS", "Banque", "P1", "Équipe Mainframe z/OS N2", "PROC-ZOS-016", 1, 1),
        ("DB2 Deadlock (-911)", "-911", "HAL/Netcool", "Banque", "P2", "Équipe DBA N2", "PROC-DB2-911", 1, 1),
        ("DB2 Ressource Indisponible (-904)", "-904", "HAL/Netcool", "Banque", "P2", "Équipe DBA N2", "PROC-DB2-911", 1, 1),
        ("Rupture Lien Réseau Backbone", "LINK_DOWN", "Centreon", "Multi-Client", "P1", "Équipe Réseau N2", "PROC-NET-001", 1, 1),
        ("Pic CPU Serveur Production", "CPU_HIGH", "Zabbix", "Multi-Client", "P3", "Pilote N1", "PROC-SRV-002", 0, 1),
        ("Alerte Sécurité Brute-Force", "BRUTE_FORCE", "HAL/Netcool", "Banque", "P1", "SOC / Cybersécurité N3", "PROC-SEC-004", 1, 1),
    ]
    conn.executemany(
        """
        INSERT INTO routing_rules
            (name, keyword, source_tool, plateau, priority, target_group, procedure_code, auto_create_ticket, enabled)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rules,
    )

    collectors = [
        ("HAL — IBM Netcool", "Hyperviseur", "Banque", "/api/webhooks/alerts (HMAC-SHA256)", 1, 1428, now_iso),
        ("Centreon Enterprise", "Supervision Réseau", "Multi-Client", "/api/webhooks/alerts (HMAC-SHA256)", 1, 864, now_iso),
        ("Zabbix Server 7.0", "Supervision Système", "Multi-Client", "/api/webhooks/alerts (HMAC-SHA256)", 1, 612, now_iso),
        ("JES2 z/OS Log Bridge", "Mainframe Batch", "Banque", "/api/webhooks/alerts (HMAC-SHA256)", 1, 319, now_iso),
        ("Bot Marvin (Bridge N1)", "Automatisation Tickets", "Banque", "Interne (Moteur Routage)", 1, 504, now_iso),
    ]
    conn.executemany(
        """
        INSERT INTO collectors (name, type, plateau, endpoint_hint, enabled, events_ingested, last_heartbeat)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        collectors,
    )

    # Tickets réalistes avec délais SLA variés (dont 1 proche de l'échéance)
    t1_sla = (now + timedelta(minutes=11)).strftime("%Y-%m-%dT%H:%M:%SZ")
    t2_sla = (now + timedelta(minutes=42)).strftime("%Y-%m-%dT%H:%M:%SZ")
    t3_sla = (now + timedelta(hours=3, minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
    t4_sla = (now - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    t_old = (now - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

    tickets = [
        (
            "INC-2026-0001",
            "Arrêt batch COBOL CH7GZBM1 — Code retour critique RC-0016",
            "Détection d'un arrêt brutal de la chaîne batch financière sous ordonnanceur JES2 (Air France). Code machine RC-0016 relevé dans le JES2 JOB LOG.",
            "P1",
            "EN_COURS",
            "Banque",
            "Mainframe z/OS",
            "ZOS-PRD-AF01",
            "RC-0016",
            "Équipe Mainframe z/OS N2",
            "pilote",
            "PROC-ZOS-016",
            t1_sla,
            1,
            None,
            "Bot Marvin",
            now_iso,
            now_iso,
        ),
        (
            "INC-2026-0002",
            "Contention DB2 -911 (Deadlock) sur cluster transactions bancaires",
            "Corrélation HAL de 14 alarmes de timeout sur les tables de compensation. Latence applicative dégradée.",
            "P2",
            "ESCALADE_N2",
            "Banque",
            "HAL/Netcool",
            "DB2-BNQ-02",
            "DB2 -911",
            "Équipe DBA N2",
            "tech_n2",
            "PROC-DB2-911",
            t2_sla,
            1,
            None,
            "pilote",
            now_iso,
            now_iso,
        ),
        (
            "INC-2026-0003",
            "Dégradation latence WAN sur lien secondaire Toulouse-Colomiers",
            "Sonde Centreon signale une perte de paquets de 6% et une latence à 189 ms sur le lien backup.",
            "P3",
            "NOUVEAU",
            "Multi-Client",
            "Centreon",
            "RTR-WAN-TLS02",
            "LINK_DEG",
            "Équipe Réseau N2",
            None,
            "PROC-NET-001",
            t3_sla,
            0,
            None,
            "pilote",
            now_iso,
            now_iso,
        ),
        (
            "INC-2026-0004",
            "Pic CPU temporaire lors de la sauvegarde nocturne (Faux positif validé)",
            "Alerte Zabbix CPU > 92% sur SRV-BKP-04 durant le créneau HNO. Vérifié conforme à la fenêtre de backup.",
            "P4",
            "CLOTURE",
            "Multi-Client",
            "Zabbix",
            "SRV-BKP-04",
            "CPU_HIGH",
            "Pilote N1",
            "pilote",
            "PROC-SRV-002",
            t4_sla,
            0,
            "Vérification des logs de sauvegarde effectuée : activité nominale de backup nocturne. Ticket clôturé avec traçabilité.",
            "pilote",
            t_old,
            now_iso,
        ),
    ]
    conn.executemany(
        """
        INSERT INTO tickets
            (reference, title, description, priority, status, plateau, source_tool, host,
             error_code, assigned_group, assigned_to, procedure_code, sla_deadline,
             rca_required, resolution_notes, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        tickets,
    )

    comments = [
        (1, "Bot Marvin", "pilote", "Qualification automatique P1 effectuée selon la règle 'Mainframe RC-0016 Critique'. Procédure PROC-ZOS-016 associée.", now_iso),
        (1, "pilote", "pilote", "Lecture du JES2 JOB LOG effectuée : étape STEP040 en échec RC-0016. Préparation de la relance contrôlée via Rundeck et notification N2.", now_iso),
        (2, "pilote", "pilote", "14 événements corrélés par HAL en un incident unique. Escalade transmise à l'équipe DBA N2.", now_iso),
        (2, "tech_n2", "n2", "Prise en charge N2 : analyse des verrous actifs sur le tablespace TS_COMP01 en cours.", now_iso),
    ]
    conn.executemany(
        """
        INSERT INTO ticket_comments (ticket_id, author, author_role, content, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        comments,
    )

    alerts = [
        ("Mainframe z/OS", "Banque", "ZOS-PRD-AF01", "RC-0016", "JOB CH7GZBM1 ENDED WITH RC-0016 AT STEP040", "P1", "QUALIFIED", 3, "Mainframe RC-0016 Critique", 1, now_iso, now_iso),
        ("HAL/Netcool", "Banque", "DB2-BNQ-02", "DB2 -911", "SQLCODE -911 DEADLOCK OR TIMEOUT ON TS_COMP01", "P2", "QUALIFIED", 14, "DB2 Deadlock (-911)", 2, now_iso, now_iso),
        ("Centreon", "Multi-Client", "RTR-WAN-TLS02", "LINK_DOWN", "Packet loss 6.4% / RTT 189ms on Gi0/1", "P1", "ACTIVE", 5, "Rupture Lien Réseau Backbone", None, now_iso, now_iso),
        ("Zabbix", "Multi-Client", "SRV-APP-12", "CPU_HIGH", "CPU utilization > 88% over 10m", "P3", "ACTIVE", 2, "Pic CPU Serveur Production", None, now_iso, now_iso),
    ]
    conn.executemany(
        """
        INSERT INTO alerts
            (source_tool, plateau, host, error_code, message, severity, status,
             occurrence_count, matched_rule, ticket_id, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        alerts,
    )

    conn.execute(
        """
        INSERT INTO audit_logs (timestamp, username, role, action, target, ip_address, status, details)
        VALUES (?, 'system', 'admin', 'SYSTEM_BOOTSTRAP', 'SQLite WAL', '127.0.0.1', 'SUCCESS',
                'Base initialisée en mode WAL avec politiques ANSSI/CNIL actives')
        """,
        (now_iso,),
    )


def log_audit(
    db_path: str,
    username: str,
    role: str,
    action: str,
    target: str,
    ip_address: str,
    status: str,
    details: Optional[str] = None,
) -> None:
    """Enregistre un événement immuable dans le journal d'audit CNIL/ANSSI."""
    with get_db(db_path) as conn:
        conn.execute(
            """
            INSERT INTO audit_logs (timestamp, username, role, action, target, ip_address, status, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (utc_now_iso(), username, role, action, target, ip_address, status, details),
        )


def revoke_jti(db_path: str, jti: str, expires_at: int) -> None:
    """Révoque immédiatement un jeton JWT (déconnexion ou invalidation forcée)."""
    with get_db(db_path) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO revoked_tokens (jti, expires_at, revoked_at) VALUES (?, ?, ?)",
            (jti, expires_at, utc_now_iso()),
        )


def is_jti_revoked(db_path: str, jti: str) -> bool:
    """Vérifie si un identifiant de jeton JWT (JTI) a été révoqué."""
    if not jti:
        return True
    with get_db(db_path) as conn:
        row = conn.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)).fetchone()
        return row is not None
