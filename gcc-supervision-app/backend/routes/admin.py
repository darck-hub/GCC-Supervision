"""Administration GCC : gestion des comptes RBAC et des collecteurs d'alertes."""

from __future__ import annotations

from flask import Blueprint, current_app, g, jsonify, request

from backend.database import get_db, log_audit, utc_now_iso
from backend.security import exiger_role, hash_password, validate_password_policy

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@admin_bp.get("/users")
@exiger_role("admin")
def list_users():
    """Liste les comptes utilisateurs (sans jamais exposer les empreintes de mots de passe)."""
    cfg = current_app.config["GCC_CONFIG"]
    with get_db(cfg.DB_PATH) as conn:
        users = [
            dict(r)
            for r in conn.execute(
                """
                SELECT id, username, full_name, role, plateau, is_active,
                       failed_attempts, locked_until, created_at
                FROM users ORDER BY id ASC
                """
            ).fetchall()
        ]
    return jsonify({"users": users})


@admin_bp.post("/users")
@exiger_role("admin")
def create_user():
    """Crée un compte opérateur avec politique de mot de passe ANSSI/CNIL."""
    cfg = current_app.config["GCC_CONFIG"]
    data = request.get_json(silent=True) or {}

    username = str(data.get("username", "")).strip().lower()
    full_name = str(data.get("full_name", "")).strip()[:80]
    password = str(data.get("password", ""))
    role = str(data.get("role", "pilote")).strip().lower()
    plateau = str(data.get("plateau", "Banque")).strip()

    if not username or len(username) < 3 or len(username) > 32 or not username.replace("_", "").isalnum():
        return jsonify({"error": "Nom d'utilisateur invalide (3-32 caractères alphanumériques/_)."}), 400
    if not full_name:
        return jsonify({"error": "Nom complet requis."}), 400
    if role not in cfg.VALID_ROLES:
        return jsonify({"error": f"Rôle invalide ({', '.join(cfg.VALID_ROLES)})."}), 400
    if plateau not in cfg.VALID_PLATEAUS:
        return jsonify({"error": "Plateau invalide."}), 400

    ok_pwd, msg_pwd = validate_password_policy(password)
    if not ok_pwd:
        return jsonify({"error": msg_pwd}), 400

    with get_db(cfg.DB_PATH) as conn:
        if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            return jsonify({"error": "Ce nom d'utilisateur existe déjà."}), 409

        cur = conn.execute(
            """
            INSERT INTO users (username, full_name, password_hash, role, plateau, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, 1, ?)
            """,
            (username, full_name, hash_password(password), role, plateau, utc_now_iso()),
        )
        new_user = dict(
            conn.execute(
                "SELECT id, username, full_name, role, plateau, is_active, created_at FROM users WHERE id = ?",
                (cur.lastrowid,),
            ).fetchone()
        )

    log_audit(
        cfg.DB_PATH,
        g.current_user["username"],
        g.current_user["role"],
        "USER_CREATE",
        username,
        request.remote_addr or "unknown",
        "SUCCESS",
        f"Rôle={role}, Plateau={plateau}",
    )
    return jsonify({"user": new_user}), 201


@admin_bp.patch("/users/<int:user_id>")
@exiger_role("admin")
def update_user(user_id: int):
    """Modifie le rôle, le plateau ou l'activation d'un compte opérateur."""
    cfg = current_app.config["GCC_CONFIG"]
    data = request.get_json(silent=True) or {}

    with get_db(cfg.DB_PATH) as conn:
        existing = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not existing:
            return jsonify({"error": "Utilisateur introuvable."}), 404

        new_role = str(data.get("role", existing["role"])).strip().lower()
        new_plateau = str(data.get("plateau", existing["plateau"])).strip()
        new_active = 1 if data.get("is_active", bool(existing["is_active"])) else 0

        if new_role not in cfg.VALID_ROLES:
            return jsonify({"error": "Rôle invalide."}), 400
        if new_plateau not in cfg.VALID_PLATEAUS:
            return jsonify({"error": "Plateau invalide."}), 400
        if user_id == g.current_user["id"] and (new_active == 0 or new_role != "admin"):
            return jsonify({"error": "Impossible de désactiver ou rétrograder votre propre compte admin."}), 400

        conn.execute(
            "UPDATE users SET role = ?, plateau = ?, is_active = ?, locked_until = NULL, failed_attempts = 0 WHERE id = ?",
            (new_role, new_plateau, new_active, user_id),
        )

    log_audit(
        cfg.DB_PATH,
        g.current_user["username"],
        g.current_user["role"],
        "USER_UPDATE",
        existing["username"],
        request.remote_addr or "unknown",
        "SUCCESS",
        f"role={new_role}, plateau={new_plateau}, active={new_active}",
    )
    return jsonify({"updated": True})


@admin_bp.get("/collectors")
@exiger_role("admin", "pilote", "auditeur")
def list_collectors():
    """Liste les collecteurs d'alertes configurés (HAL, Centreon, Zabbix, JES2, Bot Marvin)."""
    cfg = current_app.config["GCC_CONFIG"]
    with get_db(cfg.DB_PATH) as conn:
        rows = [
            dict(r)
            for r in conn.execute("SELECT * FROM collectors ORDER BY id ASC").fetchall()
        ]
    return jsonify({"collectors": rows})


@admin_bp.patch("/collectors/<int:collector_id>")
@exiger_role("admin")
def toggle_collector(collector_id: int):
    """Active ou désactive un collecteur d'alertes."""
    cfg = current_app.config["GCC_CONFIG"]
    data = request.get_json(silent=True) or {}
    enabled = 1 if data.get("enabled", True) else 0

    with get_db(cfg.DB_PATH) as conn:
        row = conn.execute("SELECT name FROM collectors WHERE id = ?", (collector_id,)).fetchone()
        if not row:
            return jsonify({"error": "Collecteur introuvable."}), 404
        conn.execute("UPDATE collectors SET enabled = ? WHERE id = ?", (enabled, collector_id))

    log_audit(
        cfg.DB_PATH,
        g.current_user["username"],
        g.current_user["role"],
        "COLLECTOR_TOGGLE",
        row["name"],
        request.remote_addr or "unknown",
        "SUCCESS",
        f"enabled={bool(enabled)}",
    )
    return jsonify({"id": collector_id, "enabled": bool(enabled)})
