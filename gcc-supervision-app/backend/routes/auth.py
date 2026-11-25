"""Routes d'authentification sécurisée (JWT RAM 15 min, anti brute-force, révocation JTI)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from flask import Blueprint, current_app, g, jsonify, request

from backend.database import get_db, log_audit, revoke_jti, utc_now_iso
from backend.security import create_jwt, exiger_role, verify_password

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.post("/login")
def login():
    """Authentifie un opérateur et délivre un JWT (TTL 15 min) + jeton CSRF lié."""
    cfg = current_app.config["GCC_CONFIG"]
    limiter = current_app.config["GCC_RATE_LIMITER"]
    ip = request.remote_addr or "unknown"

    allowed, retry_after = limiter.check_and_record(
        f"login:{ip}", cfg.LOGIN_MAX_ATTEMPTS, cfg.LOGIN_WINDOW_SECONDS
    )
    if not allowed:
        log_audit(
            cfg.DB_PATH,
            username="anonymous",
            role="none",
            action="LOGIN_RATE_LIMITED",
            target="/api/auth/login",
            ip_address=ip,
            status="BLOCKED",
            details=f"Anti brute-force déclenché (retry_after={retry_after}s)",
        )
        resp = jsonify(
            {
                "error": "Trop de tentatives de connexion. Réessayez ultérieurement.",
                "retry_after": retry_after,
            }
        )
        resp.headers["Retry-After"] = str(retry_after)
        return resp, 429

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password or len(username) > 64 or len(password) > 128:
        return jsonify({"error": "Identifiants invalides."}), 400

    now = datetime.now(timezone.utc)
    with get_db(cfg.DB_PATH) as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if not user or not int(user["is_active"]):
            log_audit(
                cfg.DB_PATH, username, "none", "LOGIN_FAILED", "/api/auth/login", ip,
                "DENIED", "Compte inexistant ou désactivé"
            )
            return jsonify({"error": "Identifiant ou mot de passe incorrect."}), 401

        # Vérification du verrouillage temporaire du compte
        if user["locked_until"]:
            locked_dt = datetime.strptime(
                user["locked_until"], "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
            if now < locked_dt:
                log_audit(
                    cfg.DB_PATH, username, user["role"], "LOGIN_LOCKED", "/api/auth/login", ip,
                    "BLOCKED", "Compte temporairement verrouillé suite à échecs répétés"
                )
                return jsonify({"error": "Compte temporairement verrouillé (protection brute-force)."}), 423

        if not verify_password(password, user["password_hash"]):
            attempts = int(user["failed_attempts"]) + 1
            locked_until = None
            if attempts >= cfg.LOGIN_MAX_ATTEMPTS:
                locked_until = (
                    now + timedelta(seconds=cfg.ACCOUNT_LOCKOUT_SECONDS)
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
                attempts = 0
            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked_until, user["id"]),
            )
            log_audit(
                cfg.DB_PATH, username, user["role"], "LOGIN_FAILED", "/api/auth/login", ip,
                "DENIED", "Mot de passe incorrect"
            )
            return jsonify({"error": "Identifiant ou mot de passe incorrect."}), 401

        # Authentification réussie : réinitialisation compteurs
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user["id"],),
        )

    limiter.reset(f"login:{ip}")
    token, csrf_token, _jti, exp = create_jwt(
        user_id=int(user["id"]),
        username=user["username"],
        role=user["role"],
        plateau=user["plateau"],
        secret=cfg.JWT_SECRET,
        ttl_seconds=cfg.JWT_TTL_SECONDS,
    )
    log_audit(
        cfg.DB_PATH,
        username=user["username"],
        role=user["role"],
        action="LOGIN_SUCCESS",
        target="/api/auth/login",
        ip_address=ip,
        status="SUCCESS",
        details="Session JWT volatile délivrée (TTL 15 min)",
    )

    return jsonify(
        {
            "token": token,
            "csrf_token": csrf_token,
            "expires_in": cfg.JWT_TTL_SECONDS,
            "expires_at": exp,
            "user": {
                "id": int(user["id"]),
                "username": user["username"],
                "full_name": user["full_name"],
                "role": user["role"],
                "plateau": user["plateau"],
            },
        }
    )


@auth_bp.post("/logout")
@exiger_role("admin", "pilote", "n2", "auditeur")
def logout():
    """Révoque le JTI courant côté serveur pour invalider définitivement la session."""
    cfg = current_app.config["GCC_CONFIG"]
    user = g.current_user
    revoke_jti(cfg.DB_PATH, user["jti"], user["exp"])
    log_audit(
        cfg.DB_PATH,
        username=user["username"],
        role=user["role"],
        action="LOGOUT",
        target="/api/auth/logout",
        ip_address=request.remote_addr or "unknown",
        status="SUCCESS",
        details="Jeton JWT révoqué côté serveur",
    )
    return jsonify({"message": "Déconnexion sécurisée effectuée.", "timestamp": utc_now_iso()})


@auth_bp.get("/me")
@exiger_role("admin", "pilote", "n2", "auditeur")
def me():
    """Retourne les informations de session courante et le temps restant avant auto-logout."""
    import time

    user = g.current_user
    remaining = max(0, int(user["exp"]) - int(time.time()))
    return jsonify(
        {
            "user": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "plateau": user["plateau"],
            },
            "expires_at": user["exp"],
            "remaining_seconds": remaining,
        }
    )
