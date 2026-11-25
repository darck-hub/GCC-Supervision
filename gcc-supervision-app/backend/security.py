"""Couches de sécurité applicative : Cryptographie, JWT, CSRF, HMAC, RBAC et Rate Limiting.

Implémentation alignée sur les référentiels ANSSI (RGS 2.0, Hygiène Informatique)
et CNIL (Guide sécurité des données personnelles).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from functools import wraps
from typing import Any, Callable, Deque, Dict, Optional, Tuple


# ---------------------------------------------------------------------------
# 1. Hachage des mots de passe (Scrypt + sel aléatoire 16 octets)
# ---------------------------------------------------------------------------
SCRYPT_N = 16384  # 2^14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32

PASSWORD_POLICY_REGEX = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,128}$"
)


def validate_password_policy(password: str) -> Tuple[bool, str]:
    """Vérifie la robustesse du mot de passe (recommandations ANSSI/CNIL : >= 12 car. 4 classes)."""
    if not isinstance(password, str):
        return False, "Mot de passe invalide."
    if not PASSWORD_POLICY_REGEX.match(password):
        return (
            False,
            "Le mot de passe doit contenir entre 12 et 128 caractères avec au moins "
            "une majuscule, une minuscule, un chiffre et un caractère spécial.",
        )
    return True, ""


def hash_password(password: str) -> str:
    """Hache un mot de passe avec scrypt et un sel CSPRNG unique."""
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Vérifie un mot de passe en temps constant (protection contre les timing attacks)."""
    try:
        algo, n_s, r_s, p_s, salt_hex, hash_hex = stored_hash.split("$")
        if algo != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        computed = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n_s),
            r=int(r_s),
            p=int(p_s),
            dklen=len(expected),
        )
        return hmac.compare_digest(computed, expected)
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# 2. JWT HS256 strict (RFC 7519) + Jeton CSRF lié à la session
# ---------------------------------------------------------------------------
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


class TokenError(Exception):
    """Erreur levée lors de la validation d'un jeton JWT."""


def create_jwt(
    user_id: int,
    username: str,
    role: str,
    plateau: str,
    secret: str,
    ttl_seconds: int = 900,
) -> Tuple[str, str, str, int]:
    """Génère un JWT HS256 avec JTI unique et un jeton CSRF cryptographiquement lié.

    Retourne (jwt_token, csrf_token, jti, exp_timestamp).
    """
    now = int(time.time())
    exp = now + ttl_seconds
    jti = secrets.token_hex(16)
    csrf_token = secrets.token_urlsafe(32)
    csrf_digest = hashlib.sha256(csrf_token.encode("utf-8")).hexdigest()

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "plateau": plateau,
        "jti": jti,
        "csrf_hash": csrf_digest,
        "iat": now,
        "exp": exp,
    }

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    token = f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"
    return token, csrf_token, jti, exp


def verify_jwt(token: str, secret: str) -> Dict[str, Any]:
    """Valide signature, algorithme (strictement HS256) et expiration d'un JWT."""
    if not token or token.count(".") != 2:
        raise TokenError("Format de jeton JWT invalide.")

    header_b64, payload_b64, sig_b64 = token.split(".")
    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        provided_sig = _b64url_decode(sig_b64)
    except Exception as exc:
        raise TokenError("Impossible de décoder le jeton JWT.") from exc

    # Verrouillage strict de l'algorithme (prévient les attaques alg:none / confusion RS256->HS256)
    if header.get("alg") != "HS256" or header.get("typ") != "JWT":
        raise TokenError("Algorithme JWT non autorisé.")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(provided_sig, expected_sig):
        raise TokenError("Signature JWT invalide.")

    now = int(time.time())
    exp = payload.get("exp")
    if not isinstance(exp, int) or now >= exp:
        raise TokenError("Session expirée (durée maximale 15 minutes atteinte).")

    return payload


def verify_csrf_token(provided_csrf: str, jwt_payload: Dict[str, Any]) -> bool:
    """Valide l'en-tête X-GCC-CSRF contre son empreinte SHA-256 liée au JWT."""
    if not provided_csrf:
        return False
    expected_hash = jwt_payload.get("csrf_hash", "")
    computed_hash = hashlib.sha256(provided_csrf.encode("utf-8")).hexdigest()
    return hmac.compare_digest(computed_hash, expected_hash)


# ---------------------------------------------------------------------------
# 3. Signature HMAC-SHA256 pour Webhooks industriels (Centreon, Zabbix, HAL)
# ---------------------------------------------------------------------------
def compute_webhook_signature(raw_body: bytes, secret: str) -> str:
    """Calcule la signature HMAC-SHA256 au format 'sha256=<hex>'."""
    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_webhook_signature(raw_body: bytes, provided_header: str, secret: str) -> bool:
    """Vérifie l'authenticité d'un payload webhook en temps constant."""
    if not provided_header or not provided_header.startswith("sha256="):
        return False
    expected = compute_webhook_signature(raw_body, secret)
    return hmac.compare_digest(expected, provided_header.strip())


# ---------------------------------------------------------------------------
# 4. Rate Limiter thread-safe en fenêtre glissante (anti brute-force & DoS)
# ---------------------------------------------------------------------------
class SlidingWindowRateLimiter:
    """Limiteur de débit thread-safe par clé (IP, endpoint, compte)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: Dict[str, Deque[float]] = defaultdict(deque)

    def check_and_record(
        self, key: str, max_requests: int, window_seconds: int
    ) -> Tuple[bool, int]:
        """Vérifie le quota et enregistre l'appel. Retourne (autorisé, retry_after_sec)."""
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            dq = self._buckets[key]
            while dq and dq[0] <= cutoff:
                dq.popleft()
            if len(dq) >= max_requests:
                retry_after = max(1, int(dq[0] + window_seconds - now))
                return False, retry_after
            dq.append(now)
            return True, 0

    def reset(self, key: str) -> None:
        """Réinitialise le compteur pour une clé donnée (ex. après login réussi)."""
        with self._lock:
            self._buckets.pop(key, None)


# ---------------------------------------------------------------------------
# 5. Décorateurs Flask : Authentification JWT, CSRF X-GCC-CSRF et RBAC
# ---------------------------------------------------------------------------
def exiger_role(*roles_autorises: str) -> Callable:
    """Décorateur métier RBAC + validation JWT + révocation + protection CSRF.

    Exemple d'usage (fidèle à l'architecture GCC) :
        @exiger_role("admin", "pilote")
        def create_ticket(): ...
    """

    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            from flask import current_app, g, jsonify, request
            from backend.database import is_jti_revoked, log_audit

            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "Authentification requise (Bearer JWT)."}), 401

            token = auth_header[7:].strip()
            cfg = current_app.config["GCC_CONFIG"]

            try:
                payload = verify_jwt(token, cfg.JWT_SECRET)
            except TokenError as exc:
                return jsonify({"error": str(exc)}), 401

            if is_jti_revoked(cfg.DB_PATH, payload.get("jti", "")):
                return jsonify({"error": "Jeton révoqué. Veuillez vous reconnecter."}), 401

            # Couche CSRF obligatoire sur toute méthode HTTP mutante
            if request.method in ("POST", "PUT", "PATCH", "DELETE"):
                csrf_header = request.headers.get("X-GCC-CSRF", "")
                if not verify_csrf_token(csrf_header, payload):
                    log_audit(
                        cfg.DB_PATH,
                        username=payload.get("username", "unknown"),
                        role=payload.get("role", "unknown"),
                        action="CSRF_BLOCKED",
                        target=request.path,
                        ip_address=request.remote_addr or "unknown",
                        status="DENIED",
                        details="En-tête X-GCC-CSRF absent ou invalide",
                    )
                    return jsonify({"error": "Échec de vérification CSRF (X-GCC-CSRF)."}), 403

            # Couche RBAC : validation des habilitations
            user_role = payload.get("role", "")
            if roles_autorises and user_role not in roles_autorises:
                log_audit(
                    cfg.DB_PATH,
                    username=payload.get("username", "unknown"),
                    role=user_role,
                    action="RBAC_DENIED",
                    target=f"{request.method} {request.path}",
                    ip_address=request.remote_addr or "unknown",
                    status="DENIED",
                    details=f"Rôles requis: {', '.join(roles_autorises)}",
                )
                return (
                    jsonify(
                        {
                            "error": "Accès refusé : privilèges RBAC insuffisants.",
                            "required_roles": list(roles_autorises),
                        }
                    ),
                    403,
                )

            g.current_user = {
                "id": int(payload["sub"]),
                "username": payload["username"],
                "role": user_role,
                "plateau": payload.get("plateau", "Banque"),
                "jti": payload["jti"],
                "exp": payload["exp"],
            }
            return fn(*args, **kwargs)

        return wrapper

    return decorator
