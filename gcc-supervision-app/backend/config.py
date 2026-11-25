"""Configuration centralisée et durcie de l'application de supervision GCC.

Tous les secrets sont chargés depuis les variables d'environnement afin de
respecter les recommandations ANSSI (Guide d'Hygiène Informatique & RGS 2.0).
"""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict

logger = logging.getLogger("gcc.config")

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_secret(env_var: str, env_mode: str, min_length: int = 32) -> str:
    """Charge un secret depuis l'environnement avec contrôle strict en production."""
    value = os.environ.get(env_var, "").strip()
    if value:
        if len(value) < min_length:
            raise ValueError(
                f"La variable d'environnement {env_var} doit contenir au moins "
                f"{min_length} caractères (conformité RGS 2.0)."
            )
        return value

    if env_mode == "production":
        raise RuntimeError(
            f"Secret obligatoire manquant en production : {env_var}. "
            "Définissez-le dans l'environnement avant le démarrage."
        )

    ephemeral = secrets.token_hex(32)
    logger.warning(
        "[DEV] %s non défini : clé éphémère générée en mémoire pour cette session.",
        env_var,
    )
    return ephemeral


@dataclass(frozen=True)
class Config:
    """Paramètres immuables d'exécution de l'application GCC."""

    ENV: str = field(default_factory=lambda: os.environ.get("GCC_ENV", "development").lower())
    HOST: str = field(default_factory=lambda: os.environ.get("GCC_HOST", "127.0.0.1"))
    PORT: int = field(default_factory=lambda: int(os.environ.get("GCC_PORT", "8443")))
    DB_PATH: str = field(
        default_factory=lambda: os.environ.get(
            "GCC_DB_PATH", str(BASE_DIR / "data" / "gcc_supervision.db")
        )
    )
    CERT_FILE: str = field(
        default_factory=lambda: os.environ.get(
            "GCC_CERT_FILE", str(BASE_DIR / "certs" / "server.crt")
        )
    )
    KEY_FILE: str = field(
        default_factory=lambda: os.environ.get(
            "GCC_KEY_FILE", str(BASE_DIR / "certs" / "server.key")
        )
    )
    USE_HTTPS: bool = field(
        default_factory=lambda: os.environ.get("GCC_USE_HTTPS", "true").lower() == "true"
    )
    DEMO_SEED: bool = field(
        default_factory=lambda: os.environ.get("GCC_DEMO_SEED", "true").lower() == "true"
    )

    # Secrets cryptographiques (aucune valeur codée en dur)
    JWT_SECRET: str = field(default="")
    WEBHOOK_SECRET: str = field(default="")

    # Sécurité des sessions (Conformité CNIL / ANSSI)
    JWT_TTL_SECONDS: int = 900          # Expiration stricte 15 minutes
    LOGIN_MAX_ATTEMPTS: int = 5         # Anti brute-force
    LOGIN_WINDOW_SECONDS: int = 300     # Fenêtre glissante 5 minutes
    ACCOUNT_LOCKOUT_SECONDS: int = 300  # Verrouillage temporaire compte 5 min
    WEBHOOK_MAX_RPM: int = 60           # Rate limiting webhooks industriels
    DEDUP_WINDOW_SECONDS: int = 1800    # Fenêtre corrélation/déduplication HAL (30 min)
    AUDIT_RETENTION_DAYS: int = 365     # Rétention journaux CNIL/ANSSI (1 an)
    MAX_CONTENT_LENGTH: int = 1 * 1024 * 1024  # 1 Mo max par requête HTTP

    # Engagements SLA en minutes par niveau de priorité
    SLA_MINUTES: Dict[str, int] = field(
        default_factory=lambda: {
            "P1": 15,    # Service critique indisponible -> Mobilisation immédiate
            "P2": 60,    # Forte dégradation -> Investigation approfondie
            "P3": 240,   # Impact limité -> Consignes standards
            "P4": 1440,  # Demande ou incident mineur -> Traitement standard
        }
    )

    VALID_ROLES: tuple = ("admin", "pilote", "n2", "auditeur")
    VALID_PRIORITIES: tuple = ("P1", "P2", "P3", "P4")
    VALID_STATUSES: tuple = (
        "NOUVEAU",
        "EN_COURS",
        "ESCALADE_N2",
        "ESCALADE_N3",
        "RESOLU",
        "CLOTURE",
    )
    VALID_PLATEAUS: tuple = ("Multi-Client", "Banque")

    def __post_init__(self) -> None:
        if not self.JWT_SECRET:
            object.__setattr__(
                self, "JWT_SECRET", _load_secret("GCC_JWT_SECRET", self.ENV)
            )
        if not self.WEBHOOK_SECRET:
            object.__setattr__(
                self, "WEBHOOK_SECRET", _load_secret("GCC_WEBHOOK_SECRET", self.ENV)
            )
