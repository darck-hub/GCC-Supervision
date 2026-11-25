"""Point d'entrée principal Flask — Serveur HTTPS TLS 1.2+ & en-têtes de sécurité."""

from __future__ import annotations

import logging
import ssl
from pathlib import Path
from typing import Optional

from flask import Flask, jsonify, send_from_directory

from backend.config import Config
from backend.database import init_db
from backend.routes.admin import admin_bp
from backend.routes.auth import auth_bp
from backend.routes.compliance import compliance_bp
from backend.routes.dashboard import dashboard_bp
from backend.routes.routing import routing_bp
from backend.routes.tickets import tickets_bp
from backend.routes.webhooks import webhooks_bp
from backend.security import SlidingWindowRateLimiter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("gcc.app")

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


def create_app(config: Optional[Config] = None) -> Flask:
    """Construit et configure l'application Flask sécurisée (Application Factory)."""
    cfg = config or Config()
    app = Flask(__name__, static_folder=None)
    app.config["GCC_CONFIG"] = cfg
    app.config["GCC_RATE_LIMITER"] = SlidingWindowRateLimiter()
    app.config["MAX_CONTENT_LENGTH"] = cfg.MAX_CONTENT_LENGTH

    init_db(cfg.DB_PATH, seed_demo=cfg.DEMO_SEED, env_mode=cfg.ENV)

    # Enregistrement des blueprints REST
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(tickets_bp)
    app.register_blueprint(routing_bp)
    app.register_blueprint(webhooks_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(compliance_bp)

    @app.after_request
    def apply_security_headers(response):
        """Injecte les en-têtes HTTP de durcissement (ANSSI / OWASP)."""
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Cache-Control"] = "no-store"
        if cfg.USE_HTTPS:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "service": "gcc-supervision"})

    @app.get("/")
    def index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.get("/css/<path:filename>")
    def serve_css(filename: str):
        return send_from_directory(FRONTEND_DIR / "css", filename)

    @app.get("/js/<path:filename>")
    def serve_js(filename: str):
        return send_from_directory(FRONTEND_DIR / "js", filename)

    @app.errorhandler(404)
    def handle_404(_err):
        return jsonify({"error": "Ressource introuvable."}), 404

    @app.errorhandler(413)
    def handle_413(_err):
        return jsonify({"error": "Payload trop volumineux (limite 1 Mo)."}), 413

    @app.errorhandler(500)
    def handle_500(_err):
        return jsonify({"error": "Erreur interne du serveur."}), 500

    return app


def build_tls_context(cert_file: str, key_file: str) -> ssl.SSLContext:
    """Crée un contexte SSLContext durci imposant TLS 1.2 minimum (RGS 2.0)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS:!3DES")
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return ctx


if __name__ == "__main__":
    cfg = Config()
    application = create_app(cfg)
    ssl_ctx = None
    if cfg.USE_HTTPS:
        cert_p = Path(cfg.CERT_FILE)
        key_p = Path(cfg.KEY_FILE)
        if not cert_p.exists() or not key_p.exists():
            logger.info("Certificats TLS absents : génération automatique pour le développement...")
            from scripts.generate_certs import generate_self_signed_cert

            generate_self_signed_cert(cert_p, key_p)
        ssl_ctx = build_tls_context(str(cert_p), str(key_p))
        logger.info("Démarrage GCC Supervision en HTTPS (TLS 1.2+) sur https://%s:%s", cfg.HOST, cfg.PORT)
    else:
        logger.warning("Démarrage en HTTP (mode dev uniquement) sur http://%s:%s", cfg.HOST, cfg.PORT)

    application.run(host=cfg.HOST, port=cfg.PORT, ssl_context=ssl_ctx, debug=False)
