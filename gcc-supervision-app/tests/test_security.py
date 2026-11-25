"""Tests automatisés de sécurité (JWT, CSRF, RBAC, Rate Limiting, HMAC, En-têtes CSP)."""

from __future__ import annotations

import json
import time
import pytest

from backend.app import create_app
from backend.config import Config
from backend.security import (
    compute_webhook_signature,
    create_jwt,
    hash_password,
    validate_password_policy,
    verify_jwt,
    verify_password,
    TokenError,
)


@pytest.fixture()
def client(tmp_path):
    cfg = Config(
        ENV="development",
        DB_PATH=str(tmp_path / "test_sec.db"),
        USE_HTTPS=False,
        DEMO_SEED=True,
        JWT_SECRET="a" * 64,
        WEBHOOK_SECRET="b" * 64,
    )
    app = create_app(cfg)
    app.config["TESTING"] = True
    return app.test_client(), cfg


def _login(client, username: str, password: str):
    res = client.post("/api/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200, res.get_json()
    return res.get_json()


def test_password_scrypt_and_policy():
    ok, _ = validate_password_policy("Weak123")
    assert not ok
    ok2, _ = validate_password_policy("StrongGcc!2026#")
    assert ok2
    hashed = hash_password("StrongGcc!2026#")
    assert verify_password("StrongGcc!2026#", hashed)
    assert not verify_password("WrongPassword!1", hashed)


def test_jwt_rejects_expired_and_tampered():
    token, _csrf, _jti, _exp = create_jwt(1, "pilote", "pilote", "Banque", "s" * 64, ttl_seconds=1)
    assert verify_jwt(token, "s" * 64)["username"] == "pilote"
    with pytest.raises(TokenError):
        verify_jwt(token + "x", "s" * 64)
    time.sleep(1.1)
    with pytest.raises(TokenError):
        verify_jwt(token, "s" * 64)


def test_csrf_required_on_mutations_and_rbac_enforced(client):
    c, _cfg = client
    pilote = _login(c, "pilote", "PiloteN1!2026#Gcc")

    # Mutation SANS X-GCC-CSRF -> 403 bloqué
    res_no_csrf = c.post(
        "/api/tickets",
        headers={"Authorization": f"Bearer {pilote['token']}"},
        json={"title": "Test incident", "description": "Sans CSRF", "priority": "P3", "plateau": "Banque"},
    )
    assert res_no_csrf.status_code == 403

    # Route admin appelée par un pilote -> 403 RBAC (@exiger_role("admin"))
    res_rbac = c.get(
        "/api/admin/users",
        headers={"Authorization": f"Bearer {pilote['token']}"},
    )
    assert res_rbac.status_code == 403


def test_logout_revokes_jti(client):
    c, _cfg = client
    session = _login(c, "admin", "AdminGcc!2026#Sec")
    headers = {
        "Authorization": f"Bearer {session['token']}",
        "X-GCC-CSRF": session["csrf_token"],
    }
    assert c.post("/api/auth/logout", headers=headers).status_code == 200
    assert c.get("/api/auth/me", headers={"Authorization": f"Bearer {session['token']}"}).status_code == 401


def test_webhook_hmac_validation(client):
    c, cfg = client
    payload = json.dumps(
        {
            "source_tool": "Mainframe z/OS",
            "plateau": "Banque",
            "host": "ZOS-TST-01",
            "error_code": "RC-0016",
            "message": "JOB TEST ENDED WITH RC-0016",
        }
    ).encode("utf-8")

    # Sans signature -> 401
    assert c.post("/api/webhooks/alerts", data=payload, content_type="application/json").status_code == 401

    # Avec signature HMAC-SHA256 valide -> 201 (exempté CSRF)
    sig = compute_webhook_signature(payload, cfg.WEBHOOK_SECRET)
    res = c.post(
        "/api/webhooks/alerts",
        data=payload,
        content_type="application/json",
        headers={"X-GCC-Signature": sig},
    )
    assert res.status_code == 201
    assert res.get_json()["severity"] == "P1"


def test_security_headers_present(client):
    c, _cfg = client
    res = c.get("/api/health")
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.headers["X-Frame-Options"] == "DENY"
    assert "script-src 'self'" in res.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in res.headers["Content-Security-Policy"]
