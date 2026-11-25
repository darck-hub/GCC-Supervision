"""Tests métier GCC : déduplication HAL, qualification P1-P4, fiche certifiée & SLA."""

from __future__ import annotations

import json
import pytest

from backend.app import create_app
from backend.config import Config
from backend.security import compute_webhook_signature


@pytest.fixture()
def client(tmp_path):
    cfg = Config(
        ENV="development",
        DB_PATH=str(tmp_path / "test_workflow.db"),
        USE_HTTPS=False,
        DEMO_SEED=True,
        JWT_SECRET="c" * 64,
        WEBHOOK_SECRET="d" * 64,
    )
    app = create_app(cfg)
    app.config["TESTING"] = True
    return app.test_client(), cfg


def test_hal_deduplication_and_auto_ticket(client):
    c, cfg = client
    body = json.dumps(
        {
            "source_tool": "Mainframe z/OS",
            "plateau": "Banque",
            "host": "ZOS-PRD-99",
            "error_code": "B37",
            "message": "ABEND SB37-04 SATURATION ESPACE DISQUE",
        }
    ).encode("utf-8")
    sig = compute_webhook_signature(body, cfg.WEBHOOK_SECRET)
    headers = {"X-GCC-Signature": sig}

    r1 = c.post("/api/webhooks/alerts", data=body, content_type="application/json", headers=headers)
    assert r1.status_code == 201
    d1 = r1.get_json()
    assert d1["deduplicated"] is False
    assert d1["severity"] == "P1"
    assert d1["ticket_id"] is not None

    # 2e événement identique -> déduplication HAL (occurrence_count=2, pas de doublon ticket)
    r2 = c.post("/api/webhooks/alerts", data=body, content_type="application/json", headers=headers)
    assert r2.status_code == 200
    d2 = r2.get_json()
    assert d2["deduplicated"] is True
    assert d2["occurrence_count"] == 2
    assert d2["ticket_id"] == d1["ticket_id"]


def test_ticket_lifecycle_and_certified_sheet(client):
    c, _cfg = client
    login = c.post(
        "/api/auth/login",
        json={"username": "pilote", "password": "PiloteN1!2026#Gcc"},
    ).get_json()
    headers = {
        "Authorization": f"Bearer {login['token']}",
        "X-GCC-CSRF": login["csrf_token"],
    }

    # Création ticket avec procédure PROC-NET-001
    created = c.post(
        "/api/tickets",
        headers=headers,
        json={
            "title": "Perte lien agence Colomiers",
            "description": "Sonde Centreon en timeout sur lien principal.",
            "priority": "P1",
            "plateau": "Multi-Client",
            "host": "RTR-COL-01",
            "error_code": "LINK_DOWN",
            "assigned_group": "Équipe Réseau N2",
            "procedure_code": "PROC-NET-001",
        },
    )
    assert created.status_code == 201
    tid = created.get_json()["ticket"]["id"]

    # Ajout d'un commentaire d'exploitation
    com = c.post(
        f"/api/tickets/{tid}/comments",
        headers=headers,
        json={"content": "Cellule d'astreinte réseau contactée en HNO."},
    )
    assert com.status_code == 201

    # Vérification de la Fiche d'Exploitation Certifiée GCC
    sheet = c.get(f"/api/tickets/{tid}", headers={"Authorization": f"Bearer {login['token']}"})
    assert sheet.status_code == 200
    payload = sheet.get_json()
    assert payload["procedure"]["code"] == "PROC-NET-001"
    assert len(payload["comments"]) >= 2
    assert payload["ticket"]["sla_state"] in ("OK", "WARNING")
