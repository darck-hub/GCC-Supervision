# Architecture Technique & Sécurité — Application de Supervision GCC

Ce document formalise les 4 vues architecturales majeures de la plateforme de supervision GCC, conçue selon le principe de **défense en profondeur** (ANSSI RGS 2.0, Guide d'Hygiène Informatique et recommandations CNIL).

---

## 1. Architecture Globale Frontend / Backend

```mermaid
flowchart LR
    subgraph Browser["Frontend SPA (ES6+ Modules — Zéro inline JS/CSS)"]
        UI["Interface NOC (Dark Mode)"]
        RAM["auth.js : JWT + CSRF en RAM uniquement<br/>(Expiration 15 min / Auto-logout)"]
        DOM["dom.js : Rendu textContent anti-XSS"]
        API["api.js : Bearer JWT + X-GCC-CSRF"]
        UI --> DOM
        UI --> API
        RAM --> API
    end

    subgraph Probes["Sondes & Hyperviseurs Industriels"]
        HAL["HAL (IBM Netcool)"]
        CEN["Centreon / Zabbix"]
        ZOS["Mainframe z/OS JES2"]
    end

    subgraph Backend["Backend Python / Flask (HTTPS TLS 1.2+)"]
        SEC["7 Couches Sécurité<br/>CSP • RateLimit • JWT • CSRF • RBAC • HMAC"]
        ENG["Moteur Métier GCC<br/>Déduplication HAL • Routage P1-P4 • SLA"]
        DB[("SQLite Mode WAL<br/>Requêtes 100% paramétrées")]
        SEC --> ENG --> DB
    end

    API -- "HTTPS TLS 1.2+<br/>Authorization + X-GCC-CSRF" --> SEC
    HAL & CEN & ZOS -- "HTTPS Webhook<br/>X-GCC-Signature (HMAC-SHA256)" --> SEC
```

---

## 2. Schéma de Base de Données Relationnelle (SQLite WAL)

```mermaid
erDiagram
    USERS ||--o{ AUDIT_LOGS : "génère"
    PROCEDURES ||--o{ ROUTING_RULES : "référence"
    PROCEDURES ||--o{ TICKETS : "certifie"
    TICKETS ||--o{ TICKET_COMMENTS : "contient"
    TICKETS ||--o{ ALERTS : "corrèle"

    USERS {
        int id PK
        string username UK
        string password_hash "Scrypt + sel 128b"
        string role "admin|pilote|n2|auditeur"
        string plateau "Banque|Multi-Client"
        int failed_attempts
        string locked_until
    }

    TICKETS {
        int id PK
        string reference UK "INC-YYYY-NNNN"
        string priority "P1|P2|P3|P4"
        string status "NOUVEAU..CLOTURE"
        string host
        string assigned_group
        string procedure_code FK
        string sla_deadline "UTC ISO-8601"
        int rca_required
    }

    ALERTS {
        int id PK
        string source_tool
        string host
        string error_code
        int occurrence_count "Déduplication HAL"
        int ticket_id FK
    }

    PROCEDURES {
        string code PK "ex: PROC-NET-001"
        string title
        string steps
        string rundeck_job
    }
```

---

## 3. Cycle de Vie d'une Requête Mutante (`POST /api/tickets`)

```mermaid
sequenceDiagram
    autonumber
    participant Op as Pilote N1 (Navigateur)
    participant API as Flask API (TLS 1.2+)
    participant Sec as Décorateur @exiger_role
    participant DB as SQLite (WAL)

    Op->>API: POST /api/tickets<br/>Authorization: Bearer <JWT RAM><br/>X-GCC-CSRF: <Jeton session>
    API->>Sec: Vérification signature HS256 & expiration (15 min)
    Sec->>DB: Contrôle révocation JTI (revoked_tokens)
    Sec->>Sec: Vérification empreinte SHA-256(X-GCC-CSRF) == jwt.csrf_hash
    Sec->>Sec: Validation RBAC (role in admin, pilote, n2)
    Sec->>API: Contexte g.current_user validé
    API->>DB: INSERT paramétré (ticket + SLA auto + 1er commentaire)
    API->>DB: INSERT audit_logs (traçabilité CNIL/RCA)
    API-->>Op: HTTP 201 Created + En-têtes CSP/HSTS/nosniff
```

---

## 4. Modèle de Défense en Profondeur (7 Couches)

| Couche | Contrôle technique | Menace neutralisée | Référentiel |
|---|---|---|---|
| **1. Transport** | `SSLContext` TLS 1.2+ (`ECDHE+AESGCM`), HSTS | Écoute réseau / MITM / downgrade | ANSSI RGS 2.0 |
| **2. En-têtes HTTP** | CSP stricte (`script-src 'self'`, `style-src 'self'`), `DENY`, `nosniff` | XSS, Clickjacking, MIME sniffing | ANSSI Hygiène |
| **3. Anti brute-force** | Rate Limiter fenêtre glissante (5 essais / 5 min) + verrouillage compte | Force brute & saturation | CNIL |
| **4. Session & Auth** | Scrypt + JWT HS256 verrouillé en **RAM uniquement** (TTL 15 min) + révocation JTI | Vol de jeton XSS (`localStorage`), rejeu | CNIL / ANSSI |
| **5. Anti-CSRF / HMAC** | En-tête `X-GCC-CSRF` lié au JWT ; webhooks isolés signés `X-GCC-Signature` | Cross-Site Request Forgery, spoofing sonde | OWASP / ANSSI |
| **6. Contrôle RBAC** | Décorateur `@exiger_role("admin", "pilote")` systématique | Élévation de privilèges horizontale/verticale | Moindre privilège |
| **7. Persistance** | SQLite WAL + requêtes 100% paramétrées + `audit_logs` + Docker non-root | Injection SQL, corruption concurrente, non-répudiation | ANSSI / RCA |
