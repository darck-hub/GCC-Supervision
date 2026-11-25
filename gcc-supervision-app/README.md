
# GCC Supervision — Plateforme de Pilotage d'Exploitation & Sécurité Opérationnelle

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-lightgrey)
![SQLite](https://img.shields.io/badge/SQLite-WAL-003B57)
![Security](https://img.shields.io/badge/Security-ANSSI%20%2F%20CNIL-green)
![Docker](https://img.shields.io/badge/Docker-Non--Root-2496ED)

Application web de supervision et de gestion des incidents inspirée du fonctionnement réel d'un **Global Command Center (GCC)** fonctionnant en 24/7 (équipes 3/8, plateaux Multi-Client et Banque, intégration des flux HAL/IBM Netcool, Centreon, Zabbix, Mainframe z/OS JES2 et Rundeck).

> **English Summary:** A hardened, lightweight NOC/GCC Incident & Supervision platform built with **Python/Flask**, **SQLite (WAL mode)**, and **modular vanilla ES6+ JavaScript** (zero build step, strict CSP). Designed around ANSSI & CNIL security principles: TLS 1.2+, RAM-only 15-minute JWTs, cryptographically bound `X-GCC-CSRF` protection, HMAC-SHA256 webhooks, `@exiger_role` RBAC, sliding-window rate limiting, and full audit logging.

---

## Fonctionnalités clés

1. **Tableau de bord temps réel** : État des services critiques (HAL, z/OS JES2, DB2, Centreon, Zabbix, Rundeck, ServiceNow), indicateurs SLA, équipe 3/8 active et simulateur de sondes intégré.
2. **Matrice de routage & Dispatching opérationnel** : Déduplication automatique des alertes (style HAL/Netcool), qualification automatique **P1 à P4**, routage vers les groupes N1/N2/N3 et acquittement des faux positifs.
3. **Registre général des incidents distribués** : Filtrage multicritères, suivi du cycle de vie (`NOUVEAU` → `EN_COURS` → `ESCALADE_N2/N3` → `RESOLU` → `CLOTURE`) et alertes de dépassement SLA en direct.
4. **Fiche d'exploitation certifiée GCC** : Rattachement des procédures officielles (`PROC-NET-001`, `PROC-ZOS-016`, `PROC-DB2-911`, `PROC-SEC-004`), job Rundeck associé et fil de discussion horodaté pour la traçabilité **RCA**.
5. **Administration RBAC & Collecteurs** : Gestion des comptes opérateurs (politique mot de passe >= 12 car., hachage Scrypt) et activation/désactivation des collecteurs d'alertes.
6. **Conformité CNIL, Sécurité ANSSI & PCA** : Vérification en direct des 7 couches de sécurité, statut du Plan de Continuité d'Activité (PCA) et journal d'audit sécurité.

---

## Démarrage rapide

### Option 1 — Scripts locaux (Linux / macOS / Windows)

```bash
# Linux / macOS
chmod +x scripts/start.sh
./scripts/start.sh
```

```bat
:: Windows
scripts\start.bat
```

Accédez ensuite à `https://127.0.0.1:8443` (certificat auto-signé RSA 3072 bits généré automatiquement en mode développement).

### Option 2 — Docker (Conteneur durci non-root)

```bash
docker compose up --build
```

### Comptes de démonstration (environnement `development` uniquement)

| Identifiant | Mot de passe dev | Rôle RBAC | Plateau |
|---|---|---|---|
| `admin` | `AdminGcc!2026#Sec` | Administrateur | Banque |
| `pilote` | `PiloteN1!2026#Gcc` | Pilote N1 (Shift 3/8) | Banque |
| `tech_n2` | `SupportN2!2026#Op` | Support N2 | Multi-Client |
| `auditeur` | `AuditCnil!2026#Ok` | Auditeur CNIL | Banque |

> En production (`GCC_ENV=production`), aucun compte de démonstration n'est créé et l'application refuse de démarrer si `GCC_JWT_SECRET` ou `GCC_WEBHOOK_SECRET` (< 32 car.) ne sont pas définis dans l'environnement.

---

## Tester un webhook industriel signé (HMAC-SHA256)

```bash
python -c '
import hmac, hashlib, json, urllib.request, ssl
secret = "VOTRE_GCC_WEBHOOK_SECRET"
payload = json.dumps({
  "source_tool": "Mainframe z/OS",
  "plateau": "Banque",
  "host": "ZOS-PRD-AF01",
  "error_code": "RC-0016",
  "message": "JOB CH7GZBM1 ABENDED RC-0016"
}).encode()
sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
req = urllib.request.Request(
  "https://127.0.0.1:8443/api/webhooks/alerts",
  data=payload,
  headers={"Content-Type": "application/json", "X-GCC-Signature": sig},
)
print(urllib.request.urlopen(req, context=ssl._create_unverified_context()).read().decode())
'
```

---

## Tests automatisés & Qualité

```bash
pytest -v
ruff check backend scripts tests
bandit -r backend scripts -ll
```

Pour le détail des schémas Mermaid et des 7 couches de sécurité, consultez [ARCHITECTURE.md](ARCHITECTURE.md).
