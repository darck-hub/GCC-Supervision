#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -d ".venv" ]; then
  echo "[GCC] Création de l'environnement virtuel Python..."
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

if [ ! -f "certs/server.crt" ] || [ ! -f "certs/server.key" ]; then
  echo "[GCC] Génération du certificat TLS 1.2+ (RSA 3072 bits)..."
  python -m scripts.generate_certs
fi

echo "[GCC] Démarrage de la plateforme de supervision GCC sur https://127.0.0.1:8443"
python -m backend.app
