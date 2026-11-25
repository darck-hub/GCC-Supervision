@echo off
setlocal
cd /d "%~dp0.."

if not exist ".venv" (
    echo [GCC] Creation de l'environnement virtuel Python...
    python -m venv .venv
)

call .venv\Scripts\activate.bat
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

if not exist "certs\server.crt" (
    echo [GCC] Generation du certificat TLS 1.2+ ^(RSA 3072 bits^)...
    python -m scripts.generate_certs
)

echo [GCC] Demarrage de la plateforme de supervision GCC sur https://127.0.0.1:8443
python -m backend.app
