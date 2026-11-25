"""Génère un certificat TLS auto-signé RSA 3072 bits (RGS 2.0) pour le développement local."""

from __future__ import annotations

import datetime
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_self_signed_cert(cert_path: Path, key_path: Path) -> None:
    """Crée une paire clé/certificat auto-signée pour localhost et 127.0.0.1."""
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GCC Supervision Dev"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(key_bytes)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    c_path = root / "certs" / "server.crt"
    k_path = root / "certs" / "server.key"
    generate_self_signed_cert(c_path, k_path)
    print(f"Certificat TLS RSA-3072 généré : {c_path}")
