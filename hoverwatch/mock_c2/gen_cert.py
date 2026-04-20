#!/usr/bin/env python3
"""
Generate self-signed SSL certificate for the Hoverwatch/Snoopza mock C2 server.

Pur Python (via `cryptography`), aucun binaire externe requis.
Produit key.pem + cert.pem dans le répertoire courant si absents, sinon no-op.

SAN inclus :
  - localhost, 127.0.0.1, 10.11.1.1 (pour accès local + VPN Corellium)
  - les 6 domaines C2 réels décryptés depuis les APKs Refog
    (utiles si un hook oublie de rediriger : le cert matchera quand même)

Usage :
    python gen_cert.py             # génère si absent
    python gen_cert.py --force     # régénère même si présent
— ou importé depuis server.py : `from gen_cert import ensure_cert`
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


# Domaines C2 Refog décryptés depuis les APKs (cf. hoverwatch_analysis.md §6)
C2_DOMAINS = [
    "a.syncvch.com",
    "hwa.cab",
    "snsync.com",
    "app.snoopza.com",
    "www.hoverwatch.com",
    "www.snoopza.com",
]


def ensure_cert(
    cert_path: Path = Path("cert.pem"),
    key_path: Path = Path("key.pem"),
    force: bool = False,
    days_valid: int = 365,
) -> tuple[Path, Path]:
    """Génère le couple cert/key si absent (ou si force=True).
    Retourne les chemins des deux fichiers."""
    if not force and cert_path.exists() and key_path.exists():
        return cert_path, key_path

    # Clé RSA 2048
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ASTRA-Research"),
        x509.NameAttribute(NameOID.COMMON_NAME, "hoverwatch-mock-c2"),
    ])

    san_entries: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv4Address("10.11.1.1")),
    ]
    for d in C2_DOMAINS:
        san_entries.append(x509.DNSName(d))

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    return cert_path, key_path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--force", action="store_true", help="régénère même si présent")
    ap.add_argument("--days", type=int, default=365)
    args = ap.parse_args()

    cert_path = Path("cert.pem")
    key_path = Path("key.pem")

    existed = cert_path.exists() and key_path.exists()
    cert, key = ensure_cert(cert_path, key_path, force=args.force, days_valid=args.days)

    if existed and not args.force:
        print(f"ℹ️  {cert} + {key} existent déjà (utilise --force pour régénérer)")
    else:
        action = "régénérés" if (existed and args.force) else "générés"
        print(f"✅ {cert} + {key} {action} (valide {args.days}j)")
        print(f"   SAN: localhost, 127.0.0.1, 10.11.1.1, {len(C2_DOMAINS)} domaines C2")
    return 0


if __name__ == "__main__":
    sys.exit(main())
