#!/usr/bin/env python3
"""
Cross-certify the Mincifry (Russian Ministry of Digital Development) root CA
with X.509 Name Constraints, so that after installation it can only be used
to validate certificates for a specific set of domains. _version 0.2.

Outputs (in --outdir):
    my_root_ca.key      -> keep SECRET / offline
    my_root_ca.crt      -> install as TRUSTED ROOT
    mincifry_cross.crt  -> install as INTERMEDIATE (Windows)
                        -> install as USER CA alongside MyRoot (Android)

IMPORTANT: After installing the new certs you MUST remove the original
Mincifry root from the trust store, otherwise chain building will
prefer it (it has no Name Constraints) and the whole exercise is void.

Requires: cryptography >= 2.0 (tested with 41+), Python >= 3.7
"""
from __future__ import annotations
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

try:
    from cryptography.hazmat.backends import default_backend
except ImportError:  # очень старые/будущие версии
    default_backend = None

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_MINCIFRY = "Russian_Trusted_Root_CA.cer"

# RFC 5280: "DNS name restrictions are expressed as host.example.com. Any DNS
# name that can be constructed by simply adding zero or more labels to the
# left-hand side of the name satisfies the name constraint." → bare FQDN
# already covers all subdomains. The dot-prefixed form (".example.com") is
# legacy NSS/OpenSSL behaviour. We include BOTH for maximum compatibility:
# modern validators (Firefox ≥NSS 3.x, Windows CryptoAPI, Conscrypt) treat
# bare FQDN as suffix match; older ones may need the dot form.
DEFAULT_PERMITTED_DNS: List[str] = [
    "gosuslugi.ru", ".gosuslugi.ru",
    "gov.ru",       ".gov.ru",
    "rosreestr.ru", ".rosreestr.ru",
    "mos.ru",       ".mos.ru",
    "domrfbank.ru", ".domrfbank.ru",
    "sberbank.ru",  ".sberbank.ru",
    "uralsib.ru",   ".uralsib.ru",
    "vtb.ru",       ".vtb.ru",
    "psbank.ru",    ".psbank.ru",
    "alfabank.ru",  ".alfabank.ru",
    "tbank.ru",     ".tbank.ru",
    "bspb.ru",      ".bspb.ru",       # Банк «Санкт-Петербург»
    "rshb.ru",      ".rshb.ru",       # Россельхозбанк
]

ROOT_CN = "Personal Constrained Root CA"
ROOT_ORG = "Personal PKI"
ROOT_VALIDITY_DAYS = 3650
CROSS_VALIDITY_DAYS = 1825

# ---------------------------------------------------------------------------
# Compat helpers (cryptography < 3.0 needs backend, >= 42 forbids it)
# ---------------------------------------------------------------------------

def _load_pem(data: bytes) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(data)
    except TypeError:
        if default_backend is None:
            raise
        return x509.load_pem_x509_certificate(data, backend=default_backend())

def _load_pem_private_key(data: bytes, password=None):
    try:
        return serialization.load_pem_private_key(data, password=password)
    except TypeError:
        if default_backend is None:
            raise
        return serialization.load_pem_private_key(
            data, password=password, backend=default_backend()
        )
        
def _load_der(data: bytes) -> x509.Certificate:
    try:
        return x509.load_der_x509_certificate(data)
    except TypeError:
        if default_backend is None:
            raise
        return x509.load_der_x509_certificate(data, backend=default_backend())


def _new_rsa_key(size: int = 4096):
    try:
        return rsa.generate_private_key(public_exponent=65537, key_size=size)
    except TypeError:
        if default_backend is None:
            raise
        return rsa.generate_private_key(
            public_exponent=65537, key_size=size, backend=default_backend()
        )


def _sign(builder: x509.CertificateBuilder, key) -> x509.Certificate:
    try:
        return builder.sign(private_key=key, algorithm=hashes.SHA256())
    except TypeError:
        if default_backend is None:
            raise
        return builder.sign(
            private_key=key, algorithm=hashes.SHA256(), backend=default_backend()
        )

# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def load_cert(path: str) -> x509.Certificate:
    data = Path(path).read_bytes()
    return _load_pem(data) if b"BEGIN CERTIFICATE" in data else _load_der(data)


def save_cert(cert: x509.Certificate, path: Path) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def save_key(key, path: Path) -> None:
    path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))


def not_after(cert: x509.Certificate):
    try:
        return cert.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        return cert.not_valid_after.replace(tzinfo=timezone.utc)

# ---------------------------------------------------------------------------
# Certificate builders
# ---------------------------------------------------------------------------

def build_root_ca(key, cn: str, org: str, days: int) -> x509.Certificate:
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
    ])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
    )
    return _sign(builder, key)


def build_cross_cert(mincifry: x509.Certificate,
                     root_key,
                     root_cert: x509.Certificate,
                     permitted_dns: List[str],
                     days: int) -> x509.Certificate:
    # Subject MUST equal the ORIGINAL Mincifry subject — leaf certs issued
    # by Mincifry carry it as issuer, and the validator looks up the CA by
    # subject while building the chain.
    now = datetime.now(timezone.utc)
    max_not_after = min(now + timedelta(days=days), not_after(mincifry))

    name_constraints = x509.NameConstraints(
        permitted_subtrees=[x509.DNSName(d) for d in permitted_dns],
        excluded_subtrees=None,
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(mincifry.subject)
        .issuer_name(root_cert.subject)
        .public_key(mincifry.public_key())    # same key as Mincifry root
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(max_not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(name_constraints, critical=True)   # <-- the point
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(mincifry.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
    )
    return _sign(builder, root_key)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--mincifry", default=DEFAULT_MINCIFRY,
                    help=f"Path to the ORIGINAL Mincifry RSA root (PEM/DER). "
                         f"Default: {DEFAULT_MINCIFRY}")
    ap.add_argument("--outdir", default=".", help="Output directory")
    ap.add_argument("--permit", action="append", metavar="DNS",
                    help="Permitted DNS name (repeatable). Overrides built-in list.")
    ap.add_argument("--root-key", help="Reuse an existing root private key (PEM)")
    ap.add_argument("--root-cert", help="Reuse an existing root cert (PEM)")
    ap.add_argument("--force", action="store_true",
                    help="Overwrite existing my_root_ca.* in --outdir "
                         "(WARNING: breaks every device that trusted the old root)")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    permitted = args.permit if args.permit else DEFAULT_PERMITTED_DNS

    root_key_path  = outdir / "my_root_ca.key"
    root_cert_path = outdir / "my_root_ca.crt"

    # --- 1. Root CA (reuse or generate) ---------------------------------
    if bool(args.root_key) ^ bool(args.root_cert):
        ap.error("--root-key and --root-cert must be provided together.")

    if args.root_key and args.root_cert:
        root_key = _load_pem_private_key(
            Path(args.root_key).read_bytes(), password=None)
        root_cert = load_cert(args.root_cert)
        print(f"[*] Reused existing root: {root_cert.subject.rfc4514_string()}")
    else:
        if (root_key_path.exists() or root_cert_path.exists()) and not args.force:
            ap.error(
                f"{root_key_path} or {root_cert_path} already exists. "
                f"Re-run with --root-key/--root-cert to reuse them, or --force "
                f"to overwrite (this will break devices that trusted the old root)."
            )
        root_key  = _new_rsa_key(4096)
        root_cert = build_root_ca(root_key, ROOT_CN, ROOT_ORG, ROOT_VALIDITY_DAYS)
        save_key(root_key, root_key_path)
        save_cert(root_cert, root_cert_path)
        print("[+] Generated new root CA:")
        print(f"    {root_cert_path}   (install as TRUSTED ROOT)")
        print(f"    {root_key_path}   (KEEP SECRET / OFFLINE)")

    # --- 2. Load Mincifry root ------------------------------------------
    mincifry = load_cert(args.mincifry)
    print(f"[*] Loaded Mincifry root: {mincifry.subject.rfc4514_string()}")
    print(f"    expires: {not_after(mincifry)}")

    # --- 3. Cross-sign --------------------------------------------------
    cross = build_cross_cert(mincifry, root_key, root_cert,
                             permitted, CROSS_VALIDITY_DAYS)
    cross_path = outdir / "mincifry_cross.crt"
    save_cert(cross, cross_path)
    print("[+] Cross-certificate written:")
    print(f"    {cross_path}")
    print("    Permitted DNS names:")
    for d in permitted:
        print(f"      - {d}")
    print(f"    valid until: {not_after(cross)}")
    print()
    print("Next steps:")
    print("  Windows:")
    print("    1. Remove the ORIGINAL Mincifry root from 'Trusted Root CA'.")
    print("    2. Import my_root_ca.crt      -> Trusted Root Certification Authorities")
    print("    3. Import mincifry_cross.crt  -> Intermediate Certification Authorities")
    print("  Android / GrapheneOS:")
    print("    1. Remove BOTH the original Mincifry root and sub-CA from user store.")
    print("    2. Settings > Security > Encryption & credentials > Install a certificate")
    print("       -> CA certificate -> install BOTH my_root_ca.crt and mincifry_cross.crt")
    print("    3. Verify with the verify.py snippet before relying on it.")


if __name__ == "__main__":
    main()