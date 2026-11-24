#!/usr/bin/env python3
"""Run once:  python3 packaging/android_keystore.py

Makes the Android release signing key (PKCS12 keystore), saves it and its password as GitHub secrets
without printing them, keeps a private backup copy, and prints only the certificate's SHA-256 fingerprint
(public: it goes in the website's assetlinks.json)."""
import base64
import datetime
import os
import secrets
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
backup = os.path.join(ROOT, "local", "android-release.p12")  # local/ is not committed
os.makedirs(os.path.dirname(backup), exist_ok=True)
if os.path.exists(backup):
    sys.exit("local/android-release.p12 already exists: the release key must stay the same, so this won't replace it.")
repo = "okjace/jace-passwords"
password = secrets.token_urlsafe(32)
key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Jace Passwords"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "okjace")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365 * 40)).sign(key, hashes.SHA256()))
p12 = pkcs12.serialize_key_and_certificates(b"jacepasswords", key, cert, None,
                                            serialization.BestAvailableEncryption(password.encode()))
fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "wb") as f:
    f.write(p12)
pw_backup = backup + ".password"
fd = os.open(pw_backup, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    f.write(password + "\n")
for name_, value in (("ANDROID_KEYSTORE_B64", base64.b64encode(p12).decode()), ("ANDROID_KEYSTORE_PASSWORD", password)):
    subprocess.run(["gh", "secret", "set", name_, "-R", repo], input=value.encode(), check=True, capture_output=True)
fp = cert.fingerprint(hashes.SHA256()).hex().upper()
print("SHA256:" + ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)))
print("Secrets ANDROID_KEYSTORE_B64 and ANDROID_KEYSTORE_PASSWORD set; backup saved.")
