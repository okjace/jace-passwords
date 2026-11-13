"""The vault's cryptography.

Two-secret key derivation, like 1Password:

    k1  = scrypt(master password, salt)          (N=2^17, r=8, p=1: ~128 MiB, slow on purpose)
    k2  = HKDF-SHA256(Secret Key, salt, info)    (128 random bits, never leaves your devices)
    KEK = k1 XOR k2

The KEK unwraps a random 256-bit vault key; the vault key encrypts the vault
with AES-256-GCM. Jace (and anyone who steals the synced copy) has neither the
master password nor the Secret Key, so a stolen vault can't be brute-forced
from the password alone.
"""
import base64
import hashlib
import json
import os
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

B32 = "ABCDEFGHJKLMNPQRSTVWXYZ23456789"  # no I, O, U, 0, 1: easy to copy by hand

DEFAULT_KDF = {"name": "scrypt", "n": 2 ** 17, "r": 8, "p": 1}


class CryptoError(Exception):
    pass


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def new_secret_key() -> str:
    """A Secret Key like J1-ABCDEF-GHJKL-MNPQR-STVWX-YZ234-56789 (26 random chars, ~128 bits)."""
    chars = "".join(secrets.choice(B32) for _ in range(26))
    groups = [chars[:6]] + [chars[6 + i * 5: 11 + i * 5] for i in range(4)]
    return "J1-" + "-".join(groups)


def normalize_secret_key(sk: str) -> str:
    raw = "".join(c for c in sk.upper() if c.isalnum())
    if raw.startswith("J1"):
        raw = raw[2:]
    if len(raw) != 26 or any(c not in B32 for c in raw):
        raise CryptoError("That Secret Key doesn't look right. It starts with J1- and has 26 more letters and numbers.")
    return raw


def derive_kek(password: str | None, secret_key: str | None, salt: bytes, kdf: dict, jace_key: bytes | None = None,
               device_key: bytes | None = None) -> bytes:
    if kdf.get("name") == "device":
        # No master password and no Jace account: opens on this device without asking. The key
        # lives in device.json next to the vault, so the vault is encrypted, but anyone who can
        # use this computer can open it.
        if not device_key:
            raise CryptoError("This vault opens only on the device that made it.")
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                    info=b"jace-passwords device unlock v1").derive(device_key)
    if kdf.get("name") == "jace":
        # No master password: unlocked with your Jace account. jace_key comes from the Jace Passwords
        # server (webapp/api/jace.py) once you're signed in. NOT end-to-end encrypted.
        if not jace_key:
            raise CryptoError("Sign in with Jace to unlock this vault.")
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                    info=b"jace-passwords jace unlock v1").derive(jace_key)
    if kdf.get("name") != "scrypt":
        raise CryptoError("Unknown key derivation.")
    n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
    k1 = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                        maxmem=128 * r * (n + p + 2) + 1024 * 1024, dklen=32)
    if kdf.get("secretKey") is False:
        # Vaults linked to a Jace account: the master password alone. The synced copy is only
        # readable with your Jace sign-in, which takes the Secret Key's place.
        return k1
    k2 = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
              info=b"jace-passwords secret key v1").derive(normalize_secret_key(secret_key).encode())
    return bytes(a ^ b for a, b in zip(k1, k2))


def seal(key: bytes, plaintext: bytes, aad: bytes = b"") -> dict:
    iv = os.urandom(12)
    return {"iv": b64e(iv), "ct": b64e(AESGCM(key).encrypt(iv, plaintext, aad))}


def open_sealed(key: bytes, box: dict, aad: bytes = b"") -> bytes:
    try:
        return AESGCM(key).decrypt(b64d(box["iv"]), b64d(box["ct"]), aad)
    except Exception as e:  # InvalidTag, bad base64, missing fields
        raise CryptoError("Wrong master password or Secret Key.") from e


def seal_json(key: bytes, obj, aad: bytes = b"") -> dict:
    return seal(key, json.dumps(obj, separators=(",", ":")).encode(), aad)


def open_json(key: bytes, box: dict, aad: bytes = b""):
    return json.loads(open_sealed(key, box, aad))
