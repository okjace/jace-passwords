"""Passkeys: a WebAuthn authenticator whose keys live in your vault (and sync with it).

Each passkey is an ES256 (P-256) key pair saved on a login item under
fields.passkeys. Registration returns a "none" attestation; sign-in signs
authenticatorData || SHA-256(clientDataJSON). The extension builds
clientDataJSON from the page's real origin; this module re-checks that the
origin is allowed to use the relying party ID.
"""
import base64
import hashlib
import json
import os
import struct
import urllib.parse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Identifies "Jace Passwords" as the authenticator (sites may show this in their passkey list).
AAGUID = bytes.fromhex("6a61636570617373776f7264732d3031")
ES256 = -7

FLAG_UP, FLAG_UV, FLAG_BE, FLAG_BS, FLAG_AT = 0x01, 0x04, 0x08, 0x10, 0x40


class PasskeyError(Exception):
    def __init__(self, message, name="NotAllowedError"):
        super().__init__(message)
        self.name = name  # the DOMException name the page should see


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------- minimal CBOR (just what WebAuthn needs) ----------
def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    if n < 256:
        return bytes([major << 5 | 24, n])
    if n < 65536:
        return bytes([major << 5 | 25]) + struct.pack(">H", n)
    return bytes([major << 5 | 26]) + struct.pack(">I", n)


def cbor(v) -> bytes:
    if isinstance(v, bool):
        return b"\xf5" if v else b"\xf4"
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, str):
        e = v.encode()
        return _head(3, len(e)) + e
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        return _head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    raise TypeError(type(v))


# ---------- origin / RP ID rules ----------
def check_origin(origin: str, rp_id: str) -> None:
    """The page's origin must be secure and its host must be the RP ID or a subdomain of it."""
    u = urllib.parse.urlparse(origin or "")
    host = (u.hostname or "").lower()
    rp_id = (rp_id or "").lower()
    local = host == "localhost" or host.endswith(".localhost")
    if u.scheme != "https" and not (u.scheme == "http" and local):
        raise PasskeyError("Passkeys only work on secure (https) sites.", "SecurityError")
    if not rp_id or not (host == rp_id or (host.endswith("." + rp_id) and "." in rp_id)):
        raise PasskeyError(f"{host} can't use passkeys for {rp_id}.", "SecurityError")


def _auth_data(rp_id: str, flags: int, attested: bytes = b"") -> bytes:
    return hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", 0) + attested


def _cose(pub: ec.EllipticCurvePublicKey) -> bytes:
    n = pub.public_numbers()
    return cbor({1: 2, 3: ES256, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})


# ---------- registration ----------
def register(rp_id: str, origin: str, client_data_json: bytes, user: dict, algs: list) -> tuple[dict, dict]:
    """Makes a new passkey. Returns (the passkey to store, the response for the page)."""
    check_origin(origin, rp_id)
    cd = json.loads(client_data_json)
    if cd.get("type") != "webauthn.create" or cd.get("origin") != origin:
        raise PasskeyError("Bad client data.", "SecurityError")
    if algs and ES256 not in algs:
        raise PasskeyError("This site doesn't accept the passkey type Jace Passwords makes.", "NotSupportedError")
    key = ec.generate_private_key(ec.SECP256R1())
    cred_id = os.urandom(16)
    pub = key.public_key()
    attested = AAGUID + struct.pack(">H", len(cred_id)) + cred_id + _cose(pub)
    auth_data = _auth_data(rp_id, FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT, attested)
    stored = {
        "credentialId": b64u(cred_id),
        "rpId": rp_id,
        "userHandle": user.get("id", ""),
        "userName": str(user.get("name", ""))[:200],
        "userDisplayName": str(user.get("displayName", ""))[:200],
        "alg": ES256,
        "privateKey": base64.b64encode(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption())).decode(),
    }
    response = {
        "credentialId": stored["credentialId"],
        "clientDataJSON": b64u(client_data_json),
        "attestationObject": b64u(cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})),
        "authenticatorData": b64u(auth_data),
        "publicKey": b64u(pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
        "publicKeyAlgorithm": ES256,
        "transports": ["internal", "hybrid"],
    }
    return stored, response


# ---------- sign-in ----------
def assert_(passkey: dict, rp_id: str, origin: str, client_data_json: bytes) -> dict:
    check_origin(origin, rp_id)
    if passkey.get("rpId") != rp_id:
        raise PasskeyError("That passkey belongs to another site.", "SecurityError")
    cd = json.loads(client_data_json)
    if cd.get("type") != "webauthn.get" or cd.get("origin") != origin:
        raise PasskeyError("Bad client data.", "SecurityError")
    key = serialization.load_der_private_key(base64.b64decode(passkey["privateKey"]), password=None)
    auth_data = _auth_data(rp_id, FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS)
    sig = key.sign(auth_data + hashlib.sha256(client_data_json).digest(), ec.ECDSA(hashes.SHA256()))
    return {
        "credentialId": passkey["credentialId"],
        "clientDataJSON": b64u(client_data_json),
        "authenticatorData": b64u(auth_data),
        "signature": b64u(sig),
        "userHandle": passkey.get("userHandle", ""),
    }


def public_info(p: dict) -> dict:
    """A passkey without its private key (for the app window and the extension)."""
    return {k: p.get(k) for k in ("credentialId", "rpId", "userName", "userDisplayName", "createdAt", "lastUsedAt")}
