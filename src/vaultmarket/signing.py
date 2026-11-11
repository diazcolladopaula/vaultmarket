"""Per-user Ed25519 signing keys.

The private key never sits in the vault in the clear: it is wrapped with AES-256-GCM
under a key derived (Argon2id) from the user's own password. Whoever holds only the
vault passphrase can read the public keys but cannot sign as a user.

Wrapped blob (base64 of): time u32 | memory_kib u32 | lanes u32 | salt[16] | nonce[12] | ct+tag.
The header, the username and the public key are bound as associated data.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import struct

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vaultmarket import crypto
from vaultmarket.errors import AuthError, StoreError

_HEADER = struct.Struct(">III16s")
_RAW = {"encoding": serialization.Encoding.Raw, "format": serialization.PublicFormat.Raw}


def _public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(**_RAW)


def generate(password: str, params: crypto.KdfParams, username: str) -> tuple[str, str]:
    """Create a key pair; return ``(public_key_b64, wrapped_private_key_b64)``."""
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = _public_bytes(key)
    salt = os.urandom(crypto.SALT_LEN)
    header = _HEADER.pack(params.time_cost, params.memory_kib, params.lanes, salt)
    nonce = os.urandom(crypto.NONCE_LEN)
    wrapping_key = crypto.derive_key(password, salt, params)
    ciphertext = AESGCM(wrapping_key).encrypt(nonce, private, header + username.encode() + public)
    wrapped = header + nonce + ciphertext
    return base64.b64encode(public).decode(), base64.b64encode(wrapped).decode()


def unwrap(wrapped_b64: str, password: str, username: str, public_b64: str) -> Ed25519PrivateKey:
    try:
        blob = base64.b64decode(wrapped_b64, validate=True)
        public = base64.b64decode(public_b64, validate=True)
        header, rest = blob[: _HEADER.size], blob[_HEADER.size :]
        time_cost, memory_kib, lanes, salt = _HEADER.unpack(header)
        params = crypto.KdfParams(time_cost, memory_kib, lanes)
        params.validate()
        nonce, ciphertext = rest[: crypto.NONCE_LEN], rest[crypto.NONCE_LEN :]
        wrapping_key = crypto.derive_key(password, salt, params)
        aad = header + username.encode() + public
        private = AESGCM(wrapping_key).decrypt(nonce, ciphertext, aad)
        key = Ed25519PrivateKey.from_private_bytes(private)
    except (InvalidTag, binascii.Error, struct.error, ValueError, StoreError):
        raise AuthError("Your signing key could not be unlocked.") from None
    if _public_bytes(key) != public:
        raise AuthError("Your signing key does not match the stored public key.")
    return key


def sign(key: Ed25519PrivateKey, message: bytes) -> str:
    return base64.b64encode(key.sign(message)).decode()


def verify(public_b64: str, message: bytes, signature_b64: str) -> bool:
    try:
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64, validate=True))
        public.verify(base64.b64decode(signature_b64, validate=True), message)
    except (InvalidSignature, binascii.Error, ValueError):
        return False
    return True


def fingerprint(public_b64: str) -> str:
    """Short, human-comparable digest of a public key, e.g. ``1a2b-3c4d-5e6f-7a8b``."""
    digest = hashlib.sha256(base64.b64decode(public_b64)).hexdigest()[:16]
    return "-".join(digest[i : i + 4] for i in range(0, 16, 4))
