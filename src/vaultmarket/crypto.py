"""Vault encryption: Argon2id key derivation + AES-256-GCM.

File layout (big endian)::

    magic "VMKT" | version u8 | time_cost u32 | memory_kib u32 | lanes u32 | salt[16]
    nonce[12] | ciphertext || tag[16]

The whole header (everything before the nonce) is passed to GCM as associated
data, so changing the KDF parameters or the salt makes decryption fail.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from vaultmarket.errors import StoreError

MAGIC = b"VMKT"
VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
_HEADER = struct.Struct(">4sBIII16s")

# Upper bounds so a tampered header cannot make us allocate gigabytes.
_MAX_TIME_COST = 20
_MAX_MEMORY_KIB = 1_048_576  # 1 GiB
_MAX_LANES = 16


@dataclass(frozen=True)
class KdfParams:
    time_cost: int = 3
    memory_kib: int = 65_536  # 64 MiB
    lanes: int = 4

    def validate(self) -> None:
        if not 1 <= self.time_cost <= _MAX_TIME_COST:
            raise StoreError("Vault header has an invalid KDF time cost.")
        if not 1 <= self.lanes <= _MAX_LANES:
            raise StoreError("Vault header has an invalid KDF lane count.")
        if not 8 * self.lanes <= self.memory_kib <= _MAX_MEMORY_KIB:
            raise StoreError("Vault header has an invalid KDF memory cost.")


def new_header(params: KdfParams) -> bytes:
    params.validate()
    return _HEADER.pack(
        MAGIC, VERSION, params.time_cost, params.memory_kib, params.lanes, os.urandom(SALT_LEN)
    )


def parse_header(blob: bytes) -> tuple[bytes, KdfParams, bytes]:
    """Return ``(header_bytes, kdf_params, salt)`` from the start of ``blob``."""
    if len(blob) < _HEADER.size + NONCE_LEN + 16:
        raise StoreError("Vault file is truncated.")
    magic, version, time_cost, memory_kib, lanes, salt = _HEADER.unpack_from(blob)
    if magic != MAGIC:
        raise StoreError("Not a vaultmarket vault file.")
    if version != VERSION:
        raise StoreError(f"Unsupported vault version {version}.")
    params = KdfParams(time_cost, memory_kib, lanes)
    params.validate()
    return blob[: _HEADER.size], params, salt


def derive_key(passphrase: str, salt: bytes, params: KdfParams) -> bytes:
    kdf = Argon2id(
        salt=salt,
        length=KEY_LEN,
        iterations=params.time_cost,
        lanes=params.lanes,
        memory_cost=params.memory_kib,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt(key: bytes, header: bytes, plaintext: bytes) -> bytes:
    """Encrypt with a fresh random nonce and return the complete file contents."""
    nonce = os.urandom(NONCE_LEN)
    return header + nonce + AESGCM(key).encrypt(nonce, plaintext, header)


def decrypt(key: bytes, blob: bytes) -> bytes:
    header, _, _ = parse_header(blob)
    nonce = blob[len(header) : len(header) + NONCE_LEN]
    ciphertext = blob[len(header) + NONCE_LEN :]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, header)
    except InvalidTag:
        raise StoreError("Wrong passphrase, or the vault file has been modified.") from None
