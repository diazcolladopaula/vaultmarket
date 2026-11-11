"""Encrypted single-file persistence for the market state."""

from __future__ import annotations

import json
import os
from pathlib import Path

from vaultmarket import crypto
from vaultmarket.errors import StoreError
from vaultmarket.models import State

VAULT_NAME = "vault.bin"


class Store:
    def __init__(self, directory: str | os.PathLike, kdf: crypto.KdfParams | None = None) -> None:
        self.directory = Path(directory)
        self.path = self.directory / VAULT_NAME
        self._kdf = kdf or crypto.KdfParams()
        self._key: bytes | None = None
        self._header: bytes | None = None

    def exists(self) -> bool:
        return self.path.exists()

    def create(self, passphrase: str, state: State) -> None:
        if self.exists():
            raise StoreError("A vault already exists in this directory.")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        header = crypto.new_header(self._kdf)
        _, params, salt = crypto.parse_header(header + bytes(crypto.NONCE_LEN + 16))
        self._header = header
        self._key = crypto.derive_key(passphrase, salt, params)
        self.save(state)

    def open(self, passphrase: str) -> State:
        try:
            blob = self.path.read_bytes()
        except FileNotFoundError:
            raise StoreError("No vault found.") from None
        header, params, salt = crypto.parse_header(blob)
        key = crypto.derive_key(passphrase, salt, params)
        plaintext = crypto.decrypt(key, blob)
        try:
            state = State.from_dict(json.loads(plaintext))
        except (ValueError, KeyError, TypeError) as exc:
            raise StoreError(f"Vault decrypted but its contents are invalid: {exc!r}") from None
        self._key, self._header = key, header
        return state

    def save(self, state: State) -> None:
        if self._key is None or self._header is None:
            raise StoreError("Vault is locked.")
        plaintext = json.dumps(state.to_dict(), separators=(",", ":")).encode("utf-8")
        _atomic_write(self.path, crypto.encrypt(self._key, self._header, plaintext))


def _atomic_write(path: Path, data: bytes) -> None:
    """Write via a temp file and rename so a crash never leaves a half-written vault."""
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    if hasattr(os, "O_DIRECTORY"):
        dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
