"""Password hashing with Argon2id, stored as a standard PHC string.

Output looks like ``$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`` (unpadded
base64), the same format used by the reference implementation and by libraries
such as argon2-cffi, so hashes are portable.
"""

from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

_PHC = re.compile(r"\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)")
_SALT_LEN = 16
_HASH_LEN = 32


@dataclass(frozen=True)
class PasswordPolicy:
    """Argon2id cost parameters (defaults follow the OWASP minimum of 19 MiB; we use 64 MiB)."""

    memory_kib: int = 65_536
    time_cost: int = 3
    lanes: int = 4


DEFAULT_POLICY = PasswordPolicy()


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode().rstrip("=")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str, policy: PasswordPolicy = DEFAULT_POLICY) -> str:
    salt = os.urandom(_SALT_LEN)
    digest = Argon2id(
        salt=salt,
        length=_HASH_LEN,
        iterations=policy.time_cost,
        lanes=policy.lanes,
        memory_cost=policy.memory_kib,
    ).derive(password.encode("utf-8"))
    return (
        f"$argon2id$v=19$m={policy.memory_kib},t={policy.time_cost},p={policy.lanes}"
        f"${_b64e(salt)}${_b64e(digest)}"
    )


def _parse(encoded: str) -> tuple[PasswordPolicy, bytes, bytes] | None:
    match = _PHC.fullmatch(encoded)
    if not match:
        return None
    memory, time_cost, lanes, salt, digest = match.groups()
    return PasswordPolicy(int(memory), int(time_cost), int(lanes)), _b64d(salt), _b64d(digest)


def verify_password(encoded: str, password: str) -> bool:
    """Constant-time check; malformed stored hashes simply fail."""
    parsed = _parse(encoded)
    if parsed is None:
        return False
    policy, salt, digest = parsed
    try:
        Argon2id(
            salt=salt,
            length=len(digest),
            iterations=policy.time_cost,
            lanes=policy.lanes,
            memory_cost=policy.memory_kib,
        ).verify(password.encode("utf-8"), digest)
    except (InvalidKey, ValueError):
        return False
    return True


def needs_rehash(encoded: str, policy: PasswordPolicy) -> bool:
    parsed = _parse(encoded)
    return parsed is None or parsed[0] != policy
