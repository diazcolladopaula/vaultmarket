"""Append-only, hash-chained, signed transaction log.

Every entry commits to the previous one, so removing or editing a record breaks the
chain. Entries made by a user carry that user's Ed25519 signature over the entry
body, so an action is attributable to a key and not just to whoever holds the vault.
``replay_balances`` rebuilds every balance from the log alone.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from typing import Any

from vaultmarket import signing

GENESIS = "0" * 64
SYSTEM = "system"
_ACTOR_FIELD = {"buy_listing": "buyer"}  # where the acting user appears in ``data``


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _digest(prev: str, content: dict[str, Any]) -> str:
    return hashlib.sha256(prev.encode() + _canonical(content)).hexdigest()


def _body(entry: dict[str, Any]) -> dict[str, Any]:
    return {k: entry.get(k) for k in ("seq", "ts", "type", "data", "actor")}


def append(
    ledger: list[dict[str, Any]],
    ts: float,
    kind: str,
    data: dict[str, Any],
    actor: str = SYSTEM,
    sign: Callable[[bytes], str] | None = None,
) -> dict[str, Any]:
    prev = ledger[-1]["hash"] if ledger else GENESIS
    body = {"seq": len(ledger), "ts": round(ts, 3), "type": kind, "data": data, "actor": actor}
    content = {**body, "sig": sign(_canonical(body)) if sign else ""}
    entry = {**content, "prev": prev, "hash": _digest(prev, content)}
    ledger.append(entry)
    return entry


def verify_chain(ledger: list[dict[str, Any]]) -> list[str]:
    problems: list[str] = []
    prev = GENESIS
    for index, entry in enumerate(ledger):
        content = {**_body(entry), "sig": entry.get("sig")}
        if entry.get("seq") != index:
            problems.append(f"entry {index}: sequence number is {entry.get('seq')}")
        if entry.get("prev") != prev:
            problems.append(f"entry {index}: does not link to the previous entry")
        if entry.get("hash") != _digest(prev, content):
            problems.append(f"entry {index}: contents do not match their hash")
        prev = entry.get("hash", "")
    return problems


def verify_signatures(ledger: list[dict[str, Any]], public_keys: Mapping[str, str]) -> list[str]:
    problems: list[str] = []
    for index, entry in enumerate(ledger):
        actor, kind, data = entry.get("actor"), entry.get("type"), entry.get("data", {})
        if actor == SYSTEM:
            if kind != "grant" or entry.get("sig"):
                problems.append(f"entry {index}: '{kind}' claims to be a system action")
            continue
        if actor not in public_keys:
            problems.append(f"entry {index}: signed by unknown user '{actor}'")
        elif not signing.verify(public_keys[actor], _canonical(_body(entry)), entry.get("sig", "")):
            problems.append(f"entry {index}: signature by '{actor}' is invalid")
        if data.get(_ACTOR_FIELD.get(kind, "user")) != actor:
            problems.append(f"entry {index}: signer '{actor}' is not the user it acts for")
    return problems


def replay_balances(ledger: list[dict[str, Any]]) -> dict[str, int]:
    """Recompute every user's balance (in cents) from the log."""
    balances: dict[str, int] = {}

    def add(user: str, cents: int) -> None:
        balances[user] = balances.get(user, 0) + cents

    for entry in ledger:
        kind, d = entry["type"], entry["data"]
        if kind in ("grant", "deposit"):
            add(d["user"], d["amount"])
        elif kind == "withdraw":
            add(d["user"], -d["amount"])
        elif kind == "buy_shop":
            add(d["user"], -d["price"])
        elif kind == "buy_listing":
            add(d["buyer"], -d["price"])
            add(d["seller"], d["price"] - d["fee"])
    return balances
