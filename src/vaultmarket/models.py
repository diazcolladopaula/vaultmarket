"""Plain data classes that make up the persisted market state."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

STATE_VERSION = 1


@dataclass
class Item:
    id: str
    kind: str
    material: str
    wear: int

    @property
    def model_key(self) -> str:
        return f"{self.kind}/{self.material}/{self.wear}"


@dataclass
class Listing:
    item: Item
    seller: str
    price: int  # cents
    listed_at: float
    offer_hash: str  # hash of the signed ledger entry that created this listing


@dataclass
class User:
    username: str
    password_hash: str
    balance: int = 0  # cents
    items: list[Item] = field(default_factory=list)
    failed_logins: int = 0
    locked_until: float = 0.0
    public_key: str = ""  # Ed25519, base64
    wrapped_key: str = ""  # private key encrypted under the user's password


@dataclass
class State:
    users: dict[str, User] = field(default_factory=dict)
    listings: list[Listing] = field(default_factory=list)
    prices: dict[str, int] = field(default_factory=dict)  # model key -> current price in cents
    ledger: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": STATE_VERSION,
            "users": {name: asdict(user) for name, user in self.users.items()},
            "listings": [asdict(listing) for listing in self.listings],
            "prices": dict(self.prices),
            "ledger": list(self.ledger),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> State:
        users = {
            name: User(
                username=u["username"],
                password_hash=u["password_hash"],
                balance=u["balance"],
                items=[Item(**i) for i in u["items"]],
                failed_logins=u["failed_logins"],
                locked_until=u["locked_until"],
                public_key=u["public_key"],
                wrapped_key=u["wrapped_key"],
            )
            for name, u in data["users"].items()
        }
        listings = [
            Listing(
                Item(**entry["item"]),
                entry["seller"],
                entry["price"],
                entry["listed_at"],
                entry["offer_hash"],
            )
            for entry in data["listings"]
        ]
        return cls(users, listings, dict(data["prices"]), list(data["ledger"]))
