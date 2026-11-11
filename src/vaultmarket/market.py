"""Marketplace rules. Pure logic: no I/O, no printing, injectable clock and RNG."""

from __future__ import annotations

import random
import re
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaultmarket import crypto, ledger, passwords, signing
from vaultmarket.catalog import Catalog, CatalogEntry, load_catalog
from vaultmarket.errors import AuthError, MarketError
from vaultmarket.models import Item, Listing, State, User
from vaultmarket.money import MAX_AMOUNT, format_amount

STARTING_BALANCE = 10_000  # 100.00 credits
SHOP_SIZE = 7
FEE_PERCENT = 5  # taken from the seller on player-to-player sales
MAX_TOP_UP = 1_000_000  # 10,000.00 credits per operation
PRICE_BAND = (50, 200)  # a sale moves the model price by at most this % of the current price
PRICE_SMOOTHING = 5  # new price = (old * (N-1) + clamped sale) / N

MIN_PASSWORD_LEN = 10
MAX_FAILED_LOGINS = 5
BASE_LOCKOUT_SECONDS = 30
MAX_LOCKOUT_SECONDS = 900
_USERNAME_RE = re.compile(r"[a-z0-9_.-]{3,24}")


@dataclass(frozen=True)
class ShopOffer:
    entry: CatalogEntry
    price: int


class Market:
    def __init__(
        self,
        state: State,
        catalog: Catalog | None = None,
        *,
        clock: Callable[[], float] = time.time,
        rng: random.Random | None = None,
        password_policy: passwords.PasswordPolicy = passwords.DEFAULT_POLICY,
    ) -> None:
        self.state = state
        self.catalog = catalog or load_catalog()
        self._clock = clock
        self._rng = rng or random.Random()
        self._policy = password_policy
        self._decoy_hash: str | None = None
        self._signers: dict[str, Ed25519PrivateKey] = {}
        self.shop: list[ShopOffer] = []
        self.refresh_shop()

    # ------------------------------------------------------------------ accounts

    def register(self, username: str, password: str) -> User:
        name = username.strip().lower()
        if not _USERNAME_RE.fullmatch(name):
            raise MarketError("Username must be 3-24 characters: letters, digits, '_', '.' or '-'.")
        if name in self.state.users:
            raise MarketError("That username is already taken.")
        if len(password) < MIN_PASSWORD_LEN:
            raise MarketError(f"Password must be at least {MIN_PASSWORD_LEN} characters long.")
        if password.lower() == name:
            raise MarketError("Password must not be the same as the username.")
        public_key, wrapped_key = signing.generate(password, self._kdf_params(), name)
        user = User(
            name,
            passwords.hash_password(password, self._policy),
            STARTING_BALANCE,
            public_key=public_key,
            wrapped_key=wrapped_key,
        )
        self.state.users[name] = user
        self._log("grant", user=name, amount=STARTING_BALANCE)
        return user

    def login(self, username: str, password: str) -> User:
        name = username.strip().lower()
        user = self.state.users.get(name)
        if user is None:
            # Burn the same CPU time as a real check so response time does not reveal
            # whether the username exists.
            passwords.verify_password(self._decoy(), password)
            raise AuthError("Invalid username or password.")

        now = self._clock()
        if user.locked_until > now:
            wait = int(user.locked_until - now) + 1
            raise AuthError(f"Too many failed attempts. Try again in {wait} s.")

        if not passwords.verify_password(user.password_hash, password):
            user.failed_logins += 1
            if user.failed_logins >= MAX_FAILED_LOGINS:
                extra = user.failed_logins - MAX_FAILED_LOGINS
                delay = min(BASE_LOCKOUT_SECONDS * 2**extra, MAX_LOCKOUT_SECONDS)
                user.locked_until = now + delay
            raise AuthError("Invalid username or password.")

        user.failed_logins = 0
        user.locked_until = 0.0
        if passwords.needs_rehash(user.password_hash, self._policy):
            user.password_hash = passwords.hash_password(password, self._policy)
        self._signers[name] = signing.unwrap(user.wrapped_key, password, name, user.public_key)
        self.refresh_shop()
        return user

    def logout(self, username: str) -> None:
        """Forget the user's unlocked signing key."""
        self._signers.pop(username, None)

    def fingerprint(self, username: str) -> str:
        return signing.fingerprint(self._user(username).public_key)

    def _kdf_params(self) -> crypto.KdfParams:
        p = self._policy
        return crypto.KdfParams(p.time_cost, p.memory_kib, p.lanes)

    def _require_login(self, username: str) -> User:
        user = self._user(username)
        if username not in self._signers:
            raise AuthError("You must be logged in to do that.")
        return user

    def _decoy(self) -> str:
        if self._decoy_hash is None:
            self._decoy_hash = passwords.hash_password("decoy-password", self._policy)
        return self._decoy_hash

    def _user(self, username: str) -> User:
        try:
            return self.state.users[username]
        except KeyError:
            raise MarketError("Unknown user.") from None

    # ------------------------------------------------------------------- wallet

    def deposit(self, username: str, cents: int) -> int:
        """Add simulated funds. Returns the new balance."""
        user = self._require_login(username)
        self._check_amount(cents, MAX_TOP_UP)
        if user.balance + cents > MAX_AMOUNT:
            raise MarketError("That would exceed the maximum wallet balance.")
        user.balance += cents
        self._log("deposit", username, user=username, amount=cents)
        return user.balance

    def withdraw(self, username: str, cents: int) -> int:
        user = self._require_login(username)
        self._check_amount(cents, MAX_AMOUNT)
        if cents > user.balance:
            raise MarketError("Insufficient balance.")
        user.balance -= cents
        self._log("withdraw", username, user=username, amount=cents)
        return user.balance

    # --------------------------------------------------------------------- shop

    def price_of(self, entry: CatalogEntry) -> int:
        return self.state.prices.get(entry.key, entry.base_price)

    def value_of(self, item: Item) -> int:
        entry = self.catalog.get(item.kind, item.material, item.wear)
        return self.price_of(entry)

    def refresh_shop(self) -> None:
        picks = self._rng.sample(self.catalog.entries, SHOP_SIZE)
        self.shop = [ShopOffer(e, self.price_of(e)) for e in picks]

    def buy_from_shop(self, username: str, index: int) -> Item:
        user = self._require_login(username)
        offer = self.pick(self.shop, index)
        price = self.price_of(offer.entry)
        if user.balance < price:
            raise MarketError(
                f"Insufficient balance: needs {format_amount(price)}, "
                f"you have {format_amount(user.balance)}."
            )
        user.balance -= price
        item = Item(uuid.uuid4().hex, offer.entry.kind, offer.entry.material, offer.entry.wear)
        user.items.append(item)
        self.shop.remove(offer)
        self._log(
            "buy_shop", username, user=username, item=item.id, model=offer.entry.key, price=price
        )
        return item

    # ------------------------------------------------------------ player market

    def list_item(self, username: str, index: int, price: int) -> Listing:
        user = self._require_login(username)
        item = self.pick(user.items, index)
        self._check_amount(price, MAX_AMOUNT)
        user.items.remove(item)
        entry = self._log("list", username, user=username, item=item.id, price=price)
        listing = Listing(item, username, price, self._clock(), entry["hash"])
        self.state.listings.append(listing)
        return listing

    def delist(self, username: str, index: int) -> Item:
        """Withdraw one of the caller's own listings (``index`` into ``state.listings``)."""
        user = self._require_login(username)
        listing = self.pick(self.state.listings, index)
        if listing.seller != username:
            raise MarketError("You can only withdraw your own listings.")
        self.state.listings.remove(listing)
        user.items.append(listing.item)
        self._log("delist", username, user=username, item=listing.item.id)
        return listing.item

    def buy_listing(self, username: str, index: int) -> Listing:
        buyer = self._require_login(username)
        listing = self.pick(self.state.listings, index)
        if listing.seller == username:
            raise MarketError("You cannot buy your own listing.")
        seller = self._user(listing.seller)
        if buyer.balance < listing.price:
            raise MarketError(
                f"Insufficient balance: needs {format_amount(listing.price)}, "
                f"you have {format_amount(buyer.balance)}."
            )
        fee = listing.price * FEE_PERCENT // 100
        buyer.balance -= listing.price
        seller.balance += listing.price - fee
        self.state.listings.remove(listing)
        buyer.items.append(listing.item)
        self._record_sale_price(listing.item, listing.price)
        self._log(
            "buy_listing",
            username,
            buyer=username,
            seller=listing.seller,
            item=listing.item.id,
            price=listing.price,
            fee=fee,
            offer=listing.offer_hash,
        )
        return listing

    def _record_sale_price(self, item: Item, sale_price: int) -> None:
        """Nudge the model's price toward the sale price, bounded so one trade cannot spike it."""
        entry = self.catalog.get(item.kind, item.material, item.wear)
        current = self.price_of(entry)
        low, high = current * PRICE_BAND[0] // 100, current * PRICE_BAND[1] // 100
        clamped = min(max(sale_price, low), high)
        updated = (current * (PRICE_SMOOTHING - 1) + clamped) // PRICE_SMOOTHING
        self.state.prices[entry.key] = max(updated, 1)

    # ------------------------------------------------------------ history / audit

    def history(self, username: str, limit: int = 20) -> list[dict]:
        def involves(entry: dict) -> bool:
            return username in {v for v in entry["data"].values() if isinstance(v, str)}

        return [e for e in self.state.ledger if involves(e)][-limit:]

    def audit(self) -> list[str]:
        """Return a list of problems; an empty list means the state is consistent."""
        problems = ledger.verify_chain(self.state.ledger)
        keys = {name: u.public_key for name, u in self.state.users.items()}
        problems += ledger.verify_signatures(self.state.ledger, keys)
        problems += self._check_offers()
        replayed = ledger.replay_balances(self.state.ledger)
        for name, user in self.state.users.items():
            expected = replayed.get(name, 0)
            if user.balance != expected:
                problems.append(
                    f"{name}: balance {format_amount(user.balance)} does not match the ledger "
                    f"({format_amount(expected)})"
                )
        for name in replayed.keys() - self.state.users.keys():
            problems.append(f"ledger references unknown user '{name}'")
        seen: set[str] = set()
        owned = [i for u in self.state.users.values() for i in u.items]
        for item in [*owned, *(listing.item for listing in self.state.listings)]:
            if item.id in seen:
                problems.append(f"item {item.id[:8]} exists more than once")
            seen.add(item.id)
        return problems

    def _check_offers(self) -> list[str]:
        """Every player purchase must match the seller's signed listing it refers to."""
        by_hash = {e["hash"]: e for e in self.state.ledger}
        problems = []
        for e in self.state.ledger:
            if e["type"] != "buy_listing":
                continue
            d = e["data"]
            offer = by_hash.get(d.get("offer"))
            if offer is None or offer["type"] != "list":
                problems.append(f"entry {e['seq']}: purchase refers to a missing listing")
            elif (
                offer["actor"] != d["seller"]
                or offer["data"]["item"] != d["item"]
                or offer["data"]["price"] != d["price"]
            ):
                problems.append(
                    f"entry {e['seq']}: purchase does not match the seller's signed offer"
                )
        return problems

    # ------------------------------------------------------------------ helpers

    def _log(self, kind: str, actor: str | None = None, **data) -> dict:
        """Append to the ledger; user actions are signed with the actor's unlocked key."""
        if actor is None:
            return ledger.append(self.state.ledger, self._clock(), kind, data)
        key = self._signers[actor]
        return ledger.append(
            self.state.ledger,
            self._clock(),
            kind,
            data,
            actor=actor,
            sign=lambda message: signing.sign(key, message),
        )

    @staticmethod
    def _check_amount(cents: int, maximum: int) -> None:
        if isinstance(cents, bool) or not isinstance(cents, int) or not 0 < cents <= maximum:
            raise MarketError(f"Amount must be between 0.01 and {format_amount(maximum)}.")

    @staticmethod
    def pick(sequence: list, index: int):
        """Resolve a 1-based menu number."""
        if not 1 <= index <= len(sequence):
            raise MarketError("That selection does not exist.")
        return sequence[index - 1]
