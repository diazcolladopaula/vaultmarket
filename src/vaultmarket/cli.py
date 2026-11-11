"""Interactive terminal front end."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Callable
from pathlib import Path

from vaultmarket import __version__
from vaultmarket.errors import AuthError, MarketError, VaultMarketError
from vaultmarket.market import MIN_PASSWORD_LEN, Market
from vaultmarket.models import State
from vaultmarket.money import format_amount, parse_amount
from vaultmarket.store import Store

MIN_PASSPHRASE_LEN = 12
PASSPHRASE_ENV = "VAULTMARKET_PASSPHRASE"


class Console:
    """Thin wrapper over stdin/stdout so the UI can be driven by tests."""

    def ask(self, prompt: str) -> str:
        return input(prompt).strip()

    def ask_secret(self, prompt: str) -> str:
        return getpass.getpass(prompt)

    def say(self, text: str = "") -> None:
        print(text)


def render_table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [max(len(str(c)) for c in col) for col in zip(headers, *rows, strict=True)]
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths, strict=True))
    out = [line, "  ".join("-" * w for w in widths)]
    out += ["  ".join(str(c).ljust(w) for c, w in zip(r, widths, strict=True)) for r in rows]
    return "\n".join(out)


class App:
    def __init__(self, market: Market, store: Store, console: Console) -> None:
        self.market, self.store, self.io = market, store, console
        self.user: str | None = None

    # ----------------------------------------------------------------- plumbing

    def run(self) -> None:
        self.io.say("Vaultmarket - type the number of an option, or 0 to go back.")
        try:
            while True:
                if self.user is None and not self._guest_menu():
                    return
                if self.user is not None:
                    self._user_menu()
        except (EOFError, KeyboardInterrupt):
            self.io.say("\nBye.")

    def _save(self) -> None:
        self.store.save(self.market.state)

    def _choose(self, title: str, options: list[str], back: str = "Back") -> int:
        self.io.say(f"\n{title}")
        for number, label in enumerate(options, start=1):
            self.io.say(f"  {number}. {label}")
        self.io.say(f"  0. {back}")
        raw = self.io.ask("> ")
        return int(raw) if raw.isdigit() else -1

    def _number(self, prompt: str) -> int:
        raw = self.io.ask(prompt)
        if not raw.isdigit():
            raise MarketError("Please enter a number.")
        return int(raw)

    def _guard(self, action: Callable[[], None]) -> None:
        try:
            action()
        except MarketError as exc:
            self.io.say(f"! {exc}")

    # --------------------------------------------------------------------- menus

    def _guest_menu(self) -> bool:
        """Return False when the user chose to quit."""
        choice = self._choose("Welcome", ["Log in", "Create account"], back="Quit")
        if choice == 0:
            return False
        if choice == 1:
            self._login()
        elif choice == 2:
            self._guard(self._register)
        else:
            self.io.say("! Invalid option.")
        return True

    def _user_menu(self) -> None:
        assert self.user is not None
        balance = format_amount(self.market.state.users[self.user].balance)
        choice = self._choose(
            f"Main menu  [{self.user} | {balance} cr]",
            ["Wallet", "Inventory", "Shop", "Player market", "History"],
            back="Log out",
        )
        actions = {
            1: self._wallet,
            2: self._inventory,
            3: self._shop,
            4: self._player_market,
            5: self._history,
        }
        if choice == 0:
            self.market.logout(self.user)
            self.user = None
            self.io.say("Logged out.")
        elif choice in actions:
            self._guard(actions[choice])
        else:
            self.io.say("! Invalid option.")

    # ------------------------------------------------------------------ accounts

    def _register(self) -> None:
        name = self.io.ask("Choose a username: ")
        password = self.io.ask_secret(f"Choose a password (min {MIN_PASSWORD_LEN} chars): ")
        if password != self.io.ask_secret("Repeat the password: "):
            raise MarketError("Passwords do not match.")
        user = self.market.register(name, password)
        self._save()
        self.io.say(f"Account '{user.username}' created with {format_amount(user.balance)} cr.")
        self.io.say(f"Signing key fingerprint: {self.market.fingerprint(user.username)}")
        self.io.say("Note it down: it identifies your signatures independently of this vault.")

    def _login(self) -> None:
        name = self.io.ask("Username: ")
        password = self.io.ask_secret("Password: ")
        try:
            user = self.market.login(name, password)
        except AuthError as exc:
            self._save()  # persist the failed-attempt counter
            self.io.say(f"! {exc}")
            return
        self._save()
        self.user = user.username
        fingerprint = self.market.fingerprint(user.username)
        self.io.say(f"Welcome back, {user.username}. Key fingerprint: {fingerprint}")

    # -------------------------------------------------------------------- screens

    def _wallet(self) -> None:
        assert self.user is not None
        while True:
            balance = self.market.state.users[self.user].balance
            choice = self._choose(
                f"Wallet - balance {format_amount(balance)} cr",
                ["Add simulated funds", "Withdraw"],
            )
            if choice == 0:
                return
            if choice not in (1, 2):
                self.io.say("! Invalid option.")
                continue
            try:
                cents = parse_amount(self.io.ask("Amount: "))
                if choice == 1:
                    new = self.market.deposit(self.user, cents)
                else:
                    new = self.market.withdraw(self.user, cents)
            except MarketError as exc:
                self.io.say(f"! {exc}")
                continue
            self._save()
            self.io.say(f"Done. Balance: {format_amount(new)} cr.")

    def _item_rows(self, items) -> list[list[str]]:
        cat = self.market.catalog
        return [
            [
                str(n),
                f"{i.kind} ({i.material})",
                cat.wear_label(i.wear),
                format_amount(self.market.value_of(i)),
            ]
            for n, i in enumerate(items, start=1)
        ]

    def _inventory(self) -> None:
        assert self.user is not None
        while True:
            items = self.market.state.users[self.user].items
            if not items:
                self.io.say("\nYour inventory is empty. Visit the shop to buy something.")
                return
            self.io.say("\nInventory")
            self.io.say(render_table(["#", "Item", "Condition", "Value"], self._item_rows(items)))
            self.io.say("\nEnter an item number to put it up for sale, or 0 to go back.")
            try:
                number = self._number("> ")
                if number == 0:
                    return
                item = self.market.pick(items, number)
                suggested = format_amount(self.market.value_of(item))
                price = parse_amount(self.io.ask(f"Asking price (market value {suggested}): "))
                self.market.list_item(self.user, number, price)
            except MarketError as exc:
                self.io.say(f"! {exc}")
                continue
            self._save()
            self.io.say(f"Listed for {format_amount(price)} cr.")

    def _shop(self) -> None:
        assert self.user is not None
        while True:
            offers = self.market.shop
            if not offers:
                self.io.say("\nThe shop is sold out. Log out and back in to restock it.")
                return
            cat = self.market.catalog
            rows = [
                [
                    str(n),
                    f"{o.entry.kind} ({o.entry.material})",
                    cat.wear_label(o.entry.wear),
                    format_amount(o.price),
                ]
                for n, o in enumerate(offers, start=1)
            ]
            self.io.say("\nShop")
            self.io.say(render_table(["#", "Item", "Condition", "Price"], rows))
            self.io.say("\nEnter a number to buy, or 0 to go back.")
            try:
                number = self._number("> ")
                if number == 0:
                    return
                item = self.market.buy_from_shop(self.user, number)
            except MarketError as exc:
                self.io.say(f"! {exc}")
                continue
            self._save()
            self.io.say(f"Bought {item.kind} ({item.material}).")

    def _player_market(self) -> None:
        assert self.user is not None
        while True:
            choice = self._choose(
                "Player market", ["Browse and buy", "Withdraw one of my listings"]
            )
            if choice == 0:
                return
            if choice == 1:
                self._guard(self._browse_listings)
            elif choice == 2:
                self._guard(self._delist)
            else:
                self.io.say("! Invalid option.")

    def _listing_rows(self, only_mine: bool = False) -> list[list[str]]:
        cat, rows = self.market.catalog, []
        for n, lst in enumerate(self.market.state.listings, start=1):
            if only_mine and lst.seller != self.user:
                continue
            rows.append(
                [
                    str(n),
                    lst.seller,
                    f"{lst.item.kind} ({lst.item.material})",
                    cat.wear_label(lst.item.wear),
                    format_amount(lst.price),
                    format_amount(self.market.value_of(lst.item)),
                ]
            )
        return rows

    def _browse_listings(self) -> None:
        assert self.user is not None
        rows = self._listing_rows()
        if not rows:
            self.io.say("\nNo listings right now.")
            return
        self.io.say("\nListings")
        self.io.say(render_table(["#", "Seller", "Item", "Condition", "Price", "Value"], rows))
        number = self._number("\nNumber to buy (0 to cancel): ")
        if number == 0:
            return
        listing = self.market.buy_listing(self.user, number)
        self._save()
        self.io.say(f"Bought {listing.item.kind} for {format_amount(listing.price)} cr.")

    def _delist(self) -> None:
        assert self.user is not None
        rows = self._listing_rows(only_mine=True)
        if not rows:
            self.io.say("\nYou have nothing listed.")
            return
        self.io.say("\nYour listings")
        self.io.say(render_table(["#", "Seller", "Item", "Condition", "Price", "Value"], rows))
        number = self._number("\nNumber to withdraw (0 to cancel): ")
        if number == 0:
            return
        item = self.market.delist(self.user, number)
        self._save()
        self.io.say(f"{item.kind} returned to your inventory.")

    def _history(self) -> None:
        assert self.user is not None
        entries = self.market.history(self.user)
        if not entries:
            self.io.say("\nNo activity yet.")
            return
        self.io.say("\nRecent activity")
        for e in entries:
            mark = "signed" if e.get("sig") else "system"
            self.io.say(f"  #{e['seq']:<4} {e['type']:<12} {mark:<7} {_describe(e['data'])}")


def _describe(data: dict) -> str:
    parts = []
    for key in ("amount", "price", "fee"):
        if key in data:
            parts.append(f"{key} {format_amount(data[key])}")
    for key in ("buyer", "seller", "model"):
        if key in data:
            parts.append(f"{key} {data[key]}")
    return ", ".join(parts)


# ---------------------------------------------------------------------- entry point


def default_data_dir() -> Path:
    return Path(os.environ.get("VAULTMARKET_HOME", Path.home() / ".vaultmarket"))


def _unlock(store: Store, console: Console) -> State | None:
    env = os.environ.get(PASSPHRASE_ENV)
    if store.exists():
        for _ in range(3):
            passphrase = env or console.ask_secret("Vault passphrase: ")
            try:
                return store.open(passphrase)
            except VaultMarketError as exc:
                console.say(f"! {exc}")
                if env:
                    break
        return None
    console.say(f"No vault found in {store.directory}. Creating a new one.")
    prompt = f"Choose a vault passphrase (min {MIN_PASSPHRASE_LEN}): "
    passphrase = env or console.ask_secret(prompt)
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        console.say(f"! Passphrase must be at least {MIN_PASSPHRASE_LEN} characters.")
        return None
    if not env and passphrase != console.ask_secret("Repeat the passphrase: "):
        console.say("! Passphrases do not match.")
        return None
    state = State()
    store.create(passphrase, state)
    return state


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vaultmarket", description="Encrypted terminal marketplace for virtual items."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="where the vault lives (default: $VAULTMARKET_HOME or ~/.vaultmarket)",
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("audit", help="verify the ledger chain and that balances match it")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console()
    store = Store(args.data_dir or default_data_dir())
    try:
        state = _unlock(store, console)
        if state is None:
            return 1
        market = Market(state)
        if args.command == "audit":
            problems = market.audit()
            if problems:
                console.say(f"Audit FAILED ({len(problems)} problem(s)):")
                for problem in problems:
                    console.say(f"  - {problem}")
                return 2
            count = len(state.ledger)
            signed = sum(1 for e in state.ledger if e.get("sig"))
            console.say(
                f"Audit OK: {count} ledger entries ({signed} signed); "
                "chain, signatures and balances are consistent."
            )
            return 0
        App(market, store, console).run()
        return 0
    except VaultMarketError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
