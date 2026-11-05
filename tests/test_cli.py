import random

from conftest import FAST_KDF, FAST_PASSWORDS, PASSWORD

from vaultmarket import cli
from vaultmarket.market import Market
from vaultmarket.models import State
from vaultmarket.store import Store


class ScriptedConsole(cli.Console):
    """Feeds canned answers and records everything the app prints."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.out = []

    def _next(self):
        if not self.answers:
            raise AssertionError("the app asked for more input than the script provides")
        return self.answers.pop(0)

    def ask(self, prompt):
        return self._next()

    def ask_secret(self, prompt):
        return self._next()

    def say(self, text=""):
        self.out.append(text)

    @property
    def text(self):
        return "\n".join(self.out)


def run_app(store, state, answers):
    console = ScriptedConsole(answers)
    market = Market(state, rng=random.Random(3), password_policy=FAST_PASSWORDS)
    cli.App(market, store, console).run()
    assert console.answers == [], f"unused answers left over: {console.answers}"
    return console, market


def fresh(tmp_path):
    store = Store(tmp_path / "v", kdf=FAST_KDF)
    state = State()
    store.create("a long passphrase", state)
    return store, state


def test_register_login_wallet_shop_and_persistence(tmp_path):
    store, state = fresh(tmp_path)
    console, market = run_app(
        store,
        state,
        [
            "2",
            "alice",
            PASSWORD,
            PASSWORD,  # create account
            "1",
            "alice",
            PASSWORD,  # log in
            "1",
            "1",
            "50",
            "0",  # wallet -> add 50.00 -> back
            "3",
            "1",
            "0",  # shop -> buy first offer -> back
            "2",
            "0",  # inventory -> back
            "0",  # log out
            "0",  # quit
        ],
    )
    assert "created with 100.00" in console.text
    assert "Balance: 150.00" in console.text
    assert "Bought" in console.text
    assert "Logged out." in console.text

    reopened = Store(store.directory, kdf=FAST_KDF).open("a long passphrase")
    alice = reopened.users["alice"]
    assert len(alice.items) == 1
    assert alice.balance < 15000
    assert Market(reopened, password_policy=FAST_PASSWORDS).audit() == []


def test_bad_input_never_crashes(tmp_path):
    store, state = fresh(tmp_path)
    console, _ = run_app(
        store,
        state,
        [
            "x",
            "9",
            "",  # junk at the guest menu
            "2",
            "al",
            PASSWORD,
            PASSWORD,  # username too short
            "2",
            "alice",
            PASSWORD,
            "different",  # mismatch
            "2",
            "alice",
            PASSWORD,
            PASSWORD,
            "1",
            "alice",
            "wrong-password-1",  # failed login
            "1",
            "alice",
            PASSWORD,
            "1",
            "1",
            "nan",
            "1",
            "-3",
            "1",
            "1e9",
            "2",
            "99999",
            "7",
            "abc",
            "0",
            "3",
            "zzz",
            "99",
            "0",  # shop: not a number, no such offer, back
            "2",  # empty inventory returns by itself
            "4",
            "1",
            "2",
            "0",  # player market: no listings, nothing to delist
            "5",  # history
            "0",
            "0",  # log out, quit
        ],
    )
    text = console.text
    assert "Invalid option" in text
    assert "Username must be" in text
    assert "Passwords do not match" in text
    assert "Invalid username or password" in text
    assert "Insufficient balance" in text
    assert "Traceback" not in text


def test_two_users_trade(tmp_path):
    store, state = fresh(tmp_path)
    # Alice buys an item and lists it; Bob buys it.
    run_app(
        store,
        state,
        [
            "2",
            "alice",
            PASSWORD,
            PASSWORD,
            "2",
            "bob",
            PASSWORD,
            PASSWORD,
            "1",
            "alice",
            PASSWORD,
            "1",
            "1",
            "5000",
            "0",  # wallet: add funds, back
            "3",
            "1",
            "0",  # shop: buy first offer, back
            "2",
            "1",
            "40",  # inventory: list it for 40.00 (returns, now empty)
            "0",
            "0",
        ],
    )
    state = Store(store.directory, kdf=FAST_KDF).open("a long passphrase")
    assert len(state.listings) == 1
    store2 = Store(store.directory, kdf=FAST_KDF)
    state = store2.open("a long passphrase")
    console, _ = run_app(
        store2,
        state,
        [
            "1",
            "bob",
            PASSWORD,
            "4",
            "1",
            "1",
            "0",  # player market: browse, buy #1, back
            "2",
            "0",  # inventory: look, back
            "0",
            "0",
        ],
    )
    assert "Bought" in console.text
    final = Store(store.directory, kdf=FAST_KDF).open("a long passphrase")
    assert final.listings == []
    assert len(final.users["bob"].items) == 1
    assert Market(final, password_policy=FAST_PASSWORDS).audit() == []


def test_failed_login_counter_is_persisted(tmp_path):
    store, state = fresh(tmp_path)
    run_app(store, state, ["2", "alice", PASSWORD, PASSWORD, "1", "alice", "bad-password-1", "0"])
    reloaded = Store(store.directory, kdf=FAST_KDF).open("a long passphrase")
    assert reloaded.users["alice"].failed_logins == 1


def test_render_table_aligns_columns():
    out = cli.render_table(["A", "Long"], [["1", "x"], ["22", "yyyy"]])
    assert out.splitlines()[0] == "A   Long"
    assert out.splitlines()[2] == "1   x   "
