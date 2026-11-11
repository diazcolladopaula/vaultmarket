import pytest
from conftest import PASSWORD

from vaultmarket.errors import AuthError, MarketError
from vaultmarket.market import (
    MAX_FAILED_LOGINS,
    SHOP_SIZE,
    STARTING_BALANCE,
)
from vaultmarket.money import format_amount, parse_amount

# --------------------------------------------------------------------- money


@pytest.mark.parametrize(
    ("text", "cents"),
    [("12", 1200), ("12.5", 1250), ("12,50", 1250), ("0.01", 1), (" 7.05 ", 705)],
)
def test_parse_amount_valid(text, cents):
    assert parse_amount(text) == cents


@pytest.mark.parametrize(
    "text", ["", "abc", "-5", "0", "0.00", "1.234", "nan", "inf", "1e9", "1_000", "99999999", "--1"]
)
def test_parse_amount_rejects_garbage(text):
    with pytest.raises(MarketError):
        parse_amount(text)


def test_format_amount():
    assert format_amount(0) == "0.00"
    assert format_amount(123456) == "1,234.56"
    assert format_amount(5) == "0.05"


# ------------------------------------------------------------------ accounts


def test_register_grants_starting_balance_and_normalises_name(market):
    user = market.register("  Alice_01 ", PASSWORD)
    assert user.username == "alice_01"
    assert user.balance == STARTING_BALANCE
    assert market.state.ledger[0]["type"] == "grant"


@pytest.mark.parametrize("name", ["", "ab", "a" * 25, "bad name", "semi;colon", "ünï"])
def test_register_rejects_bad_usernames(market, name):
    with pytest.raises(MarketError, match="Username"):
        market.register(name, PASSWORD)


def test_register_rejects_weak_or_reused(market):
    with pytest.raises(MarketError, match="at least"):
        market.register("alice", "short")
    with pytest.raises(MarketError, match="same as the username"):
        market.register("longusername", "LongUsername")
    market.register("alice", PASSWORD)
    with pytest.raises(MarketError, match="taken"):
        market.register("ALICE", PASSWORD)


def test_password_is_stored_hashed(market):
    user = market.register("alice", PASSWORD)
    assert PASSWORD not in user.password_hash
    assert user.password_hash.startswith("$argon2id$")


def test_login_success_and_failure(two_users):
    assert two_users.login("Alice", PASSWORD).username == "alice"
    with pytest.raises(AuthError, match="Invalid username or password"):
        two_users.login("alice", "wrong password")
    with pytest.raises(AuthError, match="Invalid username or password"):
        two_users.login("nobody", PASSWORD)


def test_lockout_after_repeated_failures_then_expires(two_users, clock):
    for _ in range(MAX_FAILED_LOGINS):
        with pytest.raises(AuthError, match="Invalid"):
            two_users.login("alice", "nope nope nope")
    with pytest.raises(AuthError, match="Too many failed attempts"):
        two_users.login("alice", PASSWORD)  # even the right password is refused
    two_users.login("bob", PASSWORD)  # other accounts are unaffected
    clock.advance(31)
    assert two_users.login("alice", PASSWORD).failed_logins == 0


def test_lockout_grows_with_each_further_failure(two_users, clock):
    for _ in range(MAX_FAILED_LOGINS):
        with pytest.raises(AuthError):
            two_users.login("alice", "nope nope nope")
    clock.advance(31)
    with pytest.raises(AuthError, match="Invalid"):
        two_users.login("alice", "nope nope nope")
    clock.advance(31)  # the second lock lasts 60 s, so 31 s is not enough
    with pytest.raises(AuthError, match="Too many"):
        two_users.login("alice", PASSWORD)


def test_successful_login_resets_counter(two_users):
    for _ in range(MAX_FAILED_LOGINS - 1):
        with pytest.raises(AuthError):
            two_users.login("alice", "nope nope nope")
    two_users.login("alice", PASSWORD)
    assert two_users.state.users["alice"].failed_logins == 0


# -------------------------------------------------------------------- wallet


def test_deposit_and_withdraw(two_users):
    assert two_users.deposit("alice", 2550) == STARTING_BALANCE + 2550
    assert two_users.withdraw("alice", 550) == STARTING_BALANCE + 2000


@pytest.mark.parametrize("bad", [0, -1, 10**12, 1.5, float("nan"), float("inf"), True, "10"])
def test_wallet_rejects_invalid_amounts(two_users, bad):
    with pytest.raises(MarketError):
        two_users.deposit("alice", bad)
    with pytest.raises(MarketError):
        two_users.withdraw("alice", bad)
    assert two_users.state.users["alice"].balance == STARTING_BALANCE


def test_cannot_overdraw(two_users):
    with pytest.raises(MarketError, match="Insufficient"):
        two_users.withdraw("alice", STARTING_BALANCE + 1)


# ---------------------------------------------------------------------- shop


def cheapest_offer(market):
    return min(range(1, len(market.shop) + 1), key=lambda i: market.shop[i - 1].price)


def test_shop_has_distinct_offers(market):
    assert len(market.shop) == SHOP_SIZE
    assert len({o.entry.key for o in market.shop}) == SHOP_SIZE


def test_buy_from_shop(two_users):
    market = two_users
    market.deposit("alice", 1_000_000)
    index = cheapest_offer(market)
    offer = market.shop[index - 1]
    item = market.buy_from_shop("alice", index)
    alice = market.state.users["alice"]
    assert alice.items == [item]
    assert alice.balance == STARTING_BALANCE + 1_000_000 - offer.price
    assert offer not in market.shop


def test_buy_from_shop_checks_funds_and_index(two_users):
    market = two_users
    market.withdraw("alice", STARTING_BALANCE)
    with pytest.raises(MarketError, match="Insufficient"):
        market.buy_from_shop("alice", 1)
    with pytest.raises(MarketError, match="does not exist"):
        market.buy_from_shop("alice", 0)
    with pytest.raises(MarketError, match="does not exist"):
        market.buy_from_shop("alice", SHOP_SIZE + 1)
    assert market.state.users["alice"].items == []


# ------------------------------------------------------------- player market


@pytest.fixture
def seller_with_item(two_users):
    market = two_users
    market.deposit("alice", 1_000_000)
    market.buy_from_shop("alice", cheapest_offer(market))
    return market


def test_list_and_delist_roundtrip(seller_with_item):
    market = seller_with_item
    listing = market.list_item("alice", 1, 5000)
    assert market.state.users["alice"].items == []
    assert market.state.listings == [listing]
    market.delist("alice", 1)
    assert market.state.listings == []
    assert len(market.state.users["alice"].items) == 1


def test_only_seller_can_delist(seller_with_item):
    seller_with_item.list_item("alice", 1, 5000)
    with pytest.raises(MarketError, match="own listings"):
        seller_with_item.delist("bob", 1)


def test_buy_listing_moves_money_item_and_fee(seller_with_item):
    market = seller_with_item
    market.list_item("alice", 1, 10_000)
    alice_before = market.state.users["alice"].balance
    bob_before = market.state.users["bob"].balance
    market.buy_listing("bob", 1)
    # Literal numbers on purpose: a test that recomputes the fee from the production
    # constant cannot notice when that constant is changed.
    assert market.state.users["bob"].balance == bob_before - 10_000
    assert market.state.users["alice"].balance == alice_before + 9_500  # 5 % fee = 500
    assert len(market.state.users["bob"].items) == 1
    assert market.state.listings == []


def test_fee_is_rounded_down_to_whole_cents(seller_with_item):
    market = seller_with_item
    market.list_item("alice", 1, 99)  # 5 % of 99 cents is 4.95, charged as 4
    alice_before = market.state.users["alice"].balance
    market.buy_listing("bob", 1)
    assert market.state.users["alice"].balance == alice_before + 95
    assert market.state.ledger[-1]["data"]["fee"] == 4


def test_documented_rules_are_pinned():
    """The values the README and design notes promise; changing one must be deliberate."""
    from vaultmarket import market as m

    assert m.FEE_PERCENT == 5
    assert m.STARTING_BALANCE == 10_000
    assert m.SHOP_SIZE == 7
    assert m.MAX_TOP_UP == 1_000_000
    assert m.PRICE_BAND == (50, 200)
    assert m.PRICE_SMOOTHING == 5
    assert m.MIN_PASSWORD_LEN == 10
    assert (m.MAX_FAILED_LOGINS, m.BASE_LOCKOUT_SECONDS, m.MAX_LOCKOUT_SECONDS) == (5, 30, 900)


def test_cannot_buy_own_listing_or_without_funds(seller_with_item):
    market = seller_with_item
    market.list_item("alice", 1, 5000)
    with pytest.raises(MarketError, match="own listing"):
        market.buy_listing("alice", 1)
    market.withdraw("bob", STARTING_BALANCE)
    with pytest.raises(MarketError, match="Insufficient"):
        market.buy_listing("bob", 1)
    assert len(market.state.listings) == 1


@pytest.mark.parametrize("bad", [0, -5, 10**12, 2.5, float("nan")])
def test_listing_price_validated_and_item_kept(seller_with_item, bad):
    with pytest.raises(MarketError):
        seller_with_item.list_item("alice", 1, bad)
    assert len(seller_with_item.state.users["alice"].items) == 1
    assert seller_with_item.state.listings == []


def test_price_manipulation_is_bounded(seller_with_item):
    """Selling an item to yourself at an absurd price must not blow up the catalogue price."""
    market = seller_with_item
    item = market.state.users["alice"].items[0]
    entry = market.catalog.get(item.kind, item.material, item.wear)
    before = market.price_of(entry)
    market.list_item("alice", 1, 99_000_000)
    market.state.users["bob"].balance = 99_000_000
    market.buy_listing("bob", 1)
    after = market.price_of(entry)
    assert after <= before * 120 // 100 + 1  # at most +20 % per trade
    assert after > before


def test_price_moves_toward_sale_price_downwards_too(seller_with_item):
    market = seller_with_item
    item = market.state.users["alice"].items[0]
    entry = market.catalog.get(item.kind, item.material, item.wear)
    before = market.price_of(entry)
    market.list_item("alice", 1, 1)
    market.buy_listing("bob", 1)
    assert before * 89 // 100 <= market.price_of(entry) < before


# -------------------------------------------------------------- history/audit


def test_history_only_shows_own_events(two_users):
    two_users.deposit("alice", 500)
    types = [e["type"] for e in two_users.history("alice")]
    assert types == ["grant", "deposit"]
    assert [e["type"] for e in two_users.history("bob")] == ["grant"]


def test_audit_passes_after_normal_activity(seller_with_item):
    market = seller_with_item
    market.list_item("alice", 1, 7777)
    market.buy_listing("bob", 1)
    market.withdraw("bob", 100)
    assert market.audit() == []


def test_audit_detects_balance_tampering(seller_with_item):
    seller_with_item.state.users["alice"].balance += 1
    problems = seller_with_item.audit()
    assert any("alice" in p and "does not match" in p for p in problems)


def test_audit_detects_edited_ledger_entry(seller_with_item):
    seller_with_item.state.ledger[1]["data"]["amount"] = 1
    assert any("hash" in p for p in seller_with_item.audit())


def test_audit_detects_deleted_ledger_entry(seller_with_item):
    del seller_with_item.state.ledger[1]
    assert seller_with_item.audit() != []


def test_audit_detects_duplicated_item(seller_with_item):
    market = seller_with_item
    item = market.state.users["alice"].items[0]
    market.state.users["bob"].items.append(item)
    assert any("more than once" in p for p in market.audit())
