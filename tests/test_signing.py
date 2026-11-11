import copy

import pytest
from conftest import FAST_KDF, PASSWORD
from test_market import cheapest_offer

from vaultmarket import ledger, signing
from vaultmarket.errors import AuthError
from vaultmarket.market import STARTING_BALANCE

# ---------------------------------------------------------------- key wrapping


def test_wrap_unwrap_roundtrip_and_signature():
    public, wrapped = signing.generate("pw-pw-pw-pw", FAST_KDF, "alice")
    key = signing.unwrap(wrapped, "pw-pw-pw-pw", "alice", public)
    assert signing.verify(public, b"message", signing.sign(key, b"message"))
    assert not signing.verify(public, b"other message", signing.sign(key, b"message"))


def test_wrong_password_cannot_unwrap():
    public, wrapped = signing.generate("pw-pw-pw-pw", FAST_KDF, "alice")
    with pytest.raises(AuthError):
        signing.unwrap(wrapped, "wrong-password", "alice", public)


def test_wrapped_key_is_bound_to_username_and_public_key():
    public, wrapped = signing.generate("pw-pw-pw-pw", FAST_KDF, "alice")
    other_public, _ = signing.generate("pw-pw-pw-pw", FAST_KDF, "bob")
    with pytest.raises(AuthError):
        signing.unwrap(wrapped, "pw-pw-pw-pw", "mallory", public)  # moved to another account
    with pytest.raises(AuthError):
        signing.unwrap(wrapped, "pw-pw-pw-pw", "alice", other_public)  # public key swapped


def test_tampered_or_garbage_wrapped_key_is_rejected():
    import base64

    public, wrapped = signing.generate("pw-pw-pw-pw", FAST_KDF, "alice")
    blob = bytearray(base64.b64decode(wrapped))
    blob[-1] ^= 1
    with pytest.raises(AuthError):
        signing.unwrap(base64.b64encode(bytes(blob)).decode(), "pw-pw-pw-pw", "alice", public)
    for junk in ("", "not base64!!", "AAAA"):
        with pytest.raises(AuthError):
            signing.unwrap(junk, "pw-pw-pw-pw", "alice", public)


def test_private_key_is_not_stored_in_clear(market):
    import base64

    user = market.register("alice", PASSWORD)
    market.login("alice", PASSWORD)
    raw = market._signers["alice"].private_bytes_raw()
    assert raw not in base64.b64decode(user.wrapped_key)
    assert raw not in str(market.state.to_dict()).encode()


def test_fingerprint_is_stable_and_short():
    public, _ = signing.generate("pw-pw-pw-pw", FAST_KDF, "alice")
    assert signing.fingerprint(public) == signing.fingerprint(public)
    assert len(signing.fingerprint(public)) == 19  # 4 groups of 4 hex digits + 3 dashes


def test_verify_rejects_malformed_inputs():
    public, _ = signing.generate("pw-pw-pw-pw", FAST_KDF, "alice")
    assert not signing.verify(public, b"m", "")
    assert not signing.verify(public, b"m", "!!!")
    assert not signing.verify("", b"m", "AAAA")


# ------------------------------------------------------------ login requirement


def test_actions_require_an_unlocked_key(two_users):
    two_users.logout("alice")
    with pytest.raises(AuthError, match="logged in"):
        two_users.deposit("alice", 100)
    two_users.login("alice", PASSWORD)
    two_users.deposit("alice", 100)


def test_nothing_changes_when_signing_is_refused(two_users):
    two_users.logout("alice")
    before = copy.deepcopy(two_users.state.to_dict())
    for action in (
        lambda: two_users.deposit("alice", 100),
        lambda: two_users.withdraw("alice", 100),
        lambda: two_users.buy_from_shop("alice", 1),
        lambda: two_users.list_item("alice", 1, 100),
        lambda: two_users.delist("alice", 1),
        lambda: two_users.buy_listing("alice", 1),
    ):
        with pytest.raises(AuthError):
            action()
    assert two_users.state.to_dict() == before


# ----------------------------------------------------------- signed ledger / audit


@pytest.fixture
def traded(two_users):
    m = two_users
    m.deposit("alice", 1_000_000)
    m.buy_from_shop("alice", cheapest_offer(m))
    m.list_item("alice", 1, 9000)
    m.buy_listing("bob", 1)
    assert m.audit() == []
    return m


def rehash_from(market, start):
    """Rebuild the hash chain after a tamper, as an attacker who knows the format would."""
    chain = market.state.ledger
    prev = chain[start - 1]["hash"] if start else ledger.GENESIS
    for e in chain[start:]:
        e["prev"] = prev
        content = {**ledger._body(e), "sig": e["sig"]}
        e["hash"] = ledger._digest(prev, content)
        prev = e["hash"]


def entry_of(market, kind):
    return next(e for e in market.state.ledger if e["type"] == kind)


def test_user_actions_are_signed_and_grants_are_system(traded):
    by_type = {e["type"]: e for e in traded.state.ledger}
    assert by_type["grant"]["actor"] == "system" and by_type["grant"]["sig"] == ""
    for kind in ("deposit", "buy_shop", "list", "buy_listing"):
        assert by_type[kind]["sig"]
    assert by_type["buy_listing"]["actor"] == "bob"
    assert by_type["list"]["actor"] == "alice"


def test_edited_entry_with_rebuilt_chain_fails_signature(traded):
    entry = entry_of(traded, "deposit")
    entry["data"]["amount"] = 999_999_999
    rehash_from(traded, entry["seq"])
    assert not any("hash" in p for p in traded.audit())  # chain looks fine...
    assert any("signature by 'alice' is invalid" in p for p in traded.audit())  # ...signature not


def test_entry_cannot_be_reattributed_to_another_user(traded):
    entry = entry_of(traded, "deposit")
    entry["actor"] = "bob"
    entry["data"]["user"] = "bob"
    rehash_from(traded, entry["seq"])
    assert any("invalid" in p for p in traded.audit())


def test_user_cannot_sign_for_someone_else(two_users):
    m = two_users
    m.deposit("alice", 500)
    entry = entry_of(m, "deposit")
    entry["data"]["user"] = "bob"  # alice's signature, bob's account
    rehash_from(m, entry["seq"])
    assert any("not the user it acts for" in p for p in m.audit())


def test_forged_system_entry_is_flagged(two_users):
    m = two_users
    entry = ledger.append(m.state.ledger, 1.0, "deposit", {"user": "alice", "amount": 10**6})
    m.state.users["alice"].balance += 10**6
    assert entry["actor"] == "system"
    assert any("claims to be a system action" in p for p in m.audit())


def test_replaced_public_key_is_detected(traded):
    other_public, _ = signing.generate("pw-pw-pw-pw", FAST_KDF, "alice")
    traded.state.users["alice"].public_key = other_public
    assert any("signature by 'alice' is invalid" in p for p in traded.audit())


def test_purchase_must_match_the_sellers_signed_offer(traded):
    buy = entry_of(traded, "buy_listing")
    buy["data"]["price"] = 1  # buyer's signature no longer matches either
    rehash_from(traded, buy["seq"])
    problems = traded.audit()
    assert any("does not match the seller's signed offer" in p for p in problems)


def test_purchase_referring_to_nonexistent_offer_is_flagged(traded):
    buy = entry_of(traded, "buy_listing")
    buy["data"]["offer"] = "0" * 64
    rehash_from(traded, buy["seq"])
    assert any("missing listing" in p for p in traded.audit())


def test_listing_remembers_its_signed_offer(two_users):
    m = two_users
    m.deposit("alice", 1_000_000)
    m.buy_from_shop("alice", cheapest_offer(m))
    listing = m.list_item("alice", 1, 5000)
    assert listing.offer_hash == entry_of(m, "list")["hash"]


def test_signatures_survive_persistence(two_users, store):
    m = two_users
    m.deposit("alice", 1_000)
    store.create("a long passphrase", m.state)
    reopened = type(store)(store.directory, kdf=FAST_KDF).open("a long passphrase")
    from vaultmarket.market import Market

    assert Market(reopened).audit() == []
    assert reopened.users["alice"].balance == STARTING_BALANCE + 1_000
