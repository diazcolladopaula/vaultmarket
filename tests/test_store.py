import os
import stat

import pytest
from conftest import FAST_KDF

from vaultmarket.errors import StoreError
from vaultmarket.models import Item, State, User
from vaultmarket.store import Store


def sample_state():
    state = State()
    state.users["alice"] = User("alice", "hash", 1234, [Item("abc", "Kukri", "Gold", 2)])
    state.prices["Kukri/Gold/2"] = 4242
    return state


def test_create_open_roundtrip(store):
    store.create("a long passphrase", sample_state())
    reopened = Store(store.directory, kdf=FAST_KDF).open("a long passphrase")
    assert reopened.users["alice"].balance == 1234
    assert reopened.users["alice"].items[0].kind == "Kukri"
    assert reopened.prices == {"Kukri/Gold/2": 4242}


def test_nothing_readable_on_disk(store):
    store.create("a long passphrase", sample_state())
    raw = store.path.read_bytes()
    for needle in (b"alice", b"Kukri", b"1234", b"hash"):
        assert needle not in raw


def test_wrong_passphrase(store):
    store.create("a long passphrase", sample_state())
    with pytest.raises(StoreError, match="Wrong passphrase"):
        Store(store.directory, kdf=FAST_KDF).open("not the passphrase")


def test_file_tampering_detected(store):
    store.create("a long passphrase", sample_state())
    raw = bytearray(store.path.read_bytes())
    raw[-5] ^= 0xFF
    store.path.write_bytes(bytes(raw))
    with pytest.raises(StoreError):
        Store(store.directory, kdf=FAST_KDF).open("a long passphrase")


def test_save_changes_ciphertext_but_not_salt(store):
    state = sample_state()
    store.create("a long passphrase", state)
    first = store.path.read_bytes()
    store.save(state)
    second = store.path.read_bytes()
    assert first[:33] == second[:33]  # header (incl. salt) reused
    assert first != second  # fresh nonce


def test_cannot_overwrite_existing_vault(store):
    store.create("a long passphrase", State())
    with pytest.raises(StoreError, match="already exists"):
        Store(store.directory, kdf=FAST_KDF).create("another passphrase", State())


def test_save_requires_unlock(tmp_path):
    with pytest.raises(StoreError, match="locked"):
        Store(tmp_path, kdf=FAST_KDF).save(State())


def test_missing_vault(tmp_path):
    with pytest.raises(StoreError, match="No vault"):
        Store(tmp_path, kdf=FAST_KDF).open("whatever")


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_permissions_are_private(store):
    store.create("a long passphrase", State())
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.directory.stat().st_mode) == 0o700


def test_no_temp_file_left_behind(store):
    store.create("a long passphrase", State())
    store.save(State())
    assert [p.name for p in store.directory.iterdir()] == ["vault.bin"]
