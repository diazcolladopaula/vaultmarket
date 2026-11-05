import random

import pytest

from vaultmarket import crypto, passwords
from vaultmarket.market import Market
from vaultmarket.models import State
from vaultmarket.store import Store

# Cheap parameters keep the suite fast; production defaults are exercised in test_crypto.
FAST_KDF = crypto.KdfParams(time_cost=1, memory_kib=64, lanes=1)
FAST_PASSWORDS = passwords.PasswordPolicy(memory_kib=64, time_cost=1, lanes=1)
PASSWORD = "correct horse battery"


class FakeClock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def market(clock):
    return Market(State(), clock=clock, rng=random.Random(7), password_policy=FAST_PASSWORDS)


@pytest.fixture
def two_users(market):
    for name in ("alice", "bob"):
        market.register(name, PASSWORD)
        market.login(name, PASSWORD)
    return market


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "vault", kdf=FAST_KDF)
