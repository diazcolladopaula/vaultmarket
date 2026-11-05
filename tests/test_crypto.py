import pytest
from conftest import FAST_KDF

from vaultmarket import crypto, passwords
from vaultmarket.errors import StoreError


def make_blob(passphrase="pass", plaintext=b"secret data"):
    header = crypto.new_header(FAST_KDF)
    _, params, salt = crypto.parse_header(header + bytes(40))
    key = crypto.derive_key(passphrase, salt, params)
    return key, crypto.encrypt(key, header, plaintext)


def test_roundtrip():
    key, blob = make_blob()
    assert crypto.decrypt(key, blob) == b"secret data"


def test_default_parameters_roundtrip():
    header = crypto.new_header(crypto.KdfParams())
    _, params, salt = crypto.parse_header(header + bytes(40))
    assert (params.time_cost, params.memory_kib, params.lanes) == (3, 65536, 4)
    key = crypto.derive_key("pw", salt, params)
    assert crypto.decrypt(key, crypto.encrypt(key, header, b"x")) == b"x"


def test_wrong_key_rejected():
    _, blob = make_blob("right")
    header, params, salt = crypto.parse_header(blob)
    with pytest.raises(StoreError):
        crypto.decrypt(crypto.derive_key("wrong", salt, params), blob)


def test_nonce_is_fresh_every_time():
    key, first = make_blob()
    header, _, _ = crypto.parse_header(first)
    second = crypto.encrypt(key, header, b"secret data")
    n = len(header)
    assert first[n : n + 12] != second[n : n + 12]
    assert first != second


@pytest.mark.parametrize("offset_from_end", [1, 20, 40])
def test_ciphertext_tampering_detected(offset_from_end):
    key, blob = make_blob(plaintext=b"a" * 64)
    tampered = bytearray(blob)
    tampered[-offset_from_end] ^= 0x01
    with pytest.raises(StoreError):
        crypto.decrypt(key, bytes(tampered))


def test_header_is_authenticated():
    key, blob = make_blob()
    tampered = bytearray(blob)
    tampered[8] ^= 0x01  # inside the time_cost field
    with pytest.raises(StoreError):
        crypto.decrypt(key, bytes(tampered))


def test_bad_magic_and_truncation():
    key, blob = make_blob()
    with pytest.raises(StoreError, match="Not a vaultmarket"):
        crypto.parse_header(b"XXXX" + blob[4:])
    with pytest.raises(StoreError, match="truncated"):
        crypto.parse_header(blob[:10])


def test_absurd_kdf_parameters_are_rejected_before_deriving():
    header = bytearray(crypto.new_header(FAST_KDF))
    header[9:13] = (2**31).to_bytes(4, "big")  # memory_kib
    with pytest.raises(StoreError, match="memory"):
        crypto.parse_header(bytes(header) + bytes(40))


def test_password_hash_roundtrip_and_format():
    from conftest import FAST_PASSWORDS

    encoded = passwords.hash_password("hunter2hunter2", FAST_PASSWORDS)
    assert encoded.startswith("$argon2id$v=19$m=64,t=1,p=1$")
    assert passwords.verify_password(encoded, "hunter2hunter2")
    assert not passwords.verify_password(encoded, "hunter2hunter3")
    assert encoded != passwords.hash_password("hunter2hunter2", FAST_PASSWORDS)  # random salt


def test_malformed_hash_fails_closed():
    assert not passwords.verify_password("not-a-hash", "x")
    assert not passwords.verify_password("$argon2id$v=19$m=64,t=1,p=1$!!$!!", "x")


def test_needs_rehash_when_policy_changes():
    from conftest import FAST_PASSWORDS

    encoded = passwords.hash_password("pw-pw-pw-pw", FAST_PASSWORDS)
    assert not passwords.needs_rehash(encoded, FAST_PASSWORDS)
    assert passwords.needs_rehash(encoded, passwords.PasswordPolicy())


def test_argon2id_matches_rfc9106_test_vector():
    """Known-answer test (RFC 9106, section 5.3) for the primitive both KDF uses rely on."""
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

    tag = Argon2id(
        salt=b"\x02" * 16,
        length=32,
        iterations=3,
        lanes=4,
        memory_cost=32,
        secret=b"\x03" * 8,
        ad=b"\x04" * 12,
    ).derive(b"\x01" * 32)
    assert tag.hex() == "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"


def test_phc_string_is_parsed_into_its_parameters():
    encoded = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb21lc2FsdA$" + "A" * 43
    policy, salt, digest = passwords._parse(encoded)
    assert policy == passwords.PasswordPolicy(65536, 3, 4)
    assert salt == b"somesaltsomesalt"
    assert len(digest) == 32
