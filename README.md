# vaultmarket

[English](README.md) · [Español](README.es.md)

A terminal marketplace for virtual items (think in-game knife skins) where the
entire state of the world (accounts, wallets, inventories, listings, prices and
the transaction history) lives in a single file encrypted with a key derived from a
passphrase.

It is a learning project about applying cryptography in a small, realistic
application: key derivation, authenticated encryption, password hashing, and a
tamper-evident log. It is not meant to run a real marketplace; see
[docs/DESIGN.md](docs/DESIGN.md) for exactly what it does and does not protect against.

## What it does

- Create accounts and log in. Passwords are hashed with Argon2id; five failed
  logins lock the account for a growing delay.
- Hold a wallet of simulated credits, add funds and withdraw.
- Buy from a shop that offers seven random items from a catalogue of 240 models
  (8 kinds, 6 materials, 5 wear levels).
- Resell items to other players. The marketplace takes a 5 % fee, and the
  reference price of each model drifts toward what it actually sells for, with a
  cap on how far one trade can move it.
- Every user gets an Ed25519 key pair at registration. Deposits, purchases and
  listings are signed, and a player-to-player purchase is bound to the seller's
  signed offer.
- Run `vaultmarket audit` to check the transaction log: hash chain, signatures,
  offers, and that every balance can be reproduced from it.

## Install and run

Requires Python 3.10 or newer.

```bash
git clone https://github.com/diazcolladopaula/vaultmarket.git
cd vaultmarket
pip install .
vaultmarket
```

On first run it asks for a vault passphrase (12+ characters) and creates the
vault in `~/.vaultmarket/`. Use `--data-dir` or `VAULTMARKET_HOME` to put it
somewhere else. Create two accounts to try the player market.

```text
Main menu  [bob | 40.00 cr]
  1. Wallet
  2. Inventory
  3. Shop
  4. Player market
  5. History
  0. Log out
> 4

Listings
#  Seller  Item              Condition     Price  Value
-  ------  ----------------  ------------  -----  ------
1  alice   Bowie (Obsidian)  Heavily worn  60.00  241.07
```

```text
$ vaultmarket audit
Audit OK: 6 ledger entries (4 signed); chain, signatures and balances are consistent.
```

## How the data is protected

- **Key**: derived from your passphrase with Argon2id (64 MiB, 3 passes,
  4 lanes) and a random salt. No key file is stored anywhere.
- **Encryption**: AES-256-GCM. The file header (format version, KDF parameters,
  salt) is authenticated as associated data, and every save uses a fresh random nonce.
- **Writes**: the vault is one file, written to a temporary file and renamed,
  so a crash cannot leave it half-written. Permissions are `600`.
- **Passwords**: Argon2id with a per-user salt, stored as standard PHC strings. Login
  does the same hashing work for unknown usernames, so timing does not reveal which exist.
- **Signatures**: each user's Ed25519 private key is stored in the vault encrypted
  under a key derived from *their own* password, so knowing the vault passphrase is
  not enough to sign as them.
- **Money**: integer cents throughout; amounts like `nan`, `inf` or `1e9` are rejected.

The reasoning, file format and known limitations are in
[docs/DESIGN.md](docs/DESIGN.md).

## Development

```bash
pip install -e ".[dev]"
pytest          # 110 tests
ruff check . && ruff format --check .
```

The tests include a known-answer vector for Argon2id (RFC 9106), tampering with
the vault header and ciphertext, forged and re-attributed ledger entries, lockout timing with a fake clock, and scripted
sessions through the real menus.

```text
src/vaultmarket/
  crypto.py     Argon2id key derivation, AES-GCM, file header
  passwords.py  Argon2id password hashes (PHC format)
  store.py      single-file encrypted persistence, atomic writes
  market.py     all marketplace rules (no I/O)
  ledger.py     hash-chained, signed transaction log and balance replay
  signing.py    per-user Ed25519 keys, wrapped under the user's password
  models.py     persisted state
  catalog.py    item catalogue (data/catalog.json)
  money.py      amount parsing and formatting
  cli.py        terminal interface and entry point
tests/
```

## Background

This started as a two-person university assignment for an applied
cryptography course: a command-line item marketplace with encrypted JSON files.
This repository is a redesign and rewrite of that idea: a different storage
and key-management scheme, a new codebase and tests, and fixes for the problems I
found in the original. DESIGN.md lists what changed and why.

## License

MIT, see [LICENSE](LICENSE).
