# Design notes

This document explains the choices behind vaultmarket, what the vault protects
against, and where it stops. It is written for someone reviewing the code.

## Layers

| Layer | Module | Responsibility |
|-------|--------|----------------|
| Interface | `cli.py` | Menus, input parsing, printing. Holds no business rules. |
| Rules | `market.py` | Accounts, wallet, shop, listings, fees, pricing. No I/O, clock and RNG are injected. |
| Audit | `ledger.py`, `signing.py` | Hash-chained, signed log; rebuilds balances from it. |
| Persistence | `store.py`, `crypto.py` | One encrypted file, atomic writes. |

Domain mistakes raise `MarketError` / `AuthError`; the interface catches them
and prints the message. Anything else is a bug and is allowed to crash loudly.

## Vault file

```
offset  size  field
0       4     magic "VMKT"
4       1     format version (1)
5       4     Argon2id time cost
9       4     Argon2id memory (KiB)
13      4     Argon2id lanes
17      16    salt
33      12    AES-GCM nonce
45      n     ciphertext || 16-byte tag
```

The first 33 bytes are passed to AES-GCM as associated data. Changing the
salt or any KDF parameter therefore fails authentication instead of silently
deriving a different key. The reader also bounds the KDF parameters before running
the KDF, so a modified header cannot request gigabytes of memory.

The plaintext is the JSON-serialised `State`: users (with password hashes),
inventories, listings, model prices and the ledger. Usernames and hashes are
inside the encrypted blob, not next to it.

### Choices

- **Passphrase-derived key, no key file.** A key file stored beside the data
  protects nothing against someone who can read the directory. Deriving the key
  means the vault is only as exposed as the passphrase.
- **Argon2id** for both the vault key and the password hashes. Memory-hard, and
  the OWASP-recommended choice. Parameters (64 MiB, t=3, p=4) are stored in the
  file so they can be raised later without breaking old vaults; `needs_rehash`
  upgrades password hashes at the next successful login.
- **AES-256-GCM** rather than a hand-assembled cipher + MAC. A new random 96-bit
  nonce is used on every save under the same key. With one save per user action
  this is far below the ~2^32 messages at which random-nonce collisions become a concern.
- **One file, atomic replace.** The earlier design wrote four files in
  sequence; a crash between writes could leave wallets and inventories out of sync.
  Here the temp file is fsynced, renamed over the vault, and the directory fsynced.
- **PHC password strings.** Hashes look like
  `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>`, so they stay portable. They
  are produced with the Argon2id implementation in the `cryptography` package, which
  keeps the project to one dependency; a known-answer test (RFC 9106) pins the primitive.

## Threat model

Protects against:

- Someone who obtains a copy of `vault.bin` (stolen laptop, backup, accidental
  commit) but not the passphrase: they see ciphertext only and must brute-force
  an Argon2id-protected passphrase.
- Offline modification of the file: any changed byte, including the header,
  fails authentication.
- Online guessing of user passwords through the interface: Argon2id cost plus
  lockout (30 s after 5 failures, doubling up to 15 min, persisted in the vault).

Does **not** protect against:

- Anyone who knows the passphrase. They can decrypt, edit and re-encrypt the
  state, and rebuild a consistent hash chain. What they cannot do is sign as a user
  without that user's password (see below), so edited or invented user actions fail
  signature checks. They *can* replace a user's key pair and re-sign that user's
  history with it; this is only detectable if the user wrote down their key
  fingerprint (shown at registration and login) and compares it.
- A compromised machine: keys and decrypted state live in process memory, and
  Python offers no reliable way to wipe them.
- Concurrent use. There is no file locking, so two processes writing the same
  vault will overwrite each other.
- Passphrases passed through `VAULTMARKET_PASSPHRASE`: that variable exists for
  scripts and demos, and environment variables are visible to other processes
  of the same user.

## Marketplace rules worth knowing

- **Money is integer cents.** Input goes through `parse_amount`, which accepts
  only digits with at most two decimals, so `nan`, `inf`, exponents and negatives
  never reach the wallet. The rules layer re-validates, so it is safe to call
  directly.
- **Price drift is bounded.** After a player-to-player sale, the model's price
  moves to `(4 * current + clamp(sale, 50 %, 200 % of current)) / 5`. Without the
  clamp, listing an item at an absurd price and buying it with a second account would let
  anyone set the catalogue price.
- **Seller fee.** 5 % of each player sale is removed from the economy and
  recorded in the ledger, which makes the balance replay a non-trivial check.

## Signed ledger

Each user gets an Ed25519 key pair at registration. The private key is stored in the
vault wrapped with AES-256-GCM under a key derived (Argon2id) from the user's own
password; the username and public key are bound as associated data, so a wrapped key
cannot be moved to another account or paired with a different public key. It is
unwrapped at login and kept only in memory until logout.

Every user action (deposit, withdraw, shop purchase, listing, delisting, purchase from
a player) is appended to the ledger signed over `{seq, ts, type, data, actor}`; the
signature is then part of what the hash chain commits to. Grants of the starting
balance are the only unsigned entries and are marked as `system`. A purchase records
the hash of the seller's signed `list` entry, so it is bound to the exact item and
price the seller offered.

Costs: logging in does one more Argon2id derivation (about 0.1 s with the defaults).
There is no password change or key rotation yet, because the wrapping key depends on
the password.

## Audit

`vaultmarket audit` verifies that each ledger entry links to its predecessor and
matches its hash, that every signature is valid for the stated actor and that the actor
is the user the entry acts for, that each player purchase matches the seller's signed
offer, that replaying the log reproduces every stored balance, and that no item exists
twice. Tests mutate each of these (edited entry with a rebuilt chain, re-attributed
entry, forged system entry, replaced public key, altered offer, deleted entry, altered
balance, duplicated item) and expect a failure.

## Differences from the coursework version

The original used a Fernet key kept in `secret.key` next to four encrypted JSON
files, with the user list in plaintext. Fernet itself is a sound construction; the
changes are about the system around it:

| Original | Now |
|----------|-----|
| Key file beside the data | Key derived from a passphrase |
| Four files written one after another | One file, atomic replace |
| Usernames and hashes in a plaintext file | Inside the encrypted vault |
| Float balances; `inf` accepted as an amount; negatives turned positive with `abs()` | Integer cents, strict parsing |
| Any sale price copied into the catalogue price | Bounded, smoothed price update |
| Data path relative to the working directory | Per-user data directory |
| No lockout; unknown users answered faster | Lockout and constant-work login |
| Actions not attributable to a user | Per-user Ed25519 signatures, offers bound to purchases |
| Manual tests only | Automated tests, including tampering and lockout |

## Possible next steps

- Password change and key rotation (re-wrapping the signing key).
- A lock file to make concurrent instances safe.
- Optional Argon2id parameter upgrade for the vault itself (`rekey` command).
