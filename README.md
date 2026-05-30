```
██████╗  █████╗ ███████╗███████╗██╗    ██╗ ██████╗ ██████╗ ██████╗ 
██╔══██╗██╔══██╗██╔════╝██╔════╝██║    ██║██╔═══██╗██╔══██╗██╔══██╗
██████╔╝███████║███████╗███████╗██║ █╗ ██║██║   ██║██████╔╝██║  ██║
██╔═══╝ ██╔══██║╚════██║╚════██║██║███╗██║██║   ██║██╔══██╗██║  ██║
██║     ██║  ██║███████║███████║╚███╔███╔╝╚██████╔╝██║  ██║██████╔╝
╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝ 

███╗   ███╗ █████╗ ███╗   ██╗ █████╗  ██████╗ ███████╗██████╗ 
████╗ ████║██╔══██╗████╗  ██║██╔══██╗██╔════╝ ██╔════╝██╔══██╗
██╔████╔██║███████║██╔██╗ ██║███████║██║  ███╗█████╗  ██████╔╝
██║╚██╔╝██║██╔══██║██║╚██╗██║██╔══██║██║   ██║██╔══╝  ██╔══██╗
██║ ╚═╝ ██║██║  ██║██║ ╚████║██║  ██║╚██████╔╝███████╗██║  ██║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝

  argon2id · aes-256-gcm · encrypted vault · master password unlock
```
██████╗  █████╗ ███████╗███████╗██╗    ██╗ ██████╗ ██████╗ ██████╗ 
██╔══██╗██╔══██╗██╔════╝██╔════╝██║    ██║██╔═══██╗██╔══██╗██╔══██╗
██████╔╝███████║███████╗███████╗██║ █╗ ██║██║   ██║██████╔╝██║  ██║
██╔═══╝ ██╔══██║╚════██║╚════██║██║███╗██║██║   ██║██╔══██╗██║  ██║
██║     ██║  ██║███████║███████║╚███╔███╔╝╚██████╔╝██║  ██║██████╔╝
╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝ 

███╗   ███╗ █████╗ ███╗   ██╗ █████╗  ██████╗ ███████╗██████╗ 
████╗ ████║██╔══██╗████╗  ██║██╔══██╗██╔════╝ ██╔════╝██╔══██╗
██╔████╔██║███████║██╔██╗ ██║███████║██║  ███╗█████╗  ██████╔╝
██║╚██╔╝██║██╔══██║██║╚██╗██║██╔══██║██║   ██║██╔══╝  ██╔══██╗
██║ ╚═╝ ██║██║  ██║██║ ╚████║██║  ██║╚██████╔╝███████╗██║  ██║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝

  argon2id · aes-256-gcm · encrypted vault · master password unlock
# password-manager

> An encrypted local password vault with master password unlock.
> Argon2id key derivation, AES-256-GCM authenticated encryption,
> atomic durable writes, and a cryptographically secure password generator —
> all in pure Python, no cloud, no telemetry.

---

## What it does

`password-manager` stores your credentials in a single encrypted file at
`~/.password-vault/vault.json`. Your master password never touches disk —
it is used to derive a 32-byte AES key via Argon2id, the key decrypts the
vault in memory, and the key is discarded when the operation ends.

```
$ python pv.py get github

Master password: ████████████

╭─────────────── github ───────────────╮
│  username   alice                    │
│  password   kX9#mP2$vQr!nL5@wZ8&    │
│  notes      work account             │
│  created    2024-11-03 14:22         │
╰──────────────────────────────────────╯
```

---

## Features

- **Argon2id key derivation** — OWASP-recommended parameters (~0.5 s per
  derivation), making brute-force attacks computationally expensive
- **AES-256-GCM encryption** — confidentiality and tamper detection in one
  primitive; any bit-flip in the vault file causes decryption to fail
- **Atomic durable writes** — tmp file → fsync → atomic rename → directory
  fsync; a crash mid-write never corrupts the vault
- **Advisory fcntl locking** — concurrent `pv` invocations are serialised;
  a second process fails fast rather than corrupting the file
- **Master password rotation** — re-encrypts the entire vault under a fresh
  random salt and new key; also upgrades KDF parameters to current defaults
- **KDF parameters stored in the file** — old vaults remain readable when
  defaults change; rotation can harden them transparently
- **Cryptographically secure password generator** — uses `secrets` (CSPRNG,
  backed by `os.urandom`) with a Fisher-Yates shuffle; never `random`
- **Oracle hardening** — wrong password and tampered file produce the same
  error; the tool refuses to distinguish between them
- **Typed exception hierarchy** — `WrongPasswordError`, `VaultFormatError`,
  `EntryNotFoundError`, `EntryExistsError`, `VaultLockedError`
- **Rich colored terminal output** — panels, tables, and prompts via `rich`
- **Pipe-friendly** — `--password-only` flag prints just the password to
  stdout; all UI chrome goes to stderr
- **CI/shell exit codes** — `0` success · `1` vault error · `2` wrong
  password · `130` Ctrl-C

---

## Requirements

- Python 3.10+
- [`argon2-cffi`](https://argon2-cffi.readthedocs.io/)
- [`cryptography`](https://cryptography.io/)
- [`rich`](https://github.com/Textualize/rich)

```bash
pip install argon2-cffi cryptography rich
```

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/password-manager.git
cd password-manager
python3 -m venv .venv && source .venv/bin/activate
pip install argon2-cffi cryptography rich
chmod +x pv.py

# Optional: install system-wide
ln -s "$(pwd)/pv.py" ~/.local/bin/pv
```

---

## Usage

```bash
# Create a new vault (prompts for master password twice)
python pv.py init

# Add an entry with a generated 24-character password
python pv.py add github -u alice -g -l 24

# Add an entry with a manually typed password
python pv.py add aws -u alice@example.com

# Overwrite an existing entry
python pv.py add github -u alice -g --force

# List all stored services
python pv.py list

# Retrieve a full entry (table panel)
python pv.py get github

# Get only the password — pipe to clipboard
python pv.py get github --password-only | xclip -selection clipboard

# Delete an entry (prompts for confirmation)
python pv.py delete twitter

# Rotate the master password (re-encrypts vault with fresh salt)
python pv.py rotate

# Generate a password without storing it
python pv.py generate -l 32 --no-symbols
```

---

## Exit codes

| Code  | Meaning |
|-------|---------|
| `0`   | Success |
| `1`   | Vault error (format, lock, entry not found, etc.) |
| `2`   | Wrong master password or tampered vault file |
| `130` | Interrupted with Ctrl-C |

---

## Security model

| Property | Implementation |
|----------|----------------|
| Key derivation | Argon2id, time_cost=3, memory=64 MiB, parallelism=4 |
| Encryption | AES-256-GCM with a random 96-bit nonce per write |
| Salt | 128-bit random, stored in vault file, unique per vault |
| Password generation | `secrets.choice()` + Fisher-Yates via `secrets.randbelow()` |
| Write safety | Atomic rename on same filesystem; fsync before and after |
| Concurrency | `fcntl.LOCK_EX | LOCK_NB` advisory lock |
| Oracle hardening | Wrong password and tampered file surface identical error |

The vault file is stored at `~/.password-vault/vault.json` with mode
`0600` (owner read/write only). The directory is mode `0700`.

---

## Project structure

```
password-manager/
├── vault/
│   ├── __init__.py
│   ├── exceptions.py   # typed exception hierarchy
│   ├── crypto.py       # Argon2id KDF + AES-GCM encrypt/decrypt
│   ├── store.py        # atomic file I/O + fcntl advisory locking
│   ├── manager.py      # high-level vault operations
│   ├── generator.py    # cryptographically secure password generator
│   └── display.py      # rich panels, tables, prompts
├── pv.py               # CLI entrypoint
└── tests/
    └── test_vault.py
```

---

## Running tests

```bash
python tests/test_vault.py
```

Tests redirect vault storage to a temp directory — your real vault at
`~/.password-vault/` is never touched.

---

## Backup

The vault is a single file. Back it up regularly:

```bash
cp ~/.password-vault/vault.json ~/Backups/vault-$(date +%Y%m%d).json
```

There is no password recovery. Losing the master password means losing
access to all stored credentials.

---

## License

MIT — do whatever you want, attribution appreciated.
