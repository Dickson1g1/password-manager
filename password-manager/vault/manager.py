import json
import time
from .crypto   import derive_key, encrypt, decrypt, KDF_DEFAULTS
from .store    import read_vault, write_vault, acquire_lock, release_lock
from .exceptions import (
    WrongPasswordError, VaultFormatError, EntryNotFoundError, EntryExistsError
)

# ---------------------------------------------------------------------------
# Vault on-disk schema (stored as JSON):
# {
#   "kdf": { "salt": "", "time_cost": 3, "memory_cost": 65536, ... },
#   "blob": { "nonce": "", "ciphertext": "" }
# }
#
# The "blob" is the AES-GCM encryption of a JSON string representing the
# entries dict: { "": { "username": "...", "password": "...",
#                                "notes": "...", "created_at": 1234567890 } }
#
# Storing KDF params (salt, time_cost, etc.) in plaintext alongside the blob
# is standard practice — they are not secret. They allow us to:
#   1. Decrypt old vaults even after we raise the KDF defaults
#   2. Re-encrypt with stronger params on rotation without breaking old data
# ---------------------------------------------------------------------------

import os, base64


def _init_kdf_params() -> tuple[dict, bytes]:
    """
    Generate a fresh random salt and return (kdf_params_dict, raw_salt_bytes).
    Called only when creating a vault or rotating the master password.
    """
    salt = os.urandom(KDF_DEFAULTS["salt_len"])
    params = dict(KDF_DEFAULTS)
    params["salt"] = base64.b64encode(salt).decode()
    return params, salt


def _load_and_decrypt(master_password: str) -> tuple[dict, dict]:
    """
    Read vault file, derive key from master password, decrypt entries.
    Returns (raw_vault_dict, decrypted_entries_dict).
    Raises WrongPasswordError, VaultFormatError.
    """
    raw = read_vault()
    if not raw:
        raise VaultFormatError("Vault does not exist yet — run 'pv init' first")

    try:
        kdf_params = raw["kdf"]
        salt       = base64.b64decode(kdf_params["salt"])
        blob       = raw["blob"]
    except KeyError as e:
        raise VaultFormatError(f"Vault file is missing required field: {e}")

    # derive_key is the slow step (~0.5s) — intentional, makes brute force costly
    key      = derive_key(master_password, salt, kdf_params)
    plaintext = decrypt(blob, key)       # raises WrongPasswordError on tag mismatch

    try:
        entries = json.loads(plaintext.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise VaultFormatError("Decrypted data is not valid JSON — vault may be corrupt")

    return raw, entries


def init_vault(master_password: str) -> None:
    """
    Create a new empty vault encrypted under master_password.
    Raises VaultFormatError if a vault already exists.
    """
    existing = read_vault()
    if existing:
        raise VaultFormatError("Vault already exists — use 'pv rotate' to change master password")

    kdf_params, salt = _init_kdf_params()
    key  = derive_key(master_password, salt, kdf_params)
    blob = encrypt(json.dumps({}).encode("utf-8"), key)

    lock_fd = acquire_lock()
    try:
        write_vault({"kdf": kdf_params, "blob": blob})
    finally:
        release_lock(lock_fd)


def add_entry(master_password: str, service: str,
              username: str, password: str,
              notes: str = "", force: bool = False) -> None:
    """Add a new entry. Raises EntryExistsError if service already exists unless force=True."""
    lock_fd = acquire_lock()
    try:
        raw, entries = _load_and_decrypt(master_password)

        if service in entries and not force:
            raise EntryExistsError(
                f"'{service}' already exists — use --force to overwrite"
            )

        entries[service] = {
            "username":   username,
            "password":   password,
            "notes":      notes,
            "created_at": int(time.time()),  # Unix timestamp for auditability
        }

        # Re-encrypt the whole entries dict under the SAME key (salt unchanged)
        key  = derive_key(master_password,
                          base64.b64decode(raw["kdf"]["salt"]),
                          raw["kdf"])
        blob = encrypt(json.dumps(entries).encode("utf-8"), key)
        write_vault({"kdf": raw["kdf"], "blob": blob})
    finally:
        release_lock(lock_fd)


def get_entry(master_password: str, service: str) -> dict:
    """Return the entry dict for service. Raises EntryNotFoundError if absent."""
    _, entries = _load_and_decrypt(master_password)
    if service not in entries:
        raise EntryNotFoundError(f"No entry found for '{service}'")
    return entries[service]


def list_entries(master_password: str) -> list[str]:
    """Return sorted list of all service names."""
    _, entries = _load_and_decrypt(master_password)
    return sorted(entries.keys())


def delete_entry(master_password: str, service: str) -> None:
    """Delete an entry. Raises EntryNotFoundError if it does not exist."""
    lock_fd = acquire_lock()
    try:
        raw, entries = _load_and_decrypt(master_password)
        if service not in entries:
            raise EntryNotFoundError(f"No entry found for '{service}'")

        del entries[service]
        key  = derive_key(master_password,
                          base64.b64decode(raw["kdf"]["salt"]),
                          raw["kdf"])
        blob = encrypt(json.dumps(entries).encode("utf-8"), key)
        write_vault({"kdf": raw["kdf"], "blob": blob})
    finally:
        release_lock(lock_fd)


def rotate_master_password(old_password: str, new_password: str) -> None:
    """
    Re-derive a fresh salt+key from new_password and re-encrypt the entire vault.
    This also upgrades KDF parameters to current defaults if they have changed.
    Old vaults with weaker params are automatically hardened on rotation.
    """
    lock_fd = acquire_lock()
    try:
        _, entries = _load_and_decrypt(old_password)   # verify old password first

        # Generate a completely fresh salt — never reuse the old one
        kdf_params, salt = _init_kdf_params()
        new_key = derive_key(new_password, salt, kdf_params)
        blob    = encrypt(json.dumps(entries).encode("utf-8"), new_key)
        write_vault({"kdf": kdf_params, "blob": blob})
    finally:
        release_lock(lock_fd)
