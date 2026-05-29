import os
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

# ---------------------------------------------------------------------------
# KDF parameters (OWASP recommended minimums for Argon2id as of 2024)
# ---------------------------------------------------------------------------
# These are stored IN the vault file alongside every encrypted blob so that
# if we increase the defaults later, old vaults can still be decrypted with
# their original (weaker) params, and rotation can upgrade them.

KDF_DEFAULTS = {
    "time_cost":    3,       # number of iterations (passes over memory)
    "memory_cost":  65536,   # memory in KiB (64 MiB) — main cost parameter
    "parallelism":  4,       # number of parallel threads
    "hash_len":     32,      # output length in bytes (must be 32 for AES-256)
    "salt_len":     16,      # salt length in bytes (128-bit random salt)
}

# AES-GCM nonce length: 96 bits (12 bytes) is the NIST-recommended size.
# Shorter nonces risk nonce reuse at scale; longer ones reduce GCM performance.
NONCE_LEN = 12


def derive_key(password: str, salt: bytes, params: dict) -> bytes:
    """
    Derive a 32-byte AES-256 key from a master password using Argon2id.

    Argon2id is the OWASP-recommended KDF because it combines:
      - Argon2i's resistance to side-channel attacks (data-independent memory access)
      - Argon2d's resistance to GPU/ASIC brute-force (data-dependent memory access)
    The salt is random per-vault (stored in the file), ensuring that two vaults
    with the same master password produce completely different keys.
    """
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=params["time_cost"],
        memory_cost=params["memory_cost"],
        parallelism=params["parallelism"],
        hash_len=params["hash_len"],
        type=Type.ID,          # ID = Argon2id variant
    )


def encrypt(plaintext: bytes, key: bytes) -> dict:
    """
    Encrypt plaintext with AES-256-GCM and return a serialisable dict.

    AES-GCM is an authenticated encryption scheme — it provides:
      - Confidentiality: ciphertext reveals nothing about the plaintext
      - Integrity:       any bit-flip in the ciphertext causes decryption to fail
      - Authenticity:    only someone with the key can produce a valid ciphertext

    We generate a fresh random 96-bit nonce per encryption. Nonce reuse under
    the same key is catastrophic for GCM (leaks the key), so we NEVER reuse them.
    The nonce does NOT need to be secret — it is stored alongside the ciphertext.
    """
    nonce = os.urandom(NONCE_LEN)          # 12 random bytes, never reused
    aesgcm = AESGCM(key)
    # encrypt() returns ciphertext || 16-byte GCM authentication tag (appended)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # base64-encode binary blobs so they round-trip safely through JSON
    return {
        "nonce":      base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def decrypt(blob: dict, key: bytes) -> bytes:
    """
    Decrypt an AES-256-GCM blob produced by encrypt().

    If the key is wrong OR the ciphertext was tampered with, AESGCM.decrypt()
    raises cryptography.exceptions.InvalidTag. We catch that and raise
    WrongPasswordError — we do NOT tell the caller which condition occurred.
    This is the "oracle hardening" property described in the spec.
    """
    from .exceptions import WrongPasswordError
    from cryptography.exceptions import InvalidTag

    try:
        nonce      = base64.b64decode(blob["nonce"])
        ciphertext = base64.b64decode(blob["ciphertext"])
        aesgcm     = AESGCM(key)
        # decrypt() verifies the GCM tag and raises InvalidTag on any mismatch
        return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except (InvalidTag, KeyError, Exception):
        # Deliberately vague: wrong password AND tampered file both land here
        raise WrongPasswordError("Decryption failed — wrong password or corrupted vault")
