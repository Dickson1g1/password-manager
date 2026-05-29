import sys, os, tempfile, json, base64
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import vault.store as store_mod
from vault.crypto     import derive_key, encrypt, decrypt, KDF_DEFAULTS
from vault.exceptions import WrongPasswordError, EntryNotFoundError, EntryExistsError
from vault.generator  import generate


# ---------------------------------------------------------------------------
# Redirect vault storage to a temp directory for all tests
# ---------------------------------------------------------------------------
_tmpdir = tempfile.mkdtemp()
store_mod.VAULT_DIR  = type(store_mod.VAULT_DIR)(_tmpdir)
store_mod.VAULT_FILE = store_mod.VAULT_DIR / "vault.json"
store_mod.LOCK_FILE  = store_mod.VAULT_DIR / "vault.lock"

from vault.manager import (init_vault, add_entry, get_entry,
                            list_entries, delete_entry, rotate_master_password)

MASTER = "correct-horse-battery-staple"


def test_encrypt_decrypt_roundtrip():
    """Basic AES-GCM round-trip: decrypt(encrypt(x)) == x."""
    key   = os.urandom(32)
    plain = b"super secret data"
    blob  = encrypt(plain, key)
    assert decrypt(blob, key) == plain


def test_wrong_key_raises():
    """Wrong key must raise WrongPasswordError, not return garbage."""
    key1  = os.urandom(32)
    key2  = os.urandom(32)
    blob  = encrypt(b"hello", key1)
    try:
        decrypt(blob, key2)
        assert False, "Should have raised"
    except WrongPasswordError:
        pass


def test_tampered_ciphertext_raises():
    """Flipping a bit in the ciphertext must fail authentication."""
    key  = os.urandom(32)
    blob = encrypt(b"hello", key)
    ct   = bytearray(base64.b64decode(blob["ciphertext"]))
    ct[0] ^= 0xFF                             # flip first byte
    blob["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    try:
        decrypt(blob, key)
        assert False, "Should have raised"
    except WrongPasswordError:
        pass


def test_init_and_add_get():
    init_vault(MASTER)
    add_entry(MASTER, "github", "alice", "hunter2", notes="work account")
    entry = get_entry(MASTER, "github")
    assert entry["username"] == "alice"
    assert entry["password"] == "hunter2"
    assert entry["notes"]    == "work account"


def test_list_entries():
    services = list_entries(MASTER)
    assert "github" in services


def test_entry_not_found():
    try:
        get_entry(MASTER, "nonexistent_xyz")
        assert False
    except EntryNotFoundError:
        pass


def test_entry_exists_no_force():
    try:
        add_entry(MASTER, "github", "alice", "new_pw")
        assert False
    except EntryExistsError:
        pass


def test_force_overwrite():
    add_entry(MASTER, "github", "alice", "updated_pw", force=True)
    assert get_entry(MASTER, "github")["password"] == "updated_pw"


def test_delete_entry():
    add_entry(MASTER, "twitter", "alice", "tw_pass")
    delete_entry(MASTER, "twitter")
    try:
        get_entry(MASTER, "twitter")
        assert False
    except EntryNotFoundError:
        pass


def test_rotate_password():
    NEW = "new-master-password-456"
    rotate_master_password(MASTER, NEW)
    # Old password must now fail
    try:
        list_entries(MASTER)
        assert False
    except WrongPasswordError:
        pass
    # New password must work
    services = list_entries(NEW)
    assert "github" in services


def test_generator_length():
    for length in [8, 16, 32, 64]:
        pw = generate(length=length)
        assert len(pw) == length


def test_generator_uniqueness():
    """Two generated passwords should (almost certainly) differ."""
    passwords = {generate() for _ in range(20)}
    assert len(passwords) == 20   # all unique


if __name__ == "__main__":
    tests = [(k, v) for k, v in globals().items() if k.startswith("test_")]
    passed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ✔ {name}")
            passed += 1
        except Exception as e:
            print(f"  ✘ {name}: {e}")
    print(f"\n{passed}/{len(tests)} passed")
