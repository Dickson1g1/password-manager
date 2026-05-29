import os
import json
import fcntl
import tempfile
from pathlib import Path
from .exceptions import VaultLockedError

# Vault lives in a hidden directory in the user's home folder.
# Mode 0700 on the directory, 0600 on the file — no group/world read.
VAULT_DIR  = Path.home() / ".password-vault"
VAULT_FILE = VAULT_DIR / "vault.json"
LOCK_FILE  = VAULT_DIR / "vault.lock"


def _ensure_vault_dir() -> None:
    """
    Create ~/.password-vault with mode 0700 if it does not exist.
    The directory must not be world-readable because it contains
    the encrypted vault — even though the file itself is 0600,
    defence in depth means we restrict the directory too.
    """
    VAULT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)


def acquire_lock() -> int:
    """
    Open and exclusively lock LOCK_FILE using fcntl (POSIX advisory lock).
    Returns the open file descriptor — caller must pass it to release_lock().

    LOCK_EX | LOCK_NB means: try to get exclusive lock, fail immediately
    (don't block) if another process holds it.
    """
    _ensure_vault_dir()
    fd = os.open(str(LOCK_FILE), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise VaultLockedError("Another pv process is currently accessing the vault")
    return fd


def release_lock(fd: int) -> None:
    """Release the advisory lock and close the file descriptor."""
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)


def read_vault() -> dict:
    """
    Read and parse vault.json. Returns an empty dict if the file doesn't exist yet
    (first run — vault will be initialised on first write).
    """
    if not VAULT_FILE.exists():
        return {}
    with open(VAULT_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def write_vault(data: dict) -> None:
    """
    Atomically write data to vault.json using the tmp → fsync → rename pattern.

    Why this matters:
      - A simple open(vault, 'w') + write() leaves a window where a crash
        produces a zero-byte or partial file — vault is destroyed.
      - Writing to a tmp file in the SAME directory (same filesystem) means
        os.rename() is atomic at the kernel level: the old file remains
        readable right up until the new one fully replaces it.
      - fsync on the tmp file flushes OS write-back cache to disk before rename.
      - fsync on the directory flushes the directory entry update to disk,
        ensuring the rename itself is durable across a power loss.
    """
    _ensure_vault_dir()
    payload = json.dumps(data, indent=2, ensure_ascii=False)

    # Write to a temp file in the same directory (guarantees same filesystem)
    fd, tmp_path = tempfile.mkstemp(dir=VAULT_DIR, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())       # flush to physical disk

        os.chmod(tmp_path, 0o600)      # restrict before rename so there's no readable window
        os.rename(tmp_path, VAULT_FILE) # atomic on POSIX (same filesystem)

        # Fsync the directory so the rename's directory entry is also durable
        dir_fd = os.open(str(VAULT_DIR), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    except Exception:
        # Clean up tmp file on any failure so we don't litter
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
