class VaultError(Exception):
    """Base class for all vault errors. Catch this to handle any vault failure."""
    pass


class WrongPasswordError(VaultError):
    """
    Raised when AES-GCM authentication tag verification fails.

    IMPORTANT SECURITY NOTE: We intentionally do NOT distinguish between
    "wrong master password" and "vault file was tampered with". Both
    conditions fail at the same point (GCM tag mismatch) and we surface
    the same error for both. Telling an attacker which case occurred would
    give them information about whether they are close to the right password.
    """
    pass


class VaultFormatError(VaultError):
    """
    Raised when the vault JSON is structurally invalid or missing required fields.
    Distinct from WrongPasswordError — this means the file is corrupt, not
    just encrypted under a different key.
    """
    pass


class EntryNotFoundError(VaultError):
    """Raised when a requested service name does not exist in the vault."""
    pass


class EntryExistsError(VaultError):
    """Raised when trying to add a service that already exists (without --force)."""
    pass


class VaultLockedError(VaultError):
    """Raised when a concurrent process holds the advisory lock on the vault file."""
    pass
