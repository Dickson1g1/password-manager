import secrets
import string

# Character pools — kept as module-level constants so callers can inspect them
LOWERCASE = string.ascii_lowercase          # a-z
UPPERCASE = string.ascii_uppercase          # A-Z
DIGITS    = string.digits                   # 0-9
SYMBOLS   = "!@#$%^&*()-_=+[]{}|;:,.<>?"   # common safe symbols


def generate(
    length:      int  = 20,
    use_upper:   bool = True,
    use_digits:  bool = True,
    use_symbols: bool = True,
) -> str:
    """
    Generate a cryptographically secure random password.

    Why secrets, not random?
      - random uses a Mersenne Twister, which is NOT cryptographically secure.
        Its state can be reconstructed from ~624 output values. secrets uses
        os.urandom() which draws from the kernel's CSPRNG (/dev/urandom on Linux).

    Why Fisher-Yates shuffle?
      - We guarantee at least one character from each selected pool, which
        means the first N characters of the initial build are biased (one from
        each pool in order). We shuffle to destroy that positional information.
      - We implement the shuffle ourselves using secrets.randbelow() rather than
        random.shuffle() to keep the entire pipeline CSPRNG-sourced.
    """
    if length < 4:
        raise ValueError("Password length must be at least 4")

    # Build the allowed character pool from selected categories
    pool = LOWERCASE
    if use_upper:   pool += UPPERCASE
    if use_digits:  pool += DIGITS
    if use_symbols: pool += SYMBOLS

    # Guarantee at least one character from each enabled category
    # This prevents a (vanishingly rare but possible) all-lowercase result
    required = [secrets.choice(LOWERCASE)]
    if use_upper:   required.append(secrets.choice(UPPERCASE))
    if use_digits:  required.append(secrets.choice(DIGITS))
    if use_symbols: required.append(secrets.choice(SYMBOLS))

    # Fill remaining length with random draws from the full pool
    remaining = [secrets.choice(pool) for _ in range(length - len(required))]

    # Combine and apply Fisher-Yates shuffle using secrets.randbelow
    chars = required + remaining
    for i in range(len(chars) - 1, 0, -1):
        # Pick a random index from [0, i] inclusive
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    return "".join(chars)
