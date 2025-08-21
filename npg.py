#!/usr/bin/env python3
"""
NIST-style random password / passphrase generator (SP 800-63B aligned)
- Cryptographically secure randomness (secrets module)
- No composition rules; length/entropy-focused
- Optional blocklist screening (e.g., breached passwords file, one entry per line)
- Optional passphrase mode using a user-supplied wordlist
"""

from __future__ import annotations

import argparse
import math
import secrets
import string
from pathlib import Path
from typing import Iterable, Optional, Set


# ----------------------------
# Utilities
# ----------------------------
def bits_of_entropy(space_size: int, length: int) -> float:
    """H = log2(space_size^length) = length * log2(space_size)."""
    if space_size <= 1 or length <= 0:
        return 0.0
    return length * math.log2(space_size)


def load_blocklist(path: Optional[Path]) -> Set[str]:
    """Load a blocklist file (one secret per line). Case-sensitive exact match."""
    if not path:
        return set()
    bl: Set[str] = set()
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.rstrip("\r\n")
            if s:
                bl.add(s)
    return bl


def pick_chars(alphabet: str, length: int) -> str:
    """Uniform random draw using secrets.choice (no modulo bias)."""
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_password(
    length: int = 20,
    allow_space: bool = True,
    exclude_ambiguous: bool = False,
) -> tuple[str, float, str]:
    """
    Generate a random password from printable ASCII, optionally excluding ambiguous glyphs.
    Returns (password, entropy_bits, alphabet_used)
    """
    # Base alphabet: all ASCII letters, digits, punctuation; optionally space
    alphabet = string.ascii_letters + string.digits + string.punctuation
    if allow_space:
        alphabet += " "

    if exclude_ambiguous:
        ambiguous = "Il1O0|`'\";:.,{}[]()<>^~"
        alphabet = "".join(ch for ch in alphabet if ch not in ambiguous)

    # Ensure duplicates removed and stable
    alphabet = "".join(dict.fromkeys(alphabet))  # preserve order, drop dups
    if len(alphabet) < 10:
        raise ValueError("Alphabet too small after exclusions.")

    secret = pick_chars(alphabet, length)
    entropy = bits_of_entropy(len(alphabet), length)
    return secret, entropy, alphabet


def generate_passphrase(
    num_words: int,
    wordlist_path: Path,
    separator: str = " ",
    capitalize: bool = False,
) -> tuple[str, float, int]:
    """
    Generate a random passphrase from a user-supplied wordlist (one word per line).
    Returns (passphrase, entropy_bits, vocab_size)
    """
    # Load wordlist
    words = []
    with wordlist_path.open("r", encoding="utf-8", errors="ignore") as f:
        for w in f:
            w = w.strip()
            if w and not w.startswith("#"):
                words.append(w)
    vocab = len(words)
    if vocab < 2048:
        # Not required by NIST but recommended for meaningful entropy;
        # 2048^6 ≈ 66 bits which is solid for memorized secrets.
        raise ValueError(
            "Wordlist too small; supply a larger list (>= 2048 words recommended)."
        )

    chosen = [secrets.choice(words) for _ in range(num_words)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    phrase = separator.join(chosen)
    entropy = bits_of_entropy(vocab, num_words)
    return phrase, entropy, vocab


def check_blocklist(secret: str, blocklist: Set[str]) -> bool:
    """True if secret is blocked."""
    return secret in blocklist


# ----------------------------
# CLI
# ----------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Random password/passphrase generator aligned with NIST SP 800-63B."
    )

    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--password",
        action="store_true",
        help="Generate a random character password (default).",
    )
    mode.add_argument(
        "--passphrase",
        action="store_true",
        help="Generate a passphrase from a wordlist you provide.",
    )

    # Password options
    p.add_argument(
        "--length",
        type=int,
        default=20,
        help="Password length (characters). NIST minimum is 8; 16–24 recommended. Default: 20.",
    )
    p.add_argument(
        "--no-space",
        action="store_true",
        help="Exclude spaces from the alphabet (some legacy systems mishandle spaces).",
    )
    p.add_argument(
        "--no-ambiguous",
        action="store_true",
        help="Exclude commonly ambiguous characters (e.g., 0/O, 1/l/I, |, etc.).",
    )

    # Passphrase options
    p.add_argument(
        "--words",
        type=int,
        default=6,
        help="Number of words in passphrase (default: 6).",
    )
    p.add_argument(
        "--wordlist",
        type=Path,
        help="Path to a wordlist file (one word per line). Required for --passphrase.",
    )
    p.add_argument(
        "--sep",
        default=" ",
        help="Separator between words in passphrase (default: space).",
    )
    p.add_argument(
        "--caps",
        action="store_true",
        help="Capitalize each word in the passphrase.",
    )

    # Screening & policy options
    p.add_argument(
        "--blocklist",
        type=Path,
        help="Optional path to a blocklist (e.g., breached passwords file). Exact-match check.",
    )
    p.add_argument(
        "--min-entropy",
        type=float,
        default=64.0,
        help="Minimum required entropy in bits (default: 64).",
    )

    return p.parse_args()


def main() -> None:
    args = parse_args()

    # Decide mode
    mode = "passphrase" if args.passphrase else "password"

    # Generate
    if mode == "password":
        if args.length < 8:
            raise SystemExit(
                "Refusing to generate: length must be at least 8 per NIST."
            )
        secret, entropy, alphabet = generate_password(
            length=args.length,
            allow_space=not args.no_space,
            exclude_ambiguous=args.no_ambiguous,
        )
    else:
        if not args.wordlist:
            raise SystemExit("Passphrase mode requires --wordlist <path>.")
        if args.words < 3:
            raise SystemExit("Refusing to generate: use at least 3 words (prefer 5–7).")
        secret, entropy, vocab = generate_passphrase(
            num_words=args.words,
            wordlist_path=args.wordlist,
            separator=args.sep,
            capitalize=args.caps,
        )

    # Entropy check
    if entropy < args.min_entropy:
        raise SystemExit(
            f"Refusing to output secret below entropy floor: {entropy:.1f} bits < {args.min_entropy:.1f} bits. "
            "Increase length/words or choose a larger alphabet/wordlist."
        )

    # Optional blocklist screening
    bl = load_blocklist(args.blocklist)
    if bl and check_blocklist(secret, bl):
        raise SystemExit(
            "Generated secret appears in the supplied blocklist; regenerate."
        )

    # Output (print only the secret; metadata to stderr-like note for safety is avoided here)
    print(secret)

    # If you want metadata, uncomment the lines below, but be mindful of where it’s logged/stored.
    # import sys
    # print(f"# Entropy: {entropy:.2f} bits", file=sys.stderr)


if __name__ == "__main__":
    main()
