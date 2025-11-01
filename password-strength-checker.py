#!/usr/bin/env python3
"""
password_checker.py
Simple password strength checker for learning and demonstration.

Usage:
  python3 password_checker.py       # interactive mode
  python3 password_checker.py "P@ssw0rd2025!"  # CLI mode
"""

import math
import argparse
import re
from typing import Tuple, List

# small list of extremely common / banned passwords (do not rely on this list alone)
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "qwerty", "abc123", "football", "monkey", "letmein"
}

def char_classes(password: str) -> dict:
    return {
        "lower": bool(re.search(r"[a-z]", password)),
        "upper": bool(re.search(r"[A-Z]", password)),
        "digits": bool(re.search(r"\d", password)),
        "symbols": bool(re.search(r"[^\w\s]", password)),
        "spaces": bool(re.search(r"\s", password))
    }

def estimate_entropy(password: str) -> float:
    """
    Estimate entropy (bits) using simple charset approach:
    entropy = length * log2(charset_size)
    """
    classes = char_classes(password)
    charset_size = 0
    if classes["lower"]:
        charset_size += 26
    if classes["upper"]:
        charset_size += 26
    if classes["digits"]:
        charset_size += 10
    if classes["symbols"]:
        # a rough symbol count
        charset_size += 32
    if classes["spaces"]:
        charset_size += 1

    # fallback: if nothing matched (very unlikely), assume ascii printable
    if charset_size == 0:
        charset_size = 94

    entropy = len(password) * math.log2(charset_size)
    return entropy

def score_password(password: str) -> Tuple[int, List[str]]:
    """
    Returns (score [0-100], list_of_observations)
    Score is heuristic: entropy plus bonuses/penalties.
    """
    observations = []
    password_lower = password.lower().strip()
    entropy = estimate_entropy(password)
    score = min(int(entropy), 100)

    # length bonuses / penalties
    if len(password) < 8:
        observations.append("Too short: prefer at least 8 characters.")
        score = min(score, 40)
    elif len(password) < 12:
        observations.append("Fair length: consider 12+ characters for stronger protection.")
    else:
        observations.append("Good length.")

    # common password check
    if password_lower in COMMON_PASSWORDS:
        observations.append("Password is too common — avoid simple common passwords.")
        score = min(score, 10)

    # dictionary-ish patterns: repeated sequences, keyboard patterns
    if re.search(r"(?:1234|abcd|qwerty|password|admin)", password_lower):
        observations.append("Contains common sequences or dictionary terms.")
        score = min(score, 25)

    # variety bonuses
    classes = char_classes(password)
    variety = sum([1 for k in classes if classes[k] and k != "spaces"])
    if variety >= 3:
        observations.append("Good character variety (upper/lower/digits/symbols).")
        score = min(100, score + 10)
    elif variety == 2:
        observations.append("Some variety, but add more character classes (symbols/upper/lower/digits).")
    else:
        observations.append("Low character variety — add uppercase, digits, and symbols.")

    # repeated character penalty
    if re.search(r"(.)\1\1", password):
        observations.append("Contains repeated characters (e.g., 'aaa'). Avoid long repeats.")
        score = min(score, score - 5)

    # cap score to 0-100
    score = max(0, min(100, score))

    # append entropy note
    observations.append(f"Estimated entropy: {entropy:.1f} bits (heuristic).")
    return score, observations

def categorize(score: int) -> str:
    if score >= 80:
        return "STRONG"
    if score >= 60:
        return "GOOD"
    if score >= 40:
        return "FAIR"
    return "WEAK"

def interactive():
    print("Password Strength Checker — interactive")
    print("Press Ctrl+C to exit.\n")
    try:
        while True:
            pw = input("Enter password to test: ").strip()
            if not pw:
                print("No password entered. Try again.")
                continue
            score, obs = score_password(pw)
            print(f"\nPassword Strength: {categorize(score)}  ({score}/100)")
            for o in obs:
                print(" -", o)
            print()
    except KeyboardInterrupt:
        print("\nExiting.")

def main():
    parser = argparse.ArgumentParser(description="Simple password strength checker.")
    parser.add_argument("password", nargs="?", help="Password to check (if omitted, launches interactive mode).")
    args = parser.parse_args()

    if args.password:
        score, obs = score_password(args.password)
        print(f"Password Strength: {categorize(score)}  ({score}/100)")
        for o in obs:
            print(" -", o)
    else:
        interactive()

if __name__ == "__main__":
    main()
