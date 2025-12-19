# -*- coding: utf-8 -*-
"""
Created on Fri Dec 19 16:06:15 2025

@author: kmkho
"""

# synthetic_password_dataset_generator.py
# Generates a SAFE synthetic password dataset for educational ML
# Output: synthetic_password_dataset.csv

import random
import string
import math
import csv
from datetime import datetime

# -----------------------------
# Config
# -----------------------------
N_SAMPLES = 50000          # عدّل العدد زي ما تحب
OUT_CSV = "synthetic_password_dataset.csv"
SEED = 42

random.seed(SEED)

COMMON_WEAK = [
    "password", "123456", "12345678", "qwerty", "abc123", "admin",
    "iloveyou", "welcome", "letmein", "monkey", "dragon", "football"
]

KEYBOARD_WALKS = ["qwerty", "asdfgh", "zxcvbn", "12345", "09876"]

# -----------------------------
# Helpers
# -----------------------------
def char_space_size(pw: str) -> int:
    """Approximate character set size used in the password."""
    has_lower = any(c.islower() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_symbol = any((not c.isalnum()) for c in pw)

    size = 0
    if has_lower: size += 26
    if has_upper: size += 26
    if has_digit: size += 10
    if has_symbol: size += 32  # rough printable symbol space
    return max(size, 1)

def shannon_entropy_bits(pw: str) -> float:
    """Very rough entropy estimate: length * log2(char_space)."""
    cs = char_space_size(pw)
    return len(pw) * math.log2(cs)

def unique_ratio(pw: str) -> float:
    if not pw:
        return 0.0
    return len(set(pw)) / len(pw)

def longest_run(pw: str) -> int:
    """Longest repeated-character run length."""
    if not pw:
        return 0
    best = 1
    cur = 1
    for i in range(1, len(pw)):
        if pw[i] == pw[i-1]:
            cur += 1
            best = max(best, cur)
        else:
            cur = 1
    return best

def has_year_like(pw: str) -> int:
    """Detect simple year patterns 19xx or 20xx."""
    for i in range(len(pw) - 3):
        chunk = pw[i:i+4]
        if chunk.isdigit():
            y = int(chunk)
            if 1900 <= y <= 2099:
                return 1
    return 0

def has_keyboard_walk(pw: str) -> int:
    low = pw.lower()
    return 1 if any(w in low for w in KEYBOARD_WALKS) else 0

def has_common_word(pw: str) -> int:
    low = pw.lower()
    return 1 if any(w in low for w in COMMON_WEAK) else 0

def sequential_digits_score(pw: str) -> int:
    """Detect simple sequences like 1234 / 4321 / 0123."""
    best = 0
    digits = [c for c in pw if c.isdigit()]
    s = "".join(digits)
    if len(s) < 4:
        return 0
    for i in range(len(s) - 3):
        chunk = s[i:i+4]
        if chunk in "0123456789" or chunk in "9876543210":
            best = 1
            break
    return best

def strength_score(pw: str) -> float:
    """Score = entropy - penalties (educational heuristic)."""
    ent = shannon_entropy_bits(pw)

    penalty = 0.0
    penalty += 18.0 * has_common_word(pw)
    penalty += 10.0 * has_year_like(pw)
    penalty += 8.0  * has_keyboard_walk(pw)
    penalty += 8.0  * sequential_digits_score(pw)
    # penalize very low uniqueness
    ur = unique_ratio(pw)
    if ur < 0.6:
        penalty += 10.0
    # penalize long repeated runs
    lr = longest_run(pw)
    if lr >= 3:
        penalty += 6.0

    return max(ent - penalty, 0.0)

def label_from_score(score: float) -> str:
   
    if score < 35:
        return "Weak"
    elif score < 70:
        return "Medium"
    else:
        return "Strong"

# -----------------------------
# Password generators
# -----------------------------
def gen_very_weak() -> str:
    base = random.choice(COMMON_WEAK)
    # sometimes add simple digits
    if random.random() < 0.6:
        base += str(random.randint(0, 9999)).zfill(random.choice([2, 3, 4]))
    return base

def gen_pattern_weak() -> str:
    # Name+year+symbol-ish pattern (synthetic)
    names = ["ahmed", "mohamed", "sara", "maya", "omar", "lina", "adam", "noor"]
    name = random.choice(names)
    year = str(random.randint(1990, 2026))
    suffix = random.choice(["", "!", "@", "#", "1", "12", "123"])
    # random casing
    if random.random() < 0.5:
        name = name.capitalize()
    return f"{name}{year}{suffix}"

def gen_medium() -> str:
    length = random.randint(8, 12)
    pools = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits
    ]
    # sometimes include symbols
    if random.random() < 0.4:
        pools.append("!@#$%^&*_-+=")

    allchars = "".join(pools)
    pw = "".join(random.choice(allchars) for _ in range(length))

    # ensure at least 2 pools present
    return pw

def gen_strong() -> str:
    length = random.randint(12, 20)
    allchars = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*()_+-=[]{};:,.?/|"
    pw = "".join(random.choice(allchars) for _ in range(length))

    # enforce diversity
    if not any(c.islower() for c in pw):
        pw = pw[:-1] + random.choice(string.ascii_lowercase)
    if not any(c.isupper() for c in pw):
        pw = pw[:-1] + random.choice(string.ascii_uppercase)
    if not any(c.isdigit() for c in pw):
        pw = pw[:-1] + random.choice(string.digits)
    if not any((not c.isalnum()) for c in pw):
        pw = pw[:-1] + random.choice("!@#$%^&*_-+=")

    return pw

def sample_password() -> str:
    # نسب توليد الفئات (تقدر تغيّرها)
    r = random.random()
    if r < 0.35:
        return gen_very_weak()
    elif r < 0.60:
        return gen_pattern_weak()
    elif r < 0.85:
        return gen_medium()
    else:
        return gen_strong()

# -----------------------------
# Main CSV generation
# -----------------------------
def extract_features(pw: str) -> dict:
    feats = {}
    feats["password"] = pw
    feats["length"] = len(pw)
    feats["has_lower"] = int(any(c.islower() for c in pw))
    feats["has_upper"] = int(any(c.isupper() for c in pw))
    feats["has_digit"] = int(any(c.isdigit() for c in pw))
    feats["has_symbol"] = int(any((not c.isalnum()) for c in pw))
    feats["unique_ratio"] = round(unique_ratio(pw), 4)
    feats["longest_run"] = longest_run(pw)
    feats["has_year_like"] = has_year_like(pw)
    feats["has_common_word"] = has_common_word(pw)
    feats["has_keyboard_walk"] = has_keyboard_walk(pw)
    feats["has_sequential_digits"] = sequential_digits_score(pw)
    feats["entropy_bits"] = round(shannon_entropy_bits(pw), 3)

    score = strength_score(pw)
    feats["strength_score"] = round(score, 3)
    feats["label"] = label_from_score(score)
    return feats

def main():
    print(f"[+] Generating {N_SAMPLES} synthetic passwords...")
    rows = []
    for _ in range(N_SAMPLES):
        pw = sample_password()
        rows.append(extract_features(pw))

    fieldnames = list(rows[0].keys())

    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # quick stats
    counts = {"Weak": 0, "Medium": 0, "Strong": 0}
    for r in rows:
        counts[r["label"]] += 1

    print(f"[+] Saved: {OUT_CSV}")
    print("[+] Label distribution:", counts)
    print("[+] Generated at:", datetime.now().isoformat(timespec="seconds"))

if __name__ == "__main__":
    main()
