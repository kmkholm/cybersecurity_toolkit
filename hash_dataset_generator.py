# -*- coding: utf-8 -*-
"""
Hash Dataset Generator for ML Training
Generates synthetic hash examples for training ML classifier

Author: Dr. Mohammed Tawfik
"""

import hashlib
import random
import string
import csv
import base64
from datetime import datetime

# Configuration
N_SAMPLES_PER_TYPE = 5000
OUT_CSV = "hash_training_dataset.csv"
SEED = 42

random.seed(SEED)


def generate_random_password():
    """Generate random password for hashing"""
    length = random.randint(6, 20)
    chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-="
    return ''.join(random.choice(chars) for _ in range(length))


def md4(message: bytes) -> bytes:
    """
    Pure-Python MD4 implementation (RFC 1320) for environments where hashlib does not support MD4.
    Returns raw digest bytes.
    """

    def _lrot(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def _F(x, y, z):
        return (x & y) | (~x & z)

    def _G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def _H(x, y, z):
        return x ^ y ^ z

    # Pre-processing: padding the message
    original_len_bits = (len(message) * 8) & 0xFFFFFFFFFFFFFFFF
    message += b'\x80'
    while (len(message) % 64) != 56:
        message += b'\x00'
    message += original_len_bits.to_bytes(8, byteorder='little')

    # Initialize MD4 state
    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476

    # Process message in 16-word blocks
    for offset in range(0, len(message), 64):
        block = message[offset:offset + 64]
        X = [int.from_bytes(block[i:i + 4], byteorder='little') for i in range(0, 64, 4)]

        AA, BB, CC, DD = A, B, C, D

        # Round 1
        S = [3, 7, 11, 19]
        for i in range(16):
            k = i
            s = S[i % 4]
            if i % 4 == 0:
                A = _lrot((A + _F(B, C, D) + X[k]) & 0xFFFFFFFF, s)
            elif i % 4 == 1:
                D = _lrot((D + _F(A, B, C) + X[k]) & 0xFFFFFFFF, s)
            elif i % 4 == 2:
                C = _lrot((C + _F(D, A, B) + X[k]) & 0xFFFFFFFF, s)
            else:
                B = _lrot((B + _F(C, D, A) + X[k]) & 0xFFFFFFFF, s)

        # Round 2
        S = [3, 5, 9, 13]
        for i in range(16):
            k = (i % 4) * 4 + (i // 4)
            s = S[i % 4]
            if i % 4 == 0:
                A = _lrot((A + _G(B, C, D) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
            elif i % 4 == 1:
                D = _lrot((D + _G(A, B, C) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
            elif i % 4 == 2:
                C = _lrot((C + _G(D, A, B) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
            else:
                B = _lrot((B + _G(C, D, A) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)

        # Round 3
        S = [3, 9, 11, 15]
        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            k = order[i]
            s = S[i % 4]
            if i % 4 == 0:
                A = _lrot((A + _H(B, C, D) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            elif i % 4 == 1:
                D = _lrot((D + _H(A, B, C) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            elif i % 4 == 2:
                C = _lrot((C + _H(D, A, B) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            else:
                B = _lrot((B + _H(C, D, A) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)

        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF

    return (A.to_bytes(4, 'little') +
            B.to_bytes(4, 'little') +
            C.to_bytes(4, 'little') +
            D.to_bytes(4, 'little'))


def md4_hex(message: bytes) -> str:
    return md4(message).hex()


def extract_hash_features(hash_value):
    """Extract features from hash for ML"""
    features = {}

    # Basic features
    features['length'] = len(hash_value)
    features['has_dollar'] = int('$' in hash_value)
    features['has_colon'] = int(':' in hash_value)
    features['has_uppercase'] = int(any(c.isupper() for c in hash_value))
    features['has_lowercase'] = int(any(c.islower() for c in hash_value))
    features['has_digit'] = int(any(c.isdigit() for c in hash_value))
    features['has_special'] = int(any(c in './$@+=' for c in hash_value))

    # Character distribution
    features['hex_only'] = int(all(c in '0123456789abcdefABCDEF' for c in hash_value.replace('$', '').replace(':', '')))
    features['alphanumeric_only'] = int(all(c.isalnum() or c in '$:' for c in hash_value))
    features['has_slash'] = int('/' in hash_value)
    features['has_plus'] = int('+' in hash_value)
    features['has_equals'] = int('=' in hash_value)

    # Pattern features
    features['starts_with_dollar'] = int(hash_value.startswith('$'))
    features['dollar_count'] = hash_value.count('$')
    features['colon_count'] = hash_value.count(':')

    # Statistical features
    if len(hash_value) > 0:
        features['unique_char_ratio'] = len(set(hash_value)) / len(hash_value)
        features['digit_ratio'] = sum(c.isdigit() for c in hash_value) / len(hash_value)
        features['alpha_ratio'] = sum(c.isalpha() for c in hash_value) / len(hash_value)
    else:
        features['unique_char_ratio'] = 0
        features['digit_ratio'] = 0
        features['alpha_ratio'] = 0

    # Length categories
    features['is_short'] = int(len(hash_value) <= 20)
    features['is_medium'] = int(20 < len(hash_value) <= 50)
    features['is_long'] = int(50 < len(hash_value) <= 80)
    features['is_very_long'] = int(len(hash_value) > 80)

    # Specific length markers (full string length, including any separators)
    features['is_len_16'] = int(len(hash_value) == 16)
    features['is_len_32'] = int(len(hash_value) == 32)
    features['is_len_40'] = int(len(hash_value) == 40)
    features['is_len_56'] = int(len(hash_value) == 56)
    features['is_len_64'] = int(len(hash_value) == 64)
    features['is_len_96'] = int(len(hash_value) == 96)
    features['is_len_128'] = int(len(hash_value) == 128)

    # Format patterns
    features['has_prefix_2a'] = int(hash_value.startswith('$2a$'))
    features['has_prefix_2b'] = int(hash_value.startswith('$2b$'))
    features['has_prefix_P'] = int(hash_value.startswith('$P$'))
    features['has_prefix_H'] = int(hash_value.startswith('$H$'))

    return features


def generate_hash_samples():
    """Generate hash samples with features"""
    samples = []

    print(f"[+] Generating {N_SAMPLES_PER_TYPE} samples per hash type...")

    # MD5 (32 hex chars)
    print("  → Generating MD5 samples...")
    for _ in range(N_SAMPLES_PER_TYPE):
        password = generate_random_password()
        hash_value = hashlib.md5(password.encode()).hexdigest()
        features = extract_hash_features(hash_value)
        features['label'] = 'MD5'
        features['hash'] = hash_value
        samples.append(features)

    # SHA1 (40 hex chars)
    print("  → Generating SHA1 samples...")
    for _ in range(N_SAMPLES_PER_TYPE):
        password = generate_random_password()
        hash_value = hashlib.sha1(password.encode()).hexdigest()
        features = extract_hash_features(hash_value)
        features['label'] = 'SHA1'
        features['hash'] = hash_value
        samples.append(features)

    # SHA224 (56 hex chars)
    print("  → Generating SHA224 samples...")
    for _ in range(N_SAMPLES_PER_TYPE):
        password = generate_random_password()
        hash_value = hashlib.sha224(password.encode()).hexdigest()
        features = extract_hash_features(hash_value)
        features['label'] = 'SHA224'
        features['hash'] = hash_value
        samples.append(features)

    # SHA256 (64 hex chars)
    print("  → Generating SHA256 samples...")
    for _ in range(N_SAMPLES_PER_TYPE):
        password = generate_random_password()
        hash_value = hashlib.sha256(password.encode()).hexdigest()
        features = extract_hash_features(hash_value)
        features['label'] = 'SHA256'
        features['hash'] = hash_value
        samples.append(features)

    # SHA384 (96 hex chars)
    print("  → Generating SHA384 samples...")
    for _ in range(N_SAMPLES_PER_TYPE):
        password = generate_random_password()
        hash_value = hashlib.sha384(password.encode()).hexdigest()
        features = extract_hash_features(hash_value)
        features['label'] = 'SHA384'
        features['hash'] = hash_value
        samples.append(features)

    # SHA512 (128 hex chars)
    print("  → Generating SHA512 samples...")
    for _ in range(N_SAMPLES_PER_TYPE):
        password = generate_random_password()
        hash_value = hashlib.sha512(password.encode()).hexdigest()
        features = extract_hash_features(hash_value)
        features['label'] = 'SHA512'
        features['hash'] = hash_value
        samples.append(features)

    # NTLM (32 hex chars - MD4 of UTF-16LE) using pure Python MD4
    print("  → Generating NTLM samples...")
    for _ in range(N_SAMPLES_PER_TYPE):
        password = generate_random_password()
        hash_value = md4_hex(password.encode('utf-16le'))
        features = extract_hash_features(hash_value)
        features['label'] = 'NTLM'
        features['hash'] = hash_value
        samples.append(features)

    # MySQL OLD (16 hex chars)
    print("  → Generating MySQL OLD samples...")
    for _ in range(N_SAMPLES_PER_TYPE):
        hash_value = ''.join(random.choice('0123456789abcdef') for _ in range(16))
        features = extract_hash_features(hash_value)
        features['label'] = 'MySQL_OLD'
        features['hash'] = hash_value
        samples.append(features)

    # Bcrypt-like (60 chars with $2a$ prefix)
    print("  → Generating Bcrypt samples...")
    for _ in range(N_SAMPLES_PER_TYPE):
        salt = ''.join(random.choices(string.ascii_letters + string.digits + './', k=22))
        hash_part = ''.join(random.choices(string.ascii_letters + string.digits + './', k=31))
        hash_value = f"$2a$10${salt}{hash_part}"
        features = extract_hash_features(hash_value)
        features['label'] = 'Bcrypt'
        features['hash'] = hash_value
        samples.append(features)

    # WordPress (34 chars with $P$ prefix)
    print("  → Generating WordPress samples...")
    for _ in range(N_SAMPLES_PER_TYPE):
        hash_part = ''.join(random.choices(string.ascii_letters + string.digits + './', k=31))
        hash_value = f"$P${hash_part}"
        features = extract_hash_features(hash_value)
        features['label'] = 'WordPress'
        features['hash'] = hash_value
        samples.append(features)

    # Joomla (49 chars: hash:salt)
    print("  → Generating Joomla samples...")
    for _ in range(N_SAMPLES_PER_TYPE):
        password = generate_random_password()
        salt = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        hash_part = hashlib.md5(password.encode()).hexdigest()
        hash_value = f"{hash_part}:{salt}"
        features = extract_hash_features(hash_value)
        features['label'] = 'Joomla'
        features['hash'] = hash_value
        samples.append(features)

    # Base64 encoded (variable length)
    print("  → Generating Base64 samples...")
    for _ in range(N_SAMPLES_PER_TYPE):
        password = generate_random_password()
        hash_bytes = hashlib.sha256(password.encode()).digest()
        hash_value = base64.b64encode(hash_bytes).decode()
        features = extract_hash_features(hash_value)
        features['label'] = 'Base64_Encoded'
        features['hash'] = hash_value
        samples.append(features)

    return samples


def main():
    """Main function"""
    print("\n" + "=" * 70)
    print("Hash Dataset Generator for ML Training")
    print("=" * 70 + "\n")

    # Generate samples
    samples = generate_hash_samples()

    # Shuffle
    random.shuffle(samples)

    # Write to CSV
    print(f"\n[+] Writing {len(samples)} samples to {OUT_CSV}...")

    if samples:
        fieldnames = list(samples[0].keys())

        with open(OUT_CSV, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(samples)

    # Statistics
    label_counts = {}
    for sample in samples:
        label = sample['label']
        label_counts[label] = label_counts.get(label, 0) + 1

    print(f"[+] Dataset saved: {OUT_CSV}")
    print(f"\n[+] Label distribution:")
    for label, count in sorted(label_counts.items()):
        print(f"  {label:20s}: {count:5d} samples")

    print(f"\n[+] Total samples: {len(samples)}")
    print(f"[+] Total hash types: {len(label_counts)}")
    print(f"[+] Generated at: {datetime.now().isoformat(timespec='seconds')}")
    print("\n" + "=" * 70)
    print("✓ Dataset generation complete!")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
