"""
Crypto Utilities:
1. Shamir's Secret Sharing (SSS) - Military-Grade K-of-N Threshold Cryptography
2. BIP-39 Seed Phrase Analysis & Validation
3. Shannon Entropy & Password Strength Calculator
"""

import math
import secrets
import re
from typing import List, Tuple

# Shamir's Secret Sharing over GF(257) Prime Field
PRIME_257 = 257


def shamir_split(secret: str, threshold: int, total_shares: int) -> List[str]:
    """
    Splits sensitive data (Seed Phrase, Master Key, etc.) into 'total_shares' parts.
    Reconstructing the secret requires at least 'threshold' parts.
    
    Example: In a 3-of-5 scheme, 5 shares are generated; any 3 are sufficient to recover.
    """
    if threshold > total_shares:
        raise ValueError("Threshold cannot be greater than total shares.")
    if threshold < 2:
        raise ValueError("Threshold must be at least 2.")

    data = secret.encode("utf-8")
    shares_dict = {x: bytearray() for x in range(1, total_shares + 1)}

    for b in data:
        while True:
            # Random polynomial of degree k-1: f(x) = b + c1*x + c2*x^2 + ... (mod 257)
            coeffs = [b] + [secrets.randbelow(PRIME_257) for _ in range(threshold - 1)]
            vals = []
            for x in range(1, total_shares + 1):
                val = sum(c * (x ** i) for i, c in enumerate(coeffs)) % PRIME_257
                vals.append(val)
            
            # Ensure all shares fit into byte (0-255) range via rejection sampling
            if all(v < 256 for v in vals):
                for x, v in zip(range(1, total_shares + 1), vals):
                    shares_dict[x].append(v)
                break

    # Package shares in human-readable armored format
    formatted_shares = []
    for x in range(1, total_shares + 1):
        hex_data = bytes(shares_dict[x]).hex()
        formatted_shares.append(f"AEGIS-SHR-{x:02d}-{threshold}of{total_shares}-{hex_data}")

    return formatted_shares


def shamir_combine(shares: List[str]) -> str:
    """
    Reconstructs the original secret from K Shamir shares using Lagrange interpolation.
    """
    if not shares:
        raise ValueError("No shares provided.")

    parsed_shares: List[Tuple[int, bytes]] = []
    threshold_expected = None

    pattern = re.compile(r"^AEGIS-SHR-(\d+)-(\d+)of(\d+)-([0-9a-fA-F]+)$")
    for s in shares:
        s = s.strip()
        if not s:
            continue
        m = pattern.match(s)
        if not m:
            raise ValueError(f"Invalid share format: {s[:25]}...")
        x = int(m.group(1))
        k = int(m.group(2))
        hex_data = m.group(4)
        if threshold_expected is None:
            threshold_expected = k
        elif threshold_expected != k:
            raise ValueError("Shares with different threshold parameters cannot be combined.")
        parsed_shares.append((x, bytes.fromhex(hex_data)))

    # Verify unique share coordinates
    unique_x = set(x for x, _ in parsed_shares)
    if len(unique_x) < threshold_expected:
        raise ValueError(
            f"Insufficient unique shares! Required: {threshold_expected}, provided: {len(unique_x)}"
        )

    # Use only the first K unique shares
    used_shares = []
    seen = set()
    for x, data in parsed_shares:
        if x not in seen:
            seen.add(x)
            used_shares.append((x, data))
            if len(used_shares) == threshold_expected:
                break

    data_len = len(used_shares[0][1])
    if not all(len(d) == data_len for _, d in used_shares):
        raise ValueError("Share lengths mismatch. Data might be corrupted.")

    result_bytes = bytearray()
    for idx in range(data_len):
        val = 0
        for i, (xi, data_i) in enumerate(used_shares):
            yi = data_i[idx]
            num, den = 1, 1
            for j, (xj, _) in enumerate(used_shares):
                if i != j:
                    num = (num * (-xj)) % PRIME_257
                    den = (den * (xi - xj)) % PRIME_257
            lagrange = (num * pow(den, -1, PRIME_257)) % PRIME_257
            val = (val + yi * lagrange) % PRIME_257
        result_bytes.append(val)

    try:
        return bytes(result_bytes).decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Decoded data is not valid UTF-8. Shares may be incorrect, corrupted, or below the required threshold.")


def validate_bip39_seed(phrase: str) -> dict:
    """
    Validates Bitcoin / EVM 12 or 24-word seed phrase structure.
    """
    words = phrase.strip().split()
    word_count = len(words)
    valid_lengths = [12, 15, 18, 21, 24]
    
    is_valid_len = word_count in valid_lengths
    
    # Character and word format check (lowercase alpha only)
    valid_format = all(re.match(r"^[a-z]+$", w) for w in words) if words else False

    # Calculate theoretical entropy bits (12 words = 128 bits, 24 words = 256 bits)
    bit_entropy = (word_count * 11) - (word_count // 3) if is_valid_len else 0

    return {
        "word_count": word_count,
        "is_valid_length": is_valid_len,
        "is_valid_format": valid_format,
        "entropy_bits": bit_entropy,
        "standard_status": "Valid BIP-39 Format" if (is_valid_len and valid_format) else "Invalid Word Count or Character Encoding",
    }


def calculate_password_entropy(password: str) -> dict:
    """Calculates Shannon entropy and strength score for a given password."""
    if not password:
        return {"entropy": 0, "score": 0, "label": "Empty", "color": "#ef4444"}

    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[!@#$%^&*()_\-+=\[\]{}|;:,.<>?~]", password):
        pool_size += 32

    entropy = len(password) * math.log2(pool_size) if pool_size > 0 else 0

    if entropy < 45:
        score = 1
        label = "Weak (Easily Crackable)"
        color = "#ef4444"
    elif entropy < 70:
        score = 2
        label = "Moderate"
        color = "#f59e0b"
    elif entropy < 100:
        score = 3
        label = "Strong"
        color = "#3b82f6"
    else:
        score = 4
        label = "Military-Grade (Virtually Uncrackable)"
        color = "#10b981"

    return {
        "entropy": round(entropy, 1),
        "score": score,
        "label": label,
        "color": color
    }
