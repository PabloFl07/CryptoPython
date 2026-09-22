#!/usr/bin/env python3
"""
HMAC (Hash-based Message Authentication Code) - Educational PoC
===============================================================
Demonstrates:
  1. Why simple concatenation (hash(key + message)) is vulnerable to Length Extension Attacks.
  3. How HMAC securely combines a secret key with a hash function.
  4. Verifying message integrity and authenticity in constant time.
  5. Step-by-step manual calculation of HMAC under the hood.
"""

import hashlib
import hmac
import secrets
import struct


def separator(title: str = "") -> None:
    if title:
        print(f"\n{'─' * 60}")
        print(f"  {title}")
        print(f"{'─' * 60}")
    else:
        print(f"{'─' * 60}")

    print()


# ══════════════════════════════════════════════════════════════════════════════
# LENGTH EXTENSION | WHY USE HMAC
# ══════════════════════════════════════════════════════════════════════════════

# Demonstrates the vulnerability of simple secret prefix hashing: H(secret || message).

# Inherent to Merkle-Damgård hash functions (MD5, SHA-1, SHA-256) which process input in fixed-size blocks.
# An attacker who knows H(secret || message) and len(secret || message) can resume the
# hash function state to compute H(secret || message || padding || extra_data)
# without ever knowing the secret.


def length_extension_explanation():
    separator("LENGTH EXTENSION ATTACK DEMONSTRATION")

    secret_key = b"super_secret_key"
    original_message = b"count=100&user=alice"

    # Server computes naive MAC: SHA256(secret || message)
    naive_mac = hashlib.sha256(secret_key + original_message).hexdigest()

    print("Secret Key       : [HIDDEN FROM ATTACKER]")
    print(f"Original Message : {original_message.decode()}")
    print(f"Naive MAC        : {naive_mac}")
    print("-" * 60)

    # Attacker goal: Append "&role=admin" without knowing secret_key
    tampered_extension = b"&role=admin"

    # Theoretical attack: If using raw Merkle-Damgård construction, the output hash
    # is literally the internal state vector (A, B, C, D, E, F, G, H).
    # An attacker injects the MD padding that SHA-256 would have applied:
    #   Padding = 0x80 byte + zero bytes + 64-bit length in bits

    combined_len = len(secret_key) + len(original_message)
    # Estimate SHA-256 padding for (secret + original_message)
    pad_len = (56 - (combined_len + 1) % 64) % 64
    simulated_padding = (
        b"\x80" + (b"\x00" * pad_len) + struct.pack(">Q", combined_len * 8)
    )

    forged_message = original_message + simulated_padding + tampered_extension

    # The server, upon receiving forged_message, recalculates hash(secret + forged_message)
    server_verification_hash = hashlib.sha256(secret_key + forged_message).hexdigest()

    print("Vulnerability:")
    print(
        "- Algorithms based on the Merkle-Damgård construction (MD5, SHA-1, SHA-256/512)"
    )
    print("  process input in blocks and maintain an internal state.")
    print(
        "  Appending valid padding + new data allows reconstructing a valid hash state "
    )
    print("  directly from the previous digest.")
    print("\nForged Message Payload (with injected padding):")
    print(f"  {forged_message!r}")
    print("\nServer Hash on Forged Payload:")
    print(f"  {server_verification_hash}")
    print("\n[!] HMAC prevents this by double-hashing with inner and outer key pads.")


# ══════════════════════════════════════════════════════════════════════════════
# HMAC DEMO
# ══════════════════════════════════════════════════════════════════════════════

# 1. Key Adjustment

# If the original key K is longer than the block size of the hash algorithm (for example, 64 bytes in SHA-256), it is first hashed to reduce its length.
# If it is shorter, zeros are added to the right (padding) until it reaches exactly the size of the block. The result of this adjustment is the key K'.

# 2. Internal Hash Calculation (First Pass)

# An XOR operation is performed between the adjusted key K' and a fixed, repeated pattern called the ipad (inner pad, with a value of `0x36`).
# The result is concatenated with the original message m and a hash is calculated for the entire set:

# 3. External Hash Calculation (Second Pass / Final HMAC)

# An XOR operation is performed between the adjusted key K' and another fixed, repeated pattern called the opad (outer pad, with a value of 0x5C).
# The result is concatenated with the internal hash obtained in step 2.
# The hash function is then applied again to the entire block to obtain the final signature:


def hmac_demo():
    separator("STANDARD HMAC DEMO")

    # Generate a cryptographically secure 256-bit key
    key = secrets.token_bytes(32)
    message = b"action=transfer&amount=5000&to=bob"

    # Generate HMAC-SHA256 tag
    mac = hmac.new(key, message, hashlib.sha256).digest()
    mac_hex = mac.hex()

    print(f"Secret Key (hex) : {key.hex()[:16]}...")
    print(f"Message          : {message.decode()}")
    print(f"HMAC-SHA256      : {mac_hex}")

    # 1. Verification with untampered message
    is_valid_original = hmac.compare_digest(
        hmac.new(key, message, hashlib.sha256).digest(), mac
    )
    print(
        f"\nVerification (Original Message) : {'✅ SUCCESS' if is_valid_original else '❌ FAILED'}"
    )

    # 2. Tamper attempt
    tampered_message = b"action=transfer&amount=50000&to=bob"
    is_valid_tampered = hmac.compare_digest(
        hmac.new(key, tampered_message, hashlib.sha256).digest(), mac
    )
    print(
        f"Verification (Tampered Message) : {'✅ SUCCESS' if is_valid_tampered else '❌ FAILED (Detected)'}"
    )

    # 3. Why hmac.compare_digest?
    print("\n[!] Note on Security:")
    print("  `hmac.compare_digest()` performs constant-time comparison to prevent")
    print(
        "  side-channel timing attacks (where execution time leaks matching byte prefixes)."
    )


# ══════════════════════════════════════════════════════════════════════════════
# Step-by-Step Manual HMAC Calculation
# ══════════════════════════════════════════════════════════════════════════════

# The HMAC gets calculed Manualy and checked with Python's native implementation.


def hmac_step_by_step_demo():
    separator("Step-by-Step Manual HMAC Calculation")

    block_size = 64  # Determined by the Hashing algorithm
    key = b"my_secret_key"
    message = b"hello world"

    print(f"Original Key     : {key}")
    print(f"Original Message : {message}")

    # [1] Get the adjusted Key
    if len(key) < block_size:
        padded_key = key + b"\x00" * (block_size - len(key))
    else:
        padded_key = hashlib.sha256(key).digest()
        padded_key = padded_key + b"\x00" * (block_size - len(padded_key))

    print(f"\n[1] Padded key (K') ({len(padded_key)} bytes):")
    print(f"  {padded_key.hex()}")

    # Get inner and outer pad
    ipad = bytes([0x36] * block_size)
    opad = bytes([0x5C] * block_size)

    # XORing the key with both pads
    k_ipad = bytes(x ^ y for x, y in zip(padded_key, ipad))
    k_opad = bytes(x ^ y for x, y in zip(padded_key, opad))

    print("\n[2 & 3] XOR padded key with inner_pad (0x36) and outer_pad (0x5c):")
    print(f"  K_ipad (hex): {k_ipad.hex()[:32]}... (truncated)")
    print(f"  K_opad (hex): {k_opad.hex()[:32]}... (truncated)")

    # Inner pad + message concat and hashing
    inner_concat = k_ipad + message
    inner_hash = hashlib.sha256(inner_concat).digest()

    print("\n[4] Inner Hash ( SHA256(K_ipad + message) ):")
    print(f"  Data to hash (hex) : {inner_concat.hex()[:40]}... (truncated)")
    print(f"  Inner Hash Result  : {inner_hash.hex()}")

    # Outer pad + inned hash concat and hashing
    outer_concat = k_opad + inner_hash
    final_hmac = hashlib.sha256(outer_concat).hexdigest()

    print("\n[5] Outer Hash / Final HMAC ( SHA256(K_opad + Inner Hash) ):")
    print(f"  Data to hash (hex) : {outer_concat.hex()[:40]}... (truncated)")
    print(f"  FINAL HMAC RESULT : {final_hmac}")

    expected_hmac = hmac.new(key, message, hashlib.sha256).hexdigest()
    print("\n[6] Verification with Python's native hmac library:")
    print(f"  Native HMAC        : {expected_hmac}")
    print(
        f"  Do they match?     : {'✅ YES' if final_hmac == expected_hmac else '❌ NO'}"
    )


if __name__ == "__main__":
    length_extension_explanation()
    hmac_demo()
    hmac_step_by_step_demo()
