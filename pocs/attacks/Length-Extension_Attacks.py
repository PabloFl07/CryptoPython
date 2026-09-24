#!/usr/bin/env python3

import hashlib
import hmac
import struct


"""
Length Extension Attack - Educational PoC
=========================================
Demonstration of a non-functional length extension attack for educational purposes. Covers the main steps and mitigation measures. 
It does not simulate a real attack, as this process is highly dependent on the specific implementation and context.
1. Calculates the length of the secret key using brute force.
2. Reproduces the hash padding to craft a malicious payload.
3. Mitigates the attack using HMAC to demonstrate secure message authentication.
"""


def separator(title: str = "") -> None:
    if title:
        print(f"\n{'─' * 60}")
        print(f"  {title}")
        print(f"{'─' * 60}")
    else:
        print(f"{'─' * 60}")

    print()


def subtitle(subtitle: str) -> None:
    print(f"\n{subtitle}")
    print("─" * 10)  # Adjust to the length of the subtitle


# ═══════════════════════════════════════════════════════════════════════════════════════════


def sha256_padding(message_length):
    """Calculates the exact SHA-256 padding for a given message length in bytes."""
    bit_length = message_length * 8
    padding = b"\x80"
    while (message_length + len(padding)) % 64 != 56:
        padding += b"\x00"
    padding += struct.pack(">Q", bit_length)
    return padding


# ══════════════════════════════════════════════════════════════════════════════
# LENGTH EXTENSION ATTACK DEMO
# ══════════════════════════════════════════════════════════════════════════════

# 1. The attacker observes a legitimate message (e.g., user=guest) and its corresponding signature/hash.
# 2. By loading the output hash into a custom hash engine as its initial internal state, the attacker bypasses the requirement of knowing the SecretKey.
# 3. The attacker appends malicious parameters (e.g., &role=admin) along with the computed glue/padding bytes.
# 4. The application recalculates Hash(SecretKey + UserData + Padding + MaliciousData) and finds a perfect match, authorizing the request.


def length_extension_attack_demo():
    separator("Simulating a Length Extension Attack")

    key = b"supersecretkey12345"  # n bytes (hidden from attacker)
    original_message = b"count=10&user=alice"  # 19 bytes
    original_hash = hashlib.sha256(key + original_message).hexdigest()

    append_data = b"&role=admin"

    print("[+] Intercepted Data:")
    print(f"    Original Message : {original_message.decode()}")
    print(f"    Original Hash    : {original_hash}\n")

    # GUESSING SECRET LENGTH (BRUTE FORCE)
    # ═════════════════════════════════════

    print("[1] Attacker iterates over possible secret key lengths (Brute Force):")

    found_key_len = None
    for guessed_key_len in range(1, 65):
        total_length = guessed_key_len + len(original_message)
        glue_padding = sha256_padding(total_length)
        malicious_payload = original_message + glue_padding + append_data

        # Simulated check against the server
        simulated_hash = hashlib.sha256(key + malicious_payload).hexdigest()
        server_verification_hash = hashlib.sha256(key + malicious_payload).hexdigest()

        if simulated_hash == server_verification_hash and guessed_key_len == len(key):
            found_key_len = guessed_key_len
            print(f"    [✔] Success! Valid key length found: {found_key_len} bytes\n")
            break

    # Construct the full tampered payload using the discovered key length
    total_original_length = found_key_len + len(original_message)

    glue_padding = sha256_padding(total_original_length)
    malicious_payload = original_message + glue_padding + append_data

    print("[2] Attacker crafts the malicious payload by reproducing the hash padding:")
    print(f"    Malicious Payload (hex): {malicious_payload.hex()}")

    # VISUALIZATION OF THE TAMPERED MESSAGE
    # ══════════════════════════════════════

    print("\n[+] PAYLOAD STRUCTURE BREAKDOWN:")
    print("    1. Original Data :", original_message.decode())
    print("    2. Glue Padding  :", glue_padding)
    print("    3. Injected Data :", append_data.decode())

    simulated_attacker_hash = hashlib.sha256(
        key + original_message + glue_padding + append_data
    ).hexdigest()

    print("\n[3] Attacker generates the forged signature (using tools like HashPump):")
    print(f"    Forged Hash   : {simulated_attacker_hash}")

    print("\n[+] Server receives the request and verifies the signature naively...")
    server_verification_hash = hashlib.sha256(key + malicious_payload).hexdigest()

    print(f"    Server calculated : {server_verification_hash}")

    if simulated_attacker_hash == server_verification_hash:
        print(
            "    Result            : ✅ BYPASS SUCCESSFUL! Server accepted the tampered payload."
        )
    else:
        print("    Result            : ❌ Bypass failed.")

    # DEFENSIVE DEMONSTRATION: HMAC MITIGATION
    # ════════════════════════════════════════

    separator("Mitigation using HMAC (Hash-based MAC)")

    # Server using HMAC
    valid_hmac = hmac.new(key, original_message, hashlib.sha256).hexdigest()
    print("[+] Server signs message with HMAC-SHA256:")
    print(f"    Original Message : {original_message.decode()}")
    print(f"    HMAC Signature   : {valid_hmac}")

    # Server verifies the tampered payload
    server_hmac_check = hmac.new(key, malicious_payload, hashlib.sha256).hexdigest()
    print("\n[+] Server verifies the tampered request using HMAC:")
    print(f"    Attacker's Hash   : {simulated_attacker_hash}")
    print(f"    Server calculated : {server_hmac_check}")

    if simulated_attacker_hash != server_hmac_check:
        print(
            "    Result            :  ✅ REJECTED! HMAC prevents length extension attacks."
        )


if __name__ == "__main__":
    length_extension_attack_demo()

    subtitle("[+] EXTRA:")
    print(
        "Change the length of the secret key in the code to see how the hash changes starting from the padding"
    )
