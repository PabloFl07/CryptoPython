#!/usr/bin/env python3

import secrets

# ══════════════════════════════════════════════════════════════════════════════
# Utils
# ══════════════════════════════════════════════════════════════════════════════


def to_hex(b: bytes) -> str:
    return b.hex().upper()

def printable_or_dot(b: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)

def separator(title: str = "") -> None:
    if title:
        print(f"\n{'─' * 60}")
        print(f"  {title}")
        print(f"{'─' * 60}")
    else:
        print(f"{'─' * 60}")

# ══════════════════════════════════════════════════════════════════════════════
# OTP
# ══════════════════════════════════════════════════════════════════════════════
# Requirements:
# - The key must be the EXACT same length as the plaintext.
# - The key must be truly random.
# - The key must be used only once (hence the name "one-time").

# Plaintext (P) ⊕ Key (K) = Ciphertext (C)

# "ATTACK" ⊕ "XKQPZL" = "9F2C1A"   

# [!] As XOR is its own inverse: 

# Ciphertext (C) ⊕ Key (K) = Plaintext (P)

# "9F2C1A" ⊕ "XKQPZL" = "ATTACK"

def generate_key(length: int) -> bytes:
    return secrets.token_bytes(length)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def otp_encrypt(plaintext: bytes, key: bytes) -> bytes:
    if len(key) != len(plaintext):
        raise ValueError("The key must be the EXACT same length as the plaintext.")
    return xor_bytes(plaintext, key)

def otp_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    return xor_bytes(ciphertext, key)


def demo_otp() -> None:
    separator("OTP DEMO - ENCRYPTION & DECRYPTION")

    message = b"HOLA"   # 4 bytes
    key     = generate_key(len(message))
    cipher  = otp_encrypt(message, key)
    recovered = otp_decrypt(cipher, key)

    print(f"Original message: {message.decode()}")
    print(f"Random key: {to_hex(key)}")

    print(f"\n[!] Original ciphertext: {to_hex(cipher)}")

    print(f"\t 1. Same message, same key: {to_hex(otp_encrypt(message, key))} ")
    print(f"\t 2. Same message, different key: {to_hex(otp_encrypt(message, generate_key(len(message))))}")
    print(f"\t 3. Different message, same key: {to_hex(otp_encrypt(b'ADIO', key))}")
    print("\t 4. Different message and different key produce a completely different ciphertext.")

    print(f"\n[!] Recovered message with the correct key: {recovered.decode()}")
    print(f"\t Message recovered with random key: {to_hex(otp_decrypt(cipher, generate_key(len(message))))}  (garbage, doesn't look like any message)")


# ══════════════════════════════════════════════════════════════════════════════
# PERFECT SECRECY
# ══════════════════════════════════════════════════════════════════════════════

# Perfect secrecy means that the ciphertext does not reveal any information about the original message.

# For any given ciphertext, all possible plaintexts of the same length are equally likely to be the original. 
# Because for any ciphertext, there exists a key that can produce any of those plaintexts.
# Therefore, without the key, an attacker cannot determine which plaintext is the real one.
# Even if they try all possible plaintexts, everyone will "look valid", yet there is no way to know the real one.

def demo_perfect_secrecy() -> None:
    separator("PERFECT SECRECY — Brute force is useless")
 
    real_msg = b"THIS IS SERIOUS1"   # 16 bytes
    key      = generate_key(len(real_msg))
    cipher   = otp_encrypt(real_msg, key)
 
    candidates = [  
        b"THIS IS SERIOUS1",  # The attacker doesn't know its the real one
        b"SAME LENGTH MSG1",
        b"ANOTHER ONE HERE",
    ]

    print(f"You intercept this ciphertext:\n\tC = {to_hex(cipher)}")
    print("\nYou dont have the key so you try candidate messages of the same size, and for each one, you calculate the key that would produce it:\n\tcandidate ⊕ K = C -> K = C ⊕ candidate")
    print("\nAnd you decrypt C with that key.")
 
 
    print(f"  {'Candidate':<20}  {'Calculated Key':<34}  Result after decrypting C with that key")
    print(f"  {'─'*20}  {'─'*34}  {'─'*24}")
 
    for candidate in candidates:
        candidate_key = xor_bytes(cipher, candidate)   # K = C XOR candidate
        decrypted     = otp_decrypt(cipher, candidate_key)   # C XOR K = candidate
        print(f"  {candidate.decode():<20}  {to_hex(candidate_key):<34}  '{decrypted.decode()}' ✓")
 

    print("\nYou will always get the candidate back as the decrypted message because the key was calculated with that candidate.\nAs you can see, all candidates produce a valid message, and there is no way to know which one is the real one.\nThis is perfect secrecy: the ciphertext does not reveal any information about the original message.")

    print("\nCONCLUSIONS:")
    print("- OTP provides perfect secrecy: without the key, the ciphertext does not reveal any information about the original message.")
    print("- All possible plaintexts are equally likely to be the original message.")
    print("- For each plaintext, there exists a key that can produce it from a ciphertext.")

# ══════════════════════════════════════════════════════════════════════════════
# KEY REUSE
# ══════════════════════════════════════════════════════════════════════════════

# Using the XOR properties, we can get a relationship between two plaintexts without ever knowing the key.
# By XORing two ciphertexts that used the same key.
#           C1 ⊕ C2 = (P1 ⊕ K) ⊕ (P2 ⊕ K) -> P1 ⊕ P2
# This will allow the recovery of fragments of both messages, and eventually, the reconstruction of the original plaintexts without ever knowing the key.

def demo_key_reuse() -> None:
    separator("KEY REUSE ATTACK")

    p1 = b"NEW YORK"
    p2 = b"OLD YORK"

    key = generate_key(len(p1))
    c1  = otp_encrypt(p1, key)
    c2  = otp_encrypt(p2, key)

    # We use a different key.
    c3 = otp_encrypt(p2, generate_key(len(p1)))  

    c1_xor_c2 = xor_bytes(c1, c2)
    p1_xor_p2 = xor_bytes(p1, p2)

    print("[1] Two plaintext messages:\n\tP1: 'NEW YORK'\n\tP2: 'OLD YORK'\n")

    print(f"[2] Encrypt both with the same key:\n\tC1 = P1 ⊕ K -> {to_hex(c1)}\n\tC2 = P2 ⊕ K -> {to_hex(c2)}\n")

    print(f"[3] Attacker intercepts C1 and C2, and computes C1 ⊕ C2:\n\tC1 ⊕ C2 = {to_hex(c1_xor_c2)}")

    print(f"\n[4] Exploiting the properties of XOR: C1 ⊕ C2 = (P1 ⊕ K) ⊕ (P2 ⊕ K) -> P1 ⊕ P2:\n\tP1 ⊕ P2 = {to_hex(p1_xor_p2)} == {to_hex(c1_xor_c2)} (C1 ⊕ C2)")

    print(f"\n[!] C1 ⊕ C3 (same plaintext, different key) = {to_hex(xor_bytes(c1, c3))}  (garbage, no relation with P1 ⊕ P2)")

    print("\nCONCLUSIONS:")
    print("- Reusing the key for different messages is a fatal mistake that completely destroys the security of the OTP.")
    print("- Computing C1 ⊕ C2 cancels the key and gives you P1 ⊕ P2, which is a direct relationship between the two plaintexts.")
    print("- As we will see in the next section, this allows the attacker to recover fragments of both messages, and with enough known words (cribs), reconstruct the original plaintexts without ever knowing the key.")

# ══════════════════════════════════════════════════════════════════════════════
# CRIB DRAGGING
# ══════════════════════════════════════════════════════════════════════════════

# 1. You guess a word likely to appear in P1, for example "HELLO"
# 2. You slide it across P1 XOR P2 position by position
# 3. At the right position, "HELLO" cancels out with P1 and the result is a readable fragment of P2 in plaintext
# 4. That fragment confirms the crib was placed correctly, and also gives you information about P2
# 5. You take that P2 fragment and do the same in reverse, extracting more of P1
# 6. Repeat until both messages are fully reconstructed

# Sliding a word that appears in P1 reveals information about P2 and viceversa.

#  xored[i:i+n] XOR crib = (P1[i:i+n] XOR P2[i:i+n]) XOR P1[i:i+n] = P2[i:i+n]


def crib_drag(xored: bytes, crib: bytes) -> list[tuple[int, str, bool]]:
    """
    Slides the crib across xored = P1 XOR P2.

    If the crib appears in P1 at position i:
        xored[i:i+n] XOR crib = (P1[i:i+n] XOR P2[i:i+n]) XOR P1[i:i+n]
                               = P2[i:i+n]

    So we obtain a fragment of the other message in plaintext.

    [!] Note: fragment.decode() will raise UnicodeDecodeError on non-UTF-8 bytes.
    This is intentional — the demo uses controlled messages where all XOR results
    are valid ASCII, so no error handling is needed here.
    """
    results = []
    n = len(crib)
    for i in range(len(xored) - n + 1):
        fragment = xor_bytes(xored[i : i + n], crib)
        text     = fragment.decode()
        results.append((i, text))
    return results

def demo_crib_dragging() -> None:
    separator("CRIB DRAGGING — Retrieve plaintext with known words")

    p1 = b"HELLO HELLO HELLO HELLO"
    p2 = b"BYEEE BYEEE BYEEE BYEEE"

    key   = generate_key(len(p1))
    c1    = otp_encrypt(p1, key)
    c2    = otp_encrypt(p2, key)
    xored = xor_bytes(c1, c2)

    print(f"The attacker only has:\n\tC1 XOR C2 = {to_hex(xored)}")
    
    print("\nThey suspect both messages follow a known pattern so they try candidate words ('cribs') and slide them across all positions.\nIf the result looks like readable text, they found a fragment of the other message.\n")

    cribs = [b"BYEEE", b"HELLO"]

    for crib in cribs:
        hits = [(pos, frag) for pos, frag in crib_drag(xored, crib)]
        if hits:
            print(f"  Crib '{crib.decode()}':")
            for pos, frag in hits:
                print(f"    Pos {pos:2d} → fragment of the other message: '{frag}'")

    print("\nWith enough cribs, fragments of both messages are recovered. By cross-confirming fragments, P1 and P2 can be fully reconstructedwithout ever knowing K.")

    print(f"Real P1: {p1.decode()}\nReal P2: {p2.decode()}")



# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════







if __name__ == "__main__":
    demo_otp()
    demo_perfect_secrecy()
    demo_key_reuse()
    demo_crib_dragging()