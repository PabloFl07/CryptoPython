"""
Password Hashing - POC educativo
=================================
Demuestra por qué el algoritmo y el salt importan,
y cómo comparar hashes de forma segura.

Secciones:
  1. Hashing débil (MD5 / SHA-1)
  2. Salt y rainbow tables
  3. Hashing moderno (bcrypt / Argon2)
  4. Timing attack

Dependencias: pip install bcrypt argon2-cffi
"""

import hashlib
import hmac
import time
import os
import bcrypt
from argon2 import PasswordHasher
import random
import string

# ====================================================================
# UNSAFE HASHING: Using general-purpose algorithms for passwords
# ====================================================================
#
# These algorithms are fast, deterministic, and lack a cost factor and built-in salt.
# That makes them unsuitable for password storing. 
# As they are vulnerable to brute-force attacks, rainbow tables, and GPU cracking.
# An attacker with a mid-range GPU can brute-force the entire 8-character password space in minutes.

def unsafe_hashing_demo():
    print("\n" + "=" * 70)
    print("UNSAFE HASHING DEMO: Using general-purpose algorithms for passwords")
    print("=" * 70)

    password = "password123"

    algorithms = (
        ("MD5", hashlib.md5),
        ("SHA-1", hashlib.sha1),
        ("SHA-256", hashlib.sha256),
        ("SHA-512", hashlib.sha512)
    )

    for name, func in algorithms:
        print(f"\n {name}\n{'─' * 10}")
        iterations = 500_000
        start = time.perf_counter()
        for _ in range(iterations):
            func(password.encode()).hexdigest()
        elapsed = time.perf_counter() - start

        print(f"[!] This CPU makes ~{iterations / elapsed:,.0f} hashes {name}/second")

    print("\nCONCLUSIONS:")
    print("- General-purpose hashing algorithms are far too fast for passwords. Attackers can brute-force millions of guesses per second.")
    print("- With a GPU alone, those numbers are thousands of times higher. Imagine what a dedicated brute-force hardware could do.")
    print("- On top of that, these algorithms are deterministic. Meaning that the same password will always produce the same hash.")

    password = "hellohash"

    print(f"\n[!] Determinism with SHA-256 using '{password}' password:")
    for _ in range(3):
        print(hashlib.sha256(password.encode()).hexdigest())

# ============================================================
# SALT AND RAINBOW TABLES
# ============================================================
#
# A rainbow table is a precomputed database of hash-to-password pairs. 
# If an attacker has the table and your hash, they can retrieve your password in milliseconds.
#
# The salt is a unique random value assigned to each user that is appended to the password before hashing. 
# Even if two users use the same password, their hashes will be different, rendering any precomputed table useless.

def salt_rainbow_demo():
    print("\n" + "=" * 60)
    print("SALT AND RAINBOW TABLES DEMO")
    print("=" * 60)
    salt_demo()
    rainbow_table_demo()

def random_string(length=5):
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choices(chars, k=length))

def salt_demo():
    password = "salty_password"
    print(f"Hashing '{password}' with 2 different salts:")

    salt_a = os.urandom(16)
    salt_b = os.urandom(16)

    print(f"\t1. {hashlib.sha256(salt_a + password.encode()).hexdigest()}")
    print(f"\t\t Salt:{salt_a.hex()}")
    print(f"\t2. {hashlib.sha256(salt_b + password.encode()).hexdigest()}")
    print(f"\t\t Salt:{salt_b.hex()}")

def rainbow_table_demo():
    common_passwords = ["password", "123456", "admin", "qwerty", "lethashit","monkey", "letmein", "abc123", "111111", "iloveyou","123123", "welcome", "password1", "admin123", "sunshine", "flower", "princess", "dragon", "football", "baseball", "master", "hello", "freedom", "whatever", "trustno1", "654321", "jordan23", "harley", "password123", "1234567890", "superman", "michael", "shadow", "killer", "batman", "hottie",]
    rainbow_table = {hashlib.sha256(p.encode()).hexdigest(): p for p in common_passwords}

    print(f"\nSIMPLE RAINBOW TABLE EXAMPLE (4 / {len(rainbow_table)} shown)\n"
    "───────────────────────────────────────────")
    for hash, pwd in list(rainbow_table.items())[:4]:
        print(f"{hash} → {pwd}")

    print("\nCase 1: The target password is in the rainbow table:")
    start = time.perf_counter()

    target_password = "superman"
    target_hash = hashlib.sha256(target_password.encode()).hexdigest()

    if target_hash in rainbow_table:
        found = rainbow_table[target_hash]
        elapsed = time.perf_counter() - start
        print(f"\t[+] Password found in rainbow table: '{found}'")
        print(f"\t[+] Time to retrieve: {elapsed:.8f} seconds (Almost instantaneous for a 36 entry table. In terms of complexity, O(1) lookup time.)")
    
    print("\nCase 2: The target password is not in the rainbow table so we try to brute-force:")

    start = time.perf_counter()

    for _ in range(2_000_000):
        password = random_string(8) # Remember that we didnt even include special characters and uppercase letters. So it doesnt take as long as it could
        if hashlib.sha256(password.encode()).hexdigest() == target_hash:
            print(f"\t[+] Password found by brute-force: '{password}'")
            break

    elapsed = time.perf_counter() - start
    print(f"\t[+] Time to brute-force 2 million hashes: {elapsed:.8f} seconds ( Str generation + hashing time + comparison time )")

    print("\nCase 3: The target password is salted and hashed, so we cannot use the rainbow table:")

    salt = os.urandom(16)
    salted_hash = hashlib.sha256(salt + target_password.encode()).hexdigest() # We use the same password as before, yet we cannot find it.

    print(f"\tHashed password: {salted_hash} ( We dont know if its salted or not, even then, we dont know the salt )")
    print(f"\t\tSalt used: {salt.hex()}")

    if salted_hash in rainbow_table:
        found = rainbow_table[salted_hash]
    else:
        print("\t[-] Password not found in rainbow table.")


    print("\nCONCLUSIONS:")
    print("- Following the conclussions from the previous section, generating a rainbow table with general-purpose hashing algorithms is trivial.")
    print("- Rainbow tables are effective against unsalted hashes, allowing attackers to reverse hashes to plaintext passwords in milliseconds.")
    print("- Salting hashes renders rainbow tables useless and makes brute-force attacks significantly more difficult.")
    print("- Even if we knew the salt, we would have to brute-force every possible password with that salt to find a match, which is computationally infeasible for strong passwords.")


# ============================================================
# MODERN HASHING — bcrypt and Argon2
# ============================================================
#   - Automatic and built-in salting
#   - Adjustable cost factor, helps them stay resistant as hardware improves
#   - Argon2 includes additionally memory hardness.
#
#  The difference is insignificant for a single hash (a few milliseconds) 
#  But decisive for an attacker trying billions of guesses.


def demo_hashing_moderno():
    print("\n" + "=" * 60)
    print("MODERN HASHING — bcrypt and Argon2")
    print("=" * 60)

    password = "typical_password"

    print("\n1. Hashing with bcrypt")
    start = time.perf_counter()
    hashed_bcrypt = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    elapsed_bcrypt = time.perf_counter() - start

    print(f"  Hash  : {hashed_bcrypt.decode()}")
    print(f"  Time  : {elapsed_bcrypt * 1000:.1f} ms")


    print("\n2. Hashing with Argon2")
    ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

    start = time.perf_counter()
    hashed_argon2 = ph.hash(password)
    elapsed_argon2 = time.perf_counter() - start

    print(f"  Hash  : {hashed_argon2}")
    print(f"  Time  : {elapsed_argon2 * 1000:.1f} ms")

    print("\nTime comparison:")
    print("  MD5    : ~0.0001 ms  ← unfeasible for password hashing")
    print(f"  bcrypt : {elapsed_bcrypt * 1000:.1f} ms")
    print(f"  Argon2 : {elapsed_argon2 * 1000:.1f} ms")

    print("\nCONCLUSIONS:")
    print("- bcrypt and Argon2 are designed for password hashing, so they provide features that make hashes resistant to many types of attacks.")
    print("- On top of that, they allow you to verify passwords easily.")


# ============================================================
# TIMING ATTACK
# ============================================================
#
# A naive string comparison (== in Python) short-circuits:
# it stops at the first differing character. This means it
# takes slightly longer to reject a hash that almost matches.
# An attacker who can measure those times precisely enough
# can deduce how many characters of the hash they've already
# guessed correctly.
#
# hmac.compare_digest() always compares every byte regardless
# of where the difference is. Constant time → no information
# leaked.
#
# NOTE: This effect is subtle in Python and can be masked by
# OS noise. It is much more pronounced in C or Rust, or with
# dedicated measurement hardware. The important takeaway is
# the principle: always use compare_digest() for any manual
# comparison of tokens, API keys, or hashes you implement
# yourself. bcrypt.checkpw() and Argon2's ph.verify() already
# do this internally.

def demo_timing_attack():
    print("\n" + "=" * 60)
    print("TIMING ATTACK DEMO")
    print("=" * 60)

    password = "time_flies"

    stored_hash = hashlib.sha256(password.encode()).hexdigest()

    almost_correct = stored_hash[:-1] + ("a" if stored_hash[-1] != "a" else "b")

    RUNS = 100_000

    # Insecure: stops at the first differing character
    start = time.perf_counter()
    for _ in range(RUNS):
        result = (stored_hash == almost_correct)
    time_insecure = (time.perf_counter() - start) / RUNS

    # Secure: always compares every byte
    start = time.perf_counter()
    for _ in range(RUNS):
        result = hmac.compare_digest(stored_hash, almost_correct)
        if result:
            pass
    time_secure = (time.perf_counter() - start) / RUNS

    print(f"\nStored hash : {stored_hash}")
    print(f"Almost same : {almost_correct}")
    print(f"\n  ==               : {time_insecure * 1e9:.2f} ns/op  ← variable time")
    print(f"  compare_digest() : {time_secure * 1e9:.2f} ns/op  ← constant time")

    print("\nCONCLUSIONS:")
    print("- With millions of measurements the nanosecond difference becomes statistically exploitable.")
    print("- An attacker who can measure those times precisely enough can deduce how many characters of the hash they've already guessed correctly")
    print("- Always use hmac.compare_digest() for manual comparisons of hashes, tokens, or API keys to prevent timing attacks.")

if __name__ == "__main__":
    unsafe_hashing_demo()
    salt_rainbow_demo()
    demo_hashing_moderno()
    demo_timing_attack()