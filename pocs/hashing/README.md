# Password Hashing

A hands-on demonstration of why the choice of hashing algorithm matters,
what salting is and why it defeats rainbow tables, and how to compare
hashes safely to prevent timing attacks.

## Setup

```bash
pip install bcrypt argon2-cffi
python password_hashing.py
```

---

## Sections

### 1. Unsafe hashing — MD5, SHA-1, SHA-256, SHA-512

General-purpose hashing algorithms are fast, deterministic, and lack both
a cost factor and built-in salt. That makes them unsuitable for storing
passwords: an attacker with a mid-range GPU can brute-force the entire
8-character password space in minutes. On top of that, being deterministic
means the same password always produces the same hash.

**Example output:**
```
======================================================================
UNSAFE HASHING DEMO: Using general-purpose algorithms for passwords
======================================================================

 MD5
──────────
[!] This CPU makes ~2,086,386 hashes MD5/second

 SHA-1
──────────
[!] This CPU makes ~2,326,854 hashes SHA-1/second

 SHA-256
──────────
[!] This CPU makes ~2,343,894 hashes SHA-256/second

 SHA-512
──────────
[!] This CPU makes ~1,389,257 hashes SHA-512/second

CONCLUSIONS:
- General-purpose hashing algorithms are far too fast for passwords. Attackers can brute-force millions of guesses per second.
- With a GPU alone, those numbers are thousands of times higher. Imagine what a dedicated brute-force hardware could do.
- On top of that, these algorithms are deterministic. Meaning that the same password will always produce the same hash.

[!] Determinism with SHA-256 using 'hellohash' password:
7db05a5225357d9d4a5c6fbf23978fd8d32e1162c085908c1eec3dd069c8e3f0
7db05a5225357d9d4a5c6fbf23978fd8d32e1162c085908c1eec3dd069c8e3f0
7db05a5225357d9d4a5c6fbf23978fd8d32e1162c085908c1eec3dd069c8e3f0
```

---

### 2. Salt and rainbow tables

A rainbow table is a precomputed database of `hash → password` pairs. If an
attacker has the table and your hash, they can retrieve the plaintext password
in milliseconds.

A salt is a unique random value assigned per user that is appended to the
password before hashing. Even if two users share the same password, their
hashes will differ — rendering any precomputed table useless. Even if an
attacker knows the salt, they would have to brute-force every possible
password combined with that salt, which is computationally infeasible for
strong passwords.

**Example output:**
```
============================================================
SALT AND RAINBOW TABLES DEMO
============================================================
Hashing 'salty_password' with 2 different salts:
        1. 7b34841bb9da9c78652e76c2b19eee2e0504af08d7e25d68f62d951b1e32014b
                 Salt:c5e85e7e0ada4e9cd53ddc8fe30be273
        2. 3d65d0d2fb6bd543cd75225c3a5a37b6782106f672dad8b603f912ea281ab3a9
                 Salt:b46a65ac41d2743d2c9c159da0f608ec

SIMPLE RAINBOW TABLE EXAMPLE (4 / 36 shown)
───────────────────────────────────────────
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 → password
8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92 → 123456
8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 → admin
65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5 → qwerty

Case 1: The target password is in the rainbow table:
        [+] Password found in rainbow table: 'superman'
        [+] Time to retrieve: 0.00000269 seconds (Almost instantaneous for a 36 entry table. In terms of complexity, O(1) lookup time.)

Case 2: The target password is not in the rainbow table so we try to brute-force:
        [+] Time to brute-force 2 million hashes: 3.66218535 seconds ( Str generation + hashing time + comparison time )

Case 3: The target password is salted and hashed, so we cannot use the rainbow table:
        Hashed password: 59aa5b2e962a2bcd2947b0b9fee6755e5815a9bd5a5bb11e3f58e55f976c0cfc ( We dont know if its salted or not, even then, we dont know the salt )
                Salt used: d138dd49c0a764bac3b8f206fa0194e4
        [-] Password not found in rainbow table.

CONCLUSIONS:
- Following the conclussions from the previous section, generating a rainbow table with general-purpose hashing algorithms is trivial.
- Rainbow tables are effective against unsalted hashes, allowing attackers to reverse hashes to plaintext passwords in milliseconds.
- Salting hashes renders rainbow tables useless and makes brute-force attacks significantly more difficult.
- Even if we knew the salt, we would have to brute-force every possible password with that salt to find a match, which is computationally infeasible for strong passwords.
```

---

### 3. Modern hashing — bcrypt and Argon2

bcrypt (1999) and Argon2 (winner of the Password Hashing Competition, 2015)
are designed specifically for passwords. Their key advantages over
general-purpose algorithms:

- **Built-in salt** — generated automatically, stored as part of the hash.
- **Adjustable cost factor** — can be made slower as hardware improves.
- **Memory hardness** (Argon2 only) — requires a significant amount of RAM,
  which limits attacks from GPUs and ASICs.

The extra time per hash (~100 ms) is insignificant for a legitimate user
logging in once, but decisive for an attacker trying billions of guesses.

**Example output:**
```
============================================================
MODERN HASHING — bcrypt and Argon2
============================================================

1. Hashing with bcrypt
  Hash  : $2b$12$tU3YppK6Fs/WQxu7hrJ/IeR5d8jmLH.2imSYUKZAu7/mtqtBj.4Va
  Time  : 252.9 ms

2. Hashing with Argon2
  Hash  : $argon2id$v=19$m=65536,t=3,p=4$VW/wzSr8yu1nElGaDefkmQ$MoSZmuxGLk0VBhocikpUgBhZfOwsuNV+tGcg1xg/Ypw
  Time  : 77.8 ms

Time comparison:
  MD5    : ~0.0001 ms  ← unfeasible for password hashing
  bcrypt : 252.9 ms
  Argon2 : 77.8 ms

CONCLUSIONS:
- bcrypt and Argon2 are designed for password hashing, so they provide features that make hashes resistant to many types of attacks.
- On top of that, they allow you to verify passwords easily.
```

---

### 4. Timing attack

A naive string comparison (`==` in Python) short-circuits: it stops at the
first differing character. This means it takes slightly longer to reject a
hash that almost matches. An attacker who can measure those times precisely
enough can deduce how many characters of a hash they have already guessed.

`hmac.compare_digest()` always compares every byte regardless of where the
difference is, keeping execution time constant and leaking no information.

> **Note:** This effect is subtle in Python and can be masked by OS noise.
> It is much more pronounced in C or Rust, or with dedicated measurement
> hardware. The key takeaway is the principle: always use `compare_digest()`
> for any manual comparison of hashes, tokens, or API keys.
> `bcrypt.checkpw()` and Argon2's `ph.verify()` already do this internally.

**Example output:**
```
============================================================
TIMING ATTACK DEMO
============================================================

Stored hash : 74d0816d5ac0328d980a75a04acca3a9f33508255eaf83e48ac7df871cd5367c
Almost same : 74d0816d5ac0328d980a75a04acca3a9f33508255eaf83e48ac7df871cd5367a

  ==               : 42.30 ns/op  ← variable time
  compare_digest() : 77.54 ns/op  ← constant time

CONCLUSIONS:
- With millions of measurements the nanosecond difference becomes statistically exploitable.
- An attacker who can measure those times precisely enough can deduce how many characters of the hash they've already guessed correctly
- Always use hmac.compare_digest() for manual comparisons of hashes, tokens, or API keys to prevent timing attacks.
```

---

## References

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Argon2 specification](https://github.com/P-H-C/phc-winner-argon2)
- [bcrypt](https://pypi.org/project/bcrypt/)