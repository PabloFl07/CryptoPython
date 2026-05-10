# password_hashing.py — Why Password Hashing Is Not Just Hashing

An educational Python script that demonstrates why using general-purpose hash functions to store passwords is dangerous, what salt does and why it matters, how modern password hashing algorithms work, and how timing attacks exploit naive hash comparisons. Each section is a self-contained, runnable demo with annotated output.

---

## What it does

The script builds a progressive argument from first principles: it starts by showing how fast general-purpose algorithms are (and why that is a problem), introduces salting and rainbow tables with a live lookup, compares those against bcrypt and Argon2, and closes with a subtle but real side-channel: timing attacks on string comparison. It is intended as a hands-on companion to security study, not as a production utility.

---

## Concepts covered

| Concept | How it appears in this project |
|---|---|
| **General-purpose vs. password hashing** | MD5, SHA-1, SHA-256, and SHA-512 are benchmarked to show their throughput. Speed is a feature for data integrity but a liability for passwords. |
| **Brute-force and GPU cracking** | The hash-per-second figures are put in context: a mid-range GPU multiplies them by thousands, making unsalted fast hashes trivially reversible. |
| **Determinism as a weakness** | The same password always produces the same hash. Demonstrated live: three identical SHA-256 outputs for the same input. |
| **Rainbow tables** | A precomputed hash→password table is built and queried. A known password is found with O(1) lookup in microseconds. |
| **Salt** | A random per-user value prepended to the password before hashing. Demonstrated by hashing the same password with two different salts and showing the outputs are completely unrelated. Renders rainbow tables useless. |
| **bcrypt** | Deliberately slow, with a tunable `rounds` cost factor and automatic salting. Hash includes the salt, algorithm, and cost — everything needed for verification. |
| **Argon2** | Winner of the Password Hashing Competition (2015). Adds memory hardness (`memory_cost`) on top of time cost, defeating GPU and ASIC attacks. |
| **Timing attacks** | A naive `==` comparison short-circuits on the first differing byte, leaking information about how close a guess is. `hmac.compare_digest()` always runs in constant time regardless of where the mismatch occurs. |

---

## The four demos

### 1 — Unsafe Hashing
Benchmarks MD5, SHA-1, SHA-256, and SHA-512 over 500,000 iterations each and prints hashes per second. Shows determinism by hashing the same password three times.

### 2 — Salt & Rainbow Tables
Builds a 36-entry rainbow table of common passwords and runs three cases: instant lookup for a known password, 2-million-attempt brute-force for one that is not in the table, and a salted hash that defeats the table entirely.

### 3 — Modern Hashing
Hashes the same password with bcrypt (cost 12) and Argon2 (time cost 3, 64MB memory) and prints the elapsed time for each. Places them in a comparison table alongside MD5 to make the deliberate slowness concrete.

### 4 — Timing Attack
Compares a stored SHA-256 hash against an almost-identical string using `==` and `hmac.compare_digest()` over 100,000 runs each, printing the nanoseconds-per-operation difference and explaining how that gap becomes exploitable at scale.

---

## Requirements

```
pip install bcrypt argon2-cffi
```

Python 3.6+ required.

---


## Key takeaways

- **Never use MD5, SHA-1, or SHA-256 to store passwords.** They are designed to be fast. Fast is the enemy of secure password storage.
- **Always salt.** Without a unique per-user salt, identical passwords produce identical hashes and rainbow tables become trivial.
- **Use bcrypt or Argon2 in production.** Their cost factors can be increased as hardware improves, keeping the work factor ahead of attackers without changing the stored hash format.
- **Never compare hashes with `==`.** Always use `hmac.compare_digest()` or the built-in verify methods of bcrypt and Argon2, which handle this internally.