# OTP.py — One-Time Pad: From Perfect Secrecy to Complete Breakage

An educational Python script that demonstrates the full lifecycle of the One-Time Pad cipher — from its theoretical guarantee of perfect secrecy to the catastrophic consequences of misusing it. Each section is a self-contained, runnable demo with annotated output.

---

## What it does

The script walks through four progressive demos that together tell the complete story of OTP: how it works, why it is theoretically unbreakable, and exactly how it collapses the moment a single rule is violated. It is intended as a hands-on companion to cryptography study, not as a production tool.

---

## Concepts covered

| Concept | How it appears in this project |
|---|---|
| **One-Time Pad (OTP)** | XOR-based symmetric cipher where a truly random key of the same length as the plaintext produces the ciphertext. Encryption and decryption are identical operations. |
| **XOR and its properties** | `P ⊕ K = C` and `C ⊕ K = P`. XOR is its own inverse, which is what makes OTP work — and also what makes key reuse fatal. |
| **Perfect secrecy (Shannon)** | Without the key, every possible plaintext of the correct length is equally likely. No statistical test or brute-force search can distinguish the real plaintext from any other candidate. |
| **Cryptographically secure randomness** | Keys are generated with `secrets.token_bytes`, which uses the OS CSPRNG (`/dev/urandom` on Linux/macOS). This is required for OTP's security guarantees — `random` would break them. |
| **Key reuse attack** | Encrypting two messages with the same key allows an attacker to compute `C1 ⊕ C2 = P1 ⊕ P2`, completely cancelling the key and directly exposing a relationship between both plaintexts. |
| **Crib dragging** | A known-plaintext attack on key-reused OTP. A guessed word (crib) is slid across `P1 ⊕ P2` position by position. When aligned correctly, it cancels its own plaintext and reveals a readable fragment of the other message. |

---

## The four demos

### 1 — OTP: Encryption & Decryption
Basic encrypt/decrypt cycle. Shows that the same message produces different ciphertext every run (due to a fresh random key), and that decryption with a wrong key yields garbage.

### 2 — Perfect Secrecy
Demonstrates why brute force is meaningless against OTP. For any ciphertext, the attacker can construct a key that maps it to *any* candidate plaintext of the same length — all results look equally valid, so there is no way to identify the real one without the key.

### 3 — Key Reuse Attack
Shows that XOR-ing two ciphertexts produced with the same key cancels it: `C1 ⊕ C2 = P1 ⊕ P2`. Contrasted against `C1 ⊕ C3` (different key), which produces meaningless output, making the vulnerability immediately visible.

### 4 — Crib Dragging
Implements and runs a full crib-dragging attack. A list of suspected words is slid across `P1 ⊕ P2` byte by byte; wherever a crib aligns with its plaintext, the other message appears in clear. Demonstrates how both messages can be reconstructed without ever knowing the key.

---

## Requirements

No third-party dependencies. Standard library only.

```
Python 3.6+
```

---


## Output structure

```
────────────────────────────────────────────────────────────
  OTP DEMO - ENCRYPTION & DECRYPTION
────────────────────────────────────────────────────────────
...

────────────────────────────────────────────────────────────
  PERFECT SECRECY — Brute force is useless
────────────────────────────────────────────────────────────
...

────────────────────────────────────────────────────────────
  KEY REUSE ATTACK
────────────────────────────────────────────────────────────
...

────────────────────────────────────────────────────────────
  CRIB DRAGGING — Retrieve plaintext with known words
────────────────────────────────────────────────────────────
...
```

---

## Key takeaways

The OTP has three strict requirements that must all hold simultaneously:

1. **The key must be exactly as long as the plaintext.**
2. **The key must be truly (cryptographically) random.**
3. **The key must never be reused — for any purpose, with any message.**

Violating rule 3 does not merely weaken the cipher — it destroys it entirely. Two ciphertexts under the same key expose `P1 ⊕ P2` directly, and crib dragging can reconstruct both plaintexts without the key ever being known.

This is why OTP is impractical despite being theoretically perfect: securely distributing a key as long as every message you will ever send is, in practice, harder than the original problem.