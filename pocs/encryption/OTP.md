+# One-Time Pad (OTP)

The One-Time Pad (OTP) is an encryption technique that combines a plaintext message with a secret key using bitwise XOR operations. It was invented in 1917 by AT&T engineer Gilbert Vernam and U.S. Army Cryptanalysis Chief Joseph Mauborgne.

The security of the system was mathematically proven in 1949 by Claude Shannon, establishing the One-Time Pad as the only information-theoretically secure encryption method known to exist (perfect secrecy).

> When properly implemented with a truly random key used only once, an OTP ciphertext provides absolute confidentiality that cannot be broken by any amount of computational power or time.

The most critical weakness of OTP is not mathematical, but practical: distributing, managing, and securely destroying keys that are as long as the messages themselves.

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


## How it works

1. **Key Generation** ($K$)

A truly random key $K$ is generated with the **exact same length** as the plaintext message $m$.

2. **Encryption** (First Pass)

An XOR ($\oplus$) operation is performed between each bit of the plaintext $m$ and the key $K$:

$$C = m \oplus K$$

3. **Decryption** (Reverse Pass)

Because XOR is its own inverse, the receiver performs an XOR operation between the ciphertext $C$ and the same secret key $K$ to recover the original message $m$:

$$m = C \oplus K = (m \oplus K) \oplus K$$

### Key Cryptographic Requirements
- **Key Length ($K$)**: The key must be at least as long as the plaintext message ($\vert{}K\vert{} \ge \vert{}m\vert{}$).
- **True Randomness**: Keys must be generated using a cryptographically secure random number generator (CSPRNG, e.g., `/dev/urandom` or `secrets`).
- **Single-Use Guard**: A key must **never** be reused under any circumstances.

Violating rule 3 does not merely weaken the cipher — it destroys it entirely. Two ciphertexts under the same key expose `P1 ⊕ P2` directly, and crib dragging can reconstruct both plaintexts without the key ever being known.

## Why an eavesdropper can't break it

An attacker intercepting the ciphertext $C$ gains zero statistical information about the original message $m$. <br>
For any given ciphertext $C$, **every possible plaintext** of that length is equally likely, because for every candidate message $m'$, there exists a valid key $K' = C \oplus m'$ that would produce that exact ciphertext. Thus, brute-force search is mathematically useless.

## ⚠️ Important security notes

- **Key Reuse Catastrophe.** Reusing a key across two messages ($C_1 = m_1 \oplus K$ and $C_2 = m_2 \oplus K$) completely destroys security. An attacker can compute:
  
  $$C_1 \oplus C_2 = (m_1 \oplus K) \oplus (m_2 \oplus K) = m_1 \oplus m_2$$

  This eliminates the key $K$ and allows the attacker to recover both plaintexts using **Crib Dragging** attacks.
- **OTP does not provide integrity or authenticity.** An attacker can modify bits of the ciphertext $C$ in transit, causing predictable bit flips in the decrypted message without detection.
- **Key Distribution Problem.** Securely delivering a secret key as large as the message itself is as difficult as sending the message securely in the first place.
