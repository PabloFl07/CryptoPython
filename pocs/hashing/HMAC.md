# HMAC - Hash-based Message Authentication Code

An HMAC is a type of cryptographic code that combines a message with a secret key and a hash function (such as SHA-256) to verify the integrity and authenticity of the data.

The definition and analysis of the HMAC construct were first published in 1996 by Mihir Bellare, Ran Canetti, and Hugo Krawczyk

The cryptographic strength of the HMAC depends upon the size of the secret key that is used and the security of the underlying hash function used. It has been proven that the security of an HMAC construction is directly related to security properties of the hash function used.

> Any cryptographic hash function, such as SHA-2 or SHA-3, can be used to compute an HMAC; the resulting MAC algorithm is called HMAC-SHA2 or HMAC-SHA3, respectively.

The most common attack against HMACs is brute force to uncover the secret key. HMACs are substantially less affected by collisions than their underlying hashing algorithms alone.


## How it works

1. **Key Adjustment** ($K'$)

If the original key $K$ is longer than the block size of the hash algorithm (for example, 64 bytes in SHA-256), it is first hashed to reduce its length. <br>
If it is shorter, zeros are added to the right (padding) until it reaches exactly the size of the block. The result of this adjustment is the key $K'$.

2. **Internal Hash Calculation** (First Pass)

An XOR ($\oplus$) operation is performed between the adjusted key $K'$ and a fixed, repeated pattern called the ipad (inner pad, with a value of `0x36`). <br>
The result is concatenated ($\parallel$) with the original message $m$. A hash is calculated for the entire set:

$$\text{Inner Hash} = \text{H}\big((K' \oplus ipad) \parallel m\big)$$

3. **External Hash Calculation** (Second Pass / Final HMAC)

An XOR ($\oplus$) operation is performed between the adjusted key $K'$ and another fixed, repeated pattern called the opad (outer pad, with a value of 0x5C). <br>
The result is concatenated with the internal hash obtained in step 2. <br>
The hash function is then applied again to the entire block to obtain the final signature:

$$\text{HMAC}(K, m) = \text{H}\Big(\big(K' \oplus opad\big) \parallel \text{H}\big(\big(K' \oplus ipad\big) \parallel m\big)\Big)$$

### Key Cryptographic Requirements
- **Cryptographic Hash Function ($H$)**: Any iterative cryptographic hash function can be used (e.g., SHA-256, SHA-3).
- **Secret Key Length ($K$)**: The key length should be at least equal to the output size $L$ of the chosen hash function (e.g., 256 bits for SHA-256).
- **Two-Pass Construction**: The nested inner ($ipad$) and outer ($opad$) hashing structure neutralizes **Length Extension Attacks** inherent to Merkle-Damgård constructions.

## Why an eavesdropper can't forge it

An attacker watching the transmission sees the message $M$ and the tag $\text{HMAC}(K, M)$ — but never the secret key $K$. <br>
Without $K$, an adversary cannot compute a valid MAC for a modified message $M'$. Furthermore, because of the nested $opad$/$ipad$ structure, an attacker cannot append data to $M$ and extend the hash state, forcing them to rely on **brute-force attacks against a full 256-bit key space.**

## ⚠️ Important security notes

- **HMAC does not provide confidentiality.** It guarantees authenticity and integrity, but the message $M$ itself remains readable in plain text unless encrypted separately (e.g., via AES-GCM or Encrypt-then-MAC).
- **Comparison must be constant-time.** When verifying received HMAC tags on the server, software must use constant-time byte comparisons (e.g., `hmac.compare_digest()`) to prevent side-channel **timing attacks**.


> MAC has been issued as RFC 2104 (HMAC: Keyed- Hashing for Message Authentication, 1997), has been chosen as the mandatory- to-implement MAC for IP Security, and is used in other Internet protocols, such as Transport Layer Security (TLS) and Secure Electronic Transaction (SET)