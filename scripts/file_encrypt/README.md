#  Symmetric File Encryption Tool

A command-line tool for encrypting and decrypting files using modern authenticated encryption. It supports two cipher suites (AES-256-GCM and ChaCha20-Poly1305), two key sources (key file or password), and includes integrity verification utilities. All encrypted files carry a self-describing binary header so decryption is fully automatic — no flags needed.

---

## What it does

It encrypts any file into a single `.enc` output that bundles everything needed for decryption: the algorithm used, the nonce derivation salt, the password salt (if applicable), and the original filename. The encrypted data is processed in 64KB chunks, each independently authenticated, so tampering with any part of the file is detected immediately. After decryption, a separate `verify` command can confirm byte-for-byte integrity against the original.

---

## Concepts covered

| Concept | How it appears in this project |
|---|---|
| **Symmetric encryption** | A single 256-bit key is used for both encryption and decryption, unlike the asymmetric approach used in public-key systems. |
| **Authenticated Encryption with Associated Data (AEAD)** | Both AES-256-GCM and ChaCha20-Poly1305 provide confidentiality and integrity in a single pass. A 16-byte authentication tag is appended to each chunk; any modification causes decryption to abort. |
| **Associated Data / Binding** | Each chunk is bound to the filename and its chunk index (`filename:N`) as associated data. This prevents chunk reordering and cross-file substitution attacks. |
| **Nonce derivation** | Per-chunk nonces are derived deterministically from a random 32-byte salt and the chunk index via BLAKE2s, avoiding nonce reuse without storing a nonce per chunk. |
| **Key Derivation Function (KDF)** | In password mode, the 256-bit encryption key is derived from the user's password using PBKDF2-HMAC-SHA256 with 600,000 iterations and a random 32-byte salt (OWASP 2023 recommendation). |
| **Memory hygiene** | The password is stored in a `bytearray` and explicitly zeroed after the key is derived, so plaintext credentials do not persist in process memory. |
| **Binary file header** | A 72-byte structured header (magic number + algorithm ID + salts + name length) is prepended to every `.enc` file using Python's `struct` module, making the format self-describing. |
| **Integrity verification** | A separate `verify` command recomputes SHA-256 (or any `hashlib`-supported algorithm) on both files and compares digests, providing an explicit post-decryption sanity check. |
| **Secure file permissions** | Generated key files are written with `0o600` (owner read/write only) and their parent directory with `0o700`. |
| **Key rotation awareness** | `KeyManager` warns at load time if the key file has not been modified in over 24 hours, nudging users toward regular rotation. |

---

## Cipher suites

| Flag | Algorithm | Best for |
|---|---|---|
| `-a` (default) | AES-256-GCM | Hardware-accelerated environments (AES-NI) |
| `-c` | ChaCha20-Poly1305 | Software-only or mobile environments without AES-NI |

Both provide equivalent security guarantees (256-bit key, 128-bit authentication tag). The algorithm used at encryption time is recorded in the header and detected automatically on decryption.

---

## Key sources

| Mode | Flag | Description |
|---|---|---|
| **Key file** | `-kf [path]` | A 32-byte random key stored on disk. Faster — no KDF step. |
| **Password** | *(default, no flag)* | A password entered interactively, derived to a key via PBKDF2. The salt is stored in the file header. |

If `-kf` is given without a path, the default location (`~/.secret/secret.key`) is used.

---

## Requirements

```
pip install cryptography
```

Python 3.10+ is required (the code uses structural pattern matching and `match`/`case`).

---

## Usage

### 1. Generate a key file

```bash
# Generate at the default location (~/.secret/secret.key)
python main.py genkey

# Generate at a custom path
python main.py genkey /path/to/mykey.key

# Overwrite an existing key
python main.py genkey --force
```

### 2. Encrypt a file

```bash
# Password-based encryption (AES-256-GCM by default)
python main.py encrypt document.pdf

# Password-based, ChaCha20-Poly1305
python main.py encrypt document.pdf -c

# Key-file encryption (default key location)
python main.py encrypt document.pdf -kf

# Key-file encryption (custom key path)
python main.py encrypt document.pdf -kf /path/to/mykey.key

# Custom output path
python main.py encrypt document.pdf --output document_encrypted.enc
```

### 3. Decrypt a file

```bash
# Password-based (algorithm and salt are read from the file header automatically)
python main.py decrypt document.enc

# Key-file decryption
python main.py decrypt document.enc -kf

# Custom output path
python main.py decrypt document.enc --output document_restored.pdf
```

### 4. Verify integrity

Compare an original file against a decrypted one to confirm they are byte-for-byte identical.

```bash
# Default algorithm (SHA-256)
python main.py verify document.pdf document_restored.pdf

# Custom algorithm
python main.py verify document.pdf document_restored.pdf -a sha512
```

### 5. Hash a file

```bash
python main.py hash document.pdf

python main.py hash document.pdf -a sha512
```

Output example:
```
sha256 Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

---

## Encrypted file format

Every `.enc` file starts with a fixed 72-byte binary header followed by the original filename and the ciphertext:

```
┌─────────────────────────────────────────────────────┐
│  Magic (5B) │ Algo ID (1B) │ Nonce salt (32B)       │
│  Password salt (32B)       │ Name length (2B)       │
├─────────────────────────────────────────────────────┤
│  Original filename (variable)                       │
├─────────────────────────────────────────────────────┤
│  Chunk 0: ciphertext + 16B tag                      │
│  Chunk 1: ciphertext + 16B tag                      │
│  ...                                                │
└─────────────────────────────────────────────────────┘
```

---

## Project structure

```
.
├── main.py       # CLI entry point and argument parser
├── run.py        # Orchestration layer — ties key source, cipher, and engine together
├── engine.py     # Chunk-based encrypt/decrypt logic and nonce derivation
├── header.py     # Binary file header definition (pack / unpack)
├── keys.py       # Key generation, loading, password derivation (PBKDF2)
└── integrity.py  # SHA-256 / hashlib file hashing and comparison
```

---

## Security notes

- The nonce is **never reused**: each chunk gets a unique nonce derived from a per-file random salt and the chunk index via BLAKE2s.
- In password mode, the KDF salt is stored in the header — this is standard practice and does not weaken security, as the salt's only purpose is to prevent precomputed dictionary attacks.
- Key files are **not** encrypted at rest. Keep them in a secure location with appropriate filesystem permissions, or protect them with full-disk encryption.
- The tool is designed for **personal use**. Decryption does not sanitize the filename stored in the header; if processing `.enc` files from untrusted sources, path sanitization should be added in `run.py` at the point where `file_name` is read.