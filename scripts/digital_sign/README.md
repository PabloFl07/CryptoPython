# Ed25519 File Signing Tool

A command-line tool for signing and verifying files using **Ed25519** asymmetric cryptography. It supports multiple signature modes, from simple detached signatures to directory-wide manifests, and produces self-contained envelopes that bundle the signature, public key, and metadata together.

---

## What it does

It lets you cryptographically sign any file or directory and later verify that the content has not been tampered with. The original file is never altered — instead, a separate envelope (JSON or plain text) is produced. Anyone holding the public key can independently verify authenticity and integrity, without needing access to the private key.

---

## Concepts covered

| Concept | How it appears in this project |
|---|---|
| **Asymmetric cryptography** | An Ed25519 key pair is used: the private key signs, the public key verifies. The private key never leaves the signing machine. |
| **Digital signatures** | Each envelope contains a raw Ed25519 signature over the file bytes (or canonical manifest bytes). Verification is deterministic and does not require a shared secret. |
| **Key encapsulation / Password-based encryption** | The private key is stored encrypted on disk using PKCS#8 + `BestAvailableEncryption` (PBKDF2-SHA512 + AES-256-CBC). The password is wiped from memory after use. |
| **Integrity hashing** | SHA-256 hashes are recorded alongside signatures. Detached and manifest modes recompute hashes on verification, catching corruption even if the signature check somehow passed. |
| **Envelope formats** | Three JSON-based envelope formats (detached, inline, manifest) and one human-readable plain-text format (clearsign) are supported. |
| **Secure file permissions** | Key files are created with `0o600` (owner read/write only) and their parent directory with `0o700`, following UNIX least-privilege conventions. |
| **Memory hygiene** | Sensitive buffers (passwords, key material) are zeroed via `wipe_memory()` in `finally` blocks so secrets do not linger in process memory. |
| **Path traversal protection** | Manifest verification resolves every file path and asserts it is relative to the declared base directory before reading it. |

---

## Signature modes

| Mode | Output | Use when |
|---|---|---|
| `detached` | `<file>.sig.json` | You want to distribute the original file unchanged alongside a separate proof |
| `inline` | `<file>.jsig` | You want a single self-contained archive (file content + signature) |
| `clearsign` | `<file>.signed.txt` | The file is plain text and you want a human-readable signed document |
| `manifest` | `manifest.json` | You need to sign an entire directory of files at once |

---

## Requirements

```
pip install cryptography
```

Python 3.10+ is required (the code uses structural pattern matching — `match`/`case`).

---

## Usage

### 1. Generate a key pair

```bash
# Generate at the default location (~/.../keys/private.key)
python main.py genkey

# Generate at a custom path
python main.py genkey /path/to/mykey.key
```

You will be prompted for a password that protects the private key on disk.

### 2. Export the public key

```bash
python main.py pub
# → writes private.pub next to the private key

python main.py pub /path/to/mykey.key
```

Share the `.pub` file with anyone who needs to verify your signatures.

### 3. Sign a file

```bash
# Detached signature (original file untouched)
python main.py sign document.pdf --mode detached

# Inline envelope (file content embedded in the JSON)
python main.py sign document.pdf --mode inline

# Clearsign (plain-text files only)
python main.py sign notes.txt --mode clearsign

# Manifest (sign every file in a directory)
python main.py sign ./my-project/ --mode manifest

# Manifest including subdirectories
python main.py sign ./my-project/ --mode manifest --recursive

# Custom key path and custom output path
python main.py sign document.pdf --mode detached --key /path/to/mykey.key --output document.sig.json
```

### 4. Verify a signature

```bash
# Detached mode — the original file must be supplied
python main.py auth document.sig.json --file document.pdf

# Inline mode — no original file needed
python main.py auth document.jsig

# Clearsign mode
python main.py auth notes.signed.txt

# Manifest mode — base directory defaults to the manifest's own directory
python main.py auth manifest.json

# Manifest with an explicit base directory
python main.py auth manifest.json --dir ./my-project/
```

### Output example

```
[detached] ✓  VALID
  file:      document.pdf
  signature: ok
  sha256:    ok
  signer:    3a9f1c2b4e7d8a05
  timestamp: 2025-05-09T10:30:00+00:00
```

---

## Project structure

```
.
├── main.py       # CLI entry point and argument parser
├── keys.py       # Key generation, loading, and public key export
├── signer.py     # Envelope classes and signing logic
├── verifier.py   # Verification logic for all four modes
└── utils.py      # Shared helpers (hashing, encoding, memory wiping)
```

---

## Security notes

- The private key is **never** included in any envelope — only the corresponding public key is embedded.
- Signatures are produced over the **raw file bytes** before any encoding, so base64 or JSON formatting cannot introduce ambiguity.
- The manifest canonical form uses compact JSON with sorted keys (`separators=(",",":")`, `sort_keys=True`) so the signed bytes are deterministic across platforms and JSON libraries.
- `os.O_EXCL` is used when creating key and envelope files, preventing silent overwrites.