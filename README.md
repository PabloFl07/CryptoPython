A collection of small, educational Python programs about cryptography. This repository aims to break down complex cryptographic concepts into readable and functional code, ranging from practical security tools to simple Proof of Concepts (POCs).

The goal of this project is to provide clear, documented implementations of cryptographic algorithms and protocols for learning purposes. It is designed for developers and students who want to understand how "under the hood" cryptography works using Python.

---

##  Project Structure

The repository features two main categories of content:

### 🛠️ `/scripts`
Contains fully functional and ready-to-use tools. These are more robust programs intended to solve specific tasks. They are intended to serve as examples of possible real-world implementations.

### 🧪 `/pocs` (Proof of Concepts)
It contains small programs designed to demonstrate and explain cryptographic concepts or best practices. They do not require extensive knowledge of the code, as they focus on the theoretical aspects.

---

##  Index of Contents

### Current Scripts
1.  **[File Encryptor](scripts/file_encrypt/README.md)**: Secure file encryption and decryption using symmetric keys (AES).
2.  **[Digital Signature Tool](scripts/digital_sign/README.md)**: Utility to sign documents and verify authenticity using asymmetric cryptography (RSA).

### Proof of Concepts (Planned & Current)
- **[Password Hashing](pocs/hashing/README.md)**: Comparing SHA-256, Salts, and Argon2/Bcrypt.

---

## Prerequisites
- Python 3.x
- Recommended: A virtual environment (`python -m venv venv`)

Also, you will need many dependencies:
```
pip install -r requirements.txt
```


## ⚠️ Security Disclaimer

Educational Use Only. The implementations in this repository are intended for learning and demonstration purposes. Do not use this code to secure sensitive production data or real-world communications without professional auditing. Always use industry-standard libraries and procedures.