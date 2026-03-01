# Cryptography Labs

A collection of cryptography exercises using OpenSSL (C) and the Python `cryptography` library, covering symmetric encryption, key derivation, digital certificates, and cryptographic attacks.

---

## Structure

| Task | Description | Language |
|------|-------------|----------|
| [task-01](./task-01/) | RSA PKCS#1 v1.5 padding block construction & Diffie-Hellman parameter export | C / OpenSSL |
| [task-02](./task-02/) | AES-128-CBC decryption of a Base64-encoded file using OpenSSL BIO chains | C / OpenSSL |
| [task-03](./task-03/) | PBKDF2 key derivation with SHA1 and SHA256, verified against RFC 6070 test vectors | C / OpenSSL |
| [task-04](./task-04/) | AES-128-OFB file encryption & X.509 certificate chain generation and verification | Python |
| [task-05](./task-05/) | AES-256-GCM, HKDF key derivation, ChaCha20-Poly1305, performance benchmarking & CBC bit-flipping attack | Python |

---

## Dependencies

### C tasks (task-01, task-02, task-03)
- GCC
- OpenSSL 3.x development libraries
- pkg-config

Install on Debian/Ubuntu:
```bash
sudo apt install libssl-dev pkg-config
```

### Python tasks (task-04, task-05)
- Python 3.x
- `cryptography` library

Install:
```bash
pip install -r requirements.txt
```

Each task folder contains its own `README.md` with specific build and usage instructions.

---

## Notes

- Private keys and cryptographic material (`.pem`, `key_ofb.txt`, `iv_ofb.txt`) are excluded from the repository via `.gitignore` and should never be committed.
- Hardcoded file paths in the Python scripts are Windows-specific and need to be updated to your local paths before running.
