# AES-GCM, HKDF, ChaCha20-Poly1305 & CBC Bit-Flipping Attack

A Python homework covering authenticated encryption, key derivation, performance benchmarking, and a CBC bit-flipping attack demonstration using the `cryptography` library.

---

## Structure

| File | Description |
|------|-------------|
| `aes_enc_dec.py` | Main script containing all tasks |
| `alice.txt` | Plaintext input file used for encryption tasks |
| `alice_dec.txt` | Reference decryption output for Task 2 (AES-GCM) |
| `alice_dec_hkdf.txt` | Reference decryption output for Task 3 (HKDF-derived key) |

---

## Tasks

### Task 1 — AES-256-GCM Encryption
Encrypts `alice.txt` using AES-256-GCM with a randomly generated key and 96-bit nonce (NIST standard). Additional authenticated data (AAD) is prepended to the ciphertext file alongside the nonce for use during decryption. Uses the low-level streaming API to handle large files in 4096-byte chunks.

### Task 2 — AES-256-GCM Decryption
Decrypts the file produced in Task 1. Reads the nonce and AAD from the file header, then reads and verifies the GCM authentication tag before finalizing decryption.

### Task 3 — HKDF Key Derivation + AES-GCM
Derives a 256-bit AES key from a fixed input key material using HKDF with SHA3-256 and a random 16-byte salt. The derived key is then used to encrypt and decrypt `alice.txt` with AES-GCM.

### Task 4 — ChaCha20-Poly1305 Encryption
Encrypts `alice.txt` using ChaCha20-Poly1305 with the same key and nonce as Task 1 for direct comparison. Reads the entire file into memory (suitable for files that fit in RAM).

### Task 5 — Performance Benchmark: AES-GCM vs ChaCha20-Poly1305
Runs 30,000 iterations of each cipher and compares average encryption time. Results across multiple runs showed no consistent winner — both were within ~0.1ms of each other, with each cipher winning roughly half the time.

### Task 6 — CBC Bit-Flipping Attack
Demonstrates a CBC bit-flipping attack on the message `"I would like to withdraw 100000 dollars next week"`. By XORing the previous ciphertext block with the XOR delta between the original and desired plaintext, the second plaintext block is changed to `"withdraw 500000 "` without knowledge of the key, illustrating the lack of integrity protection in CBC mode.

---

## Dependencies

- Python 3.x
- `cryptography` library

Install:
```bash
pip install -r requirements.txt
```

---

## Usage

Update the file paths in `main()` to point to your local files, then run:
```bash
python aes_enc_dec.py
```

The script runs all tasks sequentially and prints benchmark results and the bit-flipping attack output to stdout.

---

## Notes

- Keys, nonces, and salts are randomly generated at runtime with `os.urandom()` — no sensitive values are hardcoded or stored to disk.
- The hardcoded Windows paths in `main()` need to be updated to your local paths before running.
- `alice_dec.txt` and `alice_dec_hkdf.txt` are reference outputs included to verify correctness — they should match `alice.txt` exactly after decryption.
- The CBC bit-flipping attack corrupts the first plaintext block (which absorbs the XOR delta) while producing the desired change in the second block. This is expected behavior.
