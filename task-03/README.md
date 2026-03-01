# PBKDF2 Key Derivation with OpenSSL

A C program that demonstrates PBKDF2 key derivation using OpenSSL 3.x's EVP KDF API, tested against the RFC 6070 standard test vectors.

---

## Description

The program runs two tasks against a set of PBKDF2 test vectors:

**Task 1 — SHA1 verification:** Derives keys using PBKDF2-SHA1 and compares them against the RFC 6070 expected outputs using constant-time comparison (`CRYPTO_memcmp`). Passes or fails each test vector explicitly.

**Task 2 — SHA256 derivation:** Derives a 32-byte key using PBKDF2-SHA256 for each test vector and prints the result as a hex dump (no expected value to compare against, output is for inspection).

The test vectors cover edge cases including: short passwords, high iteration counts (up to 16,777,216), long passwords/salts, and null bytes embedded in passwords and salts.

---

## Dependencies

- **GCC** (or any C99-compatible compiler)
- **OpenSSL 3.x** development libraries

Install on Debian/Ubuntu:
```bash
sudo apt install libssl-dev pkg-config
```

Install on Fedora/RHEL:
```bash
sudo dnf install openssl-devel pkg-config
```

Install on macOS (Homebrew):
```bash
brew install openssl pkg-config
```

---

## Building

```bash
make
```

Clean:
```bash
make clean
```

---

## Usage

```bash
./openssl-pbkdf
```

No arguments needed. The program runs all test vectors automatically and prints results to stdout. Any failure is reported to stderr and exits with code `1`.

**Example output:**
```
Task_1: Test vector num. 1 success!
Task_2: Test vector SHA256 num. 1
56 1f 2a ... (32 bytes hex)
...
```

---

## Notes

- The key buffer is stack-allocated at 32 bytes. This is sufficient for the test vectors used here, but dynamic allocation would be needed for arbitrary key lengths.
- Test vector 4 (16,777,216 iterations) is computationally expensive and will take a noticeable amount of time to complete.
- RFC 6070 defines the SHA1 test vectors used in Task 1.
