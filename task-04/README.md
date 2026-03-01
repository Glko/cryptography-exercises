# AES-128-CBC Decryption

A C program that decrypts a Base64-encoded, AES-128-CBC encrypted file using OpenSSL's BIO API.

---

## Description

The program reads a Base64-encoded encrypted file, decodes and decrypts it using AES-128-CBC, and prints the plaintext to stdout. It uses OpenSSL's BIO chain to handle Base64 decoding and AES decryption in a single streaming pipeline:

```
File (BIO source) → Base64 filter → Cipher filter → plaintext output
```

Only printable characters, newlines, and tabs are printed via a safe print function to avoid outputting raw binary garbage on bad decryption.

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
./decrypt_aes_cbc_ssl <path_to_encrypted_file>
```

The encrypted file must be **Base64-encoded** and encrypted with **AES-128-CBC**.

**Example:**
```bash
./decrypt_aes_cbc_ssl encrypted.txt
```

---

## Key & IV

For the purpose of this exercise, the key and IV are hardcoded in `main()`:

```c
const unsigned char *key = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
const unsigned char *iv  = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0f";
```

Change these as needed before building.

---

## Notes

- The program uses `EVP_DecryptInit_ex2` and the BIO cipher API (OpenSSL 3.x). The lower-level `EVP_DecryptUpdate` / `EVP_DecryptFinal` approach is intentionally left as comments for reference.
- The program exits with code `1` on any error and prints a descriptive message to `stderr`.
