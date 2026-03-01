# RSA PKCS#1 Padding & Diffie-Hellman Parameters

A pair of C programs demonstrating cryptographic primitives using OpenSSL 3.x.

---

## Programs

### `rsa_padding.c` — RSA PKCS#1 v1.5 Signature Block (Type 1)
Hashes a file using SHA-256, wraps the digest in a DER-encoded ASN.1 `DigestInfo` structure, and manually constructs the PKCS#1 v1.5 padding block (as used in RSA signing). The resulting padded block is printed as a hex dump.

**Block format:**
```
0x00 | 0x01 | 0xff...0xff | 0x00 | DigestInfo (DER)
```

### `df_params.c` — Diffie-Hellman Parameter Export
Generates and exports Diffie-Hellman parameters using the standard `ffdhe2048` IETF group (RFC 7919). The parameters are serialized to DER format and printed as a hex dump.

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

The Makefile uses `pkg-config` to automatically detect and link OpenSSL — no manual library path configuration needed.

Build a specific program:
```bash
make rsa_padding
make df_params
```

Build both:
```bash
make all_targets
```

Clean binaries:
```bash
make clean
```

---

## Usage

### `rsa_padding`
Before running, edit the `path` variable in `main()` to point to the file you want to hash:
```c
const char *path = "/path/to/testfile";
```
You can also adjust `key_size` (in bytes) to match your RSA key size (e.g., `256` for RSA-2048).

Then run:
```bash
./rsa_padding
```

Expected output: a colon-separated hex dump of the full padded RSA block.

### `df_params`
No configuration needed. Simply run:
```bash
./df_params
```

Expected output: a space-separated hex dump of the DER-encoded `ffdhe2048` DH parameters.

---

## Notes

- `df_params.c` uses the modern `EVP_PKEY` API (OpenSSL 3.x). The older `DH_*` API is deprecated and intentionally left as comments for reference.
- `rsa_padding.c` constructs the padding block manually for educational purposes — in production, RSA signing is handled entirely by OpenSSL's signing functions.

---

## License

This project is for educational purposes. No license is currently applied — add one (e.g., MIT) before sharing publicly if needed.
