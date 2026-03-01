# AES-OFB Encryption & X.509 Certificate Chain

A Python task covering AES-128-OFB file encryption and X.509 certificate chain generation and verification using the `cryptography` library and OpenSSL CLI.

---

## Structure

| File | Description |
|------|-------------|
| `aes_ofb.py` | AES-128-OFB encryption of a plaintext file |
| `generate_cr_CA.py` | Generates CA's RSA private key and self-signed certificate |
| `generate_csr_bob.py` | Generates Bob's RSA private key and CSR |
| `generate_cr_bob.py` | Signs Bob's CSR with the CA key to produce Bob's certificate |
| `check_key_and_cr.py` | Verifies Bob's certificate matches his private key and is signed by the CA |
| `alice.txt` | Plaintext input file used for encryption |

---

## Tasks

### Task 1 & 2 — AES-128-OFB Encryption (`aes_ofb.py`)
Encrypts `alice.txt` using AES-128-OFB mode. The key and IV were generated with OpenSSL:
```bash
openssl rand -hex 16 > iv_ofb.txt
openssl rand -hex 16 > key_ofb.txt
```
Encryption and decryption can also be done via OpenSSL CLI:
```bash
openssl enc -aes-128-ofb -in alice.txt -out alice_enc.txt -K <key> -iv <iv>
openssl enc -d -aes-128-ofb -in alice_enc.txt -out alice_dec.txt -K <key> -iv <iv>
```

### Task 3 — X.509 Certificate Chain
The scripts must be run in this order:

1. **`generate_cr_CA.py`** — generates `rsa_priv_CA.pem` and `CA_cert.pem` (self-signed CA certificate)
2. **`generate_csr_bob.py`** — generates `rsa_priv.pem` and `bob.csr` (Bob's certificate signing request)
3. **`generate_cr_bob.py`** — signs Bob's CSR with the CA key, producing `bob_cr.pem`

### Task 4 — Verification (`check_key_and_cr.py`)
Verifies that:
- The public key in Bob's certificate matches his private key
- Bob's certificate is validly signed by the CA and within its validity period

---

## Dependencies

- Python 3.x
- `cryptography` library

Install dependencies:
```bash
pip install -r requirements.txt
```

---

## Usage

Update the file paths in each script's `main()` to point to your local files before running. Then execute in order:

```bash
python generate_cr_CA.py
python generate_csr_bob.py
python generate_cr_bob.py
python check_key_and_cr.py
python aes_ofb.py
```

---

## Notes

- The key and IV used for AES-OFB are stored in `key_ofb.txt` and `iv_ofb.txt` — these are **not committed** to the repository as they are sensitive values. See `.gitignore`.
- Private key files (`rsa_priv.pem`, `rsa_priv_CA.pem`) are also excluded from the repository for the same reason.
- The RSA key generation code in `generate_cr_CA.py` and `generate_csr_bob.py` is commented out since the keys were already generated and saved — uncomment it if you need to regenerate them.
- Bob's certificate is valid for 90 days and the CA certificate for 365 days from generation time.
