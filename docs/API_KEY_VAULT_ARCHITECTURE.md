# SWA AI / SNMK — API Key Vault Architecture & Cryptographic Engine

## Architecture Overview
The SWA AI / SNMK API Key Vault provides zero-trust credential storage and management for enterprise cybersecurity environments. It guarantees that sensitive credentials (LLM API keys, SIEM tokens, threat intelligence licenses, and cloud IAM keys) remain encrypted both at rest and in transit.

```
       [ Client Browser ]
               │
               ▼ (HTTPS / JSON - Masked Only)
       [ REST API Routes (server.py) ]
               │
               ▼ (In-Memory Decryption)
       [ Credentials Vault (core/credentials.py) ]
       ├── PBKDF2HMAC (SHA-256, 100k Iterations)
       ├── Salt (16 bytes per secret)
       └── Fernet (AES-128-CBC + HMAC-SHA256)
               │
       ┌───────┴────────────────────────┐
       ▼                                ▼
[ SQLite Database ]             [ Third-Party Providers ]
(Ciphertext + Salt only)        (Live Encrypted TLS Handshake)
```

---

## Cryptographic Guarantees

### 1. Key Derivation Function (KDF)
- **Master Key File:** `.swa_master.key` (or environment variable `SWA_MASTER_KEY`).
- **Algorithm:** PBKDF2HMAC with SHA-256 digest.
- **Iterations:** 100,000 rounds.
- **Per-Record Salt:** 16 random cryptographic bytes generated via `os.urandom(16)` for every stored token.

### 2. Encryption Cipher
- **Standard:** Fernet (cryptography.fernet.Fernet).
- **Underlying Primitive:** AES-128 in Cipher Block Chaining (CBC) mode with PKCS7 padding.
- **Authentication:** HMAC with SHA-256 ensures ciphertext integrity and authenticity; any tampering results in decryption failure without leaking secret fragments.

### 3. Key Masking Policy
All API serialization and UI rendering apply strict token masking:
- Prefix: Preserves first 6 characters (e.g. `sk-pro` or `AIzaSy`).
- Suffix: Preserves last 3 characters (e.g. `9aF`).
- Masking: Exact 12-character asterisk mask (`************`).
- Total tokens shorter than 10 characters are masked entirely as `************`.

### 4. Rotation Lifecycle
- When an operator initiates rotation via `POST /api/integrations/{id}/rotate`, a new 16-byte salt is generated and the new secret is encrypted into a new ciphertext.
- The existing configuration, display name, category, and audit logs are preserved.
- Old ciphertext and salt are overwritten in the SQLite transaction.
