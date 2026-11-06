# SWA AI / SNMK — Comprehensive API Key Management & Integration Audit

## Executive Summary
This document provides an exhaustive technical audit of the API Key & Provider Integrations management system in the **SNMK** platform (formerly SWA AI). It details the cryptographic storage, the client-side controller, the REST API endpoints, provider adapters, error-handling mechanisms, and agent connectivity.

---

## 1. Identified Gaps & Root Causes

### 1.1 Frontend Client Controller Missing
- **Symptom:** Opening `http://127.0.0.1:8001/#/api_keys` triggered `ReferenceError: loadApiKeysUI is not defined` or clicking "Test All Connections" triggered `ReferenceError: testAllIntegrationsUI is not defined`.
- **Root Cause:** While the HTML view `#viewApiKeys` (lines 3501–3608) and modals `#apiKeyModal` and `#rotateKeyModal` (lines 6388–6500) were structured in `web/static/index.html`, their corresponding JavaScript controller functions were completely omitted in `web/static/app.js`.
- **Resolution:** Implemented the full controller suite in `web/static/app.js`, including `loadApiKeysUI`, `openAddApiKeyModal`, `closeApiKeyModal`, `onModalProviderChange`, `toggleApiKeyInputMask`, `testModalApiKey`, `saveModalApiKey`, `openRotateKeyModal`, `closeRotateModal`, `submitRotateKey`, `testIntegrationKey`, `toggleIntegrationKey`, `deleteIntegrationKey`, `testAllIntegrationsUI`, `filterApiKeysByCategory`, and `filterApiKeysBySearch`.

### 1.2 Missing Batch Connection Test Endpoint
- **Symptom:** The UI provided a "Test All Connections" button, but no backend batch endpoint existed to test all configured credentials simultaneously.
- **Root Cause:** Only single-integration endpoints (`/api/integrations/{id}/test` and ad-hoc `/api/integrations/test`) were implemented.
- **Resolution:** Added `test_all_integrations()` to `core/integrations/registry.py` with `asyncio.Semaphore(5)` for bounded concurrency, and exposed `POST /api/integrations/test-all` in `web/server.py`.

---

## 2. Cryptographic Vault & Database Schema Audit

### 2.1 Encryption at Rest
- **Key Derivation:** PBKDF2HMAC with SHA-256 and 100,000 iterations from `.swa_master.key`.
- **Cipher:** Fernet symmetric encryption (AES-128-CBC with PKCS7 padding and HMAC-SHA256 signature verification).
- **Per-Secret Salt:** Every secret token generates a unique 16-byte cryptographic salt stored alongside the ciphertext.

### 2.2 Relational Integrity
- **Table `integrations`:**
  - `id` (TEXT PRIMARY KEY)
  - `provider_id` (TEXT NOT NULL)
  - `display_name` (TEXT)
  - `category` (TEXT)
  - `endpoint_url` (TEXT)
  - `config_json` (TEXT)
  - `scope` (TEXT DEFAULT 'global')
  - `status` (TEXT DEFAULT 'CONFIGURED')
  - `last_tested_at` (TEXT)
  - `last_error` (TEXT)
  - `enabled` (INTEGER DEFAULT 1)
  - `created_at`, `updated_at` (TEXT)
- **Table `encrypted_credentials`:**
  - `id` (TEXT PRIMARY KEY)
  - `integration_id` (TEXT NOT NULL, FOREIGN KEY REFERENCES `integrations(id)`)
  - `field_key` (TEXT NOT NULL)
  - `ciphertext_b64` (TEXT NOT NULL)
  - `salt_b64` (TEXT NOT NULL)
  - `created_at`, `updated_at` (TEXT)

---

## 3. Data Leakage Prevention Audit
- **Zero Plain-Text Leakage:**
  - REST API responses (`GET /api/integrations`, `GET /api/integrations/{id}`, `POST /api/integrations`, `POST /api/integrations/test-all`) return strictly `masked_credentials` (e.g. `sk-pro************9aF`).
  - Plain-text credentials exist only ephemerally in RAM during outbound HTTP handshakes and are never logged to console or audit trails.
  - Password inputs in the frontend zero out immediately upon submission or modal cancellation.

---

## 4. Verification & Status Taxonomy
The platform enforces an honest connection verification taxonomy:
- **`CONNECTED`**: Endpoint reached and credential authenticated successfully with valid status code and measurable roundtrip latency.
- **`AUTHENTICATION_FAILED`**: Server reachable but returned HTTP 401 Unauthorized or 403 Forbidden.
- **`UNREACHABLE`**: DNS resolution failure, network timeout, or connection refused.
- **`CONFIGURED` / `UNTESTED`**: Credentials stored in vault but not yet tested over the network.
- **`DISABLED`**: Integration explicitly toggled off by operator.
