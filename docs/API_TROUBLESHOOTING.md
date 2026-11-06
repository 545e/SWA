# SWA AI — API Troubleshooting & Diagnostics

## 1. Scope Refusal ("Target is not listed in configured scope allowlist")
### Cause
The target hostname is not yet registered in `config/targets.json` and strict allowlisting is active.
### Resolution
1. **Dynamic Authorization (Recommended)**:
   In SWA AI v2.3+, any valid public domain (e.g. `starasia.org`) entered by an operator is automatically validated and authorized into `config/targets.json`.
2. **Explicit API Authorization**:
   ```http
   POST /api/v1/assets
   Content-Type: application/json

   {
     "domain": "starasia.org",
     "description": "Operator authorized client assessment"
   }
   ```
3. **Lab Mode for Local Testing**:
   For `127.0.0.1` or `localhost`, toggle **Authorized Lab Mode** in the dashboard or pass `"lab_mode": true`.

---

## 2. SSRF Protection Refusal ("SSRF_RESTRICTED_IP")
### Cause
The target resolves to AWS/GCP/Azure instance metadata addresses (`169.254.169.254`), loopback, or private subnets without lab authorization.
### Resolution
- Cloud metadata endpoints cannot be scanned under any profile.
- Internal addresses (e.g., `10.0.0.1`, `192.168.1.1`) require `"lab_mode": true` in scan payloads.

---

## 3. Empty Agents List ("No agents match the current filter criteria")
### Cause
Active filter mismatch or search query active in the web UI.
### Resolution
- Click **"All (85)"** in the agent tier filter pills.
- Clear the search box.
- In v2.3+, an embedded fail-safe auto-recovers the full 85-agent manifest if any network glitch occurs.
- Verify via API: `GET /api/v1/ai/agents` (returns all 85 agents).

---

## 4. Connection Failures on Third-Party Integrations
### Cause
Missing API credentials or upstream provider firewall.
### Resolution
- Test connection via `POST /api/v1/integrations/test` with `"provider_id": "<id>"`.
- Inspect provider response latency and error status in the returned JSON.
