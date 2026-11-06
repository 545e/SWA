# SWA AI — API Authentication & Identity Management

## 1. Authentication Mechanisms
SWA AI supports dual-mode production authentication:
1. **Bearer Session Tokens**: Used by web SOC operators, analysts, and frontend dashboards.
2. **Master API Key (`X-API-Key` or `Authorization: Bearer <key>`)**: Used by automated CI/CD pipelines, autonomous agent swarms, and backend orchestrators.

## 2. Environment Configuration
Authentication can be configured via environment variables:
```bash
# Enable strict authentication (default: False in local lab mode, True in production)
SWA_AUTH_ENABLED=true

# Set the master API key for headless service integrations
SWA_MASTER_API_KEY=swa_sec_live_9f83b27e01d44c9b841a2e345f891b0c
```

## 3. Session Lifecycle & Token Management

### Login Endpoint
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "lead_operator",
  "password": "optional_in_lab_mode",
  "api_key": "swa_sec_live_..."
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "token": "swa_sess_a81b2c3d4e5f6789...",
    "identity": "lead_operator",
    "role": "admin"
  },
  "message": "Authentication successful"
}
```

### Using the Session Token
Pass the token in the `Authorization` header on all subsequent calls:
```http
GET /api/v1/assessments
Authorization: Bearer swa_sess_a81b2c3d4e5f6789...
```

### Logout / Invalidation
```http
POST /api/v1/auth/logout
Authorization: Bearer swa_sess_a81b2c3d4e5f6789...
```

## 4. Role-Based Access Control (RBAC) Matrix

| Subsystem | Endpoint Category | Admin | Operator | Analyst | Auditor |
| :--- | :--- | :---: | :---: | :---: | :---: |
| Auth & Users | `/api/v1/users` | Full | Read | Read | Read |
| Workspaces | `/api/v1/workspaces` | Full | Read | Read | Read |
| Assessments | `/api/v1/assessments` | Full | Create / Cancel | Read | Read |
| Findings | `/api/v1/findings` | Full | Full | Verify / Update | Read |
| Remediation | `/api/v1/remediation` | Full | Retest | Transition | Read |
| Integrations | `/api/v1/integrations` | Full | Test | Read | Read |
| Approvals | `/api/v1/approvals` | Decide | Request | Read | Read |
| Audit Logs | `/api/v1/audit/logs` | Read | Read | Read | Full |
