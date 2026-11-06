# SWA AI — REST API Status Codes Specification

## 1. HTTP Transport Protocol Standards

SWA AI adheres strictly to RFC 9110 HTTP Semantics. HTTP status codes communicate REST request outcomes, distinct from finding lifecycle statuses:

| HTTP Code | Description | Standard Usage in SWA AI API |
|---|---|---|
| `200 OK` | Request succeeded | Returned on successful GET queries, metrics retrieval, list endpoints, and reports generation. |
| `201 Created` | Resource created | Returned when a new scan, asset, or finding record is successfully created. |
| `400 Bad Request` | Invalid payload or rejected transition | Returned when a transition violates state machine rules (e.g. attempting to skip retest), missing required justification, or malformed JSON. |
| `401 Unauthorized` | Missing authentication credentials | Returned when API token or session header is missing. |
| `403 Forbidden` | Access denied or SSRF Policy violation | Returned when scanning unauthorized private IP addresses (SSRF Protection) or attempting privileged actions without role clearance. |
| `404 Not Found` | Resource nonexistent | Returned when finding ID, scan ID, or asset ID does not exist in the database. |
| `422 Unprocessable Entity` | Schema validation error | Returned by FastAPI/Pydantic when request model parameters fail typing constraints. |
| `500 Internal Server Error` | Unexpected backend exception | Unhandled runtime errors; sanitized error messages logged to audit stream. |

---

## 2. API Error Response Schema

All 4xx and 5xx API errors return standard RFC 7807 problem details:

```json
{
  "detail": "Transition not allowed from CONFIRMED to RESOLVED_VERIFIED. Allowed: ['ACCEPTED_RISK', 'DUPLICATE', 'FIX_IN_PROGRESS', 'LIKELY_FALSE_POSITIVE', 'NEEDS_VALIDATION']"
}
```
