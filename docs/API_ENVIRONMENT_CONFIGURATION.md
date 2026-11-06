# SWA AI — Environment Configuration & Operational Variables

## 1. Core Platform Variables

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `SWA_HOST` | String | `0.0.0.0` | Bind host address for API server |
| `SWA_PORT` | Integer | `8000` | Bind port for HTTP/API service |
| `HEADLESS` | Boolean | `0` | Disable automatic browser launch on startup |
| `ENVIRONMENT` | String | `production` | Deployment mode (`production`, `development`) |
| `SWA_AUTH_ENABLED` | Boolean | `false` | Enforce strict session token & API key auth |
| `SWA_MASTER_API_KEY` | String | *(None)* | Secret master key for CI/CD and automation |
| `SWA_RATE_LIMIT_ENABLED` | Boolean | `true` | Enable token-bucket DoS rate limiting |
| `SWA_ALLOWED_ORIGINS` | String | *(Local)* | Comma-separated list of trusted CORS origins |

## 2. AI Provider Keys

| Variable | Provider | Purpose |
| :--- | :--- | :--- |
| `OPENAI_API_KEY` | OpenAI | GPT-4o, o1, o3-mini models |
| `ANTHROPIC_API_KEY` | Anthropic | Claude 3.5 Sonnet, Claude 3.7 models |
| `GEMINI_API_KEY` | Google Gemini | Gemini 2.0 Flash, Gemini 1.5 Pro |
| `OPENROUTER_API_KEY` | OpenRouter | Aggregated multi-model routing |
| `OLLAMA_BASE_URL` | Ollama | Local model inference endpoint (`http://localhost:11434`) |

## 3. Threat Intelligence Keys

| Variable | Feed Provider |
| :--- | :--- |
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 API |
| `ABUSEIPDB_API_KEY` | AbuseIPDB reputation API |
| `SHODAN_API_KEY` | Shodan search engine API |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | Censys attack surface API |
| `ALIENVAULT_OTX_KEY` | AlienVault OTX community pulses |
