# SWA AI — REST API Reference Manual

Base URL: `http://127.0.0.1:8000` (or configured host/port)  
Interactive OpenAPI Documentation: `http://127.0.0.1:8000/docs`

---

## 1. Security Operations & Scans

### Launch Scan
- **Endpoint:** `POST /api/scans`
- **Description:** Enqueues an autonomous multi-phase security assessment.
- **Request Body:**
```json
{
  "target_url": "https://example.com",
  "profile": "standard",
  "max_depth": 2,
  "concurrency": 15,
  "timeout_sec": 10,
  "lab_mode": false
}
```
- **Profiles:** `passive_recon`, `recon_only`, `quick`, `standard`, `full_red_team`, `owasp_top10`, `api_security`, `lab_assessment`, `all_tools`.
- **Response:** `200 OK` returns `ScanJob` object with `id` (`scan_...`).

### Get Scan Status
- **Endpoint:** `GET /api/scans/{scan_id}`
- **Response:** Current `status`, `progress_percent`, `current_phase`, and count of findings categorized by severity.

### List Historical Scans
- **Endpoint:** `GET /api/scans`
- **Response:** List of all historical assessments.

### Scan Posture Comparison & Diff
- **Endpoint:** `POST /api/scans/compare`
- **Request Body:**
```json
{
  "base_scan_id": "scan_112233",
  "compare_scan_id": "scan_445566"
}
```
- **Response:** Score delta, new findings introduced, findings resolved, and persistent findings list.

### Get Findings
- **Endpoint:** `GET /api/scans/{scan_id}/findings`
- **Response:** List of `VulnerabilityFinding` objects including CVSS, CWE, reproduction curl PoC, request/response evidence, and remediation patch.

### Export Reports
- **Endpoint:** `GET /api/scans/{scan_id}/report?format={html|json|sarif|csv|markdown}`
- **Response:** Downloadable report document.

---

## 2. Reconnaissance & External Asset Inventory

### Autonomous Subdomain Discovery
- **Endpoint:** `POST /api/tools/subdomains`
- **Request Body:** `{"domain": "example.com", "passive_only": false, "concurrency": 20}`
- **Response:** Structured asset inventory with IP addresses, CNAME alias, verification status, and takeover risk.

### Query Asset Inventory
- **Endpoint:** `GET /api/assets?parent_domain={domain}&limit={100}&offset={0}`
- **Response:** Paginated records from persistent external asset database.

### Export Asset Inventory
- **Endpoint:** `GET /api/assets/export?format={json|csv}`
- **Response:** Downloadable CSV or JSON asset file.

---

## 3. Data Management (Phase 4)

### Upload Security Dataset
- **Endpoint:** `POST /api/datasets/upload`
- **Multipart Form:** `file` (.csv, .jsonl, .json, .txt), `name`, `source`, `license`, `target_label`.
- **Response:** Ingested metadata, 20 preview records, and leakage warnings (AWS keys, JWTs, private keys).

### List Datasets
- **Endpoint:** `GET /api/datasets`
- **Response:** Array of managed datasets with sample counts, size, and split metrics.

### Configure Train/Val/Test Splits
- **Endpoint:** `POST /api/datasets/{dataset_id}/split`
- **Request Body:** `{"train_ratio": 0.70, "val_ratio": 0.15, "test_ratio": 0.15}`
- **Response:** Partition breakdown.

### Delete Dataset
- **Endpoint:** `DELETE /api/datasets/{dataset_id}`

---

## 4. AI Model Training & Fine-Tuning (Phase 5)

### System Compute Hardware Inspection
- **Endpoint:** `GET /api/ai/hardware`
- **Response:** Detected CPU cores, system RAM, CUDA GPU device name, or Apple Silicon MPS.

### Start Training Job
- **Endpoint:** `POST /api/ai/training/start`
- **Request Body:**
```json
{
  "model_name": "swa-vuln-classifier-v1",
  "base_model": "security-roberta-base",
  "dataset_id": "ds_a1b2c3d4e5",
  "task_type": "vulnerability_classification",
  "epochs": 3,
  "batch_size": 16,
  "learning_rate": 0.001
}
```
- **Response:** `TrainingJob` object enqueued in background.

### List Training Experiments
- **Endpoint:** `GET /api/ai/training/jobs`

### Get Training Job Progress
- **Endpoint:** `GET /api/ai/training/jobs/{job_id}`
- **Response:** Epoch-by-epoch loss history, accuracy history, logs, and checkpoint artifact path.

### Cancel Training Job
- **Endpoint:** `POST /api/ai/training/jobs/{job_id}/cancel`

---

## 5. Model Tuning & Evaluation (Phase 6)

### Run Benchmark Evaluation
- **Endpoint:** `POST /api/ai/evaluation/run`
- **Request Body:**
```json
{
  "model_name": "swa-vuln-classifier-v1",
  "baseline_model_name": "heuristic-baseline-v1",
  "dataset_id": "ds_a1b2c3d4e5",
  "task_type": "classification",
  "test_sample_count": 150
}
```
- **Response:** Accuracy, Precision, Recall, F1 score, 2x2 Confusion Matrix (`TP`, `FP`, `TN`, `FN`), Latency ms, Throughput, and Cost estimate.

---

## 6. LLM Red Teaming & Security Testing (Phase 7)

### Get Test Suite Definition
- **Endpoint:** `GET /api/ai/redteam/test-cases`
- **Response:** All 12 OWASP Top 10 for LLM threat categories and descriptions.

### Execute Red-Team Assessment
- **Endpoint:** `POST /api/ai/redteam/run`
- **Request Body:**
```json
{
  "target_provider": "openai",
  "target_model": "gpt-4o",
  "category": null
}
```
- **Response:** Pass/fail audit report, overall security grade, evidence logs, and mitigation recommendations.

### Get Historical Red-Team Runs
- **Endpoint:** `GET /api/ai/redteam/runs`
