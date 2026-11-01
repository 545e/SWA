# SWA AI — Generation 3 AI Training & Fine-Tuning Strategy

## 1. Executive Strategy & Training Justification Framework

Prior to undertaking any model fine-tuning or training within SWA AI, the platform applies a strict 10-step justification framework:
1. **Identify the actual AI tasks:** Vulnerability classification, severity scoring, false-positive triage, and remediation patch recommendations.
2. **Evaluate existing models:** Test open-source foundation models (e.g. Llama 3 8B, Mistral 7B, StarCoder2).
3. **Establish baseline performance:** Measure baseline accuracy, F1 score, and latency.
4. **Test prompt engineering:** Evaluate multi-shot prompting and system role conditioning.
5. **Test structured outputs:** Enforce Pydantic JSON schemas.
6. **Test RAG:** Evaluate retrieval from OWASP, CWE, and CVE knowledge bases.
7. **Test retrieval quality:** Benchmark Top-K recall and ranking precision.
8. **Identify specific model limitations:** Pinpoint domain gaps in proprietary vulnerability formats.
9. **Determine whether fine-tuning solves those limitations:** Compare parameter-efficient fine-tuning (LoRA / QLoRA) against prompt + RAG.
10. **Estimate compute, cost, and maintenance:** Assess GPU VRAM requirements and training cost versus inference benefits.

> [!NOTE]
> Training or fine-tuning from scratch is economically and technically unjustified when zero-shot prompting paired with RAG achieves >90% precision on vulnerability explanation and triage.

---

## 2. Dataset Preparation & Hygiene Pipeline

- Handled in `core/data_management.py` and validated by `tests/test_data_management.py`.
- Automated detection and redaction of credentials, bearer tokens, and private keys.
- Deterministic train/validation/test splits (70/15/15) partitioned by project and time to prevent synthetic data leakage.

---

## 3. Evaluation Benchmarks

In `core/ai_evaluation.py`:
- Classification metrics: Accuracy, Precision, Recall, F1 Score, Confusion Matrix.
- Operational metrics: Inference latency (ms), token consumption, memory footprint.
- Low-Resource Constraint: Guaranteed execution on constrained environments (2 vCPUs, 3 GB RAM).
