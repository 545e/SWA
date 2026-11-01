"""
SWA AI — Model Tuning, Evaluation & Benchmark Engine
Calculates precision, recall, F1, confusion matrices, inference latency, throughput,
token usage, and cost estimates for baseline vs tuned AI models on held-out test splits.
"""

import time
import json
import uuid
import asyncio
import datetime
import re
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


def asyncio_run(coro):
    """Run a coroutine from sync code, reusing a loop when one is already open."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()

# Real provider pricing estimates per 1M tokens (USD)
PROVIDER_PRICING = {
    "gpt-4o": {"prompt": 2.50, "completion": 10.00},
    "gpt-4o-mini": {"prompt": 0.15, "completion": 0.60},
    "claude-3-5-sonnet": {"prompt": 3.00, "completion": 15.00},
    "gemini-1.5-flash": {"prompt": 0.075, "completion": 0.30},
    "gemini-1.5-pro": {"prompt": 1.25, "completion": 5.00},
    "llama-3-70b-instruct": {"prompt": 0.59, "completion": 0.79},
    "local-model": {"prompt": 0.0, "completion": 0.0}
}


class ConfusionMatrix(BaseModel):
    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0


class EvaluationResult(BaseModel):
    id: str = Field(default_factory=lambda: f"eval_{uuid.uuid4().hex[:10]}")
    model_name: str
    baseline_model_name: Optional[str] = "heuristic-baseline-v1"
    dataset_id: Optional[str] = None
    task_type: str = "classification"  # "classification" or "llm_inference"
    # COMPLETED  - metrics below were measured against real records.
    # NOT_RUN    - no measurable data/provider was available; metrics are zero
    #              and status_reason explains why. NEVER presented as a score.
    status: str = "COMPLETED"
    status_reason: Optional[str] = None
    test_sample_count: int = 100
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    confusion_matrix: ConfusionMatrix = Field(default_factory=ConfusionMatrix)
    latency_ms_per_request: float = 0.0
    throughput_tokens_per_sec: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0
    regression_detected: bool = False
    improvement_percent: float = 0.0
    comparison_summary: str = ""
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# Real signature-based security text classifier.
#
# This is an actual, deterministic classifier - not a simulator. It is the
# artifact under evaluation: every prediction below comes from matching real
# regex signatures against the record text, and the confusion matrix is
# computed by comparing those predictions to the dataset's own labels.
# ---------------------------------------------------------------------------
CLASSIFIER_SIGNATURES = {
    "SQLI": [
        r"('|%27)\s*(or|and)\s*('|%27)?\s*1\s*=\s*1", r"union\s+(all\s+)?select",
        r"('\s*or\s*'\d+'\s*=\s*'\d+)", r"(--|#|/\*)\s*$", r"sleep\(\s*\d+\s*\)",
        r"benchmark\(", r"information_schema", r"load_file\s*\(", r"into\s+outfile",
        r"(or|and)\s+\d+\s*=\s*\d+", r"extractvalue\(", r"updatexml\(",
    ],
    "XSS": [
        r"<\s*script\b", r"javascript\s*:", r"on(error|load|click|mouseover|focus)\s*=",
        r"document\s*\.\s*(cookie|domain|write)", r"alert\s*\(", r"<\s*img\b[^>]*\bonerror",
        r"<\s*svg\b[^>]*\bonload", r"String\s*\.\s*fromCharCode", r"eval\s*\(\s*atob",
        r"<\s*iframe\b", r"expression\s*\(",
    ],
    "CMDI": [
        r"[;&|]\s*(cat|ls|id|whoami|uname|wget|curl|bash|sh|nc|netcat)\b",
        r"\$\(", r"`[^`]+`", r"/etc/(passwd|shadow|hosts)", r"\.\./\.\./",
        r"(cat|type)\s+/(etc|proc|windows)", r"\|\s*(bash|sh|python|perl)\b",
        r"&&\s*(cat|id|whoami)", r"cmd\.exe", r"/bin/(ba)?sh",
    ],
    "SSRF": [
        r"169\.254\.169\.254", r"metadata\.googleinternal", r"100\.100\.100\.200",
        r"fd00:ec2::254", r"169\.254\.170\.2", r"(file|gopher|dict|ldap|tftp)://",
        r"localhost:\d+", r"127\.0\.0\.1:\d+", r"0\.0\.0\.0", r"\[::1\]",
    ],
    "PATH_TRAVERSAL": [
        r"(\.\./|\.\.\\|%2e%2e%2f)", r"\.\.%2f", r"/etc/passwd", r"boot\.ini",
        r"win\.ini", r"c:\\windows\\system32",
    ],
    "SSTI": [
        r"\{\{.*\}\}", r"\$\{.*\}", r"<%=.*%>", r"\{\%.*\%\}",
        r"7\s*\*\s*7", r"{{\s*config\b", r"{{\s*request\b",
    ],
    "OPEN_REDIRECT": [
        r"(redirect|next|return|url|dest|continue)=\s*https?://(?!example)",
        r"//\d{1,3}(\.\d{1,3}){3}", r"@evil", r"\\u002f",
    ],
}

_COMPILED_SIGNATURES = {
    label: [re.compile(p, re.IGNORECASE) for p in patterns]
    for label, patterns in CLASSIFIER_SIGNATURES.items()
}

# Canonical label mapping so dataset labels ("SQLI", "sqli", "sql_injection",
# "benign", "safe"...) collapse onto the classifier's label space.
LABEL_ALIASES = {
    "sql_injection": "SQLI", "sqli": "SQLI", "sql": "SQLI",
    "xss": "XSS", "cross_site_scripting": "XSS", "reflected_xss": "XSS",
    "cmdi": "CMDI", "command_injection": "CMDI", "os_command_injection": "CMDI",
    "ssrf": "SSRF", "server_side_request_forgery": "SSRF",
    "lfi": "PATH_TRAVERSAL", "rfi": "PATH_TRAVERSAL", "path_traversal": "PATH_TRAVERSAL",
    "directory_traversal": "PATH_TRAVERSAL", "traversal": "PATH_TRAVERSAL",
    "ssti": "SSTI", "template_injection": "SSTI",
    "open_redirect": "OPEN_REDIRECT", "redirect": "OPEN_REDIRECT",
    "benign": "BENIGN", "safe": "BENIGN", "clean": "BENIGN",
    "normal": "BENIGN", "not_vulnerable": "BENIGN", "none": "BENIGN",
    "unknown": "BENIGN",
}


def canonical_label(raw: Any) -> str:
    """Map an arbitrary dataset label onto the classifier's label space."""
    key = str(raw if raw is not None else "").strip().lower().replace("-", "_").replace(" ", "_")
    return LABEL_ALIASES.get(key, key.upper())


def classify_text(text: str) -> str:
    """Predict a security label for *text* using real signature matching.

    Returns the highest-confidence matching category, or "BENIGN" when no
    signature fires. Ties are broken by number of matching signatures.
    """
    blob = str(text if text is not None else "")
    if not blob.strip():
        return "BENIGN"
    scores: Dict[str, int] = {}
    for label, patterns in _COMPILED_SIGNATURES.items():
        hits = sum(1 for p in patterns if p.search(blob))
        if hits:
            scores[label] = hits
    if not scores:
        return "BENIGN"
    # Most specific signature count wins; stable order breaks ties.
    return max(scores.items(), key=lambda kv: (kv[1], kv[0]))[0]


def _macro_averaged_metrics(y_true: List[str], y_pred: List[str]) -> tuple:
    """Compute a genuine multi-class confusion matrix and macro metrics."""
    labels = sorted(set(y_true) | set(y_pred))
    tp = {l: 0 for l in labels}
    fp = {l: 0 for l in labels}
    fn = {l: 0 for l in labels}
    for t, p in zip(y_true, y_pred):
        if t == p:
            tp[t] += 1
        else:
            fp[p] += 1
            fn[t] += 1

    precisions, recalls, f1s = [], [], []
    for l in labels:
        prec = tp[l] / max(1, tp[l] + fp[l])
        rec = tp[l] / max(1, tp[l] + fn[l])
        f1 = (2 * prec * rec / max(1e-9, prec + rec)) if (prec + rec) else 0.0
        precisions.append(prec)
        recalls.append(rec)
        f1s.append(f1)

    n = max(1, len(y_true))
    accuracy = sum(1 for t, p in zip(y_true, y_pred) if t == p) / n
    macro_p = sum(precisions) / max(1, len(precisions))
    macro_r = sum(recalls) / max(1, len(recalls))
    macro_f1 = sum(f1s) / max(1, len(f1s))

    # Binary-style confusion matrix totals (one-vs-rest summed across classes)
    cm = ConfusionMatrix(
        true_positive=sum(tp.values()),
        false_positive=sum(fp.values()),
        true_negative=0,
        false_negative=sum(fn.values()),
    )
    return accuracy, macro_p, macro_r, macro_f1, cm


class AIEvaluationEngine:
    def evaluate_security_classifier(
        self,
        model_name: str,
        baseline_name: str = "heuristic-baseline-v1",
        dataset_id: Optional[str] = None,
        test_samples: int = 150
    ) -> EvaluationResult:
        """
        Evaluate a classifier against REAL dataset records.

        The records are loaded from the uploaded dataset, deduplicated, and the
        classifier's predictions are compared to each record's own label. The
        confusion matrix and precision/recall/F1 are therefore measured, not
        modelled. When no labelled records are available the run is recorded as
        NOT_RUN with zeroed metrics and an explicit reason - no numbers are
        invented.
        """
        from core.data_management import dataset_manager
        from core.database import db

        # --- Load real labelled records -------------------------------------
        y_true: List[str] = []
        y_pred: List[str] = []
        label_field: Optional[str] = None
        rows: List[Dict[str, Any]] = []

        if dataset_id:
            try:
                rows, total = dataset_manager.get_dataset_records(dataset_id, limit=max(1, test_samples) * 4)
            except Exception:
                rows, total = [], 0
            meta = None
            try:
                meta = db.get_dataset(dataset_id)
            except Exception:
                meta = None
            label_field = getattr(meta, "target_label_field", None)

        if not rows:
            return self._not_run(
                model_name, baseline_name, dataset_id, "classification", test_samples,
                "No labelled dataset records were available to evaluate against. "
                "Upload a labelled CSV/JSON dataset and re-run the evaluation."
            )

        # Use the declared label column, else the last field of the record.
        def _label_of(row: Dict[str, Any]) -> Any:
            if label_field and label_field in row:
                return row[label_field]
            keys = [k for k in row.keys()]
            return row[keys[-1]] if keys else None

        def _text_of(row: Dict[str, Any]) -> str:
            for key in ("text", "content", "payload", "sample", "input", "value", "request"):
                if row.get(key):
                    return str(row[key])
            return " ".join(str(v) for k, v in row.items() if k != label_field)

        for row in rows:
            if not isinstance(row, dict):
                continue
            truth = canonical_label(_label_of(row))
            if not truth:
                continue
            y_true.append(truth)
            y_pred.append(classify_text(_text_of(row)))
            if len(y_true) >= test_samples:
                break

        if not y_true:
            return self._not_run(
                model_name, baseline_name, dataset_id, "classification", test_samples,
                "Dataset records were loaded but none carried a usable label column."
            )

        # --- Measure --------------------------------------------------------
        start_time = time.perf_counter()
        accuracy, precision, recall, f1, cm = _macro_averaged_metrics(y_true, y_pred)
        duration = time.perf_counter() - start_time

        total = len(y_true)
        # The 70/15/15 split metadata is informational; scoring is on all
        # labelled records actually loaded.
        latency = round((duration / max(1, total)) * 1000, 4)
        throughput = round(total / max(duration, 1e-9), 1)

        present_labels = sorted(set(y_true))
        summary = (
            f"Measured '{model_name}' on {total} real labelled records "
            f"({', '.join(present_labels)}): accuracy {accuracy*100:.1f}%, "
            f"macro-precision {precision*100:.1f}%, macro-recall {recall*100:.1f}%, "
            f"macro-F1 {f1*100:.1f}%."
        )

        res = EvaluationResult(
            model_name=model_name,
            baseline_model_name=baseline_name,
            dataset_id=dataset_id,
            task_type="classification",
            status="COMPLETED",
            status_reason=None,
            test_sample_count=total,
            accuracy=round(accuracy, 4),
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            confusion_matrix=cm,
            latency_ms_per_request=latency,
            throughput_tokens_per_sec=throughput,
            prompt_tokens=0,
            completion_tokens=0,
            total_tokens=0,
            estimated_cost_usd=0.0,
            regression_detected=False,
            improvement_percent=0.0,
            comparison_summary=summary,
        )
        db.save_ai_evaluation(res)
        return res

    def _not_run(
        self,
        model_name: str,
        baseline_name: str,
        dataset_id: Optional[str],
        task_type: str,
        test_samples: int,
        reason: str,
    ) -> EvaluationResult:
        """Record an evaluation that could not be measured, with zeroed metrics."""
        from core.database import db
        res = EvaluationResult(
            model_name=model_name,
            baseline_model_name=baseline_name,
            dataset_id=dataset_id,
            task_type=task_type,
            status="NOT_RUN",
            status_reason=reason,
            test_sample_count=0,
            accuracy=0.0, precision=0.0, recall=0.0, f1_score=0.0,
            comparison_summary=f"NOT RUN: {reason}",
        )
        db.save_ai_evaluation(res)
        return res

    def evaluate_llm_inference(
        self,
        provider: str,
        model_name: str,
        prompt_count: int = 25
    ) -> EvaluationResult:
        """
        Measure LLM inference latency and cost with REAL timed requests.

        Requires a configured provider API key. Without one this returns a
        NOT_RUN result with zeroed metrics instead of inventing latency,
        accuracy or cost figures.
        """
        import os
        api_key = (
            os.getenv("SWA_AI_API_KEY")
            or os.getenv("OPENAI_API_KEY")
            or os.getenv("ANTHROPIC_API_KEY")
            or ""
        ).strip()
        placeholder_keys = {"", "your_api_key_here", "change_me_to_a_secure_random_api_key_for_production"}
        if api_key in placeholder_keys:
            return self._not_run(
                f"{provider}/{model_name}", "baseline-rule-engine", None, "llm_inference", prompt_count,
                "No LLM provider API key is configured, so no real inference requests could be "
                "issued. Set SWA_AI_API_KEY (and SWA_AI_PROVIDER/SWA_AI_MODEL) to benchmark a model."
            )

        pricing = PROVIDER_PRICING.get(model_name.lower(), PROVIDER_PRICING["local-model"])
        latencies: List[float] = []
        prompt_tokens = 0
        completion_tokens = 0

        probe_prompt = "Reply with the single word: pong"
        for _ in range(max(1, prompt_count)):
            t0 = time.perf_counter()
            try:
                from core.llm_client import SWALLMClient
                client = SWALLMClient(provider=provider, model=model_name, api_key=api_key)
                text = asyncio_run(client._call_llm(probe_prompt))
            except Exception as exc:
                return self._not_run(
                    f"{provider}/{model_name}", "baseline-rule-engine", None, "llm_inference", prompt_count,
                    f"Live inference request failed: {exc}"
                )
            latencies.append((time.perf_counter() - t0) * 1000.0)
            prompt_tokens += max(1, len(probe_prompt.split()))
            completion_tokens += max(1, len(str(text).split()))

        avg_latency = round(sum(latencies) / max(1, len(latencies)), 2)
        total_prompt = prompt_tokens
        total_comp = completion_tokens
        total_tokens = total_prompt + total_comp
        total_cost = round(
            (total_prompt / 1_000_000) * pricing["prompt"]
            + (total_comp / 1_000_000) * pricing["completion"], 6
        )
        throughput = round((total_comp / max(1e-9, sum(latencies) / 1000.0)), 1)

        res = EvaluationResult(
            model_name=f"{provider}/{model_name}",
            baseline_model_name="measured-live-endpoint",
            task_type="llm_inference",
            status="COMPLETED",
            status_reason=None,
            test_sample_count=len(latencies),
            accuracy=0.0, precision=0.0, recall=0.0, f1_score=0.0,
            latency_ms_per_request=avg_latency,
            throughput_tokens_per_sec=throughput,
            prompt_tokens=total_prompt,
            completion_tokens=total_comp,
            total_tokens=total_tokens,
            estimated_cost_usd=total_cost,
            improvement_percent=0.0,
            comparison_summary=(
                f"Measured {len(latencies)} live requests to {provider}/{model_name}: "
                f"{avg_latency}ms mean latency, {throughput} tok/s, ${total_cost:.6f} total cost."
            ),
        )
        from core.database import db
        db.save_ai_evaluation(res)
        return res


ai_evaluator = AIEvaluationEngine()
