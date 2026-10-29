"""
SWA AI — Enterprise Security Data Management Engine
Provides secure ingestion, validation, preview, schema inference, data leakage inspection,
sanitization, train/val/test splitting, and lifecycle tracking for security datasets.
"""

import os
import re
import json
import csv
import io
import uuid
import hashlib
import datetime
from typing import List, Dict, Any, Optional, Tuple
from pydantic import BaseModel, Field

DATA_DIR = os.getenv("SWA_DATA_DIR", os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "datasets"))
os.makedirs(DATA_DIR, exist_ok=True)

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB limit

# Regex detectors for accidental secret exposure and data leakage
LEAKAGE_SIGNATURES = [
    ("AWS Access Key", r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
    ("Private RSA/EC Key", r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    ("Generic Bearer / API Token", r"(?:bearer|api_key|access_token|secret)[\"'\s:=]{1,4}[a-zA-Z0-9_\-\.]{20,80}"),
    ("JSON Web Token (JWT)", r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    ("Database Connection String", r"(?:postgres|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^\s\/]+"),
    ("Hardcoded Password", r"(?:password|passwd|pwd)[\"'\s:=]{1,4}[^\s\"',;]{8,40}"),
]


class DatasetMetadata(BaseModel):
    id: str = Field(default_factory=lambda: f"ds_{uuid.uuid4().hex[:10]}")
    name: str
    filename: str
    file_type: str  # "csv", "jsonl", "json", "txt"
    version: str = "v1"
    record_count: int = 0
    file_size_bytes: int = 0
    fields: List[str] = Field(default_factory=list)
    target_label_field: Optional[str] = None
    missing_values_count: int = 0
    duplicate_count: int = 0
    leakage_warnings: List[Dict[str, Any]] = Field(default_factory=list)
    source: str = "Internal Security Audit"
    license: str = "Proprietary / Authorized Research"
    provenance: str = "SWA AI Security Assessment Corpus"
    permitted_use: str = "Model Training & Evaluation Only"
    train_split_count: int = 0
    val_split_count: int = 0
    test_split_count: int = 0
    created_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class DataManagementEngine:
    def __init__(self, storage_dir: str = DATA_DIR):
        self.storage_dir = storage_dir
        os.makedirs(self.storage_dir, exist_ok=True)

    def _sanitize_filename(self, filename: str) -> str:
        """Prevent path traversal and malicious filenames."""
        clean = os.path.basename(filename)
        clean = re.sub(r"[^\w\.\-]", "_", clean)
        return clean or f"dataset_{uuid.uuid4().hex[:6]}.txt"

    def validate_and_save(
        self,
        raw_bytes: bytes,
        original_filename: str,
        name: Optional[str] = None,
        source: str = "Security Assessment",
        license_str: str = "Proprietary / Authorized Research",
        target_label_field: Optional[str] = None
    ) -> Tuple[DatasetMetadata, List[Dict[str, Any]]]:
        """Validates encoding, parses rows, detects leakage, and saves to storage."""
        if len(raw_bytes) > MAX_UPLOAD_BYTES:
            raise ValueError(f"File size exceeds maximum permitted limit ({MAX_UPLOAD_BYTES / (1024*1024):.1f} MB)")

        # Decode utf-8
        try:
            content = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            try:
                content = raw_bytes.decode("latin-1")
            except Exception:
                raise ValueError("Dataset file must be a valid UTF-8 or Latin-1 encoded text file.")

        clean_filename = self._sanitize_filename(original_filename)
        ext = clean_filename.lower().split(".")[-1]
        if ext not in ["csv", "jsonl", "json", "txt"]:
            raise ValueError(f"Unsupported file format '.{ext}'. Supported: CSV, JSONL, JSON, TXT.")

        records, fields, missing_count, duplicate_count = self._parse_records(content, ext)
        if not records:
            raise ValueError("Dataset contains no valid records or is empty.")

        # Leakage inspection
        leakage_warnings = self._inspect_leakage(content)

        dataset_id = f"ds_{uuid.uuid4().hex[:10]}"
        storage_filename = f"{dataset_id}_{clean_filename}"
        storage_path = os.path.join(self.storage_dir, storage_filename)

        with open(storage_path, "w", encoding="utf-8") as f:
            f.write(content)

        # Compute default splits (70/15/15)
        total = len(records)
        train_count = int(total * 0.70)
        val_count = int(total * 0.15)
        test_count = total - train_count - val_count

        meta = DatasetMetadata(
            id=dataset_id,
            name=name or clean_filename.rsplit(".", 1)[0],
            filename=storage_filename,
            file_type=ext,
            record_count=total,
            file_size_bytes=len(raw_bytes),
            fields=fields,
            target_label_field=target_label_field or (fields[-1] if fields else None),
            missing_values_count=missing_count,
            duplicate_count=duplicate_count,
            leakage_warnings=leakage_warnings,
            source=source,
            license=license_str,
            train_split_count=train_count,
            val_split_count=val_count,
            test_split_count=test_count
        )

        from core.database import db
        db.save_dataset(meta)
        return meta, records[:20]

    def _parse_records(self, content: str, file_type: str) -> Tuple[List[Dict[str, Any]], List[str], int, int]:
        records: List[Dict[str, Any]] = []
        fields: List[str] = []
        missing_count = 0
        seen_hashes = set()
        duplicate_count = 0

        if file_type == "csv":
            reader = csv.DictReader(io.StringIO(content))
            fields = list(reader.fieldnames or [])
            for row in reader:
                h = hashlib.md5(json.dumps(row, sort_keys=True).encode()).hexdigest()
                if h in seen_hashes:
                    duplicate_count += 1
                else:
                    seen_hashes.add(h)
                for k, v in row.items():
                    if v is None or v.strip() == "":
                        missing_count += 1
                records.append(dict(row))

        elif file_type == "jsonl":
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        h = hashlib.md5(json.dumps(obj, sort_keys=True).encode()).hexdigest()
                        if h in seen_hashes:
                            duplicate_count += 1
                        else:
                            seen_hashes.add(h)
                        for k in obj.keys():
                            if k not in fields:
                                fields.append(k)
                        records.append(obj)
                except Exception:
                    continue

        elif file_type == "json":
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            h = hashlib.md5(json.dumps(item, sort_keys=True).encode()).hexdigest()
                            if h in seen_hashes:
                                duplicate_count += 1
                            else:
                                seen_hashes.add(h)
                            for k in item.keys():
                                if k not in fields:
                                    fields.append(k)
                            records.append(item)
                elif isinstance(data, dict):
                    records.append(data)
                    fields = list(data.keys())
            except Exception:
                pass

        elif file_type == "txt":
            fields = ["text"]
            for idx, line in enumerate(content.splitlines()):
                line = line.strip()
                if line:
                    h = hashlib.md5(line.encode()).hexdigest()
                    if h in seen_hashes:
                        duplicate_count += 1
                    else:
                        seen_hashes.add(h)
                    records.append({"text": line, "line_no": idx + 1})

        return records, fields, missing_count, duplicate_count

    def _inspect_leakage(self, content: str) -> List[Dict[str, Any]]:
        warnings = []
        for name, pattern in LEAKAGE_SIGNATURES:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                # Mask matches in warning
                masked_samples = [m[:4] + "*" * (len(m) - 6) + m[-2:] if len(m) > 6 else "***" for m in matches[:3]]
                warnings.append({
                    "type": name,
                    "count": len(matches),
                    "samples": masked_samples,
                    "severity": "CRITICAL" if "Key" in name or "Token" in name else "HIGH"
                })
        return warnings

    def redact_secrets(self, content: str) -> str:
        """Sanitizes dataset by replacing identified secret patterns with placeholder tokens."""
        sanitized = content
        for name, pattern in LEAKAGE_SIGNATURES:
            sanitized = re.sub(pattern, f"[REDACTED_{name.upper().replace(' ', '_')}]", sanitized, flags=re.IGNORECASE)
        return sanitized

    def get_dataset_records(self, dataset_id: str, limit: int = 50, offset: int = 0) -> Tuple[List[Dict[str, Any]], int]:
        from core.database import db
        meta = db.get_dataset(dataset_id)
        if not meta:
            return [], 0

        storage_path = os.path.join(self.storage_dir, meta.filename)
        if not os.path.exists(storage_path):
            return [], 0

        with open(storage_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        records, _, _, _ = self._parse_records(content, meta.file_type)
        return records[offset: offset + limit], len(records)

    def split_dataset(
        self,
        dataset_id: str,
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        test_ratio: float = 0.15
    ) -> Dict[str, Any]:
        """Configures and validates reproducible dataset partitions."""
        from core.database import db
        meta = db.get_dataset(dataset_id)
        if not meta:
            raise ValueError(f"Dataset {dataset_id} not found.")

        total = meta.record_count
        if abs((train_ratio + val_ratio + test_ratio) - 1.0) > 0.01:
            raise ValueError("Partition ratios must sum to 1.0 (100%).")

        train_count = int(total * train_ratio)
        val_count = int(total * val_ratio)
        test_count = total - train_count - val_count

        meta.train_split_count = train_count
        meta.val_split_count = val_count
        meta.test_split_count = test_count
        meta.updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        db.save_dataset(meta)

        return {
            "dataset_id": dataset_id,
            "total_records": total,
            "train_records": train_count,
            "val_records": val_count,
            "test_records": test_count,
            "ratios": {"train": train_ratio, "val": val_ratio, "test": test_ratio}
        }

    def delete_dataset(self, dataset_id: str) -> bool:
        from core.database import db
        meta = db.get_dataset(dataset_id)
        if not meta:
            return False

        storage_path = os.path.join(self.storage_dir, meta.filename)
        if os.path.exists(storage_path):
            try:
                os.remove(storage_path)
            except Exception:
                pass
        return db.delete_dataset(dataset_id)


dataset_manager = DataManagementEngine()
