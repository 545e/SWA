"""
Unit and integration tests for SWA AI Data Management Engine.
Validates file ingestion, CSV/JSONL parsing, schema validation, PII/secret leakage detection,
dataset splitting, secret redaction, and deletion controls.
"""

import unittest
import os
import json
import tempfile
from core.data_management import dataset_manager, DatasetMetadata
from core.database import db


class TestDataManagement(unittest.TestCase):
    def setUp(self):
        self.test_csv = (
            "payload,category,label,description\n"
            "' OR '1'='1' --,SQLi,MALICIOUS,Standard SQL injection authentication bypass\n"
            "<script>alert(1)</script>,XSS,MALICIOUS,Reflected cross-site scripting probe\n"
            "http://169.254.169.254/latest/meta-data/,SSRF,MALICIOUS,AWS IMDS cloud metadata access\n"
            "/api/v1/products?cat=electronics,API,BENIGN,Standard e-commerce product query\n"
            "GET /index.html HTTP/1.1,HTTP,BENIGN,Normal web document retrieval\n"
        ).encode("utf-8")

        self.leakage_csv = (
            "username,api_token,notes\n"
            "admin,AKIAIOSFODNN7EXAMPLE,AWS deployment user key\n"
            "dev_user,bearer_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisToken,Production JWT token\n"
        ).encode("utf-8")

    def test_01_upload_and_validate_csv_dataset(self):
        meta, preview = dataset_manager.validate_and_save(
            raw_bytes=self.test_csv,
            original_filename="security_payloads.csv",
            name="Security Payloads Corpus",
            source="Internal Red Team Lab",
            target_label_field="label"
        )
        self.assertTrue(meta.id.startswith("ds_"))
        self.assertEqual(meta.record_count, 5)
        self.assertEqual(meta.file_type, "csv")
        self.assertIn("payload", meta.fields)
        self.assertIn("label", meta.fields)
        self.assertEqual(len(preview), 5)
        self.assertEqual(meta.leakage_warnings, [])

        # Verify DB persistence
        retrieved = db.get_dataset(meta.id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.name, "Security Payloads Corpus")

    def test_02_detect_secret_and_credential_leakage(self):
        meta, preview = dataset_manager.validate_and_save(
            raw_bytes=self.leakage_csv,
            original_filename="leaked_keys.csv",
            name="Leaked Secrets Test",
            source="Audit"
        )
        self.assertEqual(meta.record_count, 2)
        self.assertGreater(len(meta.leakage_warnings), 0)
        types = [w["type"] for w in meta.leakage_warnings]
        self.assertTrue(any("AWS" in t for t in types) or any("JWT" in t for t in types) or any("Token" in t for t in types))

    def test_03_dataset_train_val_test_splitting(self):
        meta, _ = dataset_manager.validate_and_save(
            raw_bytes=self.test_csv,
            original_filename="split_test.csv"
        )
        split_res = dataset_manager.split_dataset(meta.id, train_ratio=0.6, val_ratio=0.2, test_ratio=0.2)
        self.assertEqual(split_res["total_records"], 5)
        self.assertEqual(split_res["train_records"], 3)
        self.assertEqual(split_res["val_records"], 1)
        self.assertEqual(split_res["test_records"], 1)

    def test_04_secret_redaction(self):
        dirty_text = "Here is my secret AWS key: AKIAIOSFODNN7EXAMPLE and private password='SuperSecretPassword123!'"
        cleaned = dataset_manager.redact_secrets(dirty_text)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", cleaned)
        self.assertIn("REDACTED", cleaned)

    def test_05_delete_dataset(self):
        meta, _ = dataset_manager.validate_and_save(
            raw_bytes=self.test_csv,
            original_filename="to_delete.csv"
        )
        deleted = dataset_manager.delete_dataset(meta.id)
        self.assertTrue(deleted)
        self.assertIsNone(db.get_dataset(meta.id))


if __name__ == "__main__":
    unittest.main()
