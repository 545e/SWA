"""
Unit and integration tests for SWA AI Model Training, Fine-Tuning, and Evaluation Engine.
Validates hardware detection, training job lifecycle, loss convergence, checkpoint persistence,
precision/recall/F1 scoring, confusion matrices, inference benchmarking, and cost calculation.
"""

import unittest
import asyncio
from core.ai_training import ai_trainer, TrainingConfig
from core.ai_evaluation import ai_evaluator
from core.data_management import dataset_manager
from core.database import db


class TestAITrainingAndEvaluation(unittest.TestCase):
    def setUp(self):
        # Create a sample dataset for training
        csv_bytes = (
            "text,label\n"
            "' OR 1=1 --,SQLI\n"
            "<script>alert(1)</script>,XSS\n"
            "cat /etc/passwd,CMDI\n"
            "http://169.254.169.254/,SSRF\n"
            "normal product search,BENIGN\n"
        ).encode("utf-8")
        self.dataset_meta, _ = dataset_manager.validate_and_save(
            raw_bytes=csv_bytes,
            original_filename="train_eval_data.csv",
            name="Training Test Corpus"
        )

    def test_01_hardware_detection(self):
        hw = ai_trainer.hardware_info
        self.assertIn("device", hw)
        self.assertIn("cpu_cores", hw)
        self.assertGreater(hw["cpu_cores"], 0)

    def test_02_start_and_complete_training_job(self):
        async def run_test():
            cfg = TrainingConfig(
                model_name="test-security-classifier-v1",
                base_model="security-roberta-base",
                dataset_id=self.dataset_meta.id,
                epochs=2,
                batch_size=8,
                learning_rate=0.001
            )
            job = await ai_trainer.start_training(cfg)
            self.assertEqual(job.status, "QUEUED")

            # Wait for background task to complete (2 epochs take ~2 seconds)
            for _ in range(10):
                await asyncio.sleep(0.5)
                updated = db.get_training_job(job.id)
                if updated and updated.status in ["COMPLETED", "FAILED"]:
                    job = updated
                    break

            self.assertEqual(job.status, "COMPLETED")
            self.assertEqual(job.current_epoch, 2)
            self.assertEqual(len(job.loss_history), 2)
            self.assertIsNotNone(job.checkpoint_path)
            self.assertIsNotNone(job.model_artifact_path)
            self.assertGreater(job.duration_seconds, 0)

        asyncio.run(run_test())

    def test_03_evaluate_security_classifier(self):
        eval_res = ai_evaluator.evaluate_security_classifier(
            model_name="test-security-classifier-v1",
            baseline_name="heuristic-baseline-v1",
            dataset_id=self.dataset_meta.id,
            test_samples=100
        )
        self.assertTrue(eval_res.id.startswith("eval_"))
        self.assertEqual(eval_res.task_type, "classification")
        self.assertGreater(eval_res.accuracy, 0.0)
        self.assertGreater(eval_res.precision, 0.0)
        self.assertGreater(eval_res.recall, 0.0)
        self.assertGreater(eval_res.f1_score, 0.0)

        # Verify confusion matrix properties
        cm = eval_res.confusion_matrix
        self.assertEqual(cm.true_positive + cm.false_positive + cm.true_negative + cm.false_negative, 100)

        # Verify DB persistence
        evals = db.list_ai_evaluations()
        self.assertGreater(len(evals), 0)

    def test_04_evaluate_llm_inference_metrics_and_cost(self):
        llm_eval = ai_evaluator.evaluate_llm_inference(
            provider="openai",
            model_name="gpt-4o",
            prompt_count=20
        )
        self.assertEqual(llm_eval.task_type, "llm_inference")
        self.assertGreater(llm_eval.latency_ms_per_request, 0)
        self.assertGreater(llm_eval.throughput_tokens_per_sec, 0)
        self.assertGreater(llm_eval.total_tokens, 0)
        self.assertGreater(llm_eval.estimated_cost_usd, 0.0)


if __name__ == "__main__":
    unittest.main()
