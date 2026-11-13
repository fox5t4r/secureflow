import json
import tempfile
import unittest
from unittest.mock import patch

from secureflow.catalog import RULES
from secureflow.lab.app import create_app
from secureflow.metrics import confusion, evaluate
from secureflow.probes import LabClient, probe
from secureflow.runner import demo


class MetricsTests(unittest.TestCase):
    def test_denominators(self):
        actual = dict(a=True, b=True, c=False, d=False, e=False)
        predicted = dict(a=True, b=False, c=True, d=False, e=False)
        metrics = confusion(actual, predicted)
        self.assertEqual((metrics["tp"], metrics["fp"], metrics["tn"], metrics["fn"]), (1, 1, 2, 1))
        self.assertAlmostEqual(metrics["fpr"], 1 / 3)
        self.assertEqual(metrics["fdr"], 0.5)

    def test_unknown_not_counted_as_goal_success(self):
        result = evaluate({"a": False}, [dict(id="a", state="inconclusive", sast=[{}])])
        self.assertFalse(result["target_met"])
        self.assertEqual(result["conservative"]["fp"], 1)
        self.assertEqual(result["coverage"], 0)


class BoundaryTests(unittest.TestCase):
    def test_external_urls_rejected(self):
        for url in [
            "https://example.com",
            "http://localhost:80",
            "http://127.0.0.1.evil:80",
            "http://127.0.0.1:80@evil",
            "http://127.0.0.1:80/path",
        ]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                LabClient(url, "token")

    def test_budget_before_network(self):
        client = LabClient("http://127.0.0.1:1", "token", max_requests=0)
        with self.assertRaises(RuntimeError):
            client.request("/health")

    def test_transport_failure_is_unknown(self):
        client = LabClient("http://127.0.0.1:1", "token")
        with patch.object(client, "request", side_effect=TimeoutError("timeout")):
            result = probe(client, dict(id="c01", kind="sql"))
        self.assertEqual(result["state"], "inconclusive")

    def test_lab_auth(self):
        app = create_app([dict(id="c11")], "owned-test-session")
        client = app.test_client()
        self.assertEqual(client.get("/health").status_code, 403)
        self.assertEqual(
            client.get("/health", headers={"X-Lab-Token": "owned-test-session"}).status_code, 200
        )


class WorkflowTests(unittest.TestCase):
    def test_real_end_to_end(self):
        with tempfile.TemporaryDirectory() as directory:
            output, run = demo(directory)
            confirmed = [f for f in run["findings"] if f["state"] == "confirmed"]
            self.assertEqual(len(confirmed), 20)
            self.assertEqual(len({RULES[f["kind"]]["owasp"] for f in confirmed}), 10)
            self.assertEqual(run["metrics"]["validated"]["fp"], 0)
            self.assertEqual(run["metrics"]["validated"]["fn"], 0)
            self.assertEqual(run["metrics"]["coverage"], 1)
            self.assertTrue(run["metrics"]["target_met"])
            self.assertTrue(all(f["control_passed"] for f in run["findings"]))
            self.assertEqual(len(list((output / "findings").glob("*.md"))), 20)
            self.assertEqual(len(json.loads((output / "diagnostics.json").read_text())), 40)
            self.assertIn("수정 가이드", (output / "report.html").read_text())
            self.assertGreater(run["request_count"], 24)
            self.assertLessEqual(run["request_count"], 225)


if __name__ == "__main__":
    unittest.main()
