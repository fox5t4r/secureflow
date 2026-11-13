import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from secureflow.dashboard import create_dashboard
from secureflow.jobs import JobEngine


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = create_dashboard(self.temp.name, start_workers=False)
        self.app.testing = True
        self.client = self.app.test_client()
        self.store = self.app.extensions["store"]
        credentials = dict(
            line.split("=", 1)
            for line in (Path(self.temp.name) / "initial-admin.txt").read_text().splitlines()
        )
        self.password = credentials["password"]
        self.csrf = self.client.get("/api/session").json["csrf"]

    def tearDown(self):
        self.temp.cleanup()

    def post(self, path, data):
        response = self.client.post(path, json=data, headers={"X-CSRF-Token": self.csrf})
        if response.is_json and response.json.get("csrf"):
            self.csrf = response.json["csrf"]
        return response

    def login(self):
        self.assertEqual(
            self.post("/api/login", {"username": "admin", "password": self.password}).status_code,
            200,
        )

    def test_login_csrf_logout_and_headers(self):
        self.assertEqual(self.client.get("/api/targets").status_code, 401)
        self.assertEqual(self.client.post("/api/login", json={}).status_code, 403)
        old = self.csrf
        self.login()
        self.assertNotEqual(self.csrf, old)
        cookie = self.client.get_cookie("session")
        response = self.client.get("/api/targets")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        self.assertEqual(self.post("/api/logout", {}).status_code, 200)
        self.client.set_cookie("session", cookie.value)
        self.assertEqual(self.client.get("/api/targets").status_code, 401)

    def test_credentials_encrypted_and_scope_restricted(self):
        self.login()
        target = {
            "name": "Local Juice",
            "url": "http://127.0.0.1:3000",
            "username": "test@example.invalid",
            "password": "unique-test-secret",
        }
        response = self.post("/api/targets", target)
        self.assertEqual(response.status_code, 201)
        public = self.client.get("/api/targets").json
        self.assertNotIn("unique-test-secret", json.dumps(public))
        row = self.store.targets(private=True)[0]
        self.assertNotEqual(row["credential"], target["password"])
        self.assertEqual(
            self.store.vault.decrypt(row["credential"].encode()).decode(), target["password"]
        )
        self.assertEqual(
            self.post("/api/targets", {**target, "url": "http://169.254.169.254:80"}).status_code,
            400,
        )
        self.assertEqual(
            self.post("/api/targets", {**target, "source_path": "/etc"}).status_code, 400
        )
        changed = {**target, "password": "", "name": "Changed"}
        result = self.client.put(
            "/api/targets/" + row["id"], json=changed, headers={"X-CSRF-Token": self.csrf}
        )
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.store.targets(private=True)[0]["credential"], row["credential"])

    def test_password_rotation_and_origin(self):
        self.login()
        response = self.client.post(
            "/api/logout",
            json={},
            headers={"X-CSRF-Token": self.csrf, "Origin": "https://evil.invalid"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            self.post(
                "/api/admin/password", {"current_password": self.password, "new_password": "short"}
            ).status_code,
            400,
        )
        self.assertEqual(
            self.post(
                "/api/admin/password",
                {"current_password": self.password, "new_password": "new-strong-test-password"},
            ).status_code,
            200,
        )
        self.assertFalse((Path(self.temp.name) / "initial-admin.txt").exists())
        self.post("/api/logout", {})
        self.assertEqual(
            self.post("/api/login", {"username": "admin", "password": self.password}).status_code,
            401,
        )
        self.assertEqual(
            self.post(
                "/api/login", {"username": "admin", "password": "new-strong-test-password"}
            ).status_code,
            200,
        )

    def test_rate_limit(self):
        for _ in range(5):
            self.assertEqual(
                self.post("/api/login", {"username": "admin", "password": "wrong"}).status_code, 401
            )
        self.assertEqual(
            self.post("/api/login", {"username": "admin", "password": "wrong"}).status_code, 429
        )

    def test_disabled_or_unavailable_ai_keeps_both_normal_reports(self):
        result = {"findings": [], "request_count": 1, "version": {"version": "test"}}
        scenarios = [
            (False, None),
            (True, FileNotFoundError("CLI missing")),
            (True, ConnectionError("AI offline")),
            (True, TimeoutError("AI timeout")),
            (True, ValueError("Malformed AI response")),
            (True, RuntimeError("usage limit")),
        ]
        for enabled, error in scenarios:
            with (
                self.subTest(error=type(error).__name__),
                patch("secureflow.jobs.scan_juice", return_value=result),
                patch("secureflow.jobs.analyze", side_effect=error) as ai,
            ):
                engine = JobEngine(self.store)
                job = engine.start(
                    {
                        "id": "fallback",
                        "name": "Fallback",
                        "url": "http://127.0.0.1:3000",
                        "credential": "",
                        "source_path": "",
                    },
                    enabled,
                    False,
                )
                engine.pool.shutdown(wait=True)
                final = self.store.job(job["id"])
                self.assertEqual(final["status"], "complete")
                self.assertTrue(final["quick_ready"] and final["final_ready"])
                self.assertEqual(final["ai_status"], "failed" if enabled else "disabled")
                if enabled:
                    self.assertEqual(final["ai"]["fallback"], "standard_analysis_only")
                else:
                    ai.assert_not_called()

    def test_quick_report_does_not_wait_for_ai(self):
        release = threading.Event()
        ai_started = threading.Event()

        def delayed_ai(*args):
            ai_started.set()
            release.wait(8)
            return {
                "status": "complete",
                "analysis": "Unverified AI hypothesis",
                "model": "test-only-stub",
            }

        result = {
            "findings": [],
            "evidence": [],
            "request_count": 1,
            "version": {"version": "test"},
        }
        engine = JobEngine(self.store)
        try:
            with (
                patch("secureflow.jobs.scan_juice", return_value=result),
                patch("secureflow.jobs.analyze", side_effect=delayed_ai),
            ):
                job = engine.start(
                    {
                        "id": "target",
                        "name": "Test",
                        "url": "http://127.0.0.1:3000",
                        "credential": "",
                        "source_path": "/source",
                    },
                    True,
                    False,
                )
                self.assertTrue(ai_started.wait(3))
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    current = self.store.job(job["id"])
                    if current["quick_ready"]:
                        break
                    time.sleep(0.05)
                self.assertTrue(current["quick_ready"])
                self.assertFalse(current["final_ready"])
                self.assertEqual(current["ai_status"], "running")
                release.set()
                engine.pool.shutdown(wait=True)
                final = self.store.job(job["id"])
                self.assertTrue(final["final_ready"])
                self.assertEqual(final["ai_status"], "complete")
                quick = (Path(self.temp.name) / "reports" / job["id"] / "quick.html").read_text()
                integrated = (
                    Path(self.temp.name) / "reports" / job["id"] / "final.html"
                ).read_text()
                self.assertNotIn("Unverified AI hypothesis", quick)
                self.assertIn("Unverified AI hypothesis", integrated)
        finally:
            release.set()
            engine.pool.shutdown(wait=True)

    def test_target_failure_is_reported_instead_of_claiming_success(self):
        engine = JobEngine(self.store)
        with patch("secureflow.jobs.scan_juice", side_effect=TimeoutError("target unreachable")):
            job = engine.start(
                {
                    "id": "offline",
                    "name": "Offline",
                    "url": "http://127.0.0.1:3000",
                    "credential": "",
                    "source_path": "",
                },
                False,
                False,
            )
            engine.pool.shutdown(wait=True)
        final = self.store.job(job["id"])
        self.assertEqual(final["status"], "failed")
        self.assertTrue(final["final_ready"])
        self.assertIn("target unreachable", final["error"])


if __name__ == "__main__":
    unittest.main()
