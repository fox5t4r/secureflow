import json
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from secureflow.ai import analyze, validate_review
from secureflow.ai.context import source_context
from secureflow.ai.providers import complete, connection_status, validate_settings
from secureflow.net import redact

CONTEXT = [{"path": "search.py", "source": "3: db.query(sql)", "sha256": "fixture"}]
FINDING = {
    "path": "search.py",
    "line": 3,
    "risk": "Untrusted SQL",
    "fix": "Use bound parameters",
    "test_plan": "Normal and quote-bearing inputs",
    "confidence": "medium",
}
REVIEW = {"summary": "Source-only hypothesis", "findings": [FINDING]}


class AITests(TestCase):
    def test_connection_uses_configured_cli_outside_service_path(self):
        with tempfile.TemporaryDirectory() as directory:
            cli = Path(directory) / "codex"
            runtime = cli.with_name("test-runtime")
            runtime.write_text("#!/bin/sh\nprintf '%s\\n' 'Logged in using ChatGPT'\n")
            runtime.chmod(0o700)
            cli.write_text('#!/bin/sh\nexec test-runtime "$@"\n')
            cli.chmod(0o700)
            with patch.dict(
                "os.environ", {"PATH": "/usr/bin:/bin", "SECUREFLOW_CODEX_BIN": str(cli)}
            ):
                status = connection_status()["codex"]
        self.assertTrue(status["installed"])
        self.assertTrue(status["authenticated"])
        self.assertTrue(status["subscription"])

    def test_ensemble_preserves_agreement_and_single_model_results(self):
        response = {"review": REVIEW, "duration_seconds": 0.1}
        with (
            patch("secureflow.ai.source_context", return_value=CONTEXT),
            patch("secureflow.ai.complete", return_value=response) as infer,
        ):
            result = analyze(
                {"ai_provider": "codex", "ai_model": "advanced"}, "/source", "ensemble"
            )
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["provider"], "ollama")
        self.assertEqual(infer.call_count, 2)
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(len(result["findings"][0]["supporting_models"]), 2)
        self.assertEqual(result["findings"][0]["state"], "unverified_hypothesis")

    def test_ensemble_one_or_both_models_unavailable(self):
        response = {"review": REVIEW, "duration_seconds": 0.1}
        for effects, status in [
            ([RuntimeError("model missing"), response], "partial"),
            ([RuntimeError("offline"), TimeoutError("timeout")], "failed"),
        ]:
            with (
                self.subTest(status=status),
                patch("secureflow.ai.source_context", return_value=CONTEXT),
                patch("secureflow.ai.complete", side_effect=effects),
            ):
                result = analyze({}, "/source", "ensemble")
                self.assertEqual(result["status"], status)
                self.assertEqual(len(result["phases"]), 2)
                if status == "failed":
                    self.assertEqual(result["fallback"], "standard_analysis_only")

    def test_citations_are_checked_and_status_is_advisory(self):
        response = {
            "review": {**REVIEW, "findings": [FINDING, {**FINDING, "path": "invented.py"}]},
            "duration_seconds": 0.1,
        }
        with (
            patch("secureflow.ai.source_context", return_value=CONTEXT),
            patch("secureflow.ai.complete", return_value=response),
        ):
            result = analyze({"ai_model": "test"}, "/source")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["classification"], "advisory_unverified")
        self.assertEqual(result["findings"][0]["state"], "unverified_hypothesis")
        self.assertEqual(result["phases"][0]["review"]["rejected_citations"], 1)

    def test_invalid_review_fails_instead_of_confirming(self):
        for review in (
            {},
            {"summary": "", "findings": [{**FINDING, "line": 99}]},
            {"summary": "", "findings": [{**FINDING, "path": []}]},
        ):
            with self.assertRaises(ValueError):
                validate_review(review, CONTEXT)

    def test_deep_review_challenges_and_synthesizes_with_selected_model(self):
        response = {"review": REVIEW, "duration_seconds": 0.1}
        with (
            patch("secureflow.ai.source_context", return_value=CONTEXT),
            patch("secureflow.ai.complete", return_value=response) as infer,
        ):
            result = analyze(
                {"ai_provider": "codex", "ai_model": "standard", "ai_deep_model": "advanced"},
                "/source",
                "deep",
            )
        self.assertEqual(result["status"], "complete")
        self.assertEqual(
            [p["phase"] for p in result["phases"]], ["review", "challenge", "synthesis"]
        )
        self.assertEqual(infer.call_count, 3)
        self.assertTrue(all(call.args[2] == "advanced" for call in infer.call_args_list))
        second_prompt = json.loads(infer.call_args_list[1].args[1][1]["content"])
        self.assertEqual(second_prompt["previous_review"]["findings"][0]["path"], "search.py")

    def test_later_failure_preserves_partial_review(self):
        with (
            patch("secureflow.ai.source_context", return_value=CONTEXT),
            patch(
                "secureflow.ai.complete",
                side_effect=[{"review": REVIEW, "duration_seconds": 0.1}, RuntimeError("quota")],
            ),
        ):
            result = analyze({"ai_model": "test"}, "/source", "deep")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["phases"][-1]["status"], "failed")
        self.assertEqual(len(result["findings"]), 1)

    def test_source_selection_excludes_secrets_symlinks_and_runtime_data(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            (root / "handler.py").write_text(
                'password = "test-secret-value"\nquery = request.args["q"]\n'
            )
            (root / "handler.spec.ts").write_text("query = request.body\n" * 100)
            (root / "test_handler.py").write_text("query = request.body\n" * 100)
            (root / ".env").write_text("API_KEY=never-read")
            (root / ".local").mkdir()
            (root / ".local" / "session.py").write_text('password = "runtime-secret"')
            (Path(outside) / "secret.py").write_text("query = outside_secret")
            (root / "linked.py").symlink_to(Path(outside) / "secret.py")
            excerpts = source_context(directory, deep=True)
        text = json.dumps(excerpts)
        self.assertEqual([e["path"] for e in excerpts], ["handler.py"])
        self.assertNotIn("test-secret-value", text)
        self.assertNotIn("runtime-secret", text)
        self.assertNotIn("outside_secret", text)
        self.assertIn("REDACTED", text)

    def test_remote_ollama_and_unknown_providers_rejected(self):
        for settings in (
            {"ai_url": "http://10.0.0.1:11434"},
            {"ai_provider": "shell"},
            {"ai_model": "$(whoami)"},
            {"ai_provider": []},
            {"ai_url": []},
        ):
            with self.assertRaises(ValueError):
                validate_settings(settings)
        result = redact({"token": "hidden", "password": "hidden"})
        self.assertNotIn("hidden", json.dumps(result))

    def test_codex_adapter_uses_isolated_read_only_cli_and_schema(self):
        seen = {}

        def run(arguments, prompt, directory, timeout):
            seen.update(arguments=arguments, prompt=prompt)
            destination = Path(arguments[arguments.index("--output-last-message") + 1])
            destination.write_text(json.dumps(REVIEW))
            return ""

        with (
            patch("secureflow.ai.providers.shutil.which", return_value="/bin/codex"),
            patch("secureflow.ai.providers._cli_run", side_effect=run),
        ):
            result = complete(
                validate_settings({"ai_provider": "codex", "ai_model": ""}),
                [{"role": "user", "content": "safe excerpt"}],
                "",
            )
        self.assertEqual(result["review"], REVIEW)
        self.assertIn("read-only", seen["arguments"])
        self.assertIn("--ignore-user-config", seen["arguments"])
        self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", seen["arguments"])
        self.assertNotIn("safe excerpt", seen["arguments"])

    def test_claude_adapter_disables_tools_and_preserves_subscription_login(self):
        with (
            patch("secureflow.ai.providers.shutil.which", return_value="/bin/claude"),
            patch(
                "secureflow.ai.providers._cli_run",
                return_value=json.dumps({"structured_output": REVIEW}),
            ) as run,
        ):
            result = complete(
                validate_settings({"ai_provider": "claude", "ai_model": "opus"}), [], "opus"
            )
        arguments = run.call_args.args[0]
        self.assertEqual(arguments[arguments.index("--tools") + 1], "")
        self.assertIn("--safe-mode", arguments)
        self.assertNotIn("--bare", arguments)
        self.assertEqual(result["review"], REVIEW)
