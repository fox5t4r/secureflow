"""Report judgments must reflect evidence and preserve quick snapshot boundaries."""

import importlib.util
import json
import unittest
from pathlib import Path

from secureflow.integrated_report import build_report
from secureflow.report_view import report_view

spec = importlib.util.spec_from_file_location(
    "refresh_reports", Path(__file__).resolve().parents[1] / "scripts" / "refresh_reports.py"
)
refresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(refresh)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.job = dict(
            id="job",
            target_name="Owned lab",
            target_url="http://127.0.0.1:3000",
            created_at="2026-11-14T00:00:00+00:00",
            error=None,
        )
        self.finding = dict(
            id="juice-search-sqli",
            title="SQL test",
            severity="HIGH",
            state="confirmed",
            source="routes/search.ts",
            owasp="A05:2025",
            cwe="CWE-89",
            detail="Controlled query returned products.",
            advice="Bind values",
            code="example",
            evidence=[],
        )

    def test_priority_does_not_promote_unverified_candidates(self):
        findings = [dict(self.finding, state="inconclusive", severity="CRITICAL"), self.finding]
        view = report_view(
            self.job, findings, [], {"status": "complete", "findings": [self.finding]}, "final"
        )
        self.assertEqual((view["confirmed"], view["high"], view["unresolved"]), (1, 1, 1))
        self.assertEqual(len(view["top"]), 1)
        self.assertEqual(view["cards"][-1]["priority"], "검토")

    def test_no_findings_and_failure_are_not_safe_verdicts(self):
        view = report_view(self.job, [], [], {}, "final")
        self.assertIn("안전을 판단할 수 없습니다", view["verdict"])
        failed = report_view(dict(self.job, error="timeout"), [], [], {}, "final")
        self.assertIn("불완전", failed["verdict"])
        self.assertEqual(failed["tools"][0]["status"], "failed")

    def test_standalone_escaping_and_quick_snapshot_excludes_later_ai(self):
        job = dict(self.job, credential="NEVER-IN-REPORT", ai={"analysis": "LATER-AI"})
        finding = dict(self.finding, detail="</script><script>alert(1)</script>")
        html = build_report(
            job, [finding], [], {"status": "running", "analysis": "LATER-AI"}, "quick"
        )
        self.assertNotIn("NEVER-IN-REPORT", html)
        self.assertNotIn("LATER-AI", html)
        self.assertNotIn("<script>alert(1)</script>", html)
        snapshot = json.loads(refresh.ReportReader(html).snapshot)
        self.assertEqual(snapshot["ai"], {"status": "running"})
        self.assertEqual(snapshot["findings"][0]["detail"], finding["detail"])
        restored = refresh.inputs_for(html, dict(job, findings=[]), "quick")
        self.assertEqual(restored["findings"], [finding])
        self.assertIn("data:font/woff2;base64,", html)
        self.assertIn('window.addEventListener("beforeprint"', html)

    def test_legacy_quick_refresh_preserves_original_tools_and_ai_state(self):
        semgrep = dict(tool="Semgrep", status="complete", count=2)
        job = dict(
            self.job,
            findings=[self.finding],
            comparison=[semgrep, dict(tool="ZAP", status="complete", count=4)],
            ai={"status": "complete"},
        )
        legacy = """<p>검증 완료 1개 / 검사 항목 1개.</p><p>상태: running · 모델: —</p>
        <table><tr><td>Semgrep</td><td>complete</td><td>2</td><td>test</td></tr></table>"""
        restored = refresh.inputs_for(legacy, job, "quick")
        self.assertEqual(restored["comparison"], [semgrep])
        self.assertEqual(restored["ai"], {"status": "running"})
        with self.assertRaises(ValueError):
            refresh.inputs_for(legacy.replace("<td>2</td>", "<td>99</td>"), job, "quick")

    def test_juice_guides_are_specific_to_the_finding(self):
        view = report_view(self.job, [dict(self.finding, id="juice-redirect")], [], {}, "final")
        guide = view["cards"][0]["guide"]
        self.assertEqual(view["cards"][0]["finding"]["cwe"], "CWE-601")
        self.assertEqual(self.finding["cwe"], "CWE-89")
        self.assertIn("destination.origin", guide["code"])
        self.assertIn("외부 URL", guide["acceptance"])


if __name__ == "__main__":
    unittest.main()
