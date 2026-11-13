"""Render portable assessment reports with automatic HTML escaping."""

from .report_view import report_assets, report_view
from .templating import render_template


def build_report(job, findings, comparison, ai, kind):
    # Preserve only report inputs, never credentials or later AI output in a quick snapshot.
    snapshot = {
        "version": 1,
        "job": {
            key: job[key]
            for key in (
                "id",
                "target_name",
                "target_url",
                "created_at",
                "summary",
                "error",
                "target_version",
            )
            if key in job
        },
        "findings": findings,
        "comparison": comparison,
        "ai": {"status": ai.get("status", "pending")} if kind == "quick" else ai,
        "kind": kind,
    }
    return render_template(
        "integrated_report.html",
        title="빠른 진단 리포트" if kind == "quick" else "통합 진단·개선 리포트",
        job=job,
        findings=findings,
        comparison=comparison,
        ai=ai,
        kind=kind,
        view=report_view(job, findings, comparison, ai, kind),
        assets=report_assets(),
        snapshot=snapshot,
    )
