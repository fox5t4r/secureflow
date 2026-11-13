"""Restyle saved reports without rescanning or adding later results to quick reports.

Original HTML is backed up once. New reports contain their immutable presentation
inputs; the legacy importer checks the original quick report's tool rows and AI state.
"""

import argparse
import json
import re
import shutil
from html.parser import HTMLParser
from pathlib import Path

from secureflow.integrated_report import build_report


class ReportReader(HTMLParser):
    def __init__(self, document):
        super().__init__()
        self.snapshot = ""
        self.paragraphs, self.rows = [], []
        self.capture = None
        self.text = ""
        self.row = None
        self.feed(document)

    def handle_starttag(self, tag, attrs):
        if tag == "script" and dict(attrs).get("id") == "report-snapshot":
            self.capture, self.text = "snapshot", ""
        elif tag == "tr":
            self.row = []
        elif tag in ("p", "td") and self.capture != "snapshot":
            self.capture, self.text = tag, ""

    def handle_data(self, data):
        if self.capture:
            self.text += data

    def handle_endtag(self, tag):
        if tag == "script" and self.capture == "snapshot":
            self.snapshot = self.text
            self.capture = None
        elif tag == self.capture:
            value = " ".join(self.text.split())
            if tag == "p":
                self.paragraphs.append(value)
            elif self.row is not None:
                self.row.append(value)
            self.capture = None
        elif tag == "tr" and self.row is not None:
            if self.row:
                self.rows.append(self.row)
            self.row = None


def inputs_for(document, job, kind):
    reader = ReportReader(document)
    if reader.snapshot:
        snapshot = json.loads(reader.snapshot)
        if snapshot.get("version") != 1 or snapshot.get("kind") != kind:
            raise ValueError("Unsupported report snapshot")
        return {key: snapshot[key] for key in ("job", "findings", "comparison", "ai", "kind")}
    if kind == "final":
        return dict(
            job=job, findings=job["findings"], comparison=job["comparison"], ai=job["ai"], kind=kind
        )
    # Legacy quick HTML retains tool names, statuses and counts as of creation.
    summary = next((p for p in reader.paragraphs if p.startswith("검증 완료 ")), "")
    match = re.match(r"검증 완료 (\d+)개 / 검사 항목 (\d+)개\.(?: |$)", summary)
    findings = job["findings"]
    if not match or tuple(map(int, match.groups())) != (
        sum(f["state"] == "confirmed" for f in findings),
        len(findings),
    ):
        raise ValueError("Legacy quick report findings cannot be verified")
    states = [p.removeprefix("상태: ") for p in reader.paragraphs if p.startswith("상태: ")]
    if len(states) != 1:
        raise ValueError("Legacy quick report AI state cannot be verified")
    comparison = []
    for row in reader.rows:
        if row[0] == "SecureFlow DAST":
            continue
        tool = next((t for t in job["comparison"] if t["tool"] == row[0]), None)
        if (
            not tool
            or len(row) != 4
            or tool["status"] != row[1]
            or str(tool.get("count", "—")) != row[2]
        ):
            raise ValueError("Legacy quick tool snapshot differs from saved results")
        comparison.append(tool)
    job = {
        **job,
        "error": next(
            (
                p.removeprefix("진단 오류: ")
                for p in reader.paragraphs
                if p.startswith("진단 오류: ")
            ),
            None,
        ),
    }
    return dict(
        job=job,
        findings=findings,
        comparison=comparison,
        ai={"status": states[0].split(" · ", 1)[0]},
        kind=kind,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("reports", type=Path)
    parser.add_argument("--backup", required=True, type=Path)
    args = parser.parse_args()
    planned = []
    for result in sorted(args.reports.glob("*/results.json")):
        job = json.loads(result.read_text())
        if job.get("status") in ("queued", "running"):
            continue
        for kind in ("quick", "final"):
            path = result.with_name(f"{kind}.html")
            if path.exists():
                planned.append((path, build_report(**inputs_for(path.read_text(), job, kind))))
    for path, document in planned:
        backup = args.backup / path.parent.name / path.name
        backup.parent.mkdir(parents=True, exist_ok=True)
        if not backup.exists():
            shutil.copy2(path, backup)
        temporary = path.with_suffix(".refresh.tmp")
        temporary.write_text(document, encoding="utf-8")
        temporary.replace(path)
    print(f"Refreshed {len(planned)} reports; original HTML retained in backup.")


if __name__ == "__main__":
    main()
