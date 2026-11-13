"""Optional UI verification: pip install -r requirements-dev.txt."""

import argparse
import json
from pathlib import Path

from playwright.sync_api import sync_playwright

parser = argparse.ArgumentParser()
parser.add_argument("report", type=Path)
parser.add_argument("--chromium", help="Use an existing Chromium binary")
args = parser.parse_args()
report = args.report.resolve()
findings = json.loads(report.with_name("results.json").read_text())["findings"]
counts = {
    state: sum(f["state"] == state for f in findings)
    for state in ("confirmed", "not_reproduced", "inconclusive")
}
errors = []
with sync_playwright() as playwright:
    browser = playwright.chromium.launch(executable_path=args.chromium, headless=True)
    page = browser.new_page(viewport={"width": 1280, "height": 900})
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto(report.as_uri())
    assert page.locator("article:visible").count() == len(findings)
    page.click('[data-filter="confirmed"]')
    assert page.locator("article:visible").count() == counts["confirmed"]
    page.click('[data-filter="not_reproduced"]')
    assert page.locator("article:visible").count() == counts["not_reproduced"]
    page.click('[data-filter="inconclusive"]')
    assert page.locator("article:visible").count() == counts["inconclusive"]
    page.click('[data-filter="all"]')
    page.screenshot(path=str(report.with_name("report-desktop.png")), full_page=False)
    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.screenshot(path=str(report.with_name("report-mobile.png")), full_page=False)
    page.set_viewport_size({"width": 1280, "height": 900})
    page.evaluate('document.querySelectorAll("details").forEach(d=>d.open=true)')
    page.pdf(path=str(report.with_suffix(".pdf")), format="A4", print_background=True)
    assert not errors, errors
    browser.close()
report.with_name("ui-check.json").write_text(
    json.dumps(
        {
            "desktop": "passed",
            "mobile_overflow": False,
            "filters": "passed",
            "javascript_errors": errors,
            "pdf": report.with_suffix(".pdf").name,
        },
        indent=2,
    )
)
print("Report UI, filters, mobile layout and PDF export passed.")
