"""Verify standalone reports offline, including toggles and A4 output."""

import argparse
import json
from pathlib import Path

from playwright.sync_api import sync_playwright


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "directory", type=Path, help="Directory containing quick.html and final.html"
    )
    args = parser.parse_args()
    directory = args.directory.resolve()
    checks = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context(
            viewport={"width": 1280, "height": 1000}, reduced_motion="reduce"
        )
        for kind in ("quick", "final"):
            errors, external = [], []
            page = context.new_page()
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on(
                "request",
                lambda request: external.append(request.url)
                if request.url.startswith(("http:", "https:"))
                else None,
            )
            page.goto((directory / f"{kind}.html").as_uri())
            page.evaluate("document.fonts.ready")
            assert not errors, errors
            assert page.evaluate(
                "[...document.fonts].some(f => f.family === 'Report Batang' && f.status === 'loaded')"
            )
            assert page.locator("#executive .priority-row").count() <= 3
            page.locator("#executive").screenshot(path=str(directory / f"{kind}-first-page.png"))
            if page.locator(".priority-row a").count():
                page.click(".priority-row a >> nth=0")
                page.locator(".finding-card details[open]").first.wait_for(state="visible")
                assert page.locator(".finding-card details[open]").count() > 0
                page.locator(".finding-card").first.screenshot(
                    path=str(directory / f"{kind}-finding.png")
                )
            page.click("#expand-all")
            total = page.locator("details[data-print-expand]").count()
            assert page.locator("details[data-print-expand][open]").count() == total
            page.click("#collapse-all")
            assert page.locator("details[open]").count() == 0
            page.evaluate("window.dispatchEvent(new Event('beforeprint'))")
            assert page.locator("details[data-print-expand][open]").count() == total
            page.evaluate("window.dispatchEvent(new Event('afterprint'))")
            assert page.locator("details[open]").count() == 0
            page.pdf(
                path=str(directory / f"{kind}.pdf"),
                format="A4",
                prefer_css_page_size=True,
                print_background=True,
            )
            assert page.locator("details[open]").count() == 0
            page.set_viewport_size({"width": 390, "height": 844})
            page.evaluate("window.scrollTo(0, 0)")
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path=str(directory / f"{kind}-mobile.png"))
            assert not errors, errors
            assert not external, external
            checks.append(
                {
                    "kind": kind,
                    "offline_font": True,
                    "toggles": True,
                    "print_state_restored": True,
                    "mobile_overflow": False,
                    "javascript_errors": errors,
                }
            )
            page.close()
        browser.close()
    (directory / "browser-checks.json").write_text(json.dumps(checks, indent=2))
    print("PASS: portable fonts, offline reports, detail navigation, toggles, print state, mobile.")


if __name__ == "__main__":
    main()
