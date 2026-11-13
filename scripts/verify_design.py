"""Read-only browser checks for the workspace's visual surfaces and interactions."""

import argparse
import json
from pathlib import Path

from playwright.sync_api import sync_playwright

parser = argparse.ArgumentParser()
parser.add_argument("--dashboard", default="http://127.0.0.1:8765")
parser.add_argument("--credentials", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
credentials = dict(line.split("=", 1) for line in args.credentials.read_text().splitlines())
errors, checks = [], []

with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    context = browser.new_context(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce")
    page = context.new_page()
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto(args.dashboard)
    page.evaluate("document.fonts.ready")
    assert page.evaluate(
        "[...document.fonts].some(font => font.family === 'Pretendard' && font.status === 'loaded')"
    )
    page.screenshot(path=str(args.output / "login.png"))
    page.fill("#login-username", credentials["username"])
    page.fill("#login-password", credentials["password"])
    page.click('#login-form button[type="submit"]')
    page.locator("#app-view").wait_for(state="visible")
    page.locator("#recent-jobs .job-row").first.wait_for()

    def capture(view, width=1440):
        page.set_viewport_size({"width": width, "height": 1000 if width > 720 else 844})
        page.locator(f'.nav-item[data-view="{view}"]').click()
        page.wait_for_timeout(250)
        if view == "settings":
            page.wait_for_function("!document.querySelector('#ai-model').disabled")
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), (view, width)
        page.screenshot(path=str(args.output / f"{view}-{width}.png"), full_page=False)
        checks.append({"view": view, "width": width, "overflow": False})

    for view in ("overview", "targets", "jobs", "settings"):
        capture(view)
    page.locator('.nav-item[data-view="overview"]').click()
    page.locator("#recent-jobs .job-row").first.click()
    page.locator("#quick-report:not(.disabled)").wait_for()
    page.locator(".finding > summary").first.click()
    page.screenshot(path=str(args.output / "detail-1440.png"))
    for kind in ("quick", "final"):
        url = page.locator(f"#{kind}-report").get_attribute("href")
        response = context.request.get(args.dashboard + url)
        assert response.status == 200 and len(response.body()) > 1000
    page.locator('.nav-item[data-view="targets"]').click()
    page.click("#add-target-button")
    page.screenshot(path=str(args.output / "target-dialog.png"))
    page.keyboard.press("Escape")
    assert not page.locator("#target-dialog").is_visible()
    page.locator('.nav-item[data-view="overview"]').click()
    page.click("#overview-new-job")
    page.check("#job-ai")
    page.select_option("#job-ai-mode", "ensemble")
    page.screenshot(path=str(args.output / "job-dialog.png"))
    page.keyboard.press("Escape")
    assert not page.locator("#job-dialog").is_visible()
    for width in (1024, 390, 320):
        for view in ("overview", "targets", "jobs", "settings"):
            capture(view, width)
    page.set_viewport_size({"width": 390, "height": 844})
    page.locator('.nav-item[data-view="overview"]').click()
    page.locator("#recent-jobs .job-row").first.click()
    page.locator("#quick-report:not(.disabled)").wait_for()
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.screenshot(path=str(args.output / "detail-390.png"))
    page.click("#mobile-logout-button")
    page.locator("#login-view").wait_for(state="visible")
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.screenshot(path=str(args.output / "login-390.png"))
    assert not errors, errors
    browser.close()

(args.output / "checks.json").write_text(
    json.dumps(
        {
            "screens": checks,
            "font": "loaded locally",
            "reports": "both downloaded",
            "dialogs": "keyboard dismissal passed",
            "javascript_errors": errors,
        },
        indent=2,
    )
)
print("PASS: real login, navigation, dialogs, reports, local font, and 320–1440px layouts.")
