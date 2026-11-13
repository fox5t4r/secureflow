"""Real browser + real local Juice Shop + real scanner/AI acceptance run."""

import argparse
import http.client
import json
import secrets
import time
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

parser = argparse.ArgumentParser()
parser.add_argument("--dashboard", default="http://127.0.0.1:8765")
parser.add_argument("--credentials", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--target", default="http://127.0.0.1:3000")
parser.add_argument("--source", type=Path, required=True)
parser.add_argument("--provider", choices=["ollama", "codex", "claude"], default="ollama")
parser.add_argument("--model", default="qwen2.5-coder:1.5b")
parser.add_argument("--mode", choices=["standard", "deep", "ensemble"], default="standard")
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
admin = dict(line.split("=", 1) for line in args.credentials.read_text().splitlines())
email = "secureflow-connected-" + secrets.token_hex(5) + "@example.invalid"
password = secrets.token_urlsafe(24)
target_url = urlsplit(args.target)
conn = http.client.HTTPConnection(target_url.hostname, target_url.port, timeout=10)
conn.request(
    "POST",
    "/api/Users",
    json.dumps({"email": email, "password": password, "passwordRepeat": password}),
    {"Content-Type": "application/json"},
)
response = conn.getresponse()
assert response.status in (200, 201), response.status
response.read()
conn.close()
errors = []
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={"width": 1440, "height": 1000}, accept_downloads=True)
    page = context.new_page()
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto(args.dashboard)
    page.locator("#login-view").wait_for(state="visible")
    page.screenshot(path=str(args.output / "login.png"))
    page.fill("#login-username", admin["username"])
    page.fill("#login-password", admin["password"])
    page.click("#login-form button[type=submit]")
    page.locator("#app-view").wait_for(state="visible")
    page.locator(".nav-item[data-view=settings]").click()
    page.select_option("#ai-provider", args.provider)
    page.fill("#ai-model", args.model)
    page.fill("#ai-deep-model", args.model)
    with page.expect_response(
        lambda r: r.url.endswith("/api/settings") and r.request.method == "PUT"
    ) as settings_response:
        page.click("#settings-form button[type=submit]")
    assert settings_response.value.status == 200
    settings = context.request.get(args.dashboard + "/api/settings").json()
    assert settings["ai_provider"] == args.provider, settings
    page.locator(".nav-item[data-view=targets]").click()
    page.click("#add-target-button")
    page.fill("#target-name", "Juice Shop · 실계정 연결 검증")
    page.fill("#target-url", args.target)
    page.fill("#target-source", str(args.source))
    page.locator(".credential-fields summary").click()
    page.fill("#target-username", email)
    page.fill("#target-password", password)
    with page.expect_response(
        lambda r: r.url.endswith("/api/targets") and r.request.method == "POST"
    ) as response_info:
        page.click("#target-form button[type=submit]")
    target = response_info.value.json()
    assert response_info.value.status == 201, target
    page.locator("#target-dialog").wait_for(state="hidden")
    page.locator(".nav-item[data-view=overview]").click()
    page.click("#overview-new-job")
    page.select_option("#job-target", target["id"])
    page.check("#job-ai")
    page.select_option("#job-ai-mode", args.mode)
    page.check("#job-compare")
    with page.expect_response(
        lambda r: r.url.endswith("/api/jobs") and r.request.method == "POST"
    ) as job_info:
        page.click("#job-form button[type=submit]")
    job = job_info.value.json()
    assert job_info.value.status == 202, job
    identifier = job["id"]
    quick_observation = None
    deadline = time.monotonic() + 960
    while time.monotonic() < deadline:
        detail = context.request.get(args.dashboard + "/api/jobs/" + identifier).json()
        current = detail["job"]
        if current["quick_ready"] and quick_observation is None:
            quick_observation = {
                "ai_status": current["ai_status"],
                "final_ready": current["final_ready"],
            }
            response = context.request.get(args.dashboard + f"/api/jobs/{identifier}/report/quick")
            assert response.status == 200
            (args.output / "quick.html").write_bytes(response.body())
            print("Quick report ready:", quick_observation, flush=True)
        if current["final_ready"]:
            break
        if current["status"] == "failed" and not current["quick_ready"]:
            raise AssertionError(current["error"])
        page.wait_for_timeout(1000)
    else:
        raise AssertionError("Integrated workflow timeout")
    assert current["status"] == "complete", current.get("error")
    assert current["ai_status"] == "complete", detail["ai"]
    assert all(c["status"] == "complete" for c in detail["comparison"]), detail["comparison"]
    assert len(detail["comparison"]) == 2
    assert current["summary"]["confirmed"] >= 5, current["summary"]
    response = context.request.get(args.dashboard + f"/api/jobs/{identifier}/report/final")
    assert response.status == 200
    final = response.body()
    assert password.encode() not in final
    (args.output / "final.html").write_bytes(final)
    (args.output / "job.json").write_text(json.dumps(detail, ensure_ascii=False, indent=2))
    page.wait_for_timeout(3500)
    page.screenshot(path=str(args.output / "dashboard-results.png"), full_page=True)
    page.locator(".nav-item[data-view=overview]").click()
    page.screenshot(path=str(args.output / "dashboard-overview.png"))
    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.screenshot(path=str(args.output / "dashboard-mobile.png"), full_page=True)
    assert not errors, errors
    context.close()
    browser.close()
(args.output / "acceptance.json").write_text(
    json.dumps(
        {
            "job_id": identifier,
            "target_id": target["id"],
            "quick_observation": quick_observation,
            "summary": current["summary"],
            "ai_status": current["ai_status"],
            "ai_provider": detail["ai"].get("provider"),
            "ai_mode": detail["ai"].get("mode"),
            "ai_phases": [p["status"] for p in detail["ai"].get("phases", [])],
            "tools": [
                {"tool": c["tool"], "count": c["count"], "status": c["status"]}
                for c in detail["comparison"]
            ],
            "javascript_errors": errors,
            "mobile_overflow": False,
            "connected_account": True,
        },
        ensure_ascii=False,
        indent=2,
    )
)
print(
    "PASS: real authenticated dashboard, connected target account, two reports, scanners and local AI.",
    flush=True,
)
