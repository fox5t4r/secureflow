"""Exercise real no-AI and unavailable-AI jobs against an already registered lab target."""

import argparse
import http.cookiejar
import json
import time
import urllib.request
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--dashboard", default="http://127.0.0.1:8765")
parser.add_argument("--credentials", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument(
    "--target-id", help="Registered local target ID; defaults to the first target with source"
)
args = parser.parse_args()
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
csrf = ""


def api(path, data=None, method=None):
    request = urllib.request.Request(
        args.dashboard + path,
        json.dumps(data).encode() if data is not None else None,
        {"Content-Type": "application/json", "X-CSRF-Token": csrf},
        method=method,
    )
    return json.load(client.open(request, timeout=30))


csrf = api("/api/session")["csrf"]
credentials = dict(line.split("=", 1) for line in args.credentials.read_text().splitlines())
csrf = api("/api/login", credentials)["csrf"]
settings = api("/api/settings")
targets = api("/api/targets")["targets"]
target = (
    next(target for target in targets if target["id"] == args.target_id)
    if args.target_id
    else next(target for target in targets if target["source_path"])
)
observations = []
try:
    api(
        "/api/settings",
        {
            **settings,
            "ai_provider": "ollama",
            "ai_url": "http://127.0.0.1:1",
            "ai_model": "unavailable-test-model",
        },
        "PUT",
    )
    for enabled in (False, True):
        job = api(
            "/api/jobs", {"target_id": target["id"], "ai_enabled": enabled, "compare_tools": False}
        )
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            detail = api("/api/jobs/" + job["id"])
            if detail["job"]["final_ready"]:
                break
            time.sleep(1)
        final = detail["job"]
        assert final["status"] == "complete" and final["quick_ready"] and final["final_ready"], (
            final
        )
        assert final["summary"]["tested"] == 7
        assert final["ai_status"] == ("failed" if enabled else "disabled"), final
        if enabled:
            assert detail["ai"]["fallback"] == "standard_analysis_only"
        for kind in ("quick", "final"):
            response = client.open(args.dashboard + f"/api/jobs/{job['id']}/report/{kind}")
            assert response.status == 200 and len(response.read()) > 1000
        observations.append(
            {
                "ai_enabled": enabled,
                "job_id": job["id"],
                "ai_status": final["ai_status"],
                "summary": final["summary"],
                "both_reports": True,
            }
        )
finally:
    api("/api/settings", settings, "PUT")
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(observations, ensure_ascii=False, indent=2))
print("PASS: real normal scans and both reports work with AI disabled or unavailable.")
