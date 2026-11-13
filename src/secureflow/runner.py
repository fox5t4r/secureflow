import hashlib
import importlib.metadata
import json
import logging
import platform
import secrets
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from werkzeug.serving import WSGIRequestHandler, make_server

from secureflow.lab.app import create_app

from .config import PACKAGE_ROOT, workspace
from .metrics import evaluate
from .probes import LabClient, probe
from .report import render

ROOT = PACKAGE_ROOT


def write_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def sast(source, output):
    command = [sys.executable, "-m", "bandit", "-r", str(source), "-f", "json", "-q"]
    result = subprocess.run(command, text=True, capture_output=True, timeout=120)
    (output / "bandit.stderr.txt").write_text(result.stderr, encoding="utf-8")
    if result.returncode not in (0, 1):
        raise RuntimeError(f"Bandit failed: {result.stderr}")
    raw = json.loads(result.stdout)
    write_json(output / "bandit.json", raw)
    if raw.get("errors"):
        raise RuntimeError("Bandit reported skipped files; inspect bandit.json")
    return raw


class QuietHandler(WSGIRequestHandler):
    def log_request(self, code="-", size="-"):
        pass


def demo(output_root):
    output_root = Path(output_root).resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = Path(tempfile.mkdtemp(prefix=stamp + "-", dir=output_root))
    events = []

    def event(stage, **values):
        item = dict(time=datetime.now(timezone.utc).isoformat(), stage=stage, **values)
        events.append(item)
        write_json(output / "workflow.json", events)
        print(f"[{stage}] {values}", flush=True)

    server = None
    thread = None
    try:
        cases = json.loads((ROOT / "lab/manifest.json").read_text())["cases"]
        event("scope", target="runner-owned IPv4 loopback lab", cases=len(cases))
        raw = sast(ROOT / "lab/cases", output)
        event("sast", alerts=len(raw["results"]))
        token = secrets.token_urlsafe(32)
        app = create_app(cases, token)
        app.logger.setLevel(logging.CRITICAL)
        server = make_server("127.0.0.1", 0, app, threaded=True, request_handler=QuietHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client = LabClient(
            f"http://127.0.0.1:{server.server_port}", token, max_requests=len(cases) * 8 + 1
        )
        status, health = client.request("/health")
        if status != 200 or health.get("service") != "secureflow-owned-lab":
            raise RuntimeError("Lab identity verification failed")
        findings = []
        for case in cases:
            signals = [
                r
                for r in raw["results"]
                if Path(r["filename"]).resolve() == (ROOT / case["source"]).resolve()
            ]
            finding = dict(**case, sast=signals, **probe(client, case))
            findings.append(finding)
            # Preserve incremental progress even if later tests fail.
            write_json(output / "diagnostics.json", findings)
            write_json(output / "evidence.json", client.evidence)
            event("validation", case=case["id"], state=finding["state"])
        # Ground-truth labels are never passed into candidate generation or probes.
        truth = json.loads((ROOT / "lab/ground_truth.json").read_text())
        metrics = evaluate(truth, findings)
        event(
            "evaluation",
            fpr_reduction_pp=metrics["fpr_reduction_pp"],
            target_met=metrics["target_met"],
        )
        run = dict(
            run_id=output.name,
            versions={
                "python": platform.python_version(),
                "bandit": importlib.metadata.version("bandit"),
                "flask": importlib.metadata.version("flask"),
            },
            source_hashes={
                c["source"]: hashlib.sha256((ROOT / c["source"]).read_bytes()).hexdigest()
                for c in cases
            },
            findings=findings,
            evidence=client.evidence,
            metrics=metrics,
            request_count=client.count,
        )
        write_json(output / "results.json", run)
        render(run, output)
        event("report", path=str(output / "report.html"))
        return output, run
    except Exception as error:
        event("failed", error=str(error))
        raise
    finally:
        if server:
            server.shutdown()
            server.server_close()
        if thread:
            thread.join(timeout=5)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="SecureFlow: local security workflow")
    sub = parser.add_subparsers(dest="command", required=True)
    setup_parser = sub.add_parser(
        "setup", help="Download versioned Juice Shop source and start local scanner dependencies"
    )
    setup_parser.add_argument(
        "--ollama", action="store_true", help="Also install the optional local AI model"
    )
    serve_parser = sub.add_parser("serve", help="Run the authenticated local dashboard")
    serve_parser.add_argument("--port", type=int, default=8765)
    demo_parser = sub.add_parser(
        "demo", help="Run SAST, owned lab DAST, evaluation, and HTML report"
    )
    demo_parser.add_argument("--output", default=str(workspace() / "artifacts"))
    static_parser = sub.add_parser("sast", help="Run Bandit on a local Python source directory")
    static_parser.add_argument("source", type=Path)
    static_parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "setup":
        from .setup import setup_lab

        setup_lab(args.ollama)
    elif args.command == "serve":
        from .dashboard import serve

        serve(args.port)
    elif args.command == "demo":
        output, _ = demo(args.output)
        print(f"REPORT={output / 'report.html'}")
    else:
        if not args.source.is_dir():
            parser.error("Source must be a directory")
        args.output.mkdir(parents=True, exist_ok=False)
        raw = sast(args.source.resolve(), args.output)
        print(f"{len(raw['results'])} static candidates; these have not been dynamically verified.")
