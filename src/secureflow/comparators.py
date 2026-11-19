import hashlib
import json
import subprocess
import time
import uuid
from pathlib import Path

from .runner import sast

ROOT = Path(__file__).resolve().parent
SEMGREP_IMAGE = (
    "semgrep/semgrep@sha256:cc1b68266f267878b39739373ea9985b9a78e5d64497dd875c8de100b22695ed"
)
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af"


def bandit_scan(source, output):
    root = Path(source)
    raw = sast(root, output, use_project_config=False)
    alerts = [
        {
            "id": item["test_id"],
            "path": str(Path(item["filename"]).relative_to(root)),
            "line": item["line_number"],
            "severity": item["issue_severity"],
            "message": item["issue_text"],
            "cwe": f"CWE-{item['issue_cwe']['id']}" if item.get("issue_cwe") else "",
            "state": "unverified",
        }
        for item in raw["results"]
    ]
    return {
        "tool": "Bandit",
        "status": "complete",
        "alerts": alerts,
        "count": len(alerts),
        "note": "Python 정적 분석. 탐지된 후보는 코드 맥락 검토가 필요합니다.",
    }


def command_result(args, output, name, timeout):
    start = time.monotonic()
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        (output / (name + ".log")).write_text(result.stdout + "\n" + result.stderr)
        return result.returncode, round(time.monotonic() - start, 2)
    except subprocess.TimeoutExpired as error:
        (output / (name + ".log")).write_text("TIMEOUT\n" + str(error))
        if "--name" in args:
            container = args[args.index("--name") + 1]
            subprocess.run(["docker", "rm", "-f", container], capture_output=True, timeout=15)
        raise RuntimeError(name + " timeout; partial results are not complete")


def semgrep_scan(source, output):
    source = Path(source).resolve()
    if not source.is_dir():
        return {
            "tool": "Semgrep CE",
            "status": "skipped",
            "reason": "Source directory not supplied",
            "alerts": [],
        }
    config = ROOT / "resources/semgrep.yaml"
    args = [
        "docker",
        "run",
        "--rm",
        "--name",
        "secureflow-semgrep-" + uuid.uuid4().hex[:10],
        "--network",
        "none",
        "--cpus",
        "2",
        "--memory",
        "1g",
        "-v",
        f"{source}:/src:ro",
        "-v",
        f"{config}:/rules.yaml:ro",
        "-v",
        f"{output}:/out",
        SEMGREP_IMAGE,
        "semgrep",
        "scan",
        "--oss-only",
        "--config",
        "/rules.yaml",
        "--metrics",
        "off",
        "--disable-version-check",
        "--json",
        "--output",
        "/out/semgrep.json",
        "--exclude",
        "node_modules",
        "--exclude",
        "frontend",
        "--exclude",
        "build",
        "--exclude",
        "test",
        "--exclude",
        "data",
        "--exclude",
        "infrastructure",
        "--exclude",
        "terraform",
        "/src",
    ]
    code, duration = command_result(args, output, "semgrep", 180)
    if code != 0 or not (output / "semgrep.json").exists():
        raise RuntimeError(f"Semgrep failed ({code}); inspect log")
    raw = json.loads((output / "semgrep.json").read_text())
    alerts = [
        dict(
            id=a["check_id"],
            path=a["path"].removeprefix("/src/"),
            line=a["start"]["line"],
            severity=a["extra"]["severity"],
            message=a["extra"]["message"],
            owasp=a["extra"].get("metadata", {}).get("owasp"),
            cwe=a["extra"].get("metadata", {}).get("cwe"),
            state="unverified",
        )
        for a in raw.get("results", [])
    ]
    return dict(
        tool="Semgrep CE + SecureFlow MIT rules",
        status="complete",
        alerts=alerts,
        count=len(alerts),
        duration_seconds=duration,
        version=raw.get("version"),
        rules_sha256=hashlib.sha256(config.read_bytes()).hexdigest(),
        errors=raw.get("errors", []),
        note="MIT 규칙 8개 고정. Semgrep 기본 정책 성능을 뜻하지 않음. 정적 후보는 미검증 상태로 보존.",
    )


def zap_scan(target, output):
    from .setup import lab_names

    container, network = lab_names()
    inspect = subprocess.run(
        ["docker", "inspect", container], capture_output=True, text=True, check=True
    )
    info = json.loads(inspect.stdout)[0]
    ip = info["NetworkSettings"]["Networks"][network]["IPAddress"]
    allowed = {f"http://{ip}:3000"}
    for binding in info["NetworkSettings"]["Ports"].get("3000/tcp") or []:
        if binding["HostIp"] == "127.0.0.1":
            allowed.add(f"http://127.0.0.1:{binding['HostPort']}")
    if target.rstrip("/") not in allowed:
        return dict(
            tool="OWASP ZAP baseline",
            status="skipped",
            alerts=[],
            reason="Comparison requires owned secureflow-juice container",
        )
    args = [
        "docker",
        "run",
        "--rm",
        "--name",
        "secureflow-zap-" + uuid.uuid4().hex[:10],
        "--network",
        network,
        "--cpus",
        "2",
        "--memory",
        "2g",
        "-v",
        f"{output}:/zap/wrk:rw",
        ZAP_IMAGE,
        "zap-baseline.py",
        "-t",
        f"http://{container}:3000",
        "-m",
        "1",
        "-T",
        "3",
        "-J",
        "zap.json",
        "-r",
        "zap.html",
        "-I",
        "--autooff",
        "-z",
        "-config spider.maxDepth=2 -config spider.maxChildren=8 -config spider.thread=2",
    ]
    code, duration = command_result(args, output, "zap", 300)
    if code not in (0, 1, 2) or not (output / "zap.json").exists():
        raise RuntimeError(f"ZAP failed ({code}); inspect log")
    raw = json.loads((output / "zap.json").read_text())
    alerts = []
    for site in raw.get("site", []):
        for a in site.get("alerts", []):
            alerts.append(
                dict(
                    id=a.get("pluginid"),
                    title=a.get("name"),
                    risk=a.get("riskdesc"),
                    confidence=a.get("confidence"),
                    instances=len(a.get("instances", [])),
                    state="unverified",
                    solution=a.get("solution"),
                    cwe=a.get("cweid"),
                )
            )
    return dict(
        tool="OWASP ZAP baseline",
        status="complete",
        alerts=alerts,
        count=len(alerts),
        duration_seconds=duration,
        version=raw.get("@version"),
        note="비인증 1분 spider + passive scan. 능동 스캔·업무 로직 검사와 다름. 미검증 경고를 FP로 계산하지 않음.",
    )
