"""Install a versioned local lab without requiring a pre-built personal checkout."""

import json
import os
import shutil
import subprocess
import time

from .comparators import SEMGREP_IMAGE, ZAP_IMAGE
from .config import managed_lab, workspace

JUICE_REVISION = "5658473cf8814459bf89000ce373b20ed0b4eb37"
JUICE_IMAGE = (
    "bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b"
)


def lab_names() -> tuple[str, str]:
    saved = managed_lab()
    if not os.getenv("SECUREFLOW_LAB_PREFIX") and saved.get("container") and saved.get("network"):
        return saved["container"], saved["network"]
    prefix = os.getenv("SECUREFLOW_LAB_PREFIX", "secureflow")
    import re

    if not re.fullmatch(r"[a-z][a-z0-9-]{0,40}", prefix):
        raise ValueError("Invalid lab container prefix")
    return f"{prefix}-juice", f"{prefix}-lab"


def run(*arguments, cwd=None):
    subprocess.run(arguments, check=True, cwd=cwd)


def inspect(kind, name):
    result = subprocess.run(["docker", kind, "inspect", name], capture_output=True, text=True)
    return json.loads(result.stdout)[0] if result.returncode == 0 else None


def setup_lab(with_ollama=False):
    for binary in ("docker", "git"):
        if not shutil.which(binary):
            raise RuntimeError(f"Install {binary} first")
    subprocess.run(["docker", "info"], check=True, stdout=subprocess.DEVNULL)
    root = workspace()
    source = root / "sources" / "juice-shop"
    if not source.exists():
        source.mkdir(parents=True)
        run("git", "init", "--quiet", str(source))
        run(
            "git",
            "remote",
            "add",
            "origin",
            "https://github.com/juice-shop/juice-shop.git",
            cwd=source,
        )
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=source, capture_output=True, text=True)
    if head.returncode:
        run("git", "fetch", "--depth=1", "origin", JUICE_REVISION, cwd=source)
        run("git", "checkout", "--detach", JUICE_REVISION, cwd=source)
    elif head.stdout.strip() != JUICE_REVISION:
        raise RuntimeError(
            "Existing lab source has a different revision; use a new SECUREFLOW_WORKSPACE"
        )
    container, network = lab_names()
    if not inspect("network", network):
        run(
            "docker",
            "network",
            "create",
            "--internal",
            "--subnet",
            os.getenv("SECUREFLOW_LAB_SUBNET", "10.203.93.0/24"),
            network,
        )
    existing = inspect("container", container)
    port = int(os.getenv("SECUREFLOW_JUICE_PORT", "3000"))
    if not existing:
        run("docker", "pull", JUICE_IMAGE)
        run(
            "docker",
            "run",
            "-d",
            "--name",
            container,
            "--network",
            network,
            "--publish",
            f"127.0.0.1:{port}:3000",
            "--memory",
            "1g",
            "--cpus",
            "2",
            JUICE_IMAGE,
        )
    else:
        run("docker", "start", container)
    for image in (SEMGREP_IMAGE, ZAP_IMAGE):
        run("docker", "pull", image)
    info = inspect("container", container)
    published = info["NetworkSettings"]["Ports"].get("3000/tcp")
    target = (
        f"http://127.0.0.1:{published[0]['HostPort']}"
        if published
        else f"http://{info['NetworkSettings']['Networks'][network]['IPAddress']}:3000"
    )
    result = {
        "target_url": target,
        "source_path": str(source),
        "source_revision": JUICE_REVISION,
        "container": container,
        "network": network,
        "image_id": info["Image"],
        "reused_container": bool(existing),
    }
    (root / "lab.json").write_text(json.dumps(result, indent=2))
    if with_ollama:
        try:
            setup_ollama()
            result["ai_setup"] = "complete"
        except (OSError, subprocess.SubprocessError) as error:
            result["ai_setup"] = "unavailable"
            print(
                f"Optional local AI setup failed ({type(error).__name__}); normal scanning remains available."
            )
        (root / "lab.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    print("Start: secureflow serve. Register the target URL and source path above.")
    return result


def setup_ollama():
    name = "secureflow-ollama"
    if not inspect("container", name):
        run(
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "-p",
            "127.0.0.1:11434:11434",
            "-v",
            "secureflow-ollama:/root/.ollama",
            "--cpus",
            "4",
            "--memory",
            "4g",
            "ollama/ollama:latest",
        )
    else:
        run("docker", "start", name)
    for _ in range(30):
        probe = subprocess.run(["docker", "exec", name, "ollama", "list"], capture_output=True)
        if probe.returncode == 0:
            break
        time.sleep(1)
    for model in ("qwen2.5-coder:1.5b", "qwen2.5:0.5b"):
        run("docker", "exec", name, "ollama", "pull", model)
