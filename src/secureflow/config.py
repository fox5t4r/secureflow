"""Runtime paths are independent of the checkout and installed package location."""

import json
import os
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent


def workspace() -> Path:
    return Path(os.getenv("SECUREFLOW_WORKSPACE", str(Path.cwd() / ".local"))).resolve()


def data_directory() -> Path:
    return Path(os.getenv("SECUREFLOW_DATA", str(workspace() / "state"))).resolve()


def source_roots() -> list[Path]:
    configured = os.getenv("SECUREFLOW_SOURCE_ROOTS", str(workspace() / "sources"))
    return [Path(value).resolve() for value in configured.split(",") if value.strip()]


def managed_lab() -> dict:
    path = workspace() / "lab.json"
    return json.loads(path.read_text()) if path.is_file() else {}
