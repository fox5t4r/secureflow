"""Validate publishable files and optionally create a source archive from an allowlist."""

import argparse
import re
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = {
    "README.md",
    "LICENSE",
    "pyproject.toml",
    "MANIFEST.in",
    ".gitignore",
    ".dockerignore",
    ".env.example",
}
DIRECTORIES = {"src", "tests", "scripts", "docs", "deploy", ".github"}
SECRET_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bsk-(?:proj-|ant-)[A-Za-z0-9_-]{24,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
]


def publishable_files():
    for entry in sorted(ROOT.iterdir()):
        paths = (
            [entry]
            if entry.name in FILES
            else sorted(entry.rglob("*"))
            if entry.name in DIRECTORIES
            else []
        )
        for path in paths:
            if (
                path.is_symlink()
                or not path.is_file()
                or any(part == "__pycache__" or part.endswith(".egg-info") for part in path.parts)
            ):
                continue
            if path.suffix in (".pyc", ".sqlite3", ".key") or path.name == "initial-admin.txt":
                raise ValueError(f"Private runtime file in release tree: {path.relative_to(ROOT)}")
            yield path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    files = list(publishable_files())
    for path in files:
        text = path.read_text(errors="replace")
        if any(pattern.search(text) for pattern in SECRET_PATTERNS):
            raise ValueError(f"Potential credential in {path.relative_to(ROOT)}")
        if re.search(r"/" + "home" + r"/[A-Za-z0-9_.-]+/", text):
            raise ValueError(f"Personal absolute path in {path.relative_to(ROOT)}")
    if args.archive:
        args.archive.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(args.archive, "w:gz") as archive:
            for path in files:
                archive.add(path, arcname=Path("secureflow") / path.relative_to(ROOT))
    print(f"Release check passed: {len(files)} allowlisted files; runtime data excluded.")


if __name__ == "__main__":
    main()
