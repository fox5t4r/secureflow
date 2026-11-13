"""Build bounded, cited source excerpts without reading credentials or project instructions."""

import hashlib
import os
import re
from pathlib import Path

EXCLUDED = {
    ".git",
    ".local",
    ".venv",
    "node_modules",
    "build",
    "dist",
    "coverage",
    "vendor",
    "test",
    "tests",
    "data",
    "assets",
    "i18n",
}
PRIORITY_DIRECTORIES = {"routes", "controllers", "middleware", "lib", "models", "server", "src"}
EXTENSIONS = {".py", ".ts", ".js", ".tsx", ".jsx", ".java", ".go", ".php", ".cs"}
SIGNALS = re.compile(
    r"query|execute|password|createHash|authorize|req\.|request\.|quantity|jwt|verify|deserialize",
    re.I,
)
SECRET = re.compile(
    r"""(?i)((?:password|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*)["'][^"'\n]*["']"""
)


def source_context(source: str, deep: bool = False) -> list[dict]:
    if not source:
        return []
    root = Path(source).resolve()
    candidates = []
    inspected = 0
    for directory, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(
            (d for d in directories if d not in EXCLUDED and not d.startswith(".")),
            key=lambda name: (name not in PRIORITY_DIRECTORIES, name),
        )
        for name in sorted(files):
            path = Path(directory) / name
            if (
                path.suffix not in EXTENSIONS
                or path.is_symlink()
                or re.search(r"(?:[._](?:test|spec)[._]|^test_)", name)
            ):
                continue
            inspected += 1
            if inspected > 1500:
                break
            if not path.resolve().is_relative_to(root) or path.stat().st_size > 250_000:
                continue
            lines = path.read_text(errors="replace").splitlines()
            hits = [index for index, line in enumerate(lines) if SIGNALS.search(line)]
            if hits:
                relative = path.relative_to(root)
                priority = (
                    100
                    if any(part in PRIORITY_DIRECTORIES for part in relative.parts[:-1])
                    and "frontend" not in relative.parts
                    else 0
                )
                candidates.append((priority + min(len(hits), 30), relative.as_posix(), lines, hits))
        if inspected > 1500:
            break
    excerpts = []
    budget = 32_000 if deep else 10_000
    for _, name, lines, hits in sorted(candidates, key=lambda item: (-item[0], item[1]))[
        : 24 if deep else 5
    ]:
        indexes = sorted(
            {i for hit in hits for i in range(max(0, hit - 2), min(len(lines), hit + 4))}
        )
        numbered = [
            f"{i + 1}: {SECRET.sub(lambda match: match.group(1) + chr(34) + '[REDACTED]' + chr(34), lines[i])[:400]}"
            for i in indexes[: 60 if deep else 20]
        ]
        text = "\n".join(numbered)
        if len(text) > budget:
            continue
        budget -= len(text)
        excerpts.append(
            {"path": name, "source": text, "sha256": hashlib.sha256(text.encode()).hexdigest()}
        )
    return excerpts
