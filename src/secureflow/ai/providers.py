"""Inference adapters. Subscription credentials remain owned by the vendor CLI."""

import http.client
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from ..net import validate_url

PROVIDERS = {"ollama", "codex", "claude"}
DEFAULTS = {
    "ai_provider": "ollama",
    "ai_url": "http://127.0.0.1:11434",
    "ai_model": "qwen2.5-coder:1.5b",
    "ai_deep_model": "",
    "ai_effort": "high",
    "ai_local_model_a": "qwen2.5-coder:1.5b",
    "ai_local_model_b": "qwen2.5:0.5b",
}
SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    key: {"type": "integer" if key == "line" else "string"}
                    for key in ("path", "line", "risk", "fix", "test_plan", "confidence")
                },
                "required": ["path", "line", "risk", "fix", "test_plan", "confidence"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["summary", "findings"],
    "additionalProperties": False,
}


def validate_settings(settings: dict) -> dict:
    config = {**DEFAULTS, **settings}
    if not isinstance(config["ai_provider"], str) or config["ai_provider"] not in PROVIDERS:
        raise ValueError("Choose ollama, codex, or claude")
    if not isinstance(config["ai_url"], str):
        raise ValueError("AI URL must be a string")
    for key in ("ai_model", "ai_deep_model", "ai_local_model_a", "ai_local_model_b"):
        if not isinstance(config[key], str) or (
            config[key] and not re.fullmatch(r"[A-Za-z0-9._:/-]{1,100}", config[key])
        ):
            raise ValueError("Invalid model identifier")
    if config["ai_effort"] not in ("low", "medium", "high"):
        raise ValueError("Reasoning effort must be low, medium, or high")
    if config["ai_provider"] == "ollama":
        validate_url(config["ai_url"], allowed={"127.0.0.1"})
        if not config["ai_model"]:
            raise ValueError("Ollama requires an installed model name")
    return {key: config[key] for key in DEFAULTS}


def _cli_executable(provider: str) -> str | None:
    configured = os.getenv(f"SECUREFLOW_{provider.upper()}_BIN")
    if configured:
        # An override belongs to the server operator, never to a dashboard request.
        return shutil.which(configured) if Path(configured).is_absolute() else None
    return shutil.which(provider)


def _cli_environment(executable: str) -> dict[str, str]:
    environment = os.environ.copy()
    for key in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDECODE"):
        environment.pop(key, None)
    # npm wrappers may need Node from the same installation directory as the wrapper.
    parent = str(Path(executable).parent)
    environment["PATH"] = os.pathsep.join((parent, environment.get("PATH", os.defpath)))
    return environment


def connection_status() -> dict:
    """Report CLI presence/auth only. Never return account identifiers or raw CLI logs."""
    status = {"ollama": {"installed": True, "note": "Connection checked when analysis starts"}}
    for provider, arguments in (("codex", ["login", "status"]), ("claude", ["auth", "status"])):
        executable = _cli_executable(provider)
        item = {"installed": bool(executable), "authenticated": False}
        if executable:
            try:
                result = subprocess.run(
                    [executable, *arguments],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    env=_cli_environment(executable),
                )
                if provider == "codex":
                    item["authenticated"] = result.returncode == 0
                    item["subscription"] = "chatgpt" in (result.stdout + result.stderr).lower()
                else:
                    data = json.loads(result.stdout)
                    item["authenticated"] = bool(data.get("loggedIn"))
                    item["subscription"] = data.get("authMethod") in ("claude.ai", "oauth")
            except (OSError, subprocess.TimeoutExpired, ValueError):
                item["note"] = "Status unavailable; run the vendor login command in a terminal"
        status[provider] = item
    return status


def _cli_run(arguments: list[str], prompt: str, directory: Path, timeout: int) -> str:
    # No shell expansion; temporary workspace has no target files/configuration.
    # Auth is reused by the CLI; SecureFlow never reads or exports its tokens.
    environment = _cli_environment(arguments[0])
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.PIPE,
            stdout=output,
            stderr=errors,
            cwd=directory,
            env=environment,
            start_new_session=True,
        )
        try:
            process.communicate(input=prompt.encode(), timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise RuntimeError("AI CLI timed out; its process group was stopped") from None
        if process.returncode:
            raise RuntimeError(
                "AI CLI failed. Check vendor login, model availability, and subscription limits in your terminal."
            )
        output.seek(0)
        data = output.read(262_145)
        if len(data) > 262_144:
            raise RuntimeError("AI response exceeds the size limit")
        return data.decode(errors="replace")


def _local_schema(messages: list[dict]) -> dict:
    """Small models need a tight output budget and explicit citation alternatives."""
    schema = json.loads(json.dumps(SCHEMA))
    schema["properties"]["summary"]["maxLength"] = 300
    findings = schema["properties"]["findings"]
    findings["maxItems"] = 2
    item = findings["items"]
    for key, limit in {"risk": 250, "fix": 350, "test_plan": 250, "confidence": 10}.items():
        item["properties"][key]["maxLength"] = limit
    try:
        context = json.loads(messages[-1]["content"])["source"]
        choices = []
        for excerpt in context:
            choice = json.loads(json.dumps(item))
            choice["properties"]["path"]["enum"] = [excerpt["path"]]
            choice["properties"]["line"]["enum"] = [
                int(line.split(":", 1)[0]) for line in excerpt["source"].splitlines()
            ]
            choices.append(choice)
        if choices:
            findings["items"] = {"anyOf": choices}
    except (KeyError, ValueError, IndexError, TypeError):
        pass
    return schema


def complete(config: dict, messages: list[dict], model: str, timeout: int = 240) -> dict:
    provider = config["ai_provider"]
    started = time.monotonic()
    if provider == "ollama":
        parsed = validate_url(config["ai_url"], allowed={"127.0.0.1"})
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
        try:
            payload = {
                "model": model,
                "messages": messages,
                "stream": False,
                "format": _local_schema(messages),
                "keep_alive": 0,
                "options": {
                    "temperature": 0,
                    "num_predict": 2200,
                    "num_ctx": 16384,
                    "num_thread": 4,
                },
            }
            connection.request(
                "POST", "/api/chat", json.dumps(payload), {"Content-Type": "application/json"}
            )
            response = connection.getresponse()
            body = response.read(262_145)
            if response.status != 200 or len(body) > 262_144:
                raise RuntimeError(f"Ollama request failed (HTTP {response.status})")
            data = json.loads(body)
            if not data.get("done"):
                raise RuntimeError("Ollama returned incomplete output")
            if data.get("done_reason") == "length":
                raise RuntimeError(
                    "Ollama output reached the token limit; partial JSON was rejected"
                )
            text = data["message"]["content"]
        finally:
            connection.close()
    else:
        executable = _cli_executable(provider)
        if not executable:
            raise RuntimeError(
                f"SecureFlow could not find {provider}. Install it or set SECUREFLOW_{provider.upper()}_BIN to its absolute path."
            )
        with tempfile.TemporaryDirectory(prefix="secureflow-ai-") as temporary:
            directory = Path(temporary)
            prompt = "\n\n".join(f"{m['role'].upper()}: {m['content']}" for m in messages)
            if provider == "codex":
                schema = directory / "schema.json"
                schema.write_text(json.dumps(SCHEMA))
                destination = directory / "response.json"
                arguments = [
                    executable,
                    "exec",
                    "--ignore-user-config",
                    "--ignore-rules",
                    "--ephemeral",
                    "--skip-git-repo-check",
                    "--sandbox",
                    "read-only",
                    "--color",
                    "never",
                    "-c",
                    'approval_policy="never"',
                    "-c",
                    'web_search="disabled"',
                    "-c",
                    "project_doc_max_bytes=0",
                    "--disable",
                    "shell_tool",
                    "--disable",
                    "unified_exec",
                    "--disable",
                    "plugins",
                    "--enable",
                    "skip_host_skill_discovery",
                    "-c",
                    f'model_reasoning_effort="{config["ai_effort"]}"',
                    "--output-schema",
                    str(schema),
                    "--output-last-message",
                    str(destination),
                ]
                if model:
                    arguments += ["--model", model]
                _cli_run([*arguments, "-"], prompt, directory, timeout)
                if not destination.exists() or destination.stat().st_size > 262_144:
                    raise RuntimeError("Codex did not return a bounded final response")
                text = destination.read_text()
            else:
                arguments = [
                    executable,
                    "--safe-mode",
                    "-p",
                    "--tools",
                    "",
                    "--no-session-persistence",
                    "--output-format",
                    "json",
                    "--json-schema",
                    json.dumps(SCHEMA),
                    "--effort",
                    config["ai_effort"],
                    "--strict-mcp-config",
                    "--mcp-config",
                    '{"mcpServers":{}}',
                ]
                if model:
                    arguments += ["--model", model]
                data = json.loads(_cli_run(arguments, prompt, directory, timeout))
                if data.get("is_error"):
                    raise RuntimeError("Claude returned an error; check login and usage limits")
                text = (
                    json.dumps(data["structured_output"])
                    if "structured_output" in data
                    else data.get("result", "")
                )
    return {"review": json.loads(text), "duration_seconds": round(time.monotonic() - started, 2)}
