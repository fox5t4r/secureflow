"""Explicit IP allowlist; no DNS, proxies, redirects, or arbitrary schemes."""

import http.client
import ipaddress
import json
import os
import re
from urllib.parse import urlsplit

from .config import managed_lab

SENSITIVE = re.compile(r"password|token|authorization|cookie|secret|signature", re.I)


def redact(value):
    if isinstance(value, dict):
        return {k: "[REDACTED]" if SENSITIVE.search(k) else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED JWT]", value)
    return value


def validate_url(url, allowed=None):
    parsed = urlsplit(url)
    hosts = allowed
    if hosts is None:
        configured = os.getenv("SECUREFLOW_ALLOWED_HOSTS")
        hosts = set(configured.split(",")) if configured else {"127.0.0.1", "10.203.93.2"}
        if not configured and managed_lab().get("target_url"):
            hosts.add(urlsplit(managed_lab()["target_url"]).hostname)
    try:
        ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except ValueError:
        raise ValueError("Numeric local IP and port required")
    if parsed.scheme != "http" or parsed.hostname not in hosts or not port:
        raise ValueError("Target is outside the explicit local lab allowlist")
    if (
        parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Use a base URL without credentials, path, query or fragment")
    return parsed


class LocalHTTP:
    def __init__(self, url, limit=120):
        self.url = validate_url(url)
        self.limit, self.count, self.evidence = limit, 0, []

    def request(self, method, path, data=None, token=None):
        if not path.startswith("/") or path.startswith("//") or "\r" in path or "\n" in path:
            raise ValueError("Invalid relative request path")
        if self.count >= self.limit:
            raise RuntimeError("HTTP request budget reached")
        self.count += 1
        conn = http.client.HTTPConnection(self.url.hostname, self.url.port, timeout=8)
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        try:
            conn.request(method, path, json.dumps(data) if data is not None else None, headers)
            response = conn.getresponse()
            raw = response.read(262145)
            if len(raw) > 262144:
                raise ValueError("Response exceeds evidence limit")
            text = raw.decode("utf-8", errors="replace")
            try:
                body = json.loads(text)
            except json.JSONDecodeError:
                body = text
            result = {
                "status": response.status,
                "body": body,
                "headers": dict(response.getheaders()),
            }
            self.evidence.append(
                {
                    "id": len(self.evidence) + 1,
                    "method": method,
                    "path": path,
                    "request": redact(data),
                    "status": response.status,
                    "response": redact(body if isinstance(body, dict) else text[:12000]),
                    "headers": redact(dict(response.getheaders())),
                }
            )
            return result
        finally:
            conn.close()
