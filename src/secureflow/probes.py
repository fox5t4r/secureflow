"""Small differential tests, restricted to a runner-owned loopback lab."""

import base64
import hashlib
import http.client
import json
import pickle
import time
from urllib.parse import urlsplit


class LabClient:
    def __init__(self, url, token, max_requests=64):
        parsed = urlsplit(url)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port:
            raise ValueError("Only numeric IPv4 loopback lab URLs are allowed")
        if (
            parsed.username
            or parsed.password
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Invalid lab URL")
        self.port, self.token, self.limit, self.count = parsed.port, token, max_requests, 0
        self.evidence = []

    def request(self, path, data=None):
        if path != "/health" and not path.startswith("/cases/"):
            raise ValueError("Outside lab route scope")
        if self.count >= self.limit:
            raise RuntimeError("Request budget exceeded")
        self.count += 1
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        start = time.monotonic()
        try:
            connection.request(
                "GET" if data is None else "POST",
                path,
                body=None if data is None else json.dumps(data),
                headers={"Content-Type": "application/json", "X-Lab-Token": self.token},
            )
            response = connection.getresponse()
            raw = response.read(65537)
            if len(raw) > 65536:
                raise ValueError("Response exceeded limit")
            if 300 <= response.status < 400:
                raise ValueError("Redirects are not followed")
            body = json.loads(raw)
            item = dict(
                id=len(self.evidence) + 1,
                path=path,
                request=data,
                status=response.status,
                response=body,
                response_headers=dict(response.getheaders()),
                duration_ms=round((time.monotonic() - start) * 1000, 2),
            )
            self.evidence.append(item)
            return response.status, body
        finally:
            connection.close()


class HarmlessRestore:
    def __reduce__(self):
        return str, ("INTEGRITY_PROBE",)


def probe(client, case):
    path, kind = "/cases/" + case["id"], case["kind"]
    start = len(client.evidence)

    def send(data):
        return client.request(path, data)

    try:
        if kind == "sql":
            status, normal = send({"name": "alice"})
            status2, attack = send({"name": "' OR 1=1 -- "})
            control = status == 200 and normal.get("rows") == [["alice"]]
            positive = status2 == 200 and ["bob"] in attack.get("rows", [])
        elif kind == "crypto":
            password = "lab-only-synthetic-value"
            status, normal = send({"password": password})
            status2, repeated = send({"password": password})
            control = status == status2 == 200 and "password_digest" in normal
            positive = (
                normal.get("password_digest")
                == hashlib.md5(password.encode(), usedforsecurity=False).hexdigest()
                == repeated.get("password_digest")
            )
        elif kind == "debug":
            status, normal = send({})
            status2, repeated = send({})
            control = status == status2 == 200 and "error" in normal
            positive = "/srv/private/settings.py" in normal.get("error", "") and normal == repeated
        elif kind == "auth":
            status, normal = send({"password": "deliberately-wrong"})
            status2, attack = send({"password": "admin123"})
            control = status == 200 and normal.get("authenticated") is False
            positive = status2 == 200 and attack.get("authenticated") is True
        elif kind == "integrity":
            # Establish each supported protocol without using ground-truth labels.
            json_status, json_result = send({"payload": '{"hello":"world"}'})
            pickle_status, pickle_result = send(
                {"payload": base64.b64encode(pickle.dumps({"hello": "world"})).decode()}
            )
            status2, attack = send(
                {"payload": base64.b64encode(pickle.dumps(HarmlessRestore())).decode()}
            )
            control = (json_status == 200 and json_result.get("value") == {"hello": "world"}) or (
                pickle_status == 200 and pickle_result.get("value") == {"hello": "world"}
            )
            positive = status2 == 200 and attack.get("value") == "INTEGRITY_PROBE"
        elif kind == "access":
            status, normal = send({"owner": "alice"})
            status2, attack = send({"owner": "bob"})
            control = status == 200 and normal.get("record") == "ALICE_RECORD"
            positive = status2 == 200 and attack.get("record") == "BOB_PRIVATE_RECORD"
        else:
            from .variants import probe_variant

            control, positive = probe_variant(kind, send, client)
        state = (
            "confirmed" if control and positive else "not_reproduced" if control else "inconclusive"
        )
        return dict(
            state=state,
            control_passed=control,
            evidence_ids=[e["id"] for e in client.evidence[start:]],
            reason="대조군과 재현 결과를 함께 확인" if control else "정상 동작 대조군 실패",
        )
    except (OSError, ValueError, RuntimeError) as error:
        return dict(
            state="inconclusive",
            control_passed=False,
            evidence_ids=[e["id"] for e in client.evidence[start:]],
            reason=str(error),
        )
