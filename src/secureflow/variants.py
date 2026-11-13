import base64
import hashlib
import hmac
import json


def probe_variant(kind, send, client):
    if kind == "sql_numeric":
        status, normal = send({"id": "1"})
        results = [send({"id": value}) for value in ("0 OR 1=1", "0 OR TRUE", "0/**/OR/**/1=1")]
        return status == 200 and normal.get("rows") == [["ONE"]], any(
            s == 200 and ["TWO"] in r.get("rows", []) for s, r in results
        )
    if kind == "sha1":
        values = ["first-lab-value", "second-lab-value"]
        results = [send({"password": value}) for value in values]
        return all(s == 200 and "password_digest" in r for s, r in results), all(
            r.get("password_digest") == hashlib.sha1(v.encode(), usedforsecurity=False).hexdigest()
            for (s, r), v in zip(results, values)
        )
    if kind == "cors":
        status, normal = send({"origin": "https://trusted.example"})
        status2, attack = send({"origin": "https://untrusted.example"})
        headers = {k.lower(): v for k, v in client.evidence[-1]["response_headers"].items()}
        return status == 200 and normal.get(
            "data"
        ) == "LAB_ACCOUNT_DATA", status2 == 200 and headers.get(
            "access-control-allow-origin"
        ) == "https://untrusted.example" and headers.get(
            "access-control-allow-credentials"
        ) == "true"
    if kind == "auth_prefix":
        status, normal = send({"password": "lab-valid-passphrase"})
        status2, wrong = send({"password": "wrong"})
        results = [send({"password": value}) for value in ("lab", "lab-valid", "l")]
        control = (
            status == status2 == 200
            and normal.get("authenticated") is True
            and wrong.get("authenticated") is False
        )
        return control, any(s == 200 and r.get("authenticated") is True for s, r in results)
    if kind == "unsigned_state":
        _, signed = send({"action": "issue"})
        status, normal = send(signed)
        signed["body"] = base64.b64encode(json.dumps({"role": "admin"}).encode()).decode()
        status2, changed = send(signed)
        return status == 200 and normal.get("role") == "user", status2 == 200 and changed.get(
            "role"
        ) == "admin"
    if kind == "mass_assignment":
        status, normal = send({"name": "Updated"})
        status2, changed = send({"name": "Updated", "role": "admin"})
        return status == 200 and normal.get("role") == "user" and normal.get(
            "name"
        ) == "Updated", status2 == 200 and changed.get("role") == "admin"
    if kind == "artifact_digest":
        status, normal = send({"artifact": 'RESULT = "TRUSTED"'})
        status2, changed = send({"artifact": 'RESULT = "ALTERED"'})
        return status == 200 and normal.get("result") == "TRUSTED", status2 == 200 and changed.get(
            "result"
        ) == "ALTERED"
    if kind == "artifact_signer":
        _, signed = send({"action": "issue"})
        status, normal = send(signed)
        artifact = 'RESULT = "ALTERED"'
        signature = hmac.new(b"untrusted-signer", artifact.encode(), hashlib.sha256).hexdigest()
        status2, changed = send(
            {"artifact": artifact, "signature": signature, "signer_key": "untrusted-signer"}
        )
        return status == 200 and normal.get("result") == "TRUSTED", status2 == 200 and changed.get(
            "result"
        ) == "ALTERED"
    if kind in ("negative_quantity", "client_price"):
        status, normal = send({"quantity": 1, "price": 10})
        outcomes = [
            send(payload)
            for payload in (
                [{"quantity": -1}, {"quantity": -5}, {"quantity": "-2"}]
                if kind == "negative_quantity"
                else [
                    {"quantity": 1, "price": 0},
                    {"quantity": 1, "price": -1},
                    {"quantity": 1, "price": "0.01"},
                ]
            )
        ]
        positive = any(s == 200 and r.get("total", 10) < 10 for s, r in outcomes)
        return status == 200 and normal.get("total") == 10, positive
    if kind == "missing_audit":
        status, normal = send({"password": "lab-valid-passphrase"})
        _, before = send({"action": "events"})
        failed_status, failed = send({"password": "wrong"})
        _, after = send({"action": "events"})
        control = (
            status == 200
            and normal.get("authenticated") is True
            and "LOGIN_OK" in before.get("events", [])
        )
        return control, failed_status == 200 and failed.get("authenticated") is False and after.get(
            "events"
        ) == before.get("events")
    if kind == "log_forgery":
        status, normal = send({"username": "alice"})
        _, before = send({"action": "events"})
        send({"username": "alice\nLOGIN_OK user=admin"})
        _, after = send({"action": "events"})
        return status == 200 and "alice" in before.get(
            "log", ""
        ), "LOGIN_OK user=admin" in after.get("log", "").splitlines()
    if kind == "fail_open":
        status, normal = send({"policy_failure": False})
        status2, failed = send({"policy_failure": True})
        return status == 200 and normal.get("allowed") is False, status2 == 200 and failed.get(
            "allowed"
        ) is True
    if kind == "partial_update":
        status, normal = send({})
        status2, failed = send({"fail_after_debit": True})
        _, state = send({"action": "read"})
        return status == 200 and normal.get("balances") == [90, 110], status2 == 503 and state.get(
            "balances"
        ) == [80, 110]
    raise ValueError("Unknown probe kind")
