"""Only the demo runner starts this app, bound to numeric loopback."""

import importlib
import pickle
import secrets

from flask import Flask, jsonify, request


def create_app(cases, token):
    app = Flask(__name__)
    modules = {c["id"]: importlib.import_module("secureflow.lab.cases." + c["id"]) for c in cases}
    contexts = {
        c["id"]: {
            "actor": "alice",
            "strong_password": secrets.token_urlsafe(32),
            "signing_key": secrets.token_bytes(32),
            "events": [],
            "balances": [100, 100],
        }
        for c in cases
    }

    @app.before_request
    def require_lab_token():
        if not secrets.compare_digest(request.headers.get("X-Lab-Token", ""), token):
            return jsonify(error="Lab session required"), 403

    @app.get("/health")
    def health():
        return jsonify(service="secureflow-owned-lab")

    @app.post("/cases/<case_id>")
    def run_case(case_id):
        if case_id not in modules:
            return jsonify(error="Unknown case"), 404
        try:
            return modules[case_id].handle(request.get_json(), contexts[case_id])
        except (ValueError, KeyError, TypeError, pickle.UnpicklingError, EOFError):
            return jsonify(error="Invalid input"), 400

    return app
