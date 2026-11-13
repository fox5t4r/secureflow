import hashlib
import os

from flask import Flask, jsonify, render_template, request, send_file

from .ai.providers import connection_status, validate_settings
from .config import data_directory
from .jobs import JobEngine
from .store import Store
from .web.auth import install_auth
from .web.targets import install_targets


def create_dashboard(directory=None, start_workers=True):
    store = Store(directory or data_directory())
    worker_lock = None
    if start_workers:
        import fcntl

        worker_lock = open(store.directory / "worker.lock", "a")
        try:
            fcntl.flock(worker_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            worker_lock.close()
            raise RuntimeError("A dashboard worker already owns this data directory")
    bootstrap = store.bootstrap()
    if bootstrap:
        print(f"Initial admin credential file (0600): {bootstrap}", flush=True)
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=hashlib.sha256(store.key + b"session-cookie").digest(),
        MAX_CONTENT_LENGTH=65536,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=os.getenv("SECUREFLOW_COOKIE_SECURE") == "1",
        TRUSTED_HOSTS=["127.0.0.1", "localhost", "secureflow-dashboard"],
    )
    engine = JobEngine(store) if start_workers else None
    app.extensions.update(store=store, engine=engine, worker_lock=worker_lock)
    authenticated = install_auth(app, store)
    install_targets(app, store, authenticated)

    @app.errorhandler(ValueError)
    def invalid(error):
        return jsonify(error=str(error)), 400

    @app.get("/")
    def index():
        return render_template("dashboard.html")

    @app.get("/api/health")
    def health():
        return jsonify(status="ok")

    @app.get("/api/settings")
    def settings():
        return jsonify(store.settings())

    @app.put("/api/settings")
    def save_settings():
        data = validate_settings({**store.settings(), **(request.get_json() or {})})
        with store.connect() as db:
            for key in data:
                db.execute(
                    "INSERT INTO settings VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, data[key]),
                )
        return jsonify(ok=True)

    @app.get("/api/ai/connections")
    def ai_connections():
        return jsonify(connection_status())

    @app.get("/api/jobs")
    def jobs():
        return jsonify(
            jobs=[
                {k: v for k, v in j.items() if k not in ("findings", "comparison", "ai")}
                for j in store.jobs()
            ]
        )

    @app.post("/api/jobs")
    def new_job():
        if engine is None:
            return jsonify(error="Workers unavailable"), 503
        data = request.get_json() or {}
        target = next(
            (t for t in store.targets(private=True) if t["id"] == data.get("target_id")), None
        )
        if not target:
            return jsonify(error="Target not found"), 404
        for key in ("ai_enabled", "compare_tools"):
            if key in data and not isinstance(data[key], bool):
                raise ValueError("Job options must be booleans")
        job = engine.start(
            target,
            data.get("ai_enabled", False),
            data.get("compare_tools", False),
            data.get("ai_mode", "standard"),
        )
        store.audit("job_started", authenticated(), job["id"])
        return jsonify(job), 202

    @app.get("/api/jobs/<identifier>")
    def job_detail(identifier):
        job = store.job(identifier)
        if not job:
            return jsonify(error="Job not found"), 404
        return jsonify(
            job=job, findings=job["findings"], comparison=job["comparison"], ai=job["ai"]
        )

    @app.get("/api/jobs/<identifier>/report/<kind>")
    def report(identifier, kind):
        job = store.job(identifier)
        if not job or kind not in ("quick", "final"):
            return jsonify(error="Report not found"), 404
        if not job[kind + "_ready"]:
            return jsonify(error="Report is not ready"), 409
        return send_file(
            store.directory / "reports" / identifier / (kind + ".html"),
            as_attachment=True,
            download_name=f"secureflow-{identifier[:8]}-{kind}.html",
        )

    return app


def serve(port=8765):
    from waitress import serve as waitress_serve

    app = create_dashboard()
    print(f"SecureFlow dashboard: http://127.0.0.1:{port}", flush=True)
    waitress_serve(app, host="127.0.0.1", port=port, threads=8)
