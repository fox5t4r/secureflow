import hmac
import secrets
import time
from urllib.parse import urlsplit

from flask import jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash


def install_auth(app, store):
    dummy_hash = generate_password_hash(secrets.token_urlsafe(24))

    def authenticated():
        identifier = session.get("sid")
        if not identifier:
            return None
        with store.connect() as db:
            row = db.execute(
                "SELECT username FROM sessions WHERE id=? AND expires>?", (identifier, time.time())
            ).fetchone()
        return row["username"] if row else None

    @app.before_request
    def protect():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        if request.path.startswith("/api/"):
            if request.method not in ("GET", "HEAD", "OPTIONS"):
                if request.is_json and not isinstance(request.get_json(silent=True), dict):
                    return jsonify(error="Request body must be a JSON object"), 400
                if not hmac.compare_digest(
                    request.headers.get("X-CSRF-Token", ""), session["csrf"]
                ):
                    return jsonify(error="Invalid CSRF token"), 403
                origin = request.headers.get("Origin")
                if origin and urlsplit(origin).netloc != request.host:
                    return jsonify(error="Cross-origin request rejected"), 403
            if (
                request.path not in ("/api/session", "/api/login", "/api/health")
                and not authenticated()
            ):
                return jsonify(error="Administrator login required"), 401

    @app.after_request
    def headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        return response

    @app.get("/api/session")
    def current_session():
        username = authenticated()
        return jsonify(authenticated=bool(username), username=username, csrf=session["csrf"])

    @app.post("/api/login")
    def login():
        data = request.get_json() or {}
        username = str(data.get("username", ""))[:100]
        password = str(data.get("password", ""))[:512]
        ip = request.remote_addr
        with store.connect() as db:
            db.execute("DELETE FROM attempts WHERE at<?", (time.time() - 300,))
            if db.execute("SELECT count(*) FROM attempts WHERE ip=?", (ip,)).fetchone()[0] >= 5:
                return jsonify(error="Too many attempts; retry after 5 minutes"), 429
            row = db.execute(
                "SELECT password_hash FROM admins WHERE username=?", (username,)
            ).fetchone()
            valid = check_password_hash(row["password_hash"] if row else dummy_hash, password)
            if not row or not valid:
                db.execute("INSERT INTO attempts VALUES (?,?)", (ip, time.time()))
                db.execute(
                    "INSERT INTO audit(at,event,username,detail) VALUES (?,?,?,?)",
                    (time.time(), "login_failed", username, ""),
                )
                return jsonify(error="Invalid username or password"), 401
            if session.get("sid"):
                db.execute("DELETE FROM sessions WHERE id=?", (session["sid"],))
            session.clear()
            session["sid"] = secrets.token_urlsafe(32)
            session["csrf"] = secrets.token_urlsafe(32)
            db.execute(
                "INSERT INTO sessions VALUES (?,?,?)",
                (session["sid"], username, time.time() + 8 * 3600),
            )
        store.audit("login", username)
        return jsonify(authenticated=True, username=username, csrf=session["csrf"])

    @app.post("/api/logout")
    def logout():
        with store.connect() as db:
            db.execute("DELETE FROM sessions WHERE id=?", (session.get("sid"),))
        session.clear()
        session["csrf"] = secrets.token_urlsafe(32)
        return jsonify(authenticated=False, csrf=session["csrf"])

    @app.post("/api/admin/password")
    def change_password():
        data = request.get_json() or {}
        username = authenticated()
        password = str(data.get("new_password", ""))
        if not 12 <= len(password) <= 200:
            raise ValueError("New password must contain 12–200 characters")
        with store.connect() as db:
            row = db.execute(
                "SELECT password_hash FROM admins WHERE username=?", (username,)
            ).fetchone()
            if not check_password_hash(row["password_hash"], str(data.get("current_password", ""))):
                return jsonify(error="Current password incorrect"), 403
            db.execute(
                "UPDATE admins SET password_hash=? WHERE username=?",
                (generate_password_hash(password), username),
            )
            db.execute(
                "DELETE FROM sessions WHERE username=? AND id<>?", (username, session["sid"])
            )
        session["csrf"] = secrets.token_urlsafe(32)
        (store.directory / "initial-admin.txt").unlink(missing_ok=True)
        store.audit("password_changed", username)
        return jsonify(ok=True, csrf=session["csrf"])

    return authenticated
