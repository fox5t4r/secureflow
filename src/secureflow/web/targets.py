import uuid

from flask import jsonify, request

from ..config import validate_source_directory
from ..net import validate_url
from ..site_review import site_endpoint


def install_targets(app, store, authenticated):
    @app.get("/api/targets")
    def targets():
        return jsonify(targets=store.targets())

    def target_data(data, old=None):
        name = str(data.get("name", "")).strip()
        if not name or len(name) > 120:
            raise ValueError("Target name required (maximum 120 characters)")
        url = str(data.get("url", "")).strip()
        mode = data.get("mode", old["mode"] if old else "juice")
        if mode == "site":
            site_endpoint(url)
        elif mode == "juice":
            url = url.rstrip("/")
            validate_url(url)
        elif mode == "source":
            if url:
                raise ValueError("소스코드 검사에는 URL을 입력하지 않습니다.")
        else:
            raise ValueError("지원하지 않는 검사 방식입니다.")
        source = str(data.get("source_path", "")).strip()
        if source or mode == "source":
            source = str(validate_source_directory(source))
        username = str(data.get("username", "")).strip()[:200]
        password = str(data.get("password", ""))
        if mode != "juice":
            if username or password:
                raise ValueError("테스트 계정은 Juice Shop 실습에만 사용합니다.")
            return name, url, source, "", "", mode
        if len(password) > 512:
            raise ValueError("Target password exceeds 512 characters")
        credential = (
            store.vault.encrypt(password.encode()).decode()
            if password
            else old["credential"]
            if old
            else ""
        )
        if bool(username) != bool(credential):
            raise ValueError("Supply both a target username and password")
        return name, url, source, username, credential, mode

    @app.post("/api/targets")
    def add_target():
        identifier = uuid.uuid4().hex
        values = target_data(request.get_json() or {})
        with store.connect() as db:
            db.execute(
                "INSERT INTO targets (id,name,url,source_path,username,credential,mode) VALUES (?,?,?,?,?,?,?)",
                (identifier, *values),
            )
        store.audit("target_created", authenticated(), identifier)
        return jsonify(id=identifier), 201

    @app.put("/api/targets/<identifier>")
    def update_target(identifier):
        old = next((t for t in store.targets(private=True) if t["id"] == identifier), None)
        if not old:
            return jsonify(error="Target not found"), 404
        values = target_data(request.get_json() or {}, old)
        with store.connect() as db:
            db.execute(
                "UPDATE targets SET name=?,url=?,source_path=?,username=?,credential=?,mode=? WHERE id=?",
                (*values, identifier),
            )
        store.audit("target_updated", authenticated(), identifier)
        return jsonify(ok=True)

    @app.delete("/api/targets/<identifier>")
    def remove_target(identifier):
        if any(
            j["target_id"] == identifier and j["status"] in ("queued", "running")
            for j in store.jobs()
        ):
            return jsonify(error="Target has an active job"), 409
        with store.connect() as db:
            changed = db.execute("DELETE FROM targets WHERE id=?", (identifier,)).rowcount
        store.audit("target_deleted", authenticated(), identifier)
        return jsonify(ok=True) if changed else (jsonify(error="Target not found"), 404)
