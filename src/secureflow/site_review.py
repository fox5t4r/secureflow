"""Read-only security header review of a single registered URL."""

import http.client
import ipaddress
import re
import socket
from urllib.parse import urlsplit

from .net import validate_url

DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
PRIVATE_V4 = tuple(
    ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def is_public(address):
    return address.is_global and not (
        address.is_multicast
        or address.is_reserved
        or address.is_link_local
        or getattr(address, "ipv4_mapped", None)
    )


def site_endpoint(url):
    if len(url) > 2048 or any(not 32 < ord(char) < 127 for char in url) or "\\" in url:
        raise ValueError("URL은 2048자 이하로 입력하고 경로의 특수문자는 인코딩하세요.")
    parsed = urlsplit(url)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path.startswith("//")
        or "?" in url
        or "#" in url
    ):
        raise ValueError("계정 정보, 쿼리, 프래그먼트가 없는 HTTP(S) URL을 입력하세요.")
    host = "127.0.0.1" if parsed.hostname == "localhost" else parsed.hostname
    try:
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    except ValueError as error:
        raise ValueError("유효한 포트를 입력하세요.") from error
    if not port:
        raise ValueError("유효한 포트를 입력하세요.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if (
            len(host) > 253
            or len(labels) < 2
            or labels[-1].isdigit()
            or not all(DOMAIN_LABEL.fullmatch(label) for label in labels)
        ):
            raise ValueError("공개 도메인, localhost 또는 허용된 사설 IP를 입력하세요.") from None
        if port != (443 if parsed.scheme == "https" else 80):
            raise ValueError("공개 도메인은 HTTP 80 또는 HTTPS 443 포트를 사용하세요.") from None
        return parsed, None, port

    if is_public(address):
        raise ValueError("인터넷 사이트는 공개 IP 대신 도메인 이름을 입력하세요.")
    if not (address.is_loopback or any(address in network for network in PRIVATE_V4)):
        raise ValueError("허용된 실습용 사설 IP를 입력하세요.")
    authority = f"[{address}]" if address.version == 6 else str(address)
    validate_url(f"http://{authority}:{port}")
    return parsed, str(address), port


def resolve_public_host(host, port):
    try:
        records = socket.getaddrinfo(host + ".", port, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise ValueError("공개 도메인의 DNS 주소를 확인할 수 없습니다.") from error
    addresses = [ipaddress.ip_address(record[4][0]) for record in records]
    if not addresses or not all(is_public(address) for address in addresses):
        raise ValueError("공개 도메인은 공개 인터넷 주소로만 연결할 수 있습니다.")
    return str(next((address for address in addresses if address.version == 4), addresses[0]))


def review_site(url):
    parsed, host, port = site_endpoint(url)
    host = host or resolve_public_host(parsed.hostname, port)
    path = parsed.path or "/"
    connection = (
        http.client.HTTPSConnection(parsed.hostname, port, timeout=5)
        if parsed.scheme == "https"
        else http.client.HTTPConnection(parsed.hostname, port, timeout=5)
    )
    # Connect to the validated numeric IP, keeping the original hostname for TLS and Host.
    connection._create_connection = lambda _address, *args: socket.create_connection(
        (host, port), *args
    )
    try:
        connection.request("HEAD", path)
        response = connection.getresponse()
        status = response.status
        nosniff = (response.getheader("X-Content-Type-Options") or "").strip().lower() == "nosniff"
    finally:
        connection.close()

    if not 200 <= status < 300:
        state, detail = (
            "inconclusive",
            f"HEAD 요청에 HTTP {status} 응답. 정상 응답의 헤더를 확인할 수 없습니다. 이동은 따라가지 않습니다.",
        )
    elif nosniff:
        state, detail = "not_reproduced", "응답에 X-Content-Type-Options: nosniff 설정이 있습니다."
    else:
        state, detail = "confirmed", "성공 응답에 X-Content-Type-Options: nosniff 설정이 없습니다."
    finding = {
        "id": "site-nosniff",
        "title": "콘텐츠 유형 추측 방지 설정",
        "state": state,
        "severity": "LOW",
        "owasp": "A02:2025",
        "cwe": "CWE-693",
        "source": path,
        "detail": detail,
        "advice": "웹 서버에서 실제 Content-Type을 설정하고 nosniff 헤더를 추가하세요.",
        "code": "add_header X-Content-Type-Options nosniff always; # Nginx 예시",
        "evidence": [
            {"id": 1, "method": "HEAD", "path": path, "status": status, "nosniff": nosniff}
        ],
    }
    return {"findings": [finding], "request_count": 1, "version": {}}
