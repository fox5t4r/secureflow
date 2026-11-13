"""Evidence-driven presentation data shared by portable reports."""

import base64
import json
from collections import Counter
from datetime import datetime
from functools import lru_cache

from .config import PACKAGE_ROOT
from .remediation import guidance

STATES = {
    "confirmed": "검증 완료",
    "not_reproduced": "미재현",
    "inconclusive": "미확인",
    "complete": "완료",
    "completed": "완료",
    "failed": "실패",
    "skipped": "건너뜀",
    "disabled": "미사용",
    "running": "진행 중",
    "pending": "대기",
    "partial": "부분 완료",
    "interrupted": "중단",
    "queued": "대기",
}
SEVERITIES = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@lru_cache(maxsize=1)
def report_assets():
    fonts = PACKAGE_ROOT / "static" / "fonts"
    return {
        "font": base64.b64encode((fonts / "NanumMyeongjo-Regular.woff2").read_bytes()).decode(),
        "license": (fonts / "NanumMyeongjo-OFL.txt").read_text(),
        "css": (PACKAGE_ROOT / "static" / "report.css").read_text(),
        "js": (PACKAGE_ROOT / "static" / "report.js").read_text(),
    }


def short(value, limit=90):
    text = str(value or "").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def timestamp(value):
    try:
        return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M %z")
    except (ValueError, TypeError):
        return str(value or "기록 없음")


def review_data(ai):
    review = ai.get("analysis", {})
    if isinstance(review, str):
        try:
            review = json.loads(review)
        except ValueError:
            return {"summary": review, "findings": []}
    if not isinstance(review, dict):
        return {"summary": "", "findings": []}
    findings = review.get("findings", [])
    return {
        "summary": review.get("summary", ""),
        "findings": [f for f in findings if isinstance(f, dict)]
        if isinstance(findings, list)
        else [],
    }


def report_view(job, findings, comparison, ai, kind):
    ordered = sorted(
        findings,
        key=lambda f: (
            0 if f.get("state") == "confirmed" else 1,
            SEVERITIES.get(str(f.get("severity", "")).upper(), 5),
        ),
    )
    cards = []
    for index, finding in enumerate(ordered, 1):
        guide = guidance(finding)
        # Preserve captured findings; specialize the generic rule's presentation metadata.
        finding = {**finding, **{key: guide[key] for key in ("cwe", "reference") if key in guide}}
        severity = str(finding.get("severity", "UNKNOWN")).upper()
        confirmed = finding.get("state") == "confirmed"
        cards.append(
            {
                "ref": f"F-{index:02}",
                "finding": finding,
                "guide": guide,
                "state_label": STATES.get(finding.get("state"), "미확인"),
                "priority": ("P1" if severity in ("CRITICAL", "HIGH") else "P2")
                if confirmed
                else "검토",
                "observation": short(finding.get("detail"), 105),
                "action_short": short(guidance(finding)["action"], 80),
            }
        )
    confirmed = [c for c in cards if c["finding"].get("state") == "confirmed"]
    counts = Counter(f.get("state", "inconclusive") for f in findings)
    high = sum(
        str(c["finding"].get("severity", "")).upper() in ("CRITICAL", "HIGH") for c in confirmed
    )
    if job.get("error"):
        verdict = "진단이 불완전합니다. 실패 원인 확인과 재실행이 필요합니다."
    elif high:
        verdict = f"높은 심각도 {high}건 확인. 우선 수정과 재검증이 필요합니다."
    elif confirmed:
        verdict = f"취약점 {len(confirmed)}건 확인. 담당자 지정과 개선 계획이 필요합니다."
    else:
        verdict = "검증된 취약점이 없습니다. 이번 결과만으로 안전을 판단할 수 없습니다."
    tools = [
        {
            "tool": "SecureFlow DAST",
            "status": "failed"
            if job.get("error")
            else "complete"
            if findings or job.get("summary", {}).get("tested") == 0
            else "inconclusive",
            "count": len(confirmed),
            "note": "앱 전용 대조 요청 기반 검증. 수치는 검증된 발견 수입니다.",
        },
        *comparison,
    ]
    issues = sum(t.get("status") not in ("complete", "completed") for t in tools)
    ai_state = ai.get("status", "disabled")
    return {
        "cards": cards,
        "top": confirmed[:3],
        "confirmed": len(confirmed),
        "high": high,
        "unresolved": counts["inconclusive"],
        "not_reproduced": counts["not_reproduced"],
        "counts": counts,
        "verdict": verdict,
        "tools": tools,
        "tool_issues": issues,
        "states": STATES,
        "ai_label": STATES.get(ai_state, ai_state),
        "ai_review": review_data(ai) if kind != "quick" else {"summary": "", "findings": []},
        "created": timestamp(job.get("created_at")),
        "categories": len({c["finding"].get("owasp") for c in confirmed}),
    }
