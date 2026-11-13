"""Prepare lab report view data and per-finding Markdown evidence."""

import json

from .catalog import RULES
from .templating import render_template


def render(run, output):
    cards = []
    for finding in run["findings"]:
        cards.append(
            {
                "finding": finding,
                "rule": RULES[finding["kind"]],
                "signals": "\n".join(
                    f"{signal['test_id']} · line {signal['line_number']}: {signal['issue_text']}"
                    for signal in finding["sast"]
                )
                or "Bandit 경고 없음; 동적 검사에서 독립적으로 확인",
                "evidence": [
                    item for item in run["evidence"] if item["id"] in finding["evidence_ids"]
                ],
            }
        )
    confirmed = [finding for finding in run["findings"] if finding["state"] == "confirmed"]
    document = render_template(
        "lab_report.html",
        run=run,
        cards=cards,
        confirmed=len(confirmed),
        categories=len({RULES[finding["kind"]]["owasp"] for finding in confirmed}),
    )
    (output / "report.html").write_text(document, encoding="utf-8")
    reports = output / "findings"
    reports.mkdir()
    for finding in run["findings"]:
        if finding["state"] != "confirmed":
            continue
        rule = RULES[finding["kind"]]
        evidence = [e for e in run["evidence"] if e["id"] in finding["evidence_ids"]]
        (reports / (finding["id"] + ".md")).write_text(
            f"# {rule['title']}\n\n분류: {rule['owasp']} / {rule['old']} / {rule['cwe']}\n\n"
            f"대상: `{finding['source']}` · 자체 실습 앱만 해당.\n\n"
            f"전제: 실행기가 발급한 실습 토큰. 객체 접근 실험의 사용자 역할은 alice.\n\n"
            f"입증된 영향: {rule['impact']}\n\n기대 동작: 정상 요청은 허용하고 경계 위반 입력은 거부.\n\n"
            f"재현: `python -m secureflow demo` 실행 후 아래 순서의 요청·응답 확인.\n\n"
            f"```json\n{json.dumps(evidence, ensure_ascii=False, indent=2)}\n```\n\n"
            f"수정: {rule['advice']}\n\n```python\n{rule['code']}\n```\n\n"
            f"참고: {rule['reference']}\n\n한계: 이 실습 상태에서의 검증이며 다른 서비스에 대한 증거가 아닙니다.\n",
            encoding="utf-8",
        )
