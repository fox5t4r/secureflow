# 실무형 리포트

대시보드의 빠른·통합 HTML 리포트는 같은 문서 구조를 사용합니다.

1. **핵심 요약 1면**: 대상, 진단 시작 시각, 종합 판단, 검증 건수, 높은 심각도 건수, 우선 조치 최대 3건, 요청 사항과 해석 범위.
2. **전체 조치 목록**: 발견별 코드 위치, 수정 방향, 재검증 완료 조건, 제안 담당 영역. 담당자·목표일·수정 완료를 임의로 확정하지 않습니다.
3. **상세 근거와 수정 가이드**: 토글을 열어 관측 내용, 적용 예시, 재검증 기준, 요청·응답 목록과 원문을 확인합니다.
4. **분석 부록**: 실행 조건, 실패 원인, 도구 비교, 미검증 AI 의견과 원문 경고.

P1은 검증된 Critical/High, P2는 그 외 검증된 항목입니다. 미재현·미확인은 검토 대상으로 분리합니다.
이는 규칙 심각도에 따른 작업 순서이며 CVSS 점수나 SLA가 아닙니다.
Juice Shop의 수정 예시는 해당 항목에 맞는 TypeScript/Express 패턴이며 자동 적용·검증한 패치가 아닙니다.
범용 규칙을 공유하던 리다이렉트와 디렉터리 목록은 보고서에서 각각
[CWE-601](https://cwe.mitre.org/data/definitions/601.html),
[CWE-548](https://cwe.mitre.org/data/definitions/548.html)로 구체화합니다. 원본 증거 스냅샷은 보존합니다.

## 읽기와 출력

- 다운로드한 HTML은 오프라인에서 열 수 있습니다. 핵심 요약의 번호를 누르면 해당 상세 토글이 열립니다.
- ‘상세 모두 펼치기/접기’로 기술 내용을 조절할 수 있습니다.
- ‘인쇄 / PDF 저장’을 누르면 기술 상세 본문을 펼쳐 출력하고, 종료 후 이전 토글 상태로 복원합니다.
- PDF는 A4 기준으로 요약을 첫 면에, 조치 목록·상세·부록을 뒤에 배치합니다. 긴 조치 목록은 다음 면으로 이어집니다.
- 대용량 원본 HTTP 본문, 도구 원문, AI 단계 원문은 PDF에서 제외됩니다. 전체 근거는 동봉 HTML의 토글로 확인하세요.
- 바탕체 계열 **Nanum Myeongjo**를 WOFF2로 내장합니다. Microsoft 바탕 글꼴을 재배포하지 않습니다.
  원본은 [Google Fonts의 Nanum Myeongjo](https://github.com/google/fonts/tree/main/ofl/nanummyeongjo),
  라이선스는 [SIL OFL 1.1](../src/secureflow/static/fonts/NanumMyeongjo-OFL.txt)이며 HTML에도 포함됩니다.

## 저장된 리포트 형식 갱신

서버에서 진행 중인 작업이 없는 상태에서 실행하세요. 재스캔·AI 재실행 없이 문서 형식만 갱신합니다.

```bash
python scripts/refresh_reports.py .local/state/reports --backup .local/report-originals
```

원본은 백업하고 보고서 입력 스냅샷으로 다시 렌더링합니다. 구형 빠른 리포트는 기존 문서의
검사 건수·도구 목록·상태·AI 상태와 저장된 결과를 대조합니다. 대조에 실패하면 쓰기 전에 중단합니다.
빠른 리포트에 나중에 도착한 AI·비교 도구 결과를 추가하지 않습니다.

## 검증

`tests/test_reports.py`는 미검증 항목의 우선순위, 실패 판정, HTML 이스케이프,
빠른 스냅샷 보존과 유형별 개선 가이드를 검증합니다.
개발용 Playwright/Chromium이 설치되어 있다면 두 HTML을 담은 폴더로 브라우저 검증을 실행할 수 있습니다.

```bash
python scripts/verify_reports.py .local/report-preview
```

오프라인 글꼴, 링크로 상세 열기, 토글, 인쇄 전후 상태, 모바일 넘침을 확인하고 PDF와 화면 캡처를 저장합니다.
PDF 페이지 경계와 긴 문서의 줄바꿈은 생성한 파일을 함께 검토하세요. Chromium을 기준으로 검증했으며,
다른 브라우저의 인쇄 결과는 다를 수 있습니다. 원본 진단 데이터가 포함되므로 HTML/PDF는 공개 소스와 분리하세요.
