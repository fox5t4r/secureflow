# 대시보드 디자인

기존 화면 구조를 유지하면서 작업 상태, 발견 근거, 다음 행동을 빠르게 읽을 수 있도록 구성했습니다.
장식보다 글자 크기와 여백으로 위계를 만들고, 색은 행동과 상태에 사용합니다.

## 시각 규칙

- 배경은 밝은 무채색, 입력과 주요 내용은 흰색입니다. 파란색은 주요 버튼과 현재 메뉴에 사용합니다.
- 요약 숫자는 하나의 면 안에 배치하고 표와 목록은 얇은 구분선으로 정리합니다.
- 녹색은 작업 완료를 뜻합니다. 발견된 취약점은 붉은색, 미확인은 중립색으로 구분합니다. 미확인을 안전 판정으로 표현하지 않습니다.
- 간격은 4px 배수, 모서리는 8/14/20px, 숫자는 동일한 폭으로 정렬합니다.
- 아이콘은 동일한 선 두께의 SVG로 표현합니다. 별도의 아이콘 CDN이나 실행 시 외부 글꼴 요청은 없습니다.
- AI 결과는 요약, 코드 위치, 위험, 수정 제안, 확인 방법으로 나눕니다. 원문 결과도 펼쳐 볼 수 있습니다.

색상·간격·반경은 `src/secureflow/static/dashboard.css`의 공통 변수로 관리합니다.
960px 이하에서는 사이드바를 상단 메뉴로 전환하고, 720px 이하에서는 단일 열과 2×2 요약을 사용합니다.
키보드 포커스, 모션 감소 설정, 대화상자 Escape 닫기를 지원합니다.

## 글꼴 출처

[Pretendard](https://github.com/orioncactus/pretendard) 1.3.9의 Variable WOFF2를 동봉했습니다.
배포 파일은 `pretendard@1.3.9/dist/web/variable/woff2/PretendardVariable.woff2`이며,
원본 [SIL Open Font License 1.1](../src/secureflow/static/fonts/OFL.txt)을 함께 배포합니다.
패키지 설치 후에도 자체 서버의 `/static/fonts/`에서 제공됩니다.

## 브라우저 검증

서버와 완료된 진단 작업이 있는 로컬 실습 환경에서 실행합니다. 관리자 로그인 후 실제 데이터를 읽으며,
새 진단 제출이나 대상 수정은 하지 않습니다. 개발용 Playwright와 Chromium이 필요합니다.

```bash
python -m pip install -e '.[dev]'
python -m playwright install --with-deps chromium
python scripts/verify_design.py \
  --credentials .local/state/initial-admin.txt \
  --output .local/design-check
```

검증 범위는 로그인·로그아웃, 네 가지 메뉴, 대상·진단 대화상자, AI 옵션 선택,
빠른/통합 리포트 다운로드, 로컬 글꼴 로딩, JavaScript 오류, 320/390/1024/1440px 가로 넘침입니다.
결과 JSON과 화면 캡처는 지정한 출력 폴더에 저장됩니다. 캡처에는 실제 진단 데이터가 포함될 수 있으므로
공개 소스에는 넣지 않습니다. 이 검증이 정식 접근성 감사나 모든 브라우저 호환성 검증을 대체하지는 않습니다.
