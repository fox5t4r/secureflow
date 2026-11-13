# Juice Shop 비교 방법

## 실행 범위

자체 DAST는 정상/비정상 응답과 본인이 생성한 두 테스트 계정의 상태를 비교합니다.
7개 검증: 검색 SQL 조건 우회, 상세 오류, metrics, FTP 목록,
리다이렉트 허용 목록, 장바구니 소유권, 음수 수량.
결제·외부 리다이렉트 이동·타 사용자 데이터 추출은 수행하지 않습니다.

Semgrep CE는 포함된 MIT규칙8개로 소스를 read-only 검사합니다.
이는 기본/전체 Semgrep 규칙 성능이 아닙니다.
ZAP baseline은 비인증 spider최대1분, depth2, children8의 passive scan입니다.
[공식 baseline 설명](https://www.zaproxy.org/docs/docker/baseline-scan/)

소스/인증/탐지 범위와 측정 단위가 다르므로 경고 수로 도구 순위를 매기지 않습니다.
전체 정답표를 확보하지 않았으므로 Juice Shop FPR을 계산하지 않습니다.
AI 결과는 별도 미검증 가설이며 확정 건수에 더하지 않습니다.

## 고정 입력

setup은 release20.2.0의 소스 commit5658473cf8814459bf89000ce373b20ed0b4eb37과 다음 이미지를 사용합니다.

```text
bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b
semgrep/semgrep@sha256:cc1b68266f267878b39739373ea9985b9a78e5d64497dd875c8de100b22695ed
ghcr.io/zaproxy/zaproxy@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af
```

기존 이름의 컨테이너가 있으면 setup은 보존합니다. 이 경우 실제 이미지 ID와 reused_container를
.local/lab.json에서 확인하고 원본 release와 동일하다고 가정하지 마세요.

2026-11-13의 초기 개발 checkout(commit1618a611b173b4bf114028e6e02549950606e29d)에서는
SecureFlow6/7, Semgrep39후보, ZAP4경고유형을 관측했습니다.
이는 새 release 설치의 측정값과 분리해서 기록합니다.

## 재현

secureflow setup → serve → 출력한 URL/소스 등록 → 도구 비교 선택 → 진단 실행.
원본 도구JSON·로그·빠른/통합HTML은 .local/state/reports/작업ID에 보존됩니다.
계정·소스 경로 등 실행 데이터가 있으므로 원본을 그대로 공개 저장소에 올리지 않습니다.
