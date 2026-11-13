# SecureFlow

**Evidence-based web security assessment, from findings to remediation.**

로컬 취약 웹앱의 정적·동적 검사, 선택적 AI 코드 검토, 수정 가이드를 하나의 관리자 대시보드로 연결합니다.
Python 3.12+ · Linux / WSL2 · MIT

## Features

- 관리자 로그인, 대상·테스트 계정 관리, 진단 이력
- 실제 HTTP 대조 검증과 Semgrep CE / OWASP ZAP 결과 통합
- **두 리포트**: AI를 기다리지 않는 빠른 보고서, 모든 작업의 통합 보고서
- **선택적 AI**: 로그인된 Codex / Claude Code 또는 로컬 Ollama
- **심층 분석**: 소스 근거 검토 → 반론·오탐 검토 → 수정안·회귀 테스트 제안
- **로컬 앙상블**: 기본 경량 모델 2종의 독립 의견·동일 위치 지적을 비교
- OWASP Top 10:2025의 10개 범주를 다루는 40개 실습 사례와 정량 평가

현재 동적 어댑터는 **자체 실습 앱과 로컬 OWASP Juice Shop**을 지원합니다.
임의 사이트 전체를 자동 진단하거나 AI 가설을 실제 취약점으로 확정하지 않습니다.

## Quick start

요구 사항: **Python 3.12 이상, Git, 실행 중인 Docker Engine**.
지원·검증 환경은 Linux 또는 WSL2의 Linux Docker입니다. Docker Desktop의 네트워크 구성은 별도 확인이 필요합니다.
소스 압축을 풀거나 이 저장소를 clone한 디렉터리에서 실행하세요.

```bash
git clone https://github.com/fox5t4r/secureflow.git
cd secureflow
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
secureflow setup --ollama
secureflow serve
```

`setup`은 고정 버전 Juice Shop 소스와 이미지, Semgrep·ZAP 이미지를 준비합니다.
Node.js 설치나 기존 Juice Shop checkout은 필요하지 않습니다. 최초 다운로드에는 인터넷과 수 GB의 디스크 여유가 필요합니다.

1. **http://127.0.0.1:8765** 접속.
2. `.local/state/initial-admin.txt`에 생성된 ID·비밀번호로 로그인.
3. 설정에서 관리자 비밀번호 변경.
4. 대상 등록: `setup`이 출력한 URL과 소스 경로 사용. 같은 값은 `.local/lab.json`에 저장됩니다.
5. 로컬 테스트 계정을 입력하거나 비워 두어 자동 생성.
6. 진단 시작 → 빠른 리포트 다운로드 → 통합 리포트 다운로드.

기본 기능에 AI 계정은 필요하지 않습니다. 경량 모델 다운로드도 생략하려면 위에서 `secureflow setup`을 사용하세요.
AI를 끄거나 미설치·연결 실패·한도 초과·응답 오류가 발생해도 일반 진단과 두 리포트는 유지됩니다.
보고서는 독립 HTML이며 브라우저 인쇄로 PDF 저장할 수 있습니다.
실행 데이터·계정 DB·보고서·다운로드 소스는 `.local/`에 저장되고 Git에서 제외됩니다.

## AI connection

| 방식 | 먼저 할 일 | 모델 선택 |
|---|---|---|
| ChatGPT 구독 / Codex | 공식 Codex CLI 설치 후 `codex login` | 계정에서 지원되는 모델 ID, 빈 값은 CLI 기본값 |
| Claude 구독 / Claude Code | 공식 Claude Code 설치 후 `claude auth login` | 예: `opus`, 실제 계정 권한에 따름 |
| 로컬 Ollama | `secureflow setup --ollama` | 기본 `qwen2.5-coder:1.5b` + `qwen2.5:0.5b` |

대시보드 **AI·계정 설정**에서 연결 방식, 일반 모델, 심층 분석용 모델, 추론 강도를 저장합니다.
진단 시작 화면에서 AI를 켜고 `일반`, `심층`, `로컬 앙상블`을 선택하세요.
앙상블은 구독 연결과 별개로 로컬 두 모델을 순차 실행합니다. 하나만 성공하면 partial로 보존하고, 둘 다 실패하면 일반 진단만 제공합니다.
동일 위치를 두 모델이 지적해도 취약점 확정이나 정확도 보증으로 처리하지 않습니다.

구독 연결은 **이 PC의 공식 CLI 로그인**을 사용합니다. SecureFlow는 구독 비밀번호·OAuth 토큰을 수집하지 않습니다.
선택된 소스 발췌가 해당 제공자로 전송되며 계정의 모델 권한과 사용량 제한을 따릅니다.
웹 ChatGPT/Claude 세션을 가져오거나 웹의 Deep Research 제품을 호출하는 기능은 아닙니다.

심층 분석은 최대 3회 모델 호출이며 일반 분석보다 느리고 사용량이 많습니다.
모든 AI 발견은 **미검증 가설**로 표시합니다. AI 오류·한도 초과 시 기본 검사 결과는 유지됩니다.
[설치·연결·데이터 범위 상세](docs/ai.md)

## Reproducible lab

Docker나 AI 없이도 자체 앱의 SAST → HTTP 검증 → 평가 → 리포트를 실행할 수 있습니다.

```bash
secureflow demo
secureflow sast ./src/secureflow/lab/cases --output .local/static-review
```

40개 사례는 20개 결함 방식의 취약/개선 쌍입니다.
기존 합성 실험에서 FPR 35% → 0%를 관측했지만 이는 일반 웹앱 정확도가 아닙니다.
Juice Shop의 경고 수를 FPR이나 도구 순위로 바꾸지 않습니다.
[평가 방법](docs/evaluation.md) · [Juice Shop 비교](docs/benchmark-juice.md) · [검증 기록](docs/verification.md)

## Development

```bash
python -m pip install -e '.[dev]'
ruff check src tests scripts
ruff format --check src tests scripts
python -m unittest discover -s tests -v
python -m build
python scripts/release_check.py --archive .local/releases/secureflow-source.tar.gz
```

| 경로 | 역할 |
|---|---|
| `src/secureflow/` | 설치 가능한 애플리케이션 |
| `src/secureflow/ai/` | 소스 선별, 추론 연결, 다단계 검토 |
| `src/secureflow/web/` | 인증 및 대상 관리 |
| `src/secureflow/lab/` | 의도적으로 취약한 실습 앱과 정답 |
| `tests/` | 단위·통합·보안 경계 테스트 |
| `scripts/` | 브라우저 검증·공개 파일 검사 |
| `deploy/` | Docker / Compose |
| `docs/` | 운영·설계·평가·기여 안내 |

[구조와 설계](docs/architecture.md) · [화면 디자인](docs/design.md) · [리포트 구성·PDF 출력](docs/reports.md) · [운영·문제 해결](docs/operations.md) · [기여 안내](docs/contributing.md)

## Scope & license

개인 노트북의 **로컬 실습·파일럿**을 위한 도구입니다. 승인된 자체 환경만 검사하세요.
대시보드는 loopback에 바인딩되며 공개 SaaS, 조직별 권한, SSO, 범용 로그인 자동화는 지원하지 않습니다.

SecureFlow 코드는 [MIT](LICENSE). 핵심 진단은 오픈소스만으로 실행됩니다.
동봉된 Pretendard 글꼴은 [SIL Open Font License 1.1](src/secureflow/static/fonts/OFL.txt)을 따릅니다.
리포트의 바탕체 계열 Nanum Myeongjo는 [SIL OFL 1.1](src/secureflow/static/fonts/NanumMyeongjo-OFL.txt)로 배포합니다.
Codex·Claude Code 연결은 선택 기능이며 각 공급자의 라이선스·구독 조건이 적용됩니다.
