# 운영과 문제 해결

## 경로와 시작

프로젝트 루트 또는 항상 동일한 작업 디렉터리에서 secureflow 명령을 실행하세요.
다른 디렉터리에서 같은 데이터를 사용하려면 SECUREFLOW_WORKSPACE를 절대 경로로 지정합니다.

| 변수 | 기본값 | 설명 |
|---|---|---|
| SECUREFLOW_WORKSPACE | cwd/.local | 소스·상태·아티팩트 루트 |
| SECUREFLOW_DATA | workspace/state | DB·키·개별 리포트 |
| SECUREFLOW_SOURCE_ROOTS | workspace/sources | 쉼표 구분 허용 소스 루트 |
| SECUREFLOW_ALLOWED_HOSTS | loopback·기존 실습IP·setup 기록 | 지정하면 해당 IP 목록만 사용 |
| SECUREFLOW_LAB_PREFIX | secureflow 또는 setup 기록 | 설치할 컨테이너·네트워크 이름 |
| SECUREFLOW_LAB_SUBNET | 10.203.93.0/24 | 새 네트워크 생성 시 |
| SECUREFLOW_JUICE_PORT | 3000 | 지원되는 Docker에서 loopback 게시 |
| SECUREFLOW_COOKIE_SECURE | 미설정 | HTTPS 환경에서만1 |

대상 URL은 명시적 숫자IP와 포트를 포함한 HTTP 기본 URL입니다.
Docker의 internal 네트워크 설정에 따라 포트 게시가 적용되지 않을 수 있습니다.
setup은 실제 설정을 확인해 접근할 URL을 출력합니다. Linux/WSL에서는 컨테이너의 사설IP를 사용할 수 있습니다.
브리지 IP에 접근할 수 없는 Docker Desktop 구성은 이 설치 경로의 검증 대상이 아닙니다.

## 자주 만나는 문제

- venv 생성 실패: 배포판의 python3-venv 설치. ensurepip 없는 환경에서는
  python3 -m venv --without-pip .venv 후 python3 -m pip --python .venv/bin/python install . 사용.
- Docker permission denied: 현재 계정의 Docker 접근을 설정한 뒤 docker info 확인.
- 주소 대역 충돌: 다른 SECUREFLOW_LAB_SUBNET과 SECUREFLOW_LAB_PREFIX로 setup 실행.
- 이미 존재하는 컨테이너: setup은 삭제/교체하지 않습니다. 이전 이미지일 수 있으므로 출력의 reused_container 확인.
- 모델 없음/한도 초과: 설정 모델 ID, CLI 로그인 상태, 계정 사용량 확인. 원본 CLI 오류 전체를 리포트에 복사하지 않습니다.
- 새 버전 설치: 같은 환경에서 pip install . 재실행. 실행 중 서버는 종료하고 다시 시작.
- 프로세스 중단: 재시작 시 진행 중 작업을 failed로 표시. 새 진단을 실행하세요.

## 계정·보관

관리자 최초 암호는 무작위이며 state/initial-admin.txt에 권한0600으로 생성됩니다.
비밀번호 변경 시 파일을 삭제합니다. target 비밀번호는 Fernet, 관리자 비밀번호는 scrypt로 저장합니다.
키와 DB를 모두 읽는 OS 사용자는 대상 암호를 복호화할 수 있습니다.
서버 종료 후 state 전체를 보호된 위치에 백업하세요. 키를 잃으면 계정 암호를 복원할 수 없습니다.

동시 작업2개, 대기 포함4개, 같은 대상 중복 실행 금지.
단일 프로세스가 해당 state를 소유하도록 잠금을 사용합니다.
상용 운영 수준의 RBAC·SSO·외부 KMS·분산 워커는 제공하지 않습니다.
실습 계정과 장바구니 데이터는 반복 진단 시 누적됩니다.

## Docker / 브라우저 QA

```bash
docker build -f deploy/Dockerfile -t secureflow:local .
docker run --rm --network none secureflow:local python -m unittest discover -s tests -v
docker build -f deploy/Dockerfile.qa -t secureflow-qa:local .
```

scripts/verify_dashboard.py --help에서 인자를 확인하세요.
실제 관리자 로그인·대상 등록·AI/스캐너 실행을 수행하는 인수 테스트입니다.
초기 암호 변경 후에는 별도 SECUREFLOW_DATA를 사용하는 테스트 서버를 준비하세요.
CLI 구독 분석은 대시보드가 실행되는 호스트의 로그인 계정을 사용합니다.
QA 브라우저 컨테이너에는 구독 인증정보를 마운트할 필요가 없습니다.
