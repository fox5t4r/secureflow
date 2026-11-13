# 기여 안내

Python3.12+와 가상환경을 사용하고 pip install -e '.[dev]'로 개발 도구를 설치합니다.
Python 형식은 Ruff, HTML/CSS/JS 형식은 Prettier3.6.2입니다.

```bash
ruff check src tests scripts
ruff format --check src tests scripts
python -m unittest discover -s tests -v
npx --yes prettier@3.6.2 --check 'src/secureflow/static/*' 'src/secureflow/templates/*.html'
python -m build
python scripts/release_check.py
```

실습 사례의 바이트/줄번호는 측정에 쓰이므로 lab/cases는 일괄 포맷 대상에서 제외합니다.
규칙이나 판정을 변경하면 양성·음성 대조와 기존 진단의 회귀 테스트를 갱신하세요.
실제 제공자 테스트는 별도 선택 실행이며 CI에서는 로그인·유료 호출을 요구하지 않습니다.
외부 서비스 무단 스캔을 테스트에 추가하지 마세요.

공개 파일 검사와 소스 archive는 allowlist를 사용합니다.
.local, 가상환경, 토큰, DB, 개인 경로, 실제 계정정보는 공유하지 않습니다.
release_check는 일부 토큰 패턴만 탐지하므로 모든 형태의 비밀정보 검사를 보장하지 않습니다.

GitHub에 올리기 전: 테스트 → 빌드 → release_check → 변경 파일 수동 검토.
원격 생성·push·릴리스 업로드는 이 프로젝트의 설치 스크립트가 수행하지 않습니다.
