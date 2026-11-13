"""Application-specific remediation examples; suggestions, never applied patches."""

JUICE_GUIDES = {
    "juice-search-sqli": {
        "action": "검색 SQL의 문자열 결합을 제거하고 검색값을 바인딩합니다.",
        "owner": "백엔드",
        "acceptance": "정상 검색은 유지되고, 두 SQL 조건 우회 입력은 결과를 확장하지 않아야 합니다.",
        "code": """// Sequelize 예시: 식별자는 고정하고 값만 바인딩
const products = await sequelize.query(
  'SELECT * FROM Products WHERE name LIKE :term AND deletedAt IS NULL',
  { replacements: { term: `%${String(req.query.q ?? '')}%` },
    type: QueryTypes.SELECT }
)
res.json({ status: 'success', data: products })""",
    },
    "juice-basket-idor": {
        "action": "장바구니 조회 시 로그인 사용자와 객체 소유자를 서버에서 대조합니다.",
        "owner": "백엔드",
        "acceptance": "자기 장바구니 조회는 성공하고, 다른 실습 계정의 장바구니 조회는 403 또는 404여야 합니다.",
        "code": """// 인증 미들웨어가 설정한 사용자 ID만 신뢰
const basket = await Basket.findOne({
  where: { id: req.params.id, UserId: req.user.id }
})
if (!basket) return res.sendStatus(404)
res.json(basket)""",
    },
    "juice-redirect": {
        "cwe": "CWE-601",
        "reference": "https://cwe.mitre.org/data/definitions/601.html",
        "action": "이동 URL을 파싱하고 프로토콜·호스트를 허용 목록과 정확히 대조합니다.",
        "owner": "백엔드",
        "acceptance": "허용 URL만 이동하고, 허용 문자열을 경로·쿼리에 넣은 외부 URL은 400으로 거부해야 합니다.",
        "code": """// 실제 서비스에서 승인한 origin으로 교체
const allowed = new Set(['https://trusted.example'])
let destination: URL
try { destination = new URL(String(req.query.to)) }
catch { return res.sendStatus(400) }
if (destination.protocol !== 'https:' || destination.username ||
    destination.password || !allowed.has(destination.origin)) {
  return res.sendStatus(400)
}
res.redirect(destination.href)""",
    },
    "juice-quantity": {
        "action": "수량이 허용 범위의 정수인지 서버에서 검증하고 소유권 검사를 함께 적용합니다.",
        "owner": "백엔드",
        "acceptance": "정상 수량은 허용하고 음수·소수·문자열·상한 초과 값은 거부해야 합니다. 주문·결제 검증은 별도입니다.",
        "code": """const quantity = req.body.quantity
if (!Number.isInteger(quantity) || quantity < 1 || quantity > 100) {
  return res.status(400).json({ error: 'Invalid quantity' })
}
// item은 인증 사용자 소유의 장바구니로 제한해 조회한 객체
await item.update({ quantity })""",
    },
    "juice-metrics": {
        "action": "계측 경로를 공개 라우팅에서 제외하고 인증된 운영자에게만 허용합니다.",
        "owner": "백엔드·인프라",
        "acceptance": "비인증 /metrics 요청은 401/403/404, 승인된 운영자 요청은 정상 응답이어야 합니다.",
        "code": """// 인증과 역할 검증 미들웨어는 서버 세션을 기준으로 구현
app.get('/metrics', requireSession, requireRole('operator'),
  async (_req, res) => {
    res.type(register.contentType).send(await register.metrics())
  })
// 외부 프록시에서도 /metrics 경로를 차단""",
    },
    "juice-directory": {
        "cwe": "CWE-548",
        "reference": "https://cwe.mitre.org/data/definitions/548.html",
        "action": "공개 디렉터리 인덱스를 제거하고 배포 파일을 허용 목록으로 제한합니다.",
        "owner": "백엔드·인프라",
        "acceptance": "디렉터리 요청에 파일 목록이 나오지 않고, 승인된 정적 파일만 접근 가능해야 합니다.",
        "code": """// 디렉터리 목록 미들웨어(serveIndex 등)를 제거
app.use('/public', express.static(approvedPublicDirectory, {
  dotfiles: 'deny', index: false, fallthrough: false
}))
// 로그·백업·키는 approvedPublicDirectory 밖에 보관""",
    },
    "juice-error": {
        "action": "오류 응답은 일반화하고 상세 SQL·스택은 접근 통제된 서버 로그에 기록합니다.",
        "owner": "백엔드",
        "acceptance": "잘못된 입력에도 응답 본문에 SQL·스택·서버 경로가 없고 정상 검색은 유지되어야 합니다.",
        "code": """// 라우트 뒤에 등록하는 운영용 오류 미들웨어
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err)
  logger.error({ requestId: req.id, err }, 'Request failed')
  res.status(500).json({ error: 'Internal server error', requestId: req.id })
})""",
    },
}


def guidance(finding):
    return JUICE_GUIDES.get(
        finding.get("id"),
        {
            "action": finding.get("advice", "원인과 영향 범위를 검토한 뒤 수정 방안을 확정하세요."),
            "owner": "담당 개발팀",
            "acceptance": "동일 전제에서 기존 재현 요청은 차단되고 정상 대조 요청은 성공하는지 확인하세요.",
            "code": finding.get("code", ""),
        },
    )
