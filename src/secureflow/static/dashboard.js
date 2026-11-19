"use strict";

const state = {
  csrf: "",
  targets: [],
  jobs: [],
  view: "overview",
  filter: "all",
  selectedJob: null,
  editingTarget: null,
  authenticated: false,
  refreshing: false,
  detailFingerprint: "",
};
const $ = (selector) => document.querySelector(selector);
const statusLabels = {
  queued: "대기 중",
  pending: "대기 중",
  running: "분석 중",
  scanning: "검사 중",
  ai_pending: "AI 분석 중",
  completed: "완료",
  complete: "완료",
  done: "완료",
  succeeded: "완료",
  failed: "실패",
  error: "오류",
  disabled: "사용 안 함",
  skipped: "건너뜀",
  not_requested: "사용 안 함",
  confirmed: "검증 완료",
  not_reproduced: "미재현",
  inconclusive: "미확인",
  unknown: "미확인",
  candidate: "검토 필요",
  partial: "부분 완료",
};
const categoryNames = [
  "접근 제어 실패",
  "보안 설정 오류",
  "소프트웨어 공급망 실패",
  "암호화 실패",
  "인젝션",
  "안전하지 않은 설계",
  "인증 실패",
  "소프트웨어·데이터 무결성 실패",
  "보안 로깅·알림 실패",
  "예외 상황 처리 실패",
];

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined && text !== null) element.textContent = String(text);
  return element;
}

// A single stroke vocabulary for navigation, actions, and data rows.
const iconPaths = {
  mark: [
    "M16 5H9a4 4 0 0 0 0 8h6a3 3 0 0 1 0 6H8",
    "m13 2 3 3-3 3",
    "m11 16-3 3 3 3",
  ],
  grid: ["M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z"],
  globe: [
    "M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0M3 12h18",
    "M12 3c5 5 5 13 0 18-5-5-5-13 0-18",
  ],
  activity: ["M4 5h16M4 12h4l2-4 4 8 2-4h4M4 19h16"],
  settings: ["M4 7h16M4 17h16", "M8 4v6M16 14v6"],
  lock: ["M7 10V7a5 5 0 0 1 10 0v3", "M5 10h14v11H5zM12 14v3"],
  logout: ["M9 4H4v16h5M10 12h11m-4-4 4 4-4 4"],
  plus: ["M12 5v14M5 12h14"],
  close: ["m6 6 12 12M18 6 6 18"],
  chevron: ["m9 5 7 7-7 7"],
  document: ["M14 3H5v18h14V8zM14 3v5h5M8 12h8M8 16h5"],
};
function icon(name) {
  const namespace = "http://www.w3.org/2000/svg";
  const element = document.createElementNS(namespace, "svg");
  element.setAttribute("viewBox", "0 0 24 24");
  element.setAttribute("class", "ui-icon");
  element.setAttribute("aria-hidden", "true");
  for (const shape of iconPaths[name] || iconPaths.document) {
    const path = document.createElementNS(namespace, "path");
    path.setAttribute("d", shape);
    element.append(path);
  }
  return element;
}

function clear(element) {
  element.replaceChildren();
}
function normalizedStatus(value) {
  const status = String(value || "unknown").toLowerCase();
  if (["completed", "done", "succeeded", "success"].includes(status))
    return "complete";
  if (["scanning", "ai_pending", "analyzing"].includes(status))
    return "running";
  return status;
}
function badge(value) {
  const raw = String(value || "unknown").toLowerCase();
  const clean = normalizedStatus(raw);
  const label = statusLabels[raw] || statusLabels[clean] || raw;
  const element = node("span", "status", label);
  if (/^[a-z_]+$/.test(clean)) element.classList.add(clean);
  return element;
}
function isRunning(job) {
  return ["running", "pending", "queued"].includes(
    normalizedStatus(job.status),
  );
}
function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString("ko-KR", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}
function pretty(value) {
  if (typeof value === "string") return value;
  return JSON.stringify(
    value,
    (key, entry) =>
      /^(password|token|access_token|refresh_token|authorization|cookie|secret|api_key)$/i.test(
        key,
      )
        ? "[보호됨]"
        : entry,
    2,
  );
}
function toast(message, error = false) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.toggle("error", error);
  element.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => {
    element.hidden = true;
  }, 5000);
}
async function api(path, options = {}) {
  const method = options.method || "GET";
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && method !== "HEAD")
    headers["X-CSRF-Token"] = state.csrf;
  const response = await fetch(path, {
    ...options,
    method,
    headers,
    credentials: "same-origin",
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const data = await response.json().catch(() => ({}));
  if (data.csrf) state.csrf = data.csrf;
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/login") showLogin();
    throw new Error(
      data.error || `요청을 처리하지 못했습니다 (${response.status}).`,
    );
  }
  return data;
}
function showLogin() {
  state.authenticated = false;
  state.selectedJob = null;
  $("#app-view").hidden = true;
  $("#login-view").hidden = false;
  document.querySelectorAll("dialog[open]").forEach((dialog) => dialog.close());
}
async function signedIn(session) {
  state.authenticated = true;
  state.csrf = session.csrf || state.csrf;
  $("#admin-name").textContent = session.username || "관리자";
  $("#login-view").hidden = true;
  $("#app-view").hidden = false;
  await refreshData();
  goTo("overview");
}
function goTo(view) {
  const allowed = ["overview", "targets", "jobs", "settings", "detail"];
  if (!allowed.includes(view)) return;
  state.view = view;
  document.querySelectorAll(".view").forEach((element) => {
    element.hidden = element.id !== `view-${view}`;
  });
  document
    .querySelectorAll(".nav-item")
    .forEach((element) =>
      element.classList.toggle(
        "active",
        element.dataset.view === (view === "detail" ? "jobs" : view),
      ),
    );
  $("#breadcrumb-current").textContent = {
    overview: "대시보드",
    targets: "진단 대상",
    jobs: "진단 작업",
    settings: "AI·계정 설정",
    detail: "진단 결과",
  }[view];
  if (view === "settings") loadSettings();
  window.scrollTo({ top: 0, behavior: "instant" });
}
function emptyState(title, description) {
  const element = node("div", "empty-state");
  element.append(
    icon("document"),
    node("h3", "", title),
    node("p", "", description),
  );
  return element;
}
function findingTotal(job) {
  const summary = job.summary || {};
  if (typeof summary === "number") return summary;
  const value =
    summary.confirmed ??
    summary.confirmed_count ??
    summary.findings_count ??
    summary.findings ??
    0;
  return Array.isArray(value) ? value.length : Number(value) || 0;
}
function reportLink(job, type, className = "report-pill") {
  const ready = Boolean(type === "quick" ? job.quick_ready : job.final_ready);
  const anchor = node(
    "a",
    className,
    type === "quick" ? "빠른 리포트" : "통합 리포트",
  );
  if (ready) {
    anchor.href = `/api/jobs/${encodeURIComponent(job.id)}/report/${type}`;
    anchor.target = "_blank";
    anchor.rel = "noopener";
  } else {
    anchor.classList.add("disabled");
    anchor.setAttribute("aria-disabled", "true");
    anchor.title = "아직 리포트가 준비되지 않았습니다.";
  }
  return anchor;
}
function updateReportButton(element, job, type) {
  const ready = Boolean(type === "quick" ? job.quick_ready : job.final_ready);
  element.classList.toggle("disabled", !ready);
  element.setAttribute("aria-disabled", String(!ready));
  element.textContent = ready ? "리포트 다운로드 ↗" : "생성 대기 중";
  if (ready) {
    element.href = `/api/jobs/${encodeURIComponent(job.id)}/report/${type}`;
    element.target = "_blank";
    element.rel = "noopener";
  } else element.removeAttribute("href");
}
function renderOverview() {
  $("#metric-targets").textContent = state.targets.length;
  $("#metric-running").textContent = state.jobs.filter(isRunning).length;
  // Avoid double-counting repeat scans: use the newest available job per target.
  const latest = new Map();
  for (const job of state.jobs) {
    const key = job.target_id ?? job.target_name;
    if (!latest.has(key) && job.quick_ready) latest.set(key, job);
  }
  $("#metric-findings").textContent = [...latest.values()].reduce(
    (sum, job) => sum + findingTotal(job),
    0,
  );
  $("#metric-reports").textContent = state.jobs.filter(
    (job) => job.final_ready,
  ).length;
  const recent = $("#recent-jobs");
  clear(recent);
  if (!state.jobs.length)
    recent.append(
      emptyState(
        "첫 진단을 시작해 보세요",
        "등록한 대상의 검증 결과가 여기에 표시됩니다.",
        "≋",
      ),
    );
  for (const job of state.jobs.slice(0, 5)) {
    const row = node("button", "job-row");
    row.type = "button";
    const body = node("div", "job-row-body");
    body.append(
      node("strong", "job-name", job.target_name || "진단 대상"),
      node(
        "small",
        "job-subtitle",
        `작업 ${String(job.id).slice(0, 10)} · ${formatTime(job.created_at)}`,
      ),
    );
    const end = node("div", "job-row-end");
    end.append(
      badge(job.status),
      node(
        "small",
        "",
        job.quick_ready ? `검증된 발견 ${findingTotal(job)}개` : "근거 수집 중",
      ),
    );
    const logo = node("span", "job-logo");
    logo.append(icon("document"));
    row.append(logo, body, end);
    row.addEventListener("click", () => openJob(job.id));
    recent.append(row);
  }
  const targets = $("#overview-targets");
  clear(targets);
  if (!state.targets.length)
    targets.append(
      emptyState(
        "등록된 대상이 없습니다",
        "자체 구축한 애플리케이션을 등록하세요.",
      ),
    );
  for (const target of state.targets.slice(0, 3)) {
    const card = node("div", "mini-target");
    card.append(
      node("h3", "", target.name),
      node("p", "", target.url),
      node(
        "small",
        "",
        target.has_credentials ? "테스트 계정 연결됨" : "실습 계정 자동 생성",
      ),
    );
    targets.append(card);
  }
}
function renderTargets() {
  $("#nav-target-count").textContent = state.targets.length;
  const list = $("#target-list");
  clear(list);
  if (!state.targets.length)
    list.append(
      emptyState(
        "첫 진단 대상을 등록하세요",
        "애플리케이션 URL과 소스 경로를 연결할 수 있습니다.",
      ),
    );
  for (const target of state.targets) {
    const card = node("article", "target-card");
    const main = node("div", "target-card-main");
    const top = node("div", "target-card-top");
    const logo = node("span", "job-logo");
    logo.append(icon("globe"));
    top.append(logo, node("h2", "", target.name));
    const properties = node("dl");
    for (const [label, value] of [
      ["애플리케이션 URL", target.url],
      ["검사 방식", target.mode === "site" ? "응답 헤더" : "Juice Shop 전용"],
      ["소스코드", target.source_path || "미연결"],
      [
        "테스트 계정",
        target.mode === "site"
          ? "사용 안 함"
          : target.has_credentials
            ? `${target.username || "계정"} · 연결됨`
            : "미연결 · 실습 계정 자동 생성",
      ],
    ])
      properties.append(node("dt", "", label), node("dd", "", value));
    main.append(top, properties);
    const actions = node("div", "target-card-actions");
    const remove = node("button", "text-button danger-button", "대상 삭제");
    remove.type = "button";
    remove.addEventListener("click", async () => {
      if (!window.confirm(`“${target.name}” 대상을 삭제할까요?`)) return;
      remove.disabled = true;
      try {
        await api(`/api/targets/${encodeURIComponent(target.id)}`, {
          method: "DELETE",
        });
        await refreshData();
        toast("진단 대상을 삭제했습니다.");
      } catch (error) {
        toast(error.message, true);
        remove.disabled = false;
      }
    });
    const run = node("button", "text-button", "진단 시작 →");
    run.type = "button";
    run.addEventListener("click", () => openJobDialog(target.id));
    const edit = node("button", "text-button", "대상 수정");
    edit.type = "button";
    edit.addEventListener("click", () => openTargetDialog(target));
    actions.append(remove, edit, run);
    card.append(main, actions);
    list.append(card);
  }
}
function renderJobs() {
  $("#nav-job-count").textContent = state.jobs.length;
  const filtered = state.jobs.filter(
    (job) =>
      state.filter === "all" ||
      (state.filter === "running"
        ? isRunning(job)
        : state.filter === "failed"
          ? ["failed", "error"].includes(normalizedStatus(job.status))
          : normalizedStatus(job.status) === state.filter),
  );
  $("#jobs-total").textContent = `총 ${filtered.length}개 작업`;
  $("#jobs-empty").hidden = Boolean(filtered.length);
  const body = $("#jobs-table");
  clear(body);
  for (const job of filtered) {
    const row = node("tr");
    const name = node("td");
    name.append(
      node("strong", "cell-title", job.target_name || "진단 대상"),
      node("small", "cell-meta", `작업 ${String(job.id).slice(0, 12)}`),
    );
    const status = node("td");
    status.append(badge(job.status));
    const ai = node("td");
    ai.append(badge(job.ai_status || "disabled"));
    const date = node("td", "", formatTime(job.created_at));
    const reports = node("td");
    const pills = node("div", "report-pills");
    pills.append(reportLink(job, "quick"), reportLink(job, "final"));
    reports.append(pills);
    const action = node("td");
    const button = node("button", "text-button", "상세 →");
    button.type = "button";
    button.addEventListener("click", () => openJob(job.id));
    action.append(button);
    row.append(name, status, ai, date, reports, action);
    body.append(row);
  }
}
async function refreshData() {
  if (!state.authenticated || state.refreshing) return;
  state.refreshing = true;
  try {
    const [targets, jobs] = await Promise.all([
      api("/api/targets"),
      api("/api/jobs"),
    ]);
    if (!state.authenticated) return;
    state.targets = targets.targets || [];
    state.jobs = (jobs.jobs || [])
      .slice()
      .sort((a, b) =>
        String(b.created_at || "").localeCompare(String(a.created_at || "")),
      );
    renderTargets();
    renderJobs();
    renderOverview();
    $("#connection-state").textContent = "서버 연결됨";
    $("#updated-time").textContent =
      `${new Date().toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit" })} 동기화`;
    if (state.view === "detail" && state.selectedJob !== null)
      await loadDetail(state.selectedJob);
  } catch (error) {
    $("#connection-state").textContent = "연결 확인 필요";
    if (!refreshData.lastError || refreshData.lastError !== error.message)
      toast(error.message, true);
    refreshData.lastError = error.message;
  } finally {
    state.refreshing = false;
  }
}
function openTargetDialog(target = null) {
  state.editingTarget = target ? target.id : null;
  $("#target-form").reset();
  $("#target-form-error").hidden = true;
  $("#target-dialog-eyebrow").textContent = target
    ? "EDIT TARGET"
    : "NEW TARGET";
  $("#target-dialog-title").textContent = target
    ? "진단 대상 수정"
    : "진단 대상 등록";
  $("#target-submit-button").textContent = target
    ? "변경 내용 저장"
    : "대상 등록";
  $("#target-password-help").hidden = !target;
  $("#target-password").placeholder = target
    ? "변경할 때만 입력"
    : "서버에 보호하여 보관";
  $("#target-dialog .credential-fields").open = Boolean(
    target?.has_credentials,
  );
  if (target) {
    $("#target-mode").value = target.mode || "juice";
    $("#target-name").value = target.name || "";
    $("#target-url").value = target.url || "";
    $("#target-source").value = target.source_path || "";
    $("#target-username").value = target.username || "";
  }
  syncTargetMode();
  $("#target-dialog").showModal();
  $("#target-name").focus();
}
function openJobDialog(targetId) {
  if (!state.targets.length) {
    goTo("targets");
    openTargetDialog();
    toast("먼저 진단 대상을 등록하세요.");
    return;
  }
  $("#job-form").reset();
  const select = $("#job-target");
  clear(select);
  for (const target of state.targets) {
    const option = node("option", "", target.name);
    option.value = String(target.id);
    select.append(option);
  }
  if (targetId !== undefined) select.value = String(targetId);
  syncJobTarget();
  $("#job-form-error").hidden = true;
  $("#job-dialog").showModal();
}
function syncTargetMode() {
  const site = $("#target-mode").value === "site";
  $("#target-dialog .credential-fields").hidden = site;
  $("#target-username").disabled = site;
  $("#target-password").disabled = site;
}
function syncJobTarget() {
  const target = state.targets.find(
    (entry) => String(entry.id) === $("#job-target").value,
  );
  const site = target?.mode === "site";
  $("#job-compare").disabled = site;
  $("#job-site-help").hidden = !site;
}
async function openJob(id) {
  state.selectedJob = id;
  state.detailFingerprint = "";
  $("#detail-title").textContent = "진단 결과 불러오는 중";
  $("#detail-meta").textContent = "";
  for (const selector of [
    "#finding-list",
    "#comparison-content",
    "#ai-content",
    "#coverage-grid",
  ])
    clear($(selector));
  $("#detail-error").hidden = true;
  updateReportButton($("#quick-report"), {}, "quick");
  updateReportButton($("#final-report"), {}, "final");
  goTo("detail");
  try {
    await loadDetail(id);
  } catch (error) {
    toast(error.message, true);
  }
}
function findingCategory(finding) {
  const value =
    finding.owasp ||
    finding.category ||
    finding.metadata?.owasp ||
    finding.rule?.owasp ||
    "";
  return Array.isArray(value) ? value.join(", ") : String(value);
}
function renderFinding(finding, index, openKeys) {
  const element = node("details", "finding");
  element.dataset.key = String(finding.id ?? index);
  element.open = openKeys.has(element.dataset.key);
  const summary = node("summary");
  const severity = String(
    finding.severity || finding.risk || finding.metadata?.severity || "INFO",
  ).toUpperCase();
  const severityBadge = node("span", "severity", severity);
  if (/^[A-Z]+$/.test(severity)) severityBadge.classList.add(severity);
  const title = node("div", "finding-heading");
  title.append(
    node(
      "strong",
      "",
      finding.title || finding.name || finding.kind || `발견 ${index + 1}`,
    ),
    node(
      "small",
      "",
      [
        findingCategory(finding),
        finding.cwe,
        finding.source || finding.path || finding.url,
      ]
        .filter(Boolean)
        .join(" · "),
    ),
  );
  summary.append(
    severityBadge,
    title,
    badge(finding.state || finding.status || "candidate"),
  );
  const body = node("div", "finding-body");
  for (const [label, value] of [
    [
      "관측된 내용",
      finding.detail || finding.description || finding.impact || finding.reason,
    ],
    ["검증 증거", finding.evidence || finding.evidence_ids || finding.details],
    ["시큐어코딩 개선", finding.advice || finding.remediation || finding.guide],
    ["수정 코드 예시", finding.code || finding.fix_code],
  ]) {
    if (value === undefined || value === null || value === "") continue;
    body.append(
      node("h3", "", label),
      node(
        label === "검증 증거" ||
          label === "수정 코드 예시" ||
          typeof value !== "string"
          ? "pre"
          : "p",
        "",
        pretty(value),
      ),
    );
  }
  if (body.childElementCount === 0)
    body.append(node("p", "", "세부 근거는 생성된 리포트에서 확인하세요."));
  element.append(summary, body);
  return element;
}
function comparisonEntries(value) {
  if (Array.isArray(value))
    return value.map((entry, index) =>
      typeof entry === "object" && entry !== null
        ? entry
        : { name: `도구 ${index + 1}`, detail: entry },
    );
  if (!value || typeof value !== "object") return [];
  if (Array.isArray(value.tools)) return comparisonEntries(value.tools);
  if (Array.isArray(value.results)) return comparisonEntries(value.results);
  return Object.entries(value)
    .filter(
      ([key]) =>
        !["note", "limitation", "methodology", "conditions"].includes(key),
    )
    .map(([name, entry]) => ({
      name,
      ...(typeof entry === "object" && entry !== null
        ? entry
        : { detail: entry }),
    }));
}
function renderComparison(value) {
  const content = $("#comparison-content");
  clear(content);
  const entries = comparisonEntries(value);
  if (!entries.length) {
    content.append(
      emptyState(
        "비교 결과 대기 중",
        "도구 비교를 선택한 작업에서 결과를 확인할 수 있습니다.",
        "⇄",
      ),
    );
    return;
  }
  for (const tool of entries) {
    const item = node("div", "comparison-item");
    const heading = node("div", "comparison-item-header");
    heading.append(
      node("strong", "", tool.name || tool.tool || tool.engine || "분석 도구"),
    );
    if (tool.status) heading.append(badge(tool.status));
    item.append(heading);
    const count =
      tool.alert_count ??
      tool.finding_count ??
      tool.findings_count ??
      tool.count ??
      (Array.isArray(tool.findings) ? tool.findings.length : undefined);
    if (count !== undefined) {
      const line = node("div");
      line.append(
        node("span", "comparison-number", count),
        node("span", "comparison-label", "수집된 경고 / 발견"),
      );
      item.append(line);
    }
    for (const [label, data] of [
      ["버전", tool.version],
      [
        "소요 시간",
        tool.duration_seconds === undefined
          ? tool.elapsed_seconds
          : `${tool.duration_seconds}초`,
      ],
      ["조건", tool.mode || tool.conditions],
      ["설명", tool.note || tool.limitation || tool.detail],
      ["오류", tool.error],
    ])
      if (data !== undefined && data !== null)
        item.append(
          node(
            "p",
            "",
            `${label}: ${typeof data === "object" ? pretty(data) : data}`,
          ),
        );
    if (count === undefined && !tool.note && !tool.detail && !tool.error)
      item.append(node("pre", "", pretty(tool)));
    content.append(item);
  }
  if (value.note || value.limitation || value.methodology)
    content.append(
      node(
        "p",
        "subtle-note",
        pretty(value.note || value.limitation || value.methodology),
      ),
    );
}
function renderAI(ai, status) {
  const content = $("#ai-content");
  clear(content);
  clear($("#ai-status"));
  $("#ai-status").append(badge(status));
  const current = normalizedStatus(status);
  if (["running", "pending", "queued"].includes(current)) {
    const waiting = node("div", "ai-wait");
    waiting.append(
      node("span", "spinner"),
      node(
        "span",
        "",
        "AI가 코드를 검토하고 있습니다. 빠른 리포트는 별도로 준비됩니다.",
      ),
    );
    content.append(waiting);
  }
  const text =
    typeof ai === "string"
      ? ai
      : ai?.analysis || ai?.text || ai?.response || ai?.summary || ai?.content;
  let review = text;
  if (typeof text === "string") {
    try {
      review = JSON.parse(text);
    } catch {
      /* Older reports can contain plain text. */
    }
  }
  if (
    review &&
    typeof review.summary === "string" &&
    Array.isArray(review.findings)
  ) {
    content.append(node("p", "ai-description", review.summary));
    for (const finding of review.findings) {
      if (!finding || typeof finding !== "object") continue;
      const article = node("article", "ai-finding");
      article.append(
        node("small", "", `${finding.path || ""}:${finding.line || ""}`),
        node("p", "", finding.risk),
      );
      const detail = node("details");
      detail.append(
        node("summary", "", "수정 제안과 확인 방법"),
        node("h3", "", "수정 제안"),
        node("pre", "", finding.fix),
        node("h3", "", "확인 방법"),
        node("p", "", finding.test_plan),
      );
      article.append(detail);
      content.append(article);
    }
  } else if (text) {
    content.append(
      node(
        "div",
        "ai-description",
        typeof text === "string" ? text : pretty(text),
      ),
    );
  }
  if (ai?.recommendations)
    content.append(node("pre", "", pretty(ai.recommendations)));
  if (ai?.error) content.append(node("p", "form-error", ai.error));
  if (ai?.fallback)
    content.append(
      node(
        "p",
        "subtle-note",
        "AI를 사용할 수 없어 일반 코드·동적 진단 결과를 제공합니다.",
      ),
    );
  if (ai?.mode)
    content.append(
      node("p", "subtle-note", `분석: ${ai.provider || ""} · ${ai.mode}`),
    );
  if (ai?.phases)
    for (const phase of ai.phases) {
      const details = node("details");
      details.append(
        node("summary", "", `${phase.phase} · ${phase.status}`),
        node("pre", "", pretty(phase.review || phase.error)),
      );
      content.append(details);
    }
  if (ai?.model)
    content.append(node("p", "subtle-note", `사용 모델: ${ai.model}`));
  if (!content.childElementCount)
    content.append(
      node(
        "p",
        "ai-description",
        ["disabled", "skipped", "not_requested"].includes(current)
          ? "이 작업은 AI 분석 없이 실행됩니다. 기본 진단 결과와 개선 가이드를 확인할 수 있습니다."
          : "AI 분석 결과가 아직 없습니다.",
      ),
    );
}
async function loadDetail(id) {
  const data = await api(`/api/jobs/${encodeURIComponent(id)}`);
  if (state.selectedJob !== id || state.view !== "detail") return;
  const fingerprint = JSON.stringify(data);
  if (fingerprint === state.detailFingerprint) return;
  state.detailFingerprint = fingerprint;
  const job = data.job || data;
  const findings = data.findings || [];
  $("#detail-title").textContent = job.target_name || "진단 결과";
  $("#detail-meta").textContent =
    `작업 ${job.id || id} · ${formatTime(job.created_at)} 시작`;
  clear($("#detail-status"));
  $("#detail-status").append(badge(job.status));
  $("#detail-error").hidden = !job.error;
  $("#detail-error").textContent = job.error || "";
  updateReportButton($("#quick-report"), job, "quick");
  updateReportButton($("#final-report"), job, "final");
  const covered = new Set();
  for (const finding of findings) {
    if (normalizedStatus(finding.state || finding.status) !== "confirmed")
      continue;
    for (const match of findingCategory(finding).matchAll(
      /A(0[1-9]|10)(?=:|\b)/g,
    ))
      covered.add(Number(match[1]));
  }
  const grid = $("#coverage-grid");
  clear(grid);
  categoryNames.forEach((name, index) => {
    const cell = node(
      "div",
      `coverage-cell${covered.has(index + 1) ? " covered" : ""}`,
    );
    cell.append(
      node(
        "strong",
        "",
        `A${String(index + 1).padStart(2, "0")} ${covered.has(index + 1) ? "· 발견" : "· 미확인"}`,
      ),
      node("span", "", name),
    );
    grid.append(cell);
  });
  $("#coverage-count").textContent = `${covered.size} / 10`;
  const openKeys = new Set(
    [...document.querySelectorAll(".finding[open]")].map(
      (element) => element.dataset.key,
    ),
  );
  const list = $("#finding-list");
  clear(list);
  $("#finding-count").textContent = `${findings.length}개`;
  if (!findings.length)
    list.append(
      emptyState(
        "발견 사항 대기 중",
        "기본 진단이 완료되면 근거와 개선 가이드가 표시됩니다.",
        "◇",
      ),
    );
  findings.forEach((finding, index) =>
    list.append(renderFinding(finding, index, openKeys)),
  );
  renderComparison(data.comparison);
  renderAI(data.ai, job.ai_status || data.ai?.status || "disabled");
}
async function loadSettings() {
  const controls = [
    ...$("#settings-form").querySelectorAll("input, select, button"),
  ];
  controls.forEach((control) => (control.disabled = true));
  try {
    const settings = await api("/api/settings");
    $("#ai-url").value = settings.ai_url || "http://127.0.0.1:11434";
    $("#ai-model").value = settings.ai_model || "";
    $("#ai-provider").value = settings.ai_provider || "ollama";
    $("#ai-deep-model").value = settings.ai_deep_model || "";
    $("#ai-effort").value = settings.ai_effort || "high";
    $("#ai-local-model-a").value =
      settings.ai_local_model_a || "qwen2.5-coder:1.5b";
    $("#ai-local-model-b").value = settings.ai_local_model_b || "qwen2.5:0.5b";
  } catch (error) {
    toast(error.message, true);
  } finally {
    controls.forEach((control) => (control.disabled = false));
  }
}
async function submitForm(form, errorElement, action) {
  const button = form.querySelector('[type="submit"]');
  button.disabled = true;
  if (errorElement) errorElement.hidden = true;
  try {
    await action();
  } catch (error) {
    if (errorElement) {
      errorElement.textContent = error.message;
      errorElement.hidden = false;
    } else toast(error.message, true);
  } finally {
    button.disabled = false;
  }
}

document.addEventListener("click", (event) => {
  const link = event.target.closest("[data-view]");
  if (link && state.authenticated) goTo(link.dataset.view);
  const close = event.target.closest("[data-close]");
  if (close) document.getElementById(close.dataset.close).close();
});
$("#login-form").addEventListener("submit", (event) => {
  event.preventDefault();
  submitForm(event.currentTarget, $("#login-error"), async () => {
    const result = await api("/api/login", {
      method: "POST",
      body: {
        username: $("#login-username").value,
        password: $("#login-password").value,
      },
    });
    $("#login-password").value = "";
    await signedIn(result);
  });
});
async function logout() {
  try {
    await api("/api/logout", { method: "POST" });
    showLogin();
    const session = await api("/api/session");
    state.csrf = session.csrf || "";
  } catch (error) {
    toast(error.message, true);
  }
}
$("#logout-button").addEventListener("click", logout);
$("#mobile-logout-button").addEventListener("click", logout);
$("#add-target-button").addEventListener("click", () => openTargetDialog());
$("#overview-new-job").addEventListener("click", () => openJobDialog());
$("#jobs-new-job").addEventListener("click", () => openJobDialog());
$("#detail-back").addEventListener("click", () => goTo("jobs"));
$("#target-mode").addEventListener("change", syncTargetMode);
$("#job-target").addEventListener("change", syncJobTarget);
$("#target-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  submitForm(form, $("#target-form-error"), async () => {
    const editing = state.editingTarget !== null;
    const path = editing
      ? `/api/targets/${encodeURIComponent(state.editingTarget)}`
      : "/api/targets";
    await api(path, {
      method: editing ? "PUT" : "POST",
      body: Object.fromEntries(new FormData(form)),
    });
    form.reset();
    state.editingTarget = null;
    $("#target-dialog").close();
    await refreshData();
    toast(editing ? "진단 대상을 수정했습니다." : "진단 대상을 등록했습니다.");
  });
});
$("#job-form").addEventListener("submit", (event) => {
  event.preventDefault();
  submitForm(event.currentTarget, $("#job-form-error"), async () => {
    const result = await api("/api/jobs", {
      method: "POST",
      body: {
        target_id: $("#job-target").value,
        ai_enabled: $("#job-ai").checked,
        compare_tools: !$("#job-compare").disabled && $("#job-compare").checked,
        ai_mode: $("#job-ai-mode").value,
      },
    });
    $("#job-dialog").close();
    await refreshData();
    toast("진단 작업을 시작했습니다.");
    const id = result.id || result.job?.id || result.job_id;
    if (id !== undefined) await openJob(id);
    else goTo("jobs");
  });
});
$("#settings-form").addEventListener("submit", (event) => {
  event.preventDefault();
  submitForm(event.currentTarget, null, async () => {
    await api("/api/settings", {
      method: "PUT",
      body: {
        ai_url: $("#ai-url").value,
        ai_model: $("#ai-model").value,
        ai_provider: $("#ai-provider").value,
        ai_deep_model: $("#ai-deep-model").value,
        ai_effort: $("#ai-effort").value,
        ai_local_model_a: $("#ai-local-model-a").value,
        ai_local_model_b: $("#ai-local-model-b").value,
      },
    });
    toast("AI 연결 설정을 저장했습니다.");
  });
});
$("#admin-password-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  submitForm(form, $("#admin-password-error"), async () => {
    const password = $("#admin-new-password").value;
    if (password.length < 12)
      throw new Error("새 비밀번호는 12자 이상이어야 합니다.");
    if (password !== $("#admin-confirm-password").value)
      throw new Error("새 비밀번호와 확인 입력이 일치하지 않습니다.");
    await api("/api/admin/password", {
      method: "POST",
      body: {
        current_password: $("#admin-current-password").value,
        new_password: password,
      },
    });
    form.reset();
    toast("관리자 비밀번호를 변경했습니다. 현재 로그인은 유지됩니다.");
  });
});
$("#job-filters").addEventListener("click", (event) => {
  const button = event.target.closest("[data-status]");
  if (!button) return;
  state.filter = button.dataset.status;
  $("#job-filters")
    .querySelectorAll("button")
    .forEach((element) =>
      element.classList.toggle("active", element === button),
    );
  renderJobs();
});
async function initialize() {
  try {
    const session = await api("/api/session");
    state.csrf = session.csrf || "";
    if (session.authenticated) await signedIn(session);
    else showLogin();
  } catch (error) {
    showLogin();
    $("#login-error").textContent = error.message;
    $("#login-error").hidden = false;
  }
}
document.querySelectorAll("[data-icon]").forEach((element) => {
  element.replaceChildren(icon(element.dataset.icon));
});
initialize();
setInterval(() => {
  if (!document.hidden) refreshData();
}, 3000);

$("#ai-provider").addEventListener("change", () => {
  $("#ai-model").value =
    $("#ai-provider").value === "ollama" ? "qwen2.5-coder:1.5b" : "";
  $("#ai-deep-model").value = "";
  $("#ai-connection-status").textContent =
    "연결 설정을 저장한 후 설치·로그인을 확인하세요.";
});
$("#ai-check-connection").addEventListener("click", async () => {
  const button = $("#ai-check-connection");
  button.disabled = true;
  try {
    const connections = await api("/api/ai/connections");
    const provider = $("#ai-provider").value;
    const connection = connections[provider];
    $("#ai-connection-status").textContent =
      provider === "ollama"
        ? "Ollama 연결은 분석 실행 시 확인합니다."
        : !connection.installed
          ? `${provider} 실행 파일을 서버에서 찾을 수 없습니다. 설치 경로나 서버 설정을 확인하세요.`
          : connection.note
            ? `${provider} 로그인 상태를 읽지 못했습니다. CLI 실행 상태를 확인하세요.`
            : connection.authenticated
              ? connection.subscription
                ? `${provider} 구독 계정 로그인 확인됨`
                : `${provider} CLI 로그인 확인됨`
              : `${provider} CLI 터미널 로그인이 필요합니다.`;
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
  }
});
