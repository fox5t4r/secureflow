"""Bounded job orchestration and immutable quick/final report snapshots."""

import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from .ai import analyze
from .comparators import semgrep_scan, zap_scan
from .integrated_report import build_report
from .juice import scan_juice
from .site_review import review_site, site_endpoint


class JobEngine:
    """Own job transitions; workers return values and never mutate shared job state."""

    def __init__(self, store):
        self.store = store
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="secureflow-job")
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(4)
        for job in store.jobs():
            if job["status"] in ("queued", "running"):
                job.update(
                    status="failed",
                    error="Server restarted; worker interrupted. Start a new scan.",
                    ai_status="interrupted",
                )
                store.save_job(job)

    def start(self, target, ai_enabled, compare_tools, ai_mode="standard"):
        mode = target.get("mode", "juice")
        if mode == "site":
            site_endpoint(target["url"])
            if compare_tools:
                raise ValueError("일반 사이트 점검에서는 ZAP 비교를 지원하지 않습니다.")
        if ai_mode not in ("standard", "deep", "ensemble"):
            raise ValueError("AI mode must be standard, deep, or ensemble")
        with self.lock:
            if any(
                job["target_id"] == target["id"] and job["status"] in ("queued", "running")
                for job in self.store.jobs()
            ):
                raise ValueError("A scan for this target is already active")
            if not self.slots.acquire(blocking=False):
                raise ValueError("Job queue full (maximum four jobs)")
            job = {
                "id": uuid.uuid4().hex,
                "target_id": target["id"],
                "target_name": target["name"],
                "target_url": target["url"],
                "target_mode": mode,
                "status": "queued",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "quick_ready": False,
                "final_ready": False,
                "ai_status": "pending" if ai_enabled else "disabled",
                "ai_mode": ai_mode,
                "summary": {},
                "error": None,
                "findings": [],
                "comparison": [],
                "ai": {"status": "pending" if ai_enabled else "disabled"},
                "timeline": [],
            }
            try:
                settings = self.store.settings()
                self.store.save_job(job)
                self.pool.submit(self.run, job, target, ai_enabled, compare_tools, settings)
            except Exception:
                self.slots.release()
                raise
            return self.store.job(job["id"])

    def _save(self, job, output, stage):
        job["timeline"].append({"stage": stage, "at": datetime.now(timezone.utc).isoformat()})
        self.store.save_job(job)
        destination = output / "results.json"
        temporary = destination.with_suffix(".tmp")
        temporary.write_text(json.dumps(job, ensure_ascii=False, indent=2))
        temporary.replace(destination)

    def _write_report(self, job, output, kind):
        ai = job["ai"] if kind == "final" else {"status": job["ai_status"]}
        (output / f"{kind}.html").write_text(
            build_report(job, job["findings"], job["comparison"], ai, kind)
        )
        job[f"{kind}_ready"] = True
        self._save(job, output, f"{kind}_report_ready")

    def _submit_workers(self, pool, job, target, output, ai_enabled, compare_tools, settings):
        credentials = None
        if target["credential"]:
            credentials = {
                "username": target["username"],
                "password": self.store.vault.decrypt(target["credential"].encode()).decode(),
            }
        if target.get("mode") == "site":
            futures = {pool.submit(review_site, target["url"]): "dast"}
        else:
            futures = {pool.submit(scan_juice, target["url"], credentials): "dast"}
        if target["source_path"]:
            futures[pool.submit(semgrep_scan, target["source_path"], output)] = "sast"
        else:
            job["comparison"].append(
                {
                    "tool": "Semgrep CE",
                    "status": "skipped",
                    "count": 0,
                    "note": "No source connected",
                }
            )
        if compare_tools:
            futures[pool.submit(zap_scan, target["url"], output)] = "zap"
        if ai_enabled:
            job["ai_status"] = "running"
            job["ai"] = {
                "status": "running",
                "provider": "ollama" if job["ai_mode"] == "ensemble" else settings["ai_provider"],
                "mode": job["ai_mode"],
                "model": (settings.get("ai_deep_model") if job["ai_mode"] == "deep" else "")
                or settings["ai_model"],
            }
            futures[pool.submit(analyze, settings, target["source_path"], job["ai_mode"])] = "ai"
        return futures

    @staticmethod
    def _accept_result(job, output, kind, result):
        if kind == "dast":
            job["findings"] = result["findings"]
            confirmed = [
                finding for finding in result["findings"] if finding["state"] == "confirmed"
            ]
            job["summary"] = {
                "confirmed": len(confirmed),
                "tested": len(result["findings"]),
                "request_count": result["request_count"],
                "categories": sorted({finding["owasp"] for finding in confirmed}),
            }
            job["target_version"] = result["version"]
            (output / "dast.json").write_text(json.dumps(result, ensure_ascii=False, indent=2))
        elif kind == "ai":
            job["ai"] = result
            job["ai_status"] = result["status"]
        else:
            job["comparison"].append(result)

    @staticmethod
    def _accept_error(job, kind, error):
        message = f"{kind}: {type(error).__name__}: {str(error)[:400]}"
        if kind == "ai":
            job["ai_status"] = "failed"
            job["ai"] = {
                "status": "failed",
                "error": message,
                "fallback": "standard_analysis_only",
                "note": "AI를 사용할 수 없어 일반 진단 결과를 제공합니다.",
            }
        elif kind == "dast":
            job["error"] = message
        else:
            job["comparison"].append(
                {"tool": kind, "status": "failed", "count": 0, "error": message, "alerts": []}
            )

    def run(self, job, target, ai_enabled, compare_tools, settings):
        output = self.store.directory / "reports" / job["id"]
        try:
            output.mkdir(parents=True, mode=0o700)
            job["status"] = "running"
            self._save(job, output, "parallel_analysis_started")
            with ThreadPoolExecutor(max_workers=4) as pool:
                futures = self._submit_workers(
                    pool, job, target, output, ai_enabled, compare_tools, settings
                )
                self._save(job, output, "workers_submitted")
                required = {"dast", "sast"} if target["source_path"] else {"dast"}
                finished = set()
                for future in as_completed(futures):
                    kind = futures[future]
                    finished.add(kind)
                    try:
                        self._accept_result(job, output, kind, future.result())
                    except Exception as error:
                        self._accept_error(job, kind, error)
                    self._save(job, output, kind + "_finished")
                    if required <= finished and not job["quick_ready"]:
                        self._write_report(job, output, "quick")
            job["status"] = "failed" if job["error"] else "complete"
            self._write_report(job, output, "final")
        except Exception as error:
            job.update(status="failed", error=f"{type(error).__name__}: {str(error)[:400]}")
            self.store.save_job(job)
        finally:
            self.slots.release()
