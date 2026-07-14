"""
SecureQA Sentinel — Flask REST API
Endpoints:
  POST /api/scan                — trigger a ZAP scan in the background (returns job_id)
  GET  /api/scan/<job_id>/status — poll progress/result of a background scan job
  GET  /api/scans                — list all past scans (summary)
  GET  /api/scan/<id>             — get one scan's full data
  GET  /api/scan/<id>/report      — get (or generate) the AI report for a scan
  GET  /api/scan/<id>/export/pdf  — export a scan's findings + AI report as a PDF
  GET  /api/scans/compare         — diff two scans' findings (new/resolved/persistent)
  GET  /api/audit/verify          — verify the SHA-256 hash chain
  GET  /api/health                — health check
"""

import sys
import threading
import traceback
import uuid
from datetime import datetime

import io
import json
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

# ── Import existing modules (do NOT modify scanner.py / database.py) ──────────
from scanner import run_scan, zap     # run_scan(target_url) → list[dict]; `zap` reused read-only for live progress
from database import save_scan, get_scan, get_all_scans, verify_chain, to_iso_utc, get_report
from llm_report import generate_report, generate_chat_answer, LLMBackendError
from pdf_export import build_report_pdf

# ── App setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__)

# Allow the React dev server on port 5173 (and optionally 5174 for Vite fallback)
CORS(app, resources={r"/api/*": {"origins": [
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    "http://localhost:8081",
    "http://127.0.0.1:8081",
]}})

# ── In-memory scan job tracker ────────────────────────────────────────────────
# Assumes single-scan-at-a-time usage (matches how this project is actually run —
# ZAP and a loaded LLM aren't meant to run concurrently on this hardware anyway).
_scan_jobs: dict[str, dict] = {}
_scan_jobs_lock = threading.Lock()


# ── Helper ────────────────────────────────────────────────────────────────────
def _severity_counts(findings: list[dict]) -> dict:
    """Tally High / Medium / Low / Info from a findings list."""
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        risk = f.get("risk", "").lower()
        if risk in counts:
            counts[risk] += 1
        elif risk == "informational":
            counts["info"] += 1
    return counts


def _normalize_findings(findings: list[dict]) -> list[dict]:
    """
    Normalize ZAP's raw alert dicts to {name, severity, cwe}. Key names are
    matched with fallbacks since the exact keys depend on scanner.py's ZAP
    version/config (name/alert, risk/riskdesc, cweid/cwe). CWE numbers get a
    'CWE-' prefix; ZAP's -1 "no CWE assigned" convention renders as None
    rather than the literal string "CWE--1".

    Shared by /export/pdf and /scans/compare so both features agree on
    exactly what a "finding" looks like — one place to fix if ZAP's field
    naming changes.
    """
    return [
        {
            "name": f.get("name") or f.get("alert") or "Unnamed finding",
            "severity": f.get("risk") or f.get("riskdesc") or "Informational",
            "cwe": f"CWE-{f['cweid']}" if f.get("cweid") not in (None, "", "-1", -1)
                   else (f"CWE-{f['cwe']}" if f.get("cwe") not in (None, "") else None),
        }
        for f in findings
    ]


def _load_findings(scan) -> list[dict]:
    """findings_json is stored as a JSON string — parse it consistently."""
    raw = scan.findings_json
    return json.loads(raw) if isinstance(raw, str) else (raw or [])


def _friendly_scan_error(exc: Exception) -> str:
    """
    Translate common low-level exceptions into a plain-English message safe
    to show in the UI. The raw exception is always still logged to stderr
    via traceback.print_exc() by the caller — this only affects what the
    frontend displays.
    """
    text = str(exc)
    lowered = text.lower()

    if "proxyerror" in lowered or "remotedisconnected" in lowered or "connection" in lowered and "refused" in lowered:
        return "Could not reach ZAP — is the ZAP Docker container running? (Check with: docker start zap-scanner)"

    if "max retries exceeded" in lowered:
        return "Lost connection to ZAP mid-scan. The scan was interrupted — check that the ZAP container is still running."

    if "timed out" in lowered or "timeout" in lowered:
        return "The request to ZAP timed out. ZAP may be overloaded or unresponsive."

    if "connection refused" in lowered:
        return "Could not reach ZAP — is the ZAP Docker container running?"

    # Fallback: show the real message, but trimmed so it doesn't dump an
    # entire multi-line stack trace into the UI.
    first_line = text.strip().splitlines()[0] if text.strip() else "Unknown error"
    return first_line[:200]


def _run_scan_job(job_id: str, target_url: str) -> None:
    """Runs the actual scan + save in a background thread; updates _scan_jobs."""
    with _scan_jobs_lock:
        _scan_jobs[job_id]["status"] = "running"

    try:
        findings: list[dict] = run_scan(target_url)
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)  # full raw traceback still logged for debugging
        with _scan_jobs_lock:
            _scan_jobs[job_id]["status"] = "failed"
            _scan_jobs[job_id]["error"] = _friendly_scan_error(exc)
        return

    try:
        counts = _severity_counts(findings)
        scan_id = save_scan(
            target_url=target_url,
            findings=findings,
            total_findings=len(findings),
            high_count=counts["high"],
            medium_count=counts["medium"],
            low_count=counts["low"],
            info_count=counts["info"],
        )
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)  # full raw traceback still logged for debugging
        with _scan_jobs_lock:
            _scan_jobs[job_id]["status"] = "failed"
            _scan_jobs[job_id]["error"] = f"Scan completed but saving failed: {_friendly_scan_error(exc)}"
        return

    with _scan_jobs_lock:
        _scan_jobs[job_id].update({
            "status": "complete",
            "scan_id": scan_id,
            "total_findings": len(findings),
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "info": counts["info"],
        })


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
def start_scan():
    """
    Trigger a new ZAP scan against the supplied target URL.
    Runs in a background thread — returns immediately with a job_id to poll
    via GET /api/scan/<job_id>/status instead of blocking for the full scan.

    Request body (JSON):
      { "target_url": "http://host.docker.internal:3000" }

    Response (202):
      { "job_id": "a1b2c3...", "status": "pending" }

    Response (400) on bad input.
    """
    body = request.get_json(silent=True)

    # ── Validate input ────────────────────────────────────────────────────────
    if not body or not body.get("target_url"):
        return jsonify({"error": "Missing required field: target_url"}), 400

    target_url: str = body["target_url"].strip()

    if not target_url.startswith(("http://", "https://")):
        return jsonify({"error": "target_url must start with http:// or https://"}), 400

    # ── Create job + kick off background thread ──────────────────────────────
    job_id = str(uuid.uuid4())
    with _scan_jobs_lock:
        _scan_jobs[job_id] = {
            "status": "pending",
            "target_url": target_url,
            "scan_id": None,
            "error": None,
        }

    thread = threading.Thread(target=_run_scan_job, args=(job_id, target_url), daemon=True)
    thread.start()

    return jsonify({"job_id": job_id, "status": "pending"}), 202


@app.route("/api/scan/<job_id>/status", methods=["GET"])
def scan_status(job_id: str):
    """
    Poll the status of a background scan job.

    Response while pending/running (200):
      {
        "job_id": "...",
        "status": "pending" | "running",
        "phase": "spider" | "active_scan" | "unknown",   (only once running)
        "percent": 43                                     (only once running; may be null)
      }

    Response when complete (200):
      {
        "job_id": "...",
        "status": "complete",
        "scan_id": 7,
        "total_findings": 594,
        "high_count": 0, "medium_count": 249, "low_count": 217, "info_count": 128
      }

    Response on failure (200):
      { "job_id": "...", "status": "failed", "error": "..." }

    Response (404) if job_id is unknown (e.g. server restarted since the scan
    was started — job tracking is in-memory only, not persisted).
    """
    with _scan_jobs_lock:
        job = _scan_jobs.get(job_id)

    if job is None:
        return jsonify({"error": f"No scan job with id {job_id}"}), 404

    response = {"job_id": job_id, "status": job["status"]}

    if job["status"] == "failed":
        response["error"] = job["error"]

    elif job["status"] == "complete":
        response.update({
            "scan_id":        job["scan_id"],
            "total_findings": job.get("total_findings"),
            "high_count":     job.get("high"),
            "medium_count":   job.get("medium"),
            "low_count":      job.get("low"),
            "info_count":     job.get("info"),
        })

    elif job["status"] == "running":
        phase, percent = "spider", 0
        try:
            spider_scans = zap.spider.scans
            if spider_scans:
                spider_pct = int(spider_scans[-1].get("progress", 0))
                if spider_pct < 100:
                    phase, percent = "spider", spider_pct
                else:
                    ascan_scans = zap.ascan.scans
                    if ascan_scans:
                        phase = "active_scan"
                        percent = int(ascan_scans[-1].get("progress", 0))
                    else:
                        phase, percent = "active_scan", 0
        except Exception:
            # Transient read failure (ZAP mid-transition between phases, client
            # library quirk, etc.) — don't fail the whole poll over it.
            phase, percent = "unknown", None

        response["phase"] = phase
        response["percent"] = percent

    # "pending" status: no extra fields needed, thread hasn't started yet

    return jsonify(response), 200


@app.route("/api/scans", methods=["GET"])
def list_scans():
    """
    Return a summary list of all past scans.

    Response (200):
      [
        {
          "id": 1,
          "target_url": "http://...",
          "timestamp": "...",
          "total_findings": 594,
          "high_count": 0,
          "medium_count": 249,
          "low_count": 217,
          "info_count": 128
        },
        ...
      ]
    """
    try:
        scans = get_all_scans()          # returns list of Scan ORM objects (or dicts)
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Failed to retrieve scans", "detail": str(exc)}), 500

    result = []
    for s in scans:
        # Support both ORM model instances and plain dicts from database.py
        if isinstance(s, dict):
            result.append({
                "id":             s.get("id"),
                "target_url":     s.get("target_url"),
                "timestamp":      s.get("timestamp"),
                "total_findings": s.get("total_findings"),
                "high_count":     s.get("high_count"),
                "medium_count":   s.get("medium_count"),
                "low_count":      s.get("low_count"),
                "info_count":     s.get("info_count"),
            })
        else:
            result.append({
                "id":             s.id,
                "target_url":     s.target_url,
                "timestamp":      to_iso_utc(s.timestamp),
                "total_findings": s.total_findings,
                "high_count":     s.high_count,
                "medium_count":   s.medium_count,
                "low_count":      s.low_count,
                "info_count":     s.info_count,
            })

    return jsonify(result), 200


@app.route("/api/scan/<int:scan_id>", methods=["GET"])
def get_scan_detail(scan_id: int):
    """
    Return the full data for a single scan, including all findings.

    Response (200):
      {
        "id": 1,
        "target_url": "http://...",
        "timestamp": "...",
        "total_findings": 594,
        "high_count": 0,
        "medium_count": 249,
        "low_count": 217,
        "info_count": 128,
        "findings": [ { ... }, ... ]
      }

    Response (404) if scan not found.
    """
    try:
        scan = get_scan(scan_id)
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Failed to retrieve scan", "detail": str(exc)}), 500

    if scan is None:
        return jsonify({"error": f"Scan {scan_id} not found"}), 404

    # Normalise ORM model vs dict
    if isinstance(scan, dict):
        findings_json = scan.get("findings_json", [])
        payload = {
            "id":             scan.get("id"),
            "target_url":     scan.get("target_url"),
            "timestamp":      scan.get("timestamp"),
            "total_findings": scan.get("total_findings"),
            "high_count":     scan.get("high_count"),
            "medium_count":   scan.get("medium_count"),
            "low_count":      scan.get("low_count"),
            "info_count":     scan.get("info_count"),
            "findings":       findings_json,
        }
    else:
        raw = scan.findings_json
        findings = json.loads(raw) if isinstance(raw, str) else raw
        payload = {
            "id":             scan.id,
            "target_url":     scan.target_url,
            "timestamp":      to_iso_utc(scan.timestamp),
            "total_findings": scan.total_findings,
            "high_count":     scan.high_count,
            "medium_count":   scan.medium_count,
            "low_count":      scan.low_count,
            "info_count":     scan.info_count,
            "findings":       findings,
            "record_hash":    scan.record_hash,
            "previous_hash":  scan.previous_hash,
        }

    return jsonify(payload), 200


@app.route("/api/scan/<int:scan_id>/report", methods=["GET"])
def get_scan_report(scan_id: int):
    """
    Return the AI-generated plain-English report for a scan. Generates it
    on first request and caches it in the DB; subsequent requests return
    the cached version instantly unless ?regenerate=true is passed.

    Response (200):
      {
        "scan_id": 1,
        "report_text": "...",
        "generated_at": "2026-07-02T10:15:00",
        "cached": true
      }

    Response (404) if scan not found.
    Response (503) if the selected LLM backend isn't reachable.
    """
    # Confirm the scan exists first so we give a clean 404 instead of a
    # confusing error bubbling up from inside generate_report()
    try:
        scan = get_scan(scan_id)
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Failed to retrieve scan", "detail": str(exc)}), 500

    if scan is None:
        return jsonify({"error": f"Scan {scan_id} not found"}), 404

    force_regenerate = request.args.get("regenerate", "false").lower() == "true"
    backend = request.args.get("backend")  # "ollama" or "groq"; None = use server default

    try:
        result = generate_report(scan_id, force_regenerate=force_regenerate, backend=backend)
    except LLMBackendError as exc:
        return jsonify({
            "error": "AI report service unavailable",
            "detail": str(exc),
        }), 503
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return jsonify({
            "error": "Report generation failed",
            "detail": str(exc),
        }), 500

    return jsonify(result), 200


@app.route("/api/scan/<int:scan_id>/export/pdf", methods=["GET"])
def export_scan_pdf(scan_id: int):
    """
    Generate a PDF report for a scan: severity summary, findings table, and
    the cached AI report if one has been generated for this scan. Not cached
    server-side — generation is cheap (unlike the LLM report itself), so it's
    rebuilt fresh on every request to always reflect the latest cached report.

    Response: application/pdf attachment.
    Response (404) if scan not found.
    """
    try:
        scan = get_scan(scan_id)
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Failed to retrieve scan", "detail": str(exc)}), 500

    if scan is None:
        return jsonify({"error": f"Scan {scan_id} not found"}), 404

    findings = _load_findings(scan)
    normalized_findings = _normalize_findings(findings)

    # Prefer Groq's cached report if present, else fall back to Ollama's.
    # Swap the order below if you'd rather default the other way.
    report_text, _ = get_report(scan_id, "groq")
    report_backend = "groq"
    if not report_text:
        report_text, _ = get_report(scan_id, "ollama")
        report_backend = "ollama" if report_text else None

    # Check THIS scan's position in the hash chain, reusing verify_chain()
    # rather than re-deriving hash logic inside the PDF module.
    audit_verified = None
    if scan.record_hash:
        chain_result = verify_chain()
        scan_has_issue = any(issue["scan_id"] == scan_id for issue in chain_result["issues"])
        audit_verified = not scan_has_issue

    pdf_bytes = build_report_pdf(
        scan={
            "id": scan.id,
            "target": scan.target_url,
            "created_at": to_iso_utc(scan.timestamp),
            "audit_hash": scan.record_hash,
        },
        findings=normalized_findings,
        audit_verified=audit_verified,
        report_text=report_text,
        report_backend=report_backend,
    )

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"secureqa-scan-{scan_id}-report.pdf",
    )


@app.route("/api/scans/compare", methods=["GET"])
def compare_scans():
    """
    Diff two scans' findings and bucket them into new / resolved / persistent.

    Findings are matched by (name, CWE) — NOT by URL. ZAP's spider doesn't
    crawl a stateful app like Juice Shop identically every run (different
    product IDs, basket/session state, etc.), so the same vulnerability
    TYPE can legitimately show up on different pages between two scans.
    Matching by URL would wrongly report that as "resolved on page X" +
    "new on page Y" when nothing was actually fixed.

    Each scan's findings are also collapsed to one entry per (name, CWE)
    pair — instance_count tracks how many pages/instances that type was
    found on, so "found on 40 pages" doesn't produce 40 duplicate rows.

    Query params:
      a = scan ID (before)
      b = scan ID (after)

    Response (200):
      {
        "scan_a": { "id", "target_url", "timestamp", "total_findings" },
        "scan_b": { "id", "target_url", "timestamp", "total_findings" },
        "new":        [ { "name", "cwe", "severity", "instance_count" } ],
        "resolved":   [ { "name", "cwe", "severity", "instance_count" } ],
        "persistent": [ { "name", "cwe", "severity_a", "severity_b",
                           "severity_changed", "instance_count_a", "instance_count_b" } ],
        "summary": { "new_count", "resolved_count", "persistent_count" }
      }

    Response (400) if params are missing or a == b.
    Response (404) if either scan doesn't exist.
    """
    a_id = request.args.get("a", type=int)
    b_id = request.args.get("b", type=int)

    if not a_id or not b_id:
        return jsonify({"error": "Both query params 'a' and 'b' (scan IDs) are required"}), 400

    if a_id == b_id:
        return jsonify({"error": "Cannot compare a scan to itself"}), 400

    try:
        scan_a = get_scan(a_id)
        scan_b = get_scan(b_id)
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Failed to retrieve scans", "detail": str(exc)}), 500

    if scan_a is None:
        return jsonify({"error": f"Scan {a_id} not found"}), 404
    if scan_b is None:
        return jsonify({"error": f"Scan {b_id} not found"}), 404

    norm_a = _normalize_findings(_load_findings(scan_a))
    norm_b = _normalize_findings(_load_findings(scan_b))

    def _collapse(norm_findings: list[dict]) -> dict:
        """Collapse to unique (name, cwe) -> {severity, count}."""
        collapsed: dict = {}
        for f in norm_findings:
            key = (f["name"], f["cwe"])
            if key not in collapsed:
                collapsed[key] = {"severity": f["severity"], "count": 0}
            collapsed[key]["count"] += 1
        return collapsed

    coll_a = _collapse(norm_a)
    coll_b = _collapse(norm_b)

    keys_a = set(coll_a.keys())
    keys_b = set(coll_b.keys())

    new_keys = keys_b - keys_a
    resolved_keys = keys_a - keys_b
    persistent_keys = keys_a & keys_b

    # Sort key handles None CWEs (ZAP's "-1 / no CWE" case) without crashing
    # on None-vs-str comparison.
    def _sort_key(k):
        return (k[0], k[1] or "")

    new = [
        {
            "name": k[0],
            "cwe": k[1],
            "severity": coll_b[k]["severity"],
            "instance_count": coll_b[k]["count"],
        }
        for k in sorted(new_keys, key=_sort_key)
    ]

    resolved = [
        {
            "name": k[0],
            "cwe": k[1],
            "severity": coll_a[k]["severity"],
            "instance_count": coll_a[k]["count"],
        }
        for k in sorted(resolved_keys, key=_sort_key)
    ]

    persistent = [
        {
            "name": k[0],
            "cwe": k[1],
            "severity_a": coll_a[k]["severity"],
            "severity_b": coll_b[k]["severity"],
            "severity_changed": coll_a[k]["severity"] != coll_b[k]["severity"],
            "instance_count_a": coll_a[k]["count"],
            "instance_count_b": coll_b[k]["count"],
        }
        for k in sorted(persistent_keys, key=_sort_key)
    ]

    response = {
        "scan_a": {
            "id": scan_a.id,
            "target_url": scan_a.target_url,
            "timestamp": to_iso_utc(scan_a.timestamp),
            "total_findings": scan_a.total_findings,
        },
        "scan_b": {
            "id": scan_b.id,
            "target_url": scan_b.target_url,
            "timestamp": to_iso_utc(scan_b.timestamp),
            "total_findings": scan_b.total_findings,
        },
        "new": new,
        "resolved": resolved,
        "persistent": persistent,
        "summary": {
            "new_count": len(new),
            "resolved_count": len(resolved),
            "persistent_count": len(persistent),
        },
    }

    return jsonify(response), 200


@app.route("/api/scan/<int:scan_id>/chat", methods=["POST"])
def scan_chat(scan_id: int):
    """
    Ask a follow-up question about a scan's findings. Not cached — every
    question is answered live against the selected LLM backend.

    Request body (JSON):
      {
        "question": "Which finding should I fix first?",
        "backend": "ollama",              (optional; defaults to server default)
        "history": [                       (optional; recent conversation turns)
          { "role": "user", "content": "..." },
          { "role": "assistant", "content": "..." }
        ]
      }

    Response (200):
      {
        "scan_id": 1,
        "question": "...",
        "answer": "...",
        "backend": "ollama",
        "generated_at": "2026-07-08T10:15:00Z"
      }

    Response (400) on missing/empty question.
    Response (404) if scan not found.
    Response (503) if the selected LLM backend isn't reachable.
    """
    body = request.get_json(silent=True)

    if not body or not body.get("question", "").strip():
        return jsonify({"error": "Missing required field: question"}), 400

    question = body["question"]
    backend = body.get("backend")   # "ollama" or "groq"; None = use server default
    history = body.get("history")   # optional list of prior {role, content} turns

    try:
        result = generate_chat_answer(scan_id, question, backend=backend, history=history)
    except ValueError as exc:
        # generate_chat_answer raises ValueError for "scan not found" and
        # "empty question" — the empty-question case is already caught above,
        # so in practice this branch is almost always the 404 case.
        return jsonify({"error": str(exc)}), 404
    except LLMBackendError as exc:
        return jsonify({
            "error": "AI chat service unavailable",
            "detail": str(exc),
        }), 503
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return jsonify({
            "error": "Chat answer generation failed",
            "detail": str(exc),
        }), 500

    return jsonify(result), 200


@app.route("/api/audit/verify", methods=["GET"])
def audit_verify():
    """
    Walk the SHA-256 hash chain across every scan and confirm nothing has
    been tampered with after the fact.

    Response (200):
      {
        "valid": true,
        "total_scans": 3,
        "verified_count": 3,
        "legacy_count": 0,
        "issues": []
      }
    """
    try:
        result = verify_chain()
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return jsonify({"error": "Audit verification failed", "detail": str(exc)}), 500

    return jsonify(result), 200


# ── Health check (handy during dev) ──────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "SecureQA Sentinel API"}), 200


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # debug=True gives auto-reload; threaded=True lets status polling requests
    # be served concurrently instead of queueing behind the scan's own request
    # thread (which no longer blocks, but this keeps things safe regardless).
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)