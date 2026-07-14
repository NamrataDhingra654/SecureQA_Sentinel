"""
SecureQA Sentinel — AI report generation

Supports two backends, selectable per-request:

  "ollama" (default) — fully local, no API key, no internet required.
      Requires: ollama pull llama3.2:3b   (or your model of choice)
                ollama serve running

  "groq" — cloud inference via Groq's OpenAI-compatible API. Much faster
      (seconds instead of minutes on constrained hardware), but findings
      leave the machine and it requires internet + a free API key.
      Requires: GROQ_API_KEY environment variable set.
      Get a free key at https://console.groq.com

The default backend is controlled by the LLM_BACKEND environment variable
("ollama" or "groq"), but callers (the frontend, via the API) can override
it per-request without restarting anything.
"""

import json
import os
from datetime import datetime

import requests

from database import get_scan, save_report, get_report, to_iso_utc

# ── Ollama (local) config ────────────────────────────────────────────────────
# Reads OLLAMA_URL from environment when set (docker-compose sets this to
# http://host.docker.internal:11434, since Ollama runs as a host process,
# not a compose service — the backend container needs the host bridge to
# reach it, same pattern as ZAP reaching Juice Shop). Falls back to the old
# localhost value for running the backend directly on the host.
OLLAMA_URL = os.environ.get('OLLAMA_URL', "http://localhost:11434")
OLLAMA_MODEL = "llama3.2:3b"
OLLAMA_TIMEOUT = 300  # seconds — CPU-only inference on modest hardware can be slow

# ── Groq (cloud) config ───────────────────────────────────────────────────────
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_TIMEOUT = 30  # seconds — Groq is fast; if it's not back in 30s something's wrong

DEFAULT_BACKEND = os.environ.get("LLM_BACKEND", "ollama").lower()


class LLMBackendError(Exception):
    """Raised when the selected LLM backend isn't reachable or fails."""
    pass


def _format_findings_block(findings, cap=20):
    """
    Shared findings formatter used by both the report prompt and the chat
    prompt. Sorts by risk, de-duplicates by (risk, name), caps at `cap`
    unique issues, and renders as a bullet list block.
    """
    risk_order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
    sorted_findings = sorted(
        findings,
        key=lambda f: risk_order.get(f.get("risk", "Informational"), 4)
    )

    seen = set()
    unique_findings = []
    for f in sorted_findings:
        key = (f.get("risk", "Informational"), f.get("name") or f.get("alert", "Unknown"))
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
        if len(unique_findings) >= cap:
            break

    block = ""
    for f in unique_findings:
        name = f.get("name") or f.get("alert", "Unnamed issue")
        risk = f.get("risk", "Informational")
        url = f.get("url") or f.get("uri", "N/A")
        solution = (f.get("solution") or "")[:200]
        block += f"\n- [{risk}] {name}\n  URL: {url}\n  Suggested fix: {solution}"

    return block


def _build_prompt(target_url, total_findings, high_count, medium_count,
                   low_count, info_count, findings):
    findings_block = _format_findings_block(findings, cap=20)

    prompt = f"""You are a security analyst writing a plain-English report for a non-technical stakeholder.

Target scanned: {target_url}
Total findings: {total_findings} (High: {high_count}, Medium: {medium_count}, Low: {low_count}, Informational: {info_count})

Below is a de-duplicated list of the distinct vulnerability types found (not every individual instance):
{findings_block}

Write a report with these sections:
1. Executive Summary (2-3 sentences, plain English, no jargon)
2. Overall Risk Assessment (one paragraph — how concerned should they be, given the counts above)
3. Key Vulnerabilities (bullet points, only the High and Medium ones, explain impact in plain terms)
4. Recommended Next Steps (prioritized bullet list)

Keep the whole report under 300 words. Do not repeat the raw data table, write in prose and bullets only.
Be concise — brevity matters more than exhaustive detail here."""

    return prompt


def _build_chat_prompt(target_url, total_findings, high_count, medium_count,
                        low_count, info_count, findings, question, history=None):
    """
    Builds a prompt for a single follow-up Q&A turn about a scan's findings.
    `history` (optional) is a list of {"role": "user"|"assistant", "content": str}
    dicts — recent conversation turns, so the model has context for follow-ups
    like "which of those is worst?" without re-explaining everything.
    """
    findings_block = _format_findings_block(findings, cap=20)

    history_block = ""
    if history:
        # Cap history to the last few turns to keep the prompt a reasonable
        # size — old turns matter far less than the current question.
        for turn in history[-6:]:
            role = "User" if turn.get("role") == "user" else "Assistant"
            history_block += f"\n{role}: {turn.get('content', '')}"

    conversation_section = f"\nConversation so far:{history_block}\n" if history_block else ""

    prompt = f"""You are a security analyst assistant answering follow-up questions about a vulnerability scan. Be concise, specific, and reference the findings below where relevant. If the question can't be answered from the findings provided, say so honestly rather than guessing.

Target scanned: {target_url}
Total findings: {total_findings} (High: {high_count}, Medium: {medium_count}, Low: {low_count}, Informational: {info_count})

Findings (de-duplicated, top {min(20, len(findings))} by severity):
{findings_block}
{conversation_section}
Question: {question}

Answer:"""

    return prompt


def _call_ollama(prompt):
    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
            },
            timeout=OLLAMA_TIMEOUT,
        )
    except requests.exceptions.ConnectionError:
        raise LLMBackendError(
            f"Could not reach Ollama at {OLLAMA_URL}. "
            "Is it running? Try: ollama serve"
        )
    except requests.exceptions.Timeout:
        raise LLMBackendError(
            f"Ollama did not respond within {OLLAMA_TIMEOUT}s. "
            "The model may still be loading, or your machine may be low on RAM — try again."
        )

    if response.status_code == 404:
        raise LLMBackendError(
            f"Model '{OLLAMA_MODEL}' not found. Run: ollama pull {OLLAMA_MODEL}"
        )
    if response.status_code != 200:
        raise LLMBackendError(
            f"Ollama returned HTTP {response.status_code}: {response.text[:300]}"
        )

    data = response.json()
    return data.get("response", "").strip()


def _call_groq(prompt):
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise LLMBackendError(
            "GROQ_API_KEY environment variable is not set. "
            "Get a free key at https://console.groq.com and set it, then restart Flask."
        )

    try:
        response = requests.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": GROQ_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 600,
                "temperature": 0.4,
            },
            timeout=GROQ_TIMEOUT,
        )
    except requests.exceptions.ConnectionError:
        raise LLMBackendError(
            "Could not reach Groq's API. Check your internet connection."
        )
    except requests.exceptions.Timeout:
        raise LLMBackendError(
            f"Groq did not respond within {GROQ_TIMEOUT}s. Unusual for their API — try again."
        )

    if response.status_code == 401:
        raise LLMBackendError("Groq API key was rejected (401). Check GROQ_API_KEY is correct.")
    if response.status_code == 429:
        raise LLMBackendError("Groq rate limit hit (429). Wait a moment and try again.")
    if response.status_code != 200:
        raise LLMBackendError(
            f"Groq returned HTTP {response.status_code}: {response.text[:300]}"
        )

    data = response.json()
    try:
        return data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError):
        raise LLMBackendError(f"Unexpected Groq response shape: {json.dumps(data)[:300]}")


def generate_report(scan_id, force_regenerate=False, backend=None):
    """
    Generate (or fetch cached) AI report for a scan.

    backend: "ollama" or "groq". Defaults to the LLM_BACKEND environment
             variable if not passed explicitly.

    Returns: { "scan_id", "report_text", "generated_at", "cached", "backend" }
    Raises: ValueError if scan not found, LLMBackendError if the LLM call fails.
    """
    scan = get_scan(scan_id)
    if scan is None:
        raise ValueError(f"Scan {scan_id} not found")

    backend = (backend or DEFAULT_BACKEND).lower()
    if backend not in ("ollama", "groq"):
        raise LLMBackendError(f"Unknown backend '{backend}' — must be 'ollama' or 'groq'")

    if not force_regenerate:
        cached_text, cached_at = get_report(scan_id, backend)
        if cached_text:
            return {
                "scan_id": scan_id,
                "report_text": cached_text,
                "generated_at": to_iso_utc(cached_at),
                "cached": True,
                "backend": backend,
            }

    findings = json.loads(scan.findings_json) if isinstance(scan.findings_json, str) else scan.findings_json

    prompt = _build_prompt(
        target_url=scan.target_url,
        total_findings=scan.total_findings,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        info_count=scan.info_count,
        findings=findings,
    )

    report_text = _call_groq(prompt) if backend == "groq" else _call_ollama(prompt)

    if not report_text:
        raise LLMBackendError(f"{backend} returned an empty response")

    save_report(scan_id, report_text, backend)

    return {
        "scan_id": scan_id,
        "report_text": report_text,
        "generated_at": to_iso_utc(datetime.utcnow()),
        "cached": False,
        "backend": backend,
    }


def generate_chat_answer(scan_id, question, backend=None, history=None):
    """
    Answer a follow-up question about a scan's findings. Unlike
    generate_report(), this is never cached — every question is different,
    so there's nothing sensible to key a cache on. Every call is a live
    LLM request.

    history: optional list of {"role": "user"|"assistant", "content": str}
             dicts — recent prior turns in this chat, for follow-up context.

    Returns: { "scan_id", "question", "answer", "backend", "generated_at" }
    Raises: ValueError if scan not found, LLMBackendError if the LLM call fails.
    """
    scan = get_scan(scan_id)
    if scan is None:
        raise ValueError(f"Scan {scan_id} not found")

    if not question or not question.strip():
        raise ValueError("Question must not be empty")

    backend = (backend or DEFAULT_BACKEND).lower()
    if backend not in ("ollama", "groq"):
        raise LLMBackendError(f"Unknown backend '{backend}' — must be 'ollama' or 'groq'")

    findings = json.loads(scan.findings_json) if isinstance(scan.findings_json, str) else scan.findings_json

    prompt = _build_chat_prompt(
        target_url=scan.target_url,
        total_findings=scan.total_findings,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        info_count=scan.info_count,
        findings=findings,
        question=question.strip(),
        history=history,
    )

    answer = _call_groq(prompt) if backend == "groq" else _call_ollama(prompt)

    if not answer:
        raise LLMBackendError(f"{backend} returned an empty response")

    return {
        "scan_id": scan_id,
        "question": question.strip(),
        "answer": answer,
        "backend": backend,
        "generated_at": to_iso_utc(datetime.utcnow()),
    }