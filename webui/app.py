"""FastAPI web application for vulnerability triage and grounding inspection.

Provides endpoints for running triage against uploaded scans and previewing
or downloading assessment reports in Markdown, HTML, and JSON formats.
"""
from __future__ import annotations

import copy
import json
import logging
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from triage import __version__
from triage.agent import TriageAgent, TriageResult, finalise_grounded
from triage.llm import MockBackend, OllamaBackend, OpenAIBackend, ollama_models
from triage.parsers import PARSERS, detect_format
from triage.report import to_html, to_json, to_markdown
from triage.tools import dedupe

from .security import (
    MAX_FINDINGS,
    MAX_FINDINGS_LOCAL,
    RateLimiter,
    Rejected,
    cap_findings,
    cap_local_findings,
    validate_api_key,
    validate_ollama_model,
    validate_render_payload,
    validate_scan,
)

logger = logging.getLogger("webui")

BASE_DIR = Path(__file__).parent
ROOT = BASE_DIR.parent

app = FastAPI(
    title="vuln-triage-agent",
    version=__version__,
    docs_url=None,
    redoc_url=None,
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

# Safe environment variable configuration with fallback defaults
try:
    _rate_limit = int(os.environ.get("TRIAGE_RATE", "15"))
except ValueError:
    logger.warning("Invalid TRIAGE_RATE environment variable; defaulting to 15")
    _rate_limit = 15

limiter = RateLimiter(max_calls=_rate_limit)

try:
    PROXY_DEPTH = max(0, int(os.environ.get("TRIAGE_PROXY_DEPTH", "1")))
except ValueError:
    logger.warning("Invalid TRIAGE_PROXY_DEPTH environment variable; defaulting to 1")
    PROXY_DEPTH = 1


class TriageRequest(BaseModel):
    """Schema for incoming triage requests."""
    scan: str = Field(max_length=4_000_000)
    backend: str = Field(default="mock", pattern="^(mock|openai|ollama)$")
    api_key: str | None = Field(default=None, max_length=400)
    model: str | None = Field(default=None, max_length=120)


class RenderRequest(BaseModel):
    """Schema for report re-rendering requests."""
    payload: dict[str, Any]
    format: str = Field(default="markdown", pattern="^(markdown|html|json)$")


def _client(request: Request) -> str:
    """Extract caller identity for rate limiting based on configured proxy depth."""
    peer = request.client.host if request.client else "unknown"
    if not PROXY_DEPTH:
        return peer

    xff = request.headers.get("x-forwarded-for", "")
    parts = [p.strip() for p in xff.split(",") if p.strip()]
    if len(parts) < PROXY_DEPTH:
        return peer
    return parts[-PROXY_DEPTH]


def _serialise(findings) -> list[dict[str, Any]]:
    """Convert a list of findings to dictionaries."""
    return [f.to_dict() for f in findings]


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serve the main interactive triage dashboard."""
    models = ollama_models()
    ctx = {
        "version": __version__,
        "max_findings": MAX_FINDINGS,
        "ollama_models": models,
        "max_findings_local": MAX_FINDINGS_LOCAL,
    }
    try:
        return templates.TemplateResponse(request, "index.html", ctx)
    except TypeError:
        return templates.TemplateResponse("index.html", {"request": request, **ctx})


@app.get("/api/health")
async def health():
    """Service health and backend capability status."""
    models = ollama_models()
    return {
        "ok": True,
        "version": __version__,
        "ollamaAvailable": bool(models),
        "ollamaModels": models,
    }


@app.get("/api/example")
async def example():
    """Return the bundled sample scanner findings."""
    sample_file = ROOT / "data" / "sample_scan.json"
    return JSONResponse(json.loads(sample_file.read_text(encoding="utf-8")))


@app.post("/api/triage")
def triage(req: TriageRequest, request: Request):
    """Execute triage on scanner output with dual ungrounded and grounded views.

    Runs synchronously in FastAPI's external worker thread pool to avoid blocking
    the asyncio event loop during LLM inference or network requests.
    """
    client_ip = _client(request)
    try:
        limiter.check(client_ip)
        text = validate_scan(req.scan)
        key = validate_api_key(req.api_key)
    except Rejected as exc:
        status_code = 429 if "Rate limit" in str(exc) else 400
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=status_code)

    # Parse scanner payload
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return JSONResponse(
            {"ok": False, "error": f"Invalid JSON: {exc.msg} (line {exc.lineno})"},
            status_code=400,
        )

    if isinstance(data, list):
        data = {"findings": data}
    if not isinstance(data, dict):
        return JSONResponse(
            {"ok": False, "error": "Expected a JSON object or array."},
            status_code=400,
        )

    fmt = detect_format(data)
    try:
        findings = PARSERS[fmt](data)
        if not findings:
            raise ValueError("No findings found in scanner payload.")
        cap_findings(len(findings))
    except Rejected as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    except Exception as exc:
        logger.warning("Failed parsing scanner input (%s): %s", fmt, exc)
        return JSONResponse({"ok": False, "error": f"Could not parse scan: {exc}"}, status_code=400)

    # Deduplicate findings before backend invocation
    grouped = dedupe(findings)

    # Resolve backend
    if req.backend == "ollama":
        try:
            cap_local_findings(len(grouped))
            model = validate_ollama_model(req.model, ollama_models())
        except Rejected as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
        backend = OllamaBackend(model=model)
    elif req.backend == "openai":
        if not key:
            return JSONResponse(
                {
                    "ok": False,
                    "error": "Paste your own OpenAI key to run against a real model. "
                             "It is used for this request only and never stored.",
                },
                status_code=400,
            )
        try:
            backend = OpenAIBackend(api_key=key)
        except ImportError:
            return JSONResponse(
                {"ok": False, "error": "The openai package is not installed on this server."},
                status_code=503,
            )
    else:
        backend = MockBackend()

    # Perform triage: single LLM generation with subsequent grounded view enforcement
    agent = TriageAgent(backend=backend, grounding=False)
    raw_view, grounded_view = [], []
    errors: list[tuple[str, str]] = []

    for raw, dupes in grouped:
        try:
            unchecked = agent.triage_one(raw, dupes)
            raw_view.append(unchecked)
            grounded_view.append(finalise_grounded(raw, copy.deepcopy(unchecked)))
        except Exception as exc:
            logger.error("Triage failed for finding %s: %s", raw.id, exc, exc_info=True)
            errors.append((raw.id, f"{type(exc).__name__}: {exc}"))
            continue

    if not raw_view and errors:
        return JSONResponse(
            {"ok": False, "error": f"Triage failed ({errors[0][1]}). Check the scan format or API credentials."},
            status_code=502,
        )

    raw_view.sort(key=lambda f: -f.cvss_score)
    grounded_view.sort(key=lambda f: -f.cvss_score)

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
    for f in grounded_view:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    return JSONResponse({
        "ok": True,
        "target": data.get("target", ""),
        "backend": backend.name,
        "format": fmt,
        "counts": counts,
        "duplicatesRemoved": len(findings) - len(grouped),
        "flaggedCount": sum(1 for f in grounded_view if f.flags),
        "ungrounded": _serialise(raw_view),
        "grounded": _serialise(grounded_view),
    })


@app.post("/api/render")
def render(req: RenderRequest, request: Request):
    """Render client-supplied triage results into Markdown, HTML, or JSON reports."""
    try:
        limiter.check(_client(request))
        findings, duplicates_removed, backend, target = validate_render_payload(req.payload)
    except Rejected as exc:
        status_code = 429 if "Rate limit" in str(exc) else 400
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=status_code)
    except Exception as exc:
        logger.warning("Unexpected error during payload validation in /api/render: %s", exc)
        return JSONResponse({"ok": False, "error": "Malformed result payload."}, status_code=400)

    result = TriageResult(
        findings=findings,
        duplicates_removed=duplicates_removed,
        backend=backend,
    )

    renderers = {"markdown": to_markdown, "html": to_html, "json": to_json}
    body = renderers[req.format](result, target)
    return JSONResponse({"ok": True, "body": body})
