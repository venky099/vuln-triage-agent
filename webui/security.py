"""Security controls and input validation guards for the web interface.

Enforces bounds on request payloads, validates API key formats, limits rate of calls,
and sanitizes data for the report rendering endpoints.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from collections import defaultdict, deque
from typing import Any

from triage.models import SEVERITIES, TriagedFinding

logger = logging.getLogger(__name__)

# Request payload constraints
MAX_SCAN_BYTES = 512 * 1024
MAX_FINDINGS = 60
MAX_FINDINGS_LOCAL = 5

# Maximum string length constraints for report rendering
MAX_TITLE_LEN = 300
MAX_TEXT_LEN = 5000
MAX_TARGET_LEN = 250

KEY_SHAPE = re.compile(r"^sk-[A-Za-z0-9_\-]{20,}$")
CWE_PATTERN = re.compile(r"^(CWE-\d{1,4})?$", re.IGNORECASE)


class Rejected(Exception):
    """Raised when user input violates validation or security constraints."""


def validate_scan(text: str) -> str:
    """Validate scanner JSON input size and presence."""
    if not text or not text.strip():
        raise Rejected("Paste a scan first, or load the example.")
    size = len(text.encode("utf-8"))
    if size > MAX_SCAN_BYTES:
        raise Rejected(
            f"Scan is {size / 1024:.0f} KB; the limit is {MAX_SCAN_BYTES / 1024:.0f} KB."
        )
    return text


def validate_api_key(key: str | None) -> str | None:
    """Validate the syntax of an optional user-supplied OpenAI API key.

    Does not persist, log, or echo the key.
    """
    if not key or not key.strip():
        return None
    key = key.strip()
    if len(key) > 300:
        raise Rejected("That does not look like an API key.")
    if not KEY_SHAPE.match(key):
        raise Rejected("That does not look like an OpenAI key (expected sk-...).")
    return key


def cap_findings(n: int) -> None:
    """Enforce upper limit on total findings processed in a single web request."""
    if n > MAX_FINDINGS:
        raise Rejected(
            f"This scan has {n} findings; the demo caps at {MAX_FINDINGS}. "
            "Run the CLI locally for larger scans."
        )


def cap_local_findings(n: int) -> None:
    """Enforce stricter limit for local Ollama runs due to CPU inference latency."""
    if n > MAX_FINDINGS_LOCAL:
        raise Rejected(
            f"A local model takes about a minute per finding, so the browser caps "
            f"Ollama runs at {MAX_FINDINGS_LOCAL} (this scan needs {n} after merging duplicates). "
            "Use the simulated model here, or run the CLI for the full scan."
        )


def validate_ollama_model(name: str | None, available: list[str]) -> str:
    """Confirm requested Ollama model is present on the host."""
    if not available:
        raise Rejected("Ollama is not reachable. Start it with `ollama serve`.")
    name = (name or "").strip()
    if not name:
        return available[0]
    if name not in available:
        raise Rejected(
            f"Ollama has no model named {name!r}. Available: {', '.join(available)}."
        )
    return name


class RateLimiter:
    """Thread-safe sliding-window rate limiter per client IP."""

    def __init__(
        self,
        max_calls: int = 15,
        window_seconds: int = 60,
        max_clients: int = 4096,
    ) -> None:
        self.max_calls = max_calls
        self.window = window_seconds
        self.max_clients = max_clients
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        """Record an access for key or raise Rejected if rate limit exceeded."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if len(hits) >= self.max_calls:
                raise Rejected(
                    f"Rate limit reached ({self.max_calls}/minute). Try again shortly."
                )
            hits.append(now)
            if len(self._hits) > self.max_clients:
                self._evict(now)

    def _evict(self, now: float) -> None:
        """Evict stale client windows to bound memory consumption."""
        stale_keys = [
            k for k, v in self._hits.items()
            if not v or now - v[-1] > self.window
        ]
        for k in stale_keys:
            del self._hits[k]

        if len(self._hits) <= self.max_clients:
            return

        # Prioritize keeping active/heaviest users in the table to prevent quota evasion
        ranked = sorted(self._hits.items(), key=lambda kv: (len(kv[1]), kv[1][-1]))
        excess = len(self._hits) - self.max_clients
        for k, _ in ranked[:excess]:
            del self._hits[k]


def _validate_finding_dict(f: dict[str, Any]) -> TriagedFinding:
    """Validate and sanitize a raw finding dictionary from an untrusted client request."""
    if not isinstance(f, dict):
        raise Rejected("Each finding entry must be a JSON object.")

    raw_title = str(f.get("title", "")).strip()
    if not raw_title:
        raise Rejected("Finding title cannot be empty.")
    if len(raw_title) > MAX_TITLE_LEN:
        raise Rejected(f"Finding title exceeds maximum length of {MAX_TITLE_LEN} characters.")

    raw_summary = str(f.get("summary", ""))
    raw_repro = str(f.get("reproduction", ""))
    raw_remed = str(f.get("remediation", ""))
    if any(len(t) > MAX_TEXT_LEN for t in (raw_summary, raw_repro, raw_remed)):
        raise Rejected(f"Finding text fields exceed maximum length of {MAX_TEXT_LEN} characters.")

    source_id = str(f.get("source_id", ""))[:100]
    cwe_id = str(f.get("cwe_id", "")).strip()[:20]
    cwe_name = str(f.get("cwe_name", "")).strip()[:150]
    cvss_vector = str(f.get("cvss_vector", "")).strip()[:120]

    if cwe_id and not CWE_PATTERN.match(cwe_id):
        raise Rejected(f"Invalid CWE identifier shape: {cwe_id}")

    # Validate CVSS score range
    raw_score = f.get("cvss_score", 0.0)
    try:
        score = float(raw_score)
        if not (0.0 <= score <= 10.0):
            raise ValueError
    except (TypeError, ValueError):
        raise Rejected(f"Invalid CVSS score: {raw_score}")

    # Validate qualitative severity
    severity = str(f.get("severity", "None")).capitalize()
    if severity not in SEVERITIES:
        severity = "None"

    # Validate list fields
    raw_dupes = f.get("duplicates", [])
    duplicates = (
        [str(d)[:100] for d in raw_dupes[:50]]
        if isinstance(raw_dupes, list) else []
    )

    raw_flags = f.get("flags", [])
    flags = (
        [str(fl)[:500] for fl in raw_flags[:50]]
        if isinstance(raw_flags, list) else []
    )

    return TriagedFinding(
        source_id=source_id,
        title=raw_title,
        cwe_id=cwe_id,
        cwe_name=cwe_name,
        cvss_vector=cvss_vector,
        cvss_score=score,
        severity=severity,
        summary=raw_summary,
        reproduction=raw_repro,
        remediation=raw_remed,
        duplicates=duplicates,
        flags=flags,
    )


def validate_render_payload(payload: dict[str, Any]) -> tuple[list[TriagedFinding], int, str, str]:
    """Validate the incoming payload for report rendering.

    Returns:
        (validated_findings, duplicates_removed, backend, target)
    """
    if not isinstance(payload, dict):
        raise Rejected("Payload must be a JSON object.")

    entries = payload.get("grounded", [])
    if not isinstance(entries, list):
        raise Rejected("Grounded findings must be an array.")
    if len(entries) > MAX_FINDINGS:
        raise Rejected(f"Render payload exceeds maximum findings limit ({MAX_FINDINGS}).")

    findings = [_validate_finding_dict(entry) for entry in entries]

    try:
        duplicates_removed = int(payload.get("duplicatesRemoved", 0))
        if duplicates_removed < 0:
            duplicates_removed = 0
    except (TypeError, ValueError):
        duplicates_removed = 0

    backend = str(payload.get("backend", ""))[:50]
    target = str(payload.get("target", ""))[:MAX_TARGET_LEN]

    return findings, duplicates_removed, backend, target
