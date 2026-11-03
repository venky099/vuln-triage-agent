"""Vulnerability triage orchestration loop.

Coordinates finding deduplication, structured model elicitation, schema validation,
deterministic CVSS computation, and grounding validation.
"""
from __future__ import annotations

import copy
import json
import logging
import re
import time
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Callable

from .grounding import enforce
from .llm import SYSTEM_PROMPT, Backend, get_backend
from .models import TRIAGE_SCHEMA, RawFinding, TriagedFinding
from .tools import build_vector, cwe_catalogue, dedupe, lookup_cwe, score_cvss

logger = logging.getLogger(__name__)

# Base network and I/O error types indicating a retryable transient failure
TRANSIENT_NETWORK_ERRORS = (ConnectionError, TimeoutError, urllib.error.URLError, OSError)


def is_transient_error(exc: Exception) -> bool:
    """Determine whether an exception represents a retryable transient network/API fault."""
    if isinstance(exc, TRANSIENT_NETWORK_ERRORS):
        return True

    # Check for HTTP status codes commonly associated with temporary provider unavailability
    status_code = getattr(exc, "status_code", None)
    if status_code in (429, 500, 502, 503, 504):
        return True

    # Match common provider SDK error names without requiring direct imports
    exc_type = type(exc).__name__
    transient_names = (
        "APIConnectionError",
        "APITimeoutError",
        "RateLimitError",
        "InternalServerError",
        "ServiceUnavailableError",
    )
    return any(name in exc_type for name in transient_names)


class SchemaError(ValueError):
    """Raised when an LLM completion does not conform to the required JSON schema."""


class UnsupportedSchema(Exception):
    """Raised when TRIAGE_SCHEMA specifies a keyword or type unsupported by the validator."""


def validate(payload: Any) -> dict[str, Any]:
    """Validate a parsed JSON dictionary against TRIAGE_SCHEMA.

    Implements the subset of JSON Schema required for triage entries without
    external schema validation dependencies.
    """
    if not isinstance(payload, dict):
        raise SchemaError("Expected a JSON object.")

    props = TRIAGE_SCHEMA["properties"]
    for key in TRIAGE_SCHEMA["required"]:
        if key not in payload:
            raise SchemaError(f"Missing required field: {key}")

    for key in payload:
        if key not in props:
            raise SchemaError(f"Unexpected field: {key}")

    for key, spec in props.items():
        if key not in payload:
            continue
        value = payload[key]
        spec_type = spec.get("type")

        if spec_type == "string":
            if not isinstance(value, str):
                raise SchemaError(f"{key} must be a string")
            min_len = spec.get("minLength", 0)
            max_len = spec.get("maxLength", 10 ** 9)
            if len(value) < min_len:
                raise SchemaError(f"{key} is too short (minimum {min_len} characters)")
            if len(value) > max_len:
                raise SchemaError(f"{key} is too long (maximum {max_len} characters)")
            if "pattern" in spec and not re.fullmatch(spec["pattern"], value):
                raise SchemaError(f"{key} does not match required pattern: {spec['pattern']}")

        elif spec_type == "object":
            if not isinstance(value, dict):
                raise SchemaError(f"{key} must be a JSON object")
            for sub in spec.get("required", []):
                if sub not in value:
                    raise SchemaError(f"Missing metric property: {key}.{sub}")
            for sub, sub_value in value.items():
                sub_spec = spec["properties"].get(sub)
                if sub_spec is None:
                    raise SchemaError(f"Unexpected metric: {sub}")
                if "enum" not in sub_spec:
                    raise UnsupportedSchema(
                        f"Validator only supports enum validation for metric properties: {key}.{sub}"
                    )
                if sub_value not in sub_spec["enum"]:
                    raise SchemaError(
                        f"Invalid metric value {key}.{sub}={sub_value!r}; must be one of {sub_spec['enum']}"
                    )
        else:
            raise UnsupportedSchema(
                f"Field {key!r} specifies type {spec_type!r}, which is unsupported by the validator"
            )

    return payload


def _context(raw: RawFinding) -> str:
    """Format finding evidence and schema constraints into user prompt context."""
    return json.dumps({
        "id": raw.id,
        "scanner": raw.scanner,
        "kind": raw.kind,
        "url": raw.url,
        "parameter": raw.parameter,
        "method": raw.method,
        "payload": raw.payload,
        "evidence": raw.evidence,
        "extra": raw.raw,
        "allowed_cwe_ids": sorted(cwe_catalogue().keys()),
        "schema": TRIAGE_SCHEMA,
    }, indent=2)


def _adds_information(catalogue_text: str, model_text: str, threshold: float = 0.4) -> bool:
    """Return True if the catalogue guidance adds substantive words beyond model remediation."""
    cat_words = set(re.findall(r"[a-z]{4,}", catalogue_text.lower()))
    mod_words = set(re.findall(r"[a-z]{4,}", model_text.lower()))
    if not cat_words:
        return False
    return len(cat_words - mod_words) / len(cat_words) >= threshold


def finalise_grounded(raw: RawFinding, triaged: TriagedFinding, redact: bool = True) -> TriagedFinding:
    """Enforce grounding validation and optionally augment remediation with catalogue guidance."""
    triaged = enforce(raw, triaged, redact=redact)
    entry = lookup_cwe(triaged.cwe_id) if triaged.cwe_id else None
    if entry and _adds_information(entry["remediation"], triaged.remediation):
        triaged.remediation = f"{entry['remediation']} {triaged.remediation}".strip()
    return triaged


@dataclass
class TriageResult:
    """Aggregate result from a batch triage run."""
    findings: list[TriagedFinding] = field(default_factory=list)
    duplicates_removed: int = 0
    schema_retries: int = 0
    backend: str = ""
    errors: list[tuple[str, str]] = field(default_factory=list)

    @property
    def flagged(self) -> list[TriagedFinding]:
        """Findings containing one or more grounding flags."""
        return [f for f in self.findings if f.flags]

    def counts(self) -> dict[str, int]:
        """Return finding counts grouped by qualitative severity rating."""
        out = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out


class TriageAgent:
    """Orchestrates vulnerability triage and grounding validation."""

    def __init__(
        self,
        backend: Backend | None = None,
        *,
        grounding: bool = True,
        redact: bool = True,
        max_retries: int = 2,
        net_retries: int = 2,
        backoff: float = 1.0,
    ) -> None:
        self.backend = backend or get_backend()
        self.grounding = grounding
        self.redact = redact
        self.max_retries = max_retries
        self.net_retries = net_retries
        self.backoff = backoff
        self._last_transient: str = ""

    def _complete(self, prompt: str) -> str:
        """Execute model completion with exponential backoff on transient errors."""
        delay = self.backoff
        for attempt in range(self.net_retries + 1):
            try:
                return self.backend.complete_json(SYSTEM_PROMPT, prompt)
            except Exception as exc:
                if not is_transient_error(exc) or attempt == self.net_retries:
                    logger.error("Network or API failure on attempt %d: %s", attempt + 1, exc)
                    raise
                self._last_transient = f"{type(exc).__name__}: {exc}"
                logger.warning(
                    "Transient error on attempt %d/%d (%s); retrying in %.2fs",
                    attempt + 1, self.net_retries, self._last_transient, delay,
                )
                time.sleep(delay)
                delay *= 2
        raise AssertionError("Unreachable retry state")

    def _ask(self, raw: RawFinding) -> tuple[dict[str, Any], int]:
        """Request structured triage output, retrying on schema violations with feedback."""
        user = _context(raw)
        retries = 0
        last_error = ""

        for attempt in range(self.max_retries + 1):
            if attempt == 0:
                prompt = user
            else:
                prompt = (
                    f"{user}\n\nYour previous answer was rejected: {last_error}\n"
                    "Return corrected JSON matching the schema exactly."
                )

            text = self._complete(prompt)
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as exc:
                last_error = f"Invalid JSON ({exc.msg})"
                retries += 1
                logger.debug("Finding %s returned malformed JSON on attempt %d", raw.id, attempt + 1)
                continue

            try:
                return validate(payload), retries
            except SchemaError as exc:
                last_error = str(exc)
                retries += 1
                logger.debug("Finding %s failed schema validation on attempt %d: %s", raw.id, attempt + 1, exc)

        raise SchemaError(
            f"Model did not satisfy schema after {self.max_retries + 1} attempts: {last_error}"
        )

    def triage_one(self, raw: RawFinding, duplicates: list[str] | None = None) -> TriagedFinding:
        """Process a single RawFinding into a validated TriagedFinding."""
        payload, retries = self._ask(raw)

        # CVSS score is derived by arithmetic from model-selected metrics
        vector = build_vector(payload["cvss_metrics"])
        score, severity = score_cvss(vector)

        entry = lookup_cwe(payload["cwe_id"])
        cwe_name = (entry or {}).get("name", "")

        triaged = TriagedFinding(
            source_id=raw.id,
            title=payload["title"].strip(),
            cwe_id=payload["cwe_id"].upper(),
            cwe_name=cwe_name,
            cvss_vector=vector,
            cvss_score=score,
            severity=severity,
            summary=payload["summary"].strip(),
            reproduction=payload["reproduction"].strip(),
            remediation=payload["remediation"].strip(),
            duplicates=list(duplicates or []),
            retries=retries,
        )

        if self.grounding:
            triaged = finalise_grounded(raw, triaged, redact=self.redact)
        else:
            triaged.flags = []

        return triaged

    def run(
        self,
        findings: list[RawFinding],
        progress: Callable[[int, int, RawFinding], None] | None = None,
    ) -> TriageResult:
        """Deduplicate and triage a collection of raw findings."""
        grouped = dedupe(findings)
        result = TriageResult(
            backend=self.backend.name,
            duplicates_removed=len(findings) - len(grouped),
        )

        for i, (raw, dupes) in enumerate(grouped, 1):
            if progress:
                progress(i, len(grouped), raw)
            try:
                triaged = self.triage_one(raw, dupes)
            except UnsupportedSchema:
                # Fatal implementation issue: do not continue running uncheckable schema
                logger.critical("Fatal: unsupported schema detected in triage loop")
                raise
            except Exception as exc:
                logger.error("Triage failed for finding %s: %s", raw.id, exc, exc_info=True)
                result.errors.append((raw.id, f"{type(exc).__name__}: {exc}"))
                continue

            result.schema_retries += getattr(triaged, "_retries", 0)
            result.findings.append(triaged)

        result.findings.sort(key=lambda f: -f.cvss_score)
        return result
