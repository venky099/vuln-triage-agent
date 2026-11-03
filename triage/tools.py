"""Deterministic security tools and utilities for the triage pipeline.

Handles factual computations:
- CVSS v3.1 vector scoring (Appendix A compliant arithmetic)
- CWE catalogue verification
- Scanner finding deduplication
"""
from __future__ import annotations

import json
import logging
import math
import re
from pathlib import Path
from typing import Any

from .models import RawFinding

logger = logging.getLogger(__name__)

DATA = Path(__file__).resolve().parent.parent / "data"

# --------------------------------------------------------------------------
# CWE catalogue lookup
# --------------------------------------------------------------------------

_CWE_CACHE: dict[str, dict[str, str]] | None = None


def cwe_catalogue() -> dict[str, dict[str, str]]:
    """Return the cached CWE dictionary loaded from data/cwe.json."""
    global _CWE_CACHE
    if _CWE_CACHE is None:
        cwe_file = DATA / "cwe.json"
        if not cwe_file.exists():
            raise FileNotFoundError(f"Authoritative CWE catalogue not found at {cwe_file}")
        _CWE_CACHE = json.loads(cwe_file.read_text(encoding="utf-8"))
    return _CWE_CACHE


def lookup_cwe(cwe_id: str) -> dict[str, str] | None:
    """Return the catalogue entry for the given CWE ID, or None if unknown."""
    if not cwe_id:
        return None
    return cwe_catalogue().get(cwe_id.strip().upper())


# --------------------------------------------------------------------------
# CVSS v3.1 base score computation
# --------------------------------------------------------------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

VECTOR_RE = re.compile(
    r"^CVSS:3\.1/AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/"
    r"S:([UC])/C:([HLN])/I:([HLN])/A:([HLN])$"
)


def _roundup(value: float) -> float:
    """Perform CVSS v3.1 Appendix A round-up calculation using integer arithmetic."""
    i = int(round(value * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def build_vector(m: dict[str, str]) -> str:
    """Format an 8-metric dictionary into a standardized CVSS v3.1 vector string."""
    return (
        "CVSS:3.1/AV:{AV}/AC:{AC}/PR:{PR}/UI:{UI}/"
        "S:{S}/C:{C}/I:{I}/A:{A}"
    ).format(**m)


def score_cvss(vector: str) -> tuple[float, str]:
    """Compute CVSS v3.1 base score and qualitative severity rating from a vector.

    Raises ValueError if the vector does not match the official CVSS 3.1 specification.
    """
    match = VECTOR_RE.match((vector or "").strip())
    if not match:
        raise ValueError(f"Malformed or unsupported CVSS v3.1 vector: {vector!r}")

    av, ac, pr, ui, scope, c, i, a = match.groups()

    iss = 1.0 - ((1.0 - _CIA[c]) * (1.0 - _CIA[i]) * (1.0 - _CIA[a]))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    pr_val = _PR_U[pr] if scope == "U" else _PR_C[pr]
    exploitability = 8.22 * _AV[av] * _AC[ac] * pr_val * _UI[ui]

    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = _roundup(min(impact + exploitability, 10.0))
    else:
        score = _roundup(min(1.08 * (impact + exploitability), 10.0))

    return score, severity_of(score)


def severity_of(score: float) -> str:
    """Map a CVSS numeric score to its qualitative severity rating."""
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


# --------------------------------------------------------------------------
# Deduplication
# --------------------------------------------------------------------------

def _dedupe_key(f: RawFinding) -> tuple[str, str, str]:
    """Derive unique identity: vulnerability kind, normalized URL path, parameter.

    Query parameters and fragments are stripped from the URL to merge repeated
    findings on the same endpoint.
    """
    path = re.sub(r"[?#].*$", "", f.url or "").rstrip("/").lower()
    return (f.kind.strip().lower(), path, (f.parameter or "").strip().lower())


def dedupe(findings: list[RawFinding]) -> list[tuple[RawFinding, list[str]]]:
    """Group duplicate findings, returning [(representative_finding, [absorbed_ids])]."""
    groups: dict[tuple[str, str, str], list[RawFinding]] = {}
    order: list[tuple[str, str, str]] = []
    for f in findings:
        key = _dedupe_key(f)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)
    return [(groups[k][0], [d.id for d in groups[k][1:]]) for k in order]


# --------------------------------------------------------------------------
# Tool definitions for function calling
# --------------------------------------------------------------------------

TOOL_SPECS: list[dict[str, Any]] = [
    {
        "name": "lookup_cwe",
        "description": "Look up a CWE identifier in the authoritative local catalogue.",
        "parameters": {
            "type": "object",
            "properties": {"cwe_id": {"type": "string", "description": "e.g. CWE-89"}},
            "required": ["cwe_id"],
        },
    },
    {
        "name": "score_cvss",
        "description": "Compute the CVSS v3.1 base score and severity from a vector string.",
        "parameters": {
            "type": "object",
            "properties": {"vector": {"type": "string"}},
            "required": ["vector"],
        },
    },
]

TOOL_IMPLS = {
    "lookup_cwe": lambda cwe_id: lookup_cwe(cwe_id),
    "score_cvss": lambda vector: (lambda s: {"score": s[0], "severity": s[1]})(score_cvss(vector)),
}
