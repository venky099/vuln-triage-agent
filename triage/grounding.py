"""Grounding and validation layer for triage outputs.

Verifies generated findings against two sources of truth:
1. The scanner's RawFinding evidence corpus
2. The local authoritative CWE catalogue

Validates:
- CVE identifiers (must originate from scan data)
- CWE classifications and catalogue consistency
- CVSS vectors and computed scores
- URL paths and endpoints
- Qualitative severity ratings
- Unsupported security impact claims
"""
from __future__ import annotations

import logging
import re

from .models import RawFinding, TriagedFinding
from .tools import VECTOR_RE, lookup_cwe, score_cvss, severity_of

logger = logging.getLogger(__name__)

# Patterns for claims prone to model fabrication
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CWE_RE = re.compile(r"\bCWE-\d{1,4}\b", re.IGNORECASE)

# Strips vectors embedded in prose to avoid false positive CVSS score matches
VECTOR_IN_PROSE = re.compile(r"CVSS:3\.\d/(?:[A-Z]{1,2}:[A-Z](?:/|\b))+", re.IGNORECASE)

# Captures numerical CVSS scores declared in prose (e.g. "CVSS score of 9.8", "CVSS: 9.8", "CVSS base score is 7.5")
# Distinguishes actual numerical scores from methodology references like "CVSS 3.1 methodology"
SCORE_RE = re.compile(
    r"\bCVSS(?:\s*v?3(?:\.\d)?)?\s*(?:base\s*)?(?:score\s*(?:of|is|:|=)?|[:=])\s*"
    r"(\d{1,2}(?:\.\d)?)\b",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+")

# Absolute impact claims that a single automated scanner finding cannot substantiate
# unless explicitly corroborated by scanner evidence
OVERCLAIM_RE = re.compile(
    r"\b(?:remote code execution|arbitrary code execution|full (?:system|server) compromise|"
    r"complete (?:system |server |database )?takeover|root access|"
    r"all (?:customer|user) (?:data|records) (?:were|was) (?:exposed|stolen))\b",
    re.IGNORECASE,
)

# Reference mappings between scanner vulnerability types and standard CWE identifiers.
# Used for consistency validation; discrepancies are flagged for human review.
COMMON_CWE_MAPPINGS: dict[str, str] = {
    "sql injection": "CWE-89",
    "sqli": "CWE-89",
    "cross-site scripting": "CWE-79",
    "reflected xss": "CWE-79",
    "stored xss": "CWE-79",
    "xss": "CWE-79",
    "csrf": "CWE-352",
    "cross-site request forgery": "CWE-352",
    "request forgery": "CWE-352",
    "path traversal": "CWE-22",
    "directory traversal": "CWE-22",
    "server-side request forgery": "CWE-918",
    "ssrf": "CWE-918",
    "command injection": "CWE-78",
    "os command injection": "CWE-78",
    "insecure direct object": "CWE-639",
    "direct object": "CWE-639",
    "idor": "CWE-639",
    "error message": "CWE-209",
    "verbose error": "CWE-209",
    "exposed service": "CWE-200",
}


def _normalise(text: str) -> str:
    """Normalize whitespace and case for robust matching."""
    return re.sub(r"\s+", " ", (text or "")).lower()


def _endpoint(url: str) -> str:
    """Normalize URL to scheme://host/path for comparing touched endpoints."""
    url = (url or "").strip().lower()
    url = re.split(r"[?#]", url, 1)[0]
    return url.rstrip("/")


def _expected_cwe_for(kind: str) -> str | None:
    """Return the reference CWE for a given vulnerability kind, if known."""
    kind_lower = (kind or "").strip().lower()
    for pattern, cwe in COMMON_CWE_MAPPINGS.items():
        if pattern in kind_lower:
            return cwe
    return None


def check(raw: RawFinding, triaged: TriagedFinding) -> list[str]:
    """Inspect a triaged finding against ground truth, returning any raised flags."""
    flags: list[str] = []
    corpus = _normalise(raw.evidence_corpus())
    prose = " ".join([
        triaged.title,
        triaged.summary,
        triaged.reproduction,
        triaged.remediation,
    ])

    # 1. CVE validation: Reject fabricated CVE references not present in scanner evidence
    for cve in set(CVE_RE.findall(prose)):
        if cve.lower() not in corpus:
            flags.append(f"invented CVE reference: {cve.upper()}")

    # 2. CWE catalogue validation: Reject unknown CWE identifiers
    cited_cwes = set(CWE_RE.findall(prose))
    if triaged.cwe_id:
        cited_cwes.add(triaged.cwe_id)

    for cwe in cited_cwes:
        if not lookup_cwe(cwe):
            flags.append(f"CWE not in catalogue: {cwe.upper()}")

    # 3. Vulnerability classification consistency check
    expected_cwe = _expected_cwe_for(raw.kind)
    if expected_cwe and triaged.cwe_id and triaged.cwe_id.upper() != expected_cwe:
        flags.append(
            f"classification mismatch: scanner reported '{raw.kind}' "
            f"(commonly {expected_cwe}), but finding was assigned {triaged.cwe_id} — "
            f"manual verification recommended"
        )

    # 4. Score stated in prose vs computed score
    for stated in SCORE_RE.findall(VECTOR_IN_PROSE.sub(" ", prose)):
        try:
            if abs(float(stated) - triaged.cvss_score) > 0.05:
                flags.append(
                    f"stated CVSS {stated} does not match computed {triaged.cvss_score}"
                )
        except ValueError:
            flags.append(f"unparseable CVSS score in prose: {stated}")

    # 5. Vector validation and mathematical consistency
    if triaged.cvss_vector:
        if not VECTOR_RE.match(triaged.cvss_vector):
            flags.append(f"malformed CVSS vector: {triaged.cvss_vector}")
        else:
            computed_score, expected_sev = score_cvss(triaged.cvss_vector)
            if abs(computed_score - triaged.cvss_score) > 0.001:
                flags.append(f"score {triaged.cvss_score} does not follow from vector")
            if triaged.severity and triaged.severity != expected_sev:
                flags.append(
                    f"severity rating '{triaged.severity}' does not match "
                    f"vector rating '{expected_sev}'"
                )

    # 6. URL endpoint verification
    scanned = {_endpoint(u) for u in URL_RE.findall(raw.evidence_corpus())}
    scanned.add(_endpoint(raw.url))
    scanned.discard("")
    for url in set(URL_RE.findall(prose)):
        clean_url = _endpoint(url.rstrip(".,);"))
        if clean_url and clean_url not in scanned:
            flags.append(f"URL not present in scan data: {url}")

    # 7. Unsupported impact claims: checked against evidence corpus to prevent false positives
    for match in OVERCLAIM_RE.finditer(prose):
        phrase = match.group(0)
        if phrase.lower() not in corpus:
            flags.append(f"unsupported impact claim: {phrase.lower()}")

    return flags


def enforce(raw: RawFinding, triaged: TriagedFinding, redact: bool = True) -> TriagedFinding:
    """Run grounding validation and optionally redact unsupported claims from text."""
    triaged.flags = check(raw, triaged)
    if not (redact and triaged.flags):
        return triaged

    corpus = _normalise(raw.evidence_corpus())

    def scrub(text: str) -> str:
        text = CVE_RE.sub(
            lambda m: m.group(0) if m.group(0).lower() in corpus else "[UNVERIFIED REFERENCE REMOVED]",
            text,
        )
        text = OVERCLAIM_RE.sub(
            lambda m: m.group(0) if m.group(0).lower() in corpus else "[UNSUPPORTED CLAIM REMOVED]",
            text,
        )
        return text

    triaged.title = scrub(triaged.title)
    triaged.summary = scrub(triaged.summary)
    triaged.reproduction = scrub(triaged.reproduction)
    triaged.remediation = scrub(triaged.remediation)

    # If the cited CWE identifier does not exist in the catalogue, drop it
    if any(f.startswith("CWE not in catalogue") for f in triaged.flags):
        triaged.cwe_id = ""
        triaged.cwe_name = ""

    return triaged
