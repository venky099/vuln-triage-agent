"""Tests for the web UI: the toggle contract, input guards, and key handling.

Uses FastAPI's TestClient, so no server and no network.

Run: pytest -q
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

fastapi = pytest.importorskip("fastapi", reason="web extra not installed")
from fastapi.testclient import TestClient                       # noqa: E402

from webui.app import app                                       # noqa: E402
from webui.security import (                                    # noqa: E402
    MAX_SCAN_BYTES, RateLimiter, Rejected, cap_findings,
    validate_api_key, validate_scan,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = (ROOT / "data" / "sample_scan.json").read_text(encoding="utf-8")

client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """The limiter is module-level and shared, so without this the suite
    exhausts its own quota and later tests fail with 429 depending on order."""
    from webui.app import limiter
    limiter._hits.clear()
    yield
    limiter._hits.clear()


def triage(scan=SAMPLE, backend="mock", api_key=None):
    return client.post("/api/triage",
                       json={"scan": scan, "backend": backend, "api_key": api_key})


# --------------------------- pages and static ---------------------------

def test_index_renders():
    r = client.get("/")
    assert r.status_code == 200
    assert "Grounding checks" in r.text


def test_health():
    body = client.get("/api/health").json()
    assert body["ok"] is True
    assert body["version"]


def test_html_report_escapes_client_supplied_fields():
    """Regression: /api/render accepts a client-built result, so severity,
    score and cwe_id are attacker-controlled and must not reach the HTML raw."""
    import re as _re
    from triage.agent import TriageResult
    from triage.models import TriagedFinding
    from triage.report import to_html
    evil = TriagedFinding(
        source_id="X", title="t", cwe_id='CWE-1"><script>alert(1)</script>',
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score="<img src=x onerror=alert(1)>", severity="Critical",
        summary="s", reproduction="r", remediation="m")
    out = to_html(TriageResult(findings=[evil]))
    assert not _re.search(r"<(script|img)", out)
    assert "&lt;script&gt;" in out


def test_example_endpoint_serves_the_sample():
    body = client.get("/api/example").json()
    assert len(body["findings"]) == 6


# --------------------------- the toggle contract ---------------------------

def test_triage_returns_both_views():
    body = triage().json()
    assert body["ok"] is True
    assert len(body["ungrounded"]) == len(body["grounded"]) > 0
    assert body["duplicatesRemoved"] == 1          # the two SQLi findings merge


def test_views_differ_exactly_where_claims_were_ungrounded():
    """The demo depends on this: same findings, different text."""
    body = triage().json()
    ung = {f["source_id"]: f for f in body["ungrounded"]}
    gr = {f["source_id"]: f for f in body["grounded"]}
    assert ung.keys() == gr.keys()

    changed = [k for k in gr if gr[k]["summary"] != ung[k]["summary"]
               or gr[k]["cwe_id"] != ung[k]["cwe_id"]]
    assert changed, "grounding should have altered at least one finding"
    assert body["flaggedCount"] == len(changed)

    for k in gr:
        if not gr[k]["flags"]:
            # untouched findings must be byte-identical across both views
            assert gr[k]["summary"] == ung[k]["summary"]


PROSE = ("title", "summary", "reproduction", "remediation")


def _prose(findings) -> str:
    """Only the fields that end up in the report body.

    The flag messages deliberately name the removed reference -- a reviewer has
    to know which claim was pulled -- so they are not part of this check.
    """
    return " ".join(f[k] for f in findings for k in PROSE)


def test_fabricated_cve_present_ungrounded_and_gone_grounded():
    body = triage().json()
    assert "CVE-2019-3253" in _prose(body["ungrounded"])
    assert "CVE-2019-3253" not in _prose(body["grounded"])
    assert "UNVERIFIED REFERENCE REMOVED" in _prose(body["grounded"])


def test_flag_message_still_names_the_removed_reference():
    """Redaction hides the claim from the report, not from the reviewer."""
    body = triage().json()
    flags = [x for f in body["grounded"] for x in f["flags"]]
    assert any("CVE-2019-3253" in x for x in flags)


def test_scores_are_consistent_across_both_views():
    from triage.tools import score_cvss
    body = triage().json()
    for view in ("ungrounded", "grounded"):
        for f in body[view]:
            assert f["cvss_score"] == score_cvss(f["cvss_vector"])[0]


# --------------------------- input guards ---------------------------

@pytest.mark.parametrize("scan,fragment", [
    ("", "Paste a scan"),
    ("{not json", "Invalid JSON"),
    ('{"findings": []}', "No findings"),
])
def test_bad_input_rejected(scan, fragment):
    r = triage(scan=scan)
    assert r.status_code == 400
    assert fragment in r.json()["error"]


def test_finding_cap_enforced():
    many = json.dumps({"findings": [
        {"id": "x%d" % i, "type": "SQL Injection", "url": "https://t/%d" % i,
         "parameter": "id", "evidence": "e"} for i in range(80)]})
    r = triage(scan=many)
    assert r.status_code == 400
    assert "caps at" in r.json()["error"]


def test_oversized_scan_gets_a_useful_message():
    """Regression: pydantic's max_length must not pre-empt validate_scan()."""
    big = json.dumps({"findings": [{"id": "x", "type": "SQL Injection",
                                    "evidence": "e" * (MAX_SCAN_BYTES + 5000)}]})
    r = triage(scan=big)
    assert r.status_code == 400
    assert "limit is" in r.json()["error"]


def test_unknown_backend_rejected():
    r = client.post("/api/triage", json={"scan": SAMPLE, "backend": "evil"})
    assert r.status_code == 422


# --------------------------- API key handling ---------------------------

def test_openai_requires_a_key():
    r = triage(backend="openai", api_key=None)
    assert r.status_code == 400
    assert "your own OpenAI key" in r.json()["error"]


def test_malformed_key_rejected_before_any_network_call():
    r = triage(backend="openai", api_key="not-a-key")
    assert r.status_code == 400
    assert "does not look like" in r.json()["error"]


def test_key_never_appears_in_any_response():
    """Errors are the usual place secrets leak. They must not here."""
    key = "sk-" + "A" * 40
    r = triage(backend="openai", api_key=key)
    assert key not in r.text
    assert "sk-" not in r.text


def test_validate_api_key_shape():
    assert validate_api_key(None) is None
    assert validate_api_key("   ") is None
    assert validate_api_key("sk-" + "b" * 30) == "sk-" + "b" * 30
    for bad in ["hello", "sk-short", "x" * 400]:
        with pytest.raises(Rejected):
            validate_api_key(bad)


# --------------------------- render / download ---------------------------

@pytest.mark.parametrize("fmt,marker", [
    ("markdown", "# Vulnerability Assessment Report"),
    ("html", "<!doctype html>"),
    ("json", '"findings"'),
])
def test_render_formats(fmt, marker):
    payload = triage().json()
    r = client.post("/api/render", json={"payload": payload, "format": fmt})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and marker in body["body"]


def test_render_rejects_malformed_payload():
    r = client.post("/api/render", json={"payload": {"grounded": [{"nope": 1}]},
                                         "format": "markdown"})
    assert r.status_code == 400


# --------------------------- rate limiting ---------------------------

def test_rate_limiter_blocks_then_is_per_client():
    rl = RateLimiter(max_calls=3, window_seconds=60)
    for _ in range(3):
        rl.check("1.1.1.1")
    with pytest.raises(Rejected, match="Rate limit"):
        rl.check("1.1.1.1")
    rl.check("2.2.2.2")          # a different client is unaffected


def test_cap_findings_helper():
    cap_findings(1)
    with pytest.raises(Rejected):
        cap_findings(10_000)


def test_validate_scan_accepts_normal_input():
    assert validate_scan(SAMPLE) == SAMPLE


# --------------------------- rate limiting is not a suggestion ---------------------------
#
# _client() used to read the LEFTMOST X-Forwarded-For entry, which is whatever
# the caller typed. Rotating it made every request look like a new visitor and
# the limiter did nothing at all.

def _spoof_burst(n, xff):
    """n requests, each with a different attacker-controlled XFF prefix.

    The trailing address is what a real proxy appends -- the part an attacker
    cannot forge -- so all n requests come from one client.
    """
    blocked = 0
    for i in range(n):
        r = client.post("/api/triage",
                        json={"scan": SAMPLE, "backend": "mock"},
                        headers={"X-Forwarded-For": xff(i)})
        if r.status_code == 429:
            blocked += 1
    return blocked


def test_rotating_x_forwarded_for_does_not_bypass_the_limit():
    from webui.app import limiter
    limiter._hits.clear()
    limit = limiter.max_calls
    blocked = _spoof_burst(limit + 5, lambda i: "10.0.0.{}, 203.0.113.9".format(i))
    assert blocked == 5, "rotating the forgeable part of XFF bypassed the limiter"


def test_client_identity_ignores_the_header_when_no_proxy_is_configured():
    import webui.app as app_mod
    original = app_mod.PROXY_DEPTH
    app_mod.PROXY_DEPTH = 0
    app_mod.limiter._hits.clear()
    try:
        blocked = _spoof_burst(app_mod.limiter.max_calls + 3, lambda i: "10.0.0.{}".format(i))
        assert blocked == 3
    finally:
        app_mod.PROXY_DEPTH = original
        app_mod.limiter._hits.clear()


def test_flooding_the_table_cannot_reset_someone_elses_limit():
    """Eviction used to clear() the whole table, which was a free reset button."""
    lim = RateLimiter(max_calls=3, window_seconds=60, max_clients=10)
    for _ in range(3):
        lim.check("victim")
    for i in range(50):
        try:
            lim.check("filler-{}".format(i))
        except Rejected:
            pass
    with pytest.raises(Rejected):
        lim.check("victim")
    assert len(lim._hits) <= 10


# --------------------------- Render Endpoint & Concurrency Hardening ---------------------------

def test_render_rejects_oversized_title():
    finding = {
        "source_id": "T-1",
        "title": "A" * 350,
        "cwe_id": "CWE-89",
        "cvss_score": 9.8,
        "severity": "Critical",
        "summary": "Summary text",
        "reproduction": "Repro step",
        "remediation": "Remediation guidance",
    }
    r = client.post("/api/render", json={"payload": {"grounded": [finding]}, "format": "markdown"})
    assert r.status_code == 400


def test_render_rejects_out_of_range_cvss_score():
    finding = {
        "source_id": "T-1",
        "title": "SQL Injection",
        "cwe_id": "CWE-89",
        "cvss_score": 15.0,
        "severity": "Critical",
        "summary": "Summary text",
        "reproduction": "Repro step",
        "remediation": "Remediation guidance",
    }
    r = client.post("/api/render", json={"payload": {"grounded": [finding]}, "format": "markdown"})
    assert r.status_code == 400
    assert "Invalid CVSS score" in r.json()["error"]


def test_render_rejects_invalid_cwe_shape():
    finding = {
        "source_id": "T-1",
        "title": "SQL Injection",
        "cwe_id": "CWE-NOT-A-NUMBER",
        "cvss_score": 9.8,
        "severity": "Critical",
        "summary": "Summary text",
        "reproduction": "Repro step",
        "remediation": "Remediation guidance",
    }
    r = client.post("/api/render", json={"payload": {"grounded": [finding]}, "format": "markdown"})
    assert r.status_code == 400
    assert "Invalid CWE identifier shape" in r.json()["error"]


def test_render_rejects_non_list_grounded():
    r = client.post("/api/render", json={"payload": {"grounded": "not a list"}, "format": "markdown"})
    assert r.status_code == 400
    assert "array" in r.json()["error"]


def test_to_markdown_sanitizes_newlines_in_target():
    from triage.agent import TriageResult
    from triage.models import TriagedFinding
    from triage.report import to_markdown

    f = TriagedFinding(
        source_id="T-1",
        title="SQL Injection",
        cwe_id="CWE-89",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score=9.8,
        severity="Critical",
        summary="Concatenation flaw.",
        reproduction="Submit payload.",
        remediation="Parameterize.",
    )
    md = to_markdown(TriageResult(findings=[f]), target="evil.example\n\n## Injected Section")
    assert "\n\n## Injected Section" not in md
    assert "**Target:** evil.example ## Injected Section" in md


def test_rate_limiter_multithreaded_concurrency():
    import concurrent.futures

    lim = RateLimiter(max_calls=50, window_seconds=60)
    errors = []

    def hit(client_id):
        try:
            lim.check(client_id)
        except Exception as exc:
            errors.append(exc)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(hit, f"client-{i % 5}") for i in range(100)]
        concurrent.futures.wait(futures)

    # Some will be Rejected (due to hitting limit of 50 per client), but no internal concurrency errors
    for err in errors:
        assert isinstance(err, Rejected)


def test_bug5_webui_partial_finding_failure_resilience(monkeypatch):
    """Bug 5: An unprocessable finding in web triage does not discard successful findings."""
    from triage.agent import TriageAgent

    original_triage_one = TriageAgent.triage_one

    call_count = 0
    def flaky_triage_one(self, raw, duplicates=None):
        nonlocal call_count
        call_count += 1
        if raw.id == "VS-004":
            raise RuntimeError("Temporary provider processing error")
        return original_triage_one(self, raw, duplicates)

    monkeypatch.setattr(TriageAgent, "triage_one", flaky_triage_one)

    r = triage()
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    # The other findings succeeded and are returned
    assert len(body["grounded"]) > 0
    source_ids = [f["source_id"] for f in body["grounded"]]
    assert "VS-004" not in source_ids
    assert "VS-001" in source_ids


