"""Parsers for ingesting vulnerability scanner outputs into RawFinding objects.

Supports VibeScanner, Burp Suite (Professional XML/JSON exports and Enterprise REST),
OWASP ZAP, and Nmap JSON outputs.
"""
from __future__ import annotations

import html
import json
import logging
import re
from pathlib import Path
from typing import Any

from .models import RawFinding

logger = logging.getLogger(__name__)

_TAGS = re.compile(r"<[^>]+>")
_PARAM_RE = re.compile(
    r"(?:^|[\s(>])The\s+(?:<[^>]+>\s*)?([\w.\-]{1,40})(?:\s*<[^>]+>)?\s+"
    r"(?:URL parameter|parameter|cookie|header)",
    re.IGNORECASE,
)


def _s(value: Any) -> str:
    """Convert any value to a stripped string, returning empty string for None."""
    return "" if value is None else str(value).strip()


def parse_vibescanner(data: dict[str, Any]) -> list[RawFinding]:
    """Parse VibeScanner JSON data into normalized RawFinding instances."""
    if not isinstance(data, dict):
        raise ValueError("VibeScanner data must be a JSON object.")

    findings_raw = data.get("findings")
    if findings_raw is None:
        findings_raw = data.get("results")
    if not isinstance(findings_raw, list):
        return []

    out: list[RawFinding] = []
    for i, item in enumerate(findings_raw):
        if not isinstance(item, dict):
            logger.debug("Skipping non-dict finding in VibeScanner output at index %d", i)
            continue

        item_id = _s(item.get("id")) or f"VS-{i + 1:03d}"
        kind = _s(item.get("type") or item.get("kind") or "Unknown")
        method = _s(item.get("method") or "GET").upper()

        raw_extra = {
            k: v for k, v in item.items()
            if k not in {
                "id", "type", "kind", "url", "parameter", "param",
                "method", "payload", "evidence", "proof",
            }
        }

        out.append(RawFinding(
            id=item_id,
            scanner="VibeScanner",
            kind=kind,
            url=_s(item.get("url")),
            parameter=_s(item.get("parameter") or item.get("param")),
            method=method,
            payload=_s(item.get("payload")),
            evidence=_s(item.get("evidence") or item.get("proof")),
            raw=raw_extra,
        ))
    return out


def parse_zap(data: dict[str, Any]) -> list[RawFinding]:
    """Parse OWASP ZAP scan export JSON into RawFinding instances."""
    if not isinstance(data, dict):
        raise ValueError("ZAP data must be a JSON object.")

    sites = data.get("site")
    if not isinstance(sites, list):
        return []

    out: list[RawFinding] = []
    n = 0
    for site in sites:
        if not isinstance(site, dict):
            continue
        alerts = site.get("alerts")
        if not isinstance(alerts, list):
            continue
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            instances = alert.get("instances")
            if not isinstance(instances, list) or not instances:
                instances = [{}]
            for inst in instances:
                if not isinstance(inst, dict):
                    inst = {}
                n += 1
                out.append(RawFinding(
                    id=f"ZAP-{n:03d}",
                    scanner="OWASP ZAP",
                    kind=_s(alert.get("alert") or alert.get("name") or "Unknown"),
                    url=_s(inst.get("uri")),
                    parameter=_s(inst.get("param")),
                    method=_s(inst.get("method") or "GET").upper(),
                    payload=_s(inst.get("attack")),
                    evidence=_s(inst.get("evidence")),
                    raw={"confidence": _s(alert.get("confidence"))},
                ))
    return out


def parse_nmap(data: dict[str, Any]) -> list[RawFinding]:
    """Parse Nmap JSON output into RawFinding instances for exposed services."""
    if not isinstance(data, dict):
        raise ValueError("Nmap data must be a JSON object.")

    hosts = data.get("hosts")
    if not isinstance(hosts, list):
        return []

    out: list[RawFinding] = []
    n = 0
    for host in hosts:
        if not isinstance(host, dict):
            continue
        ports = host.get("ports")
        if not isinstance(ports, list):
            continue
        for port in ports:
            if not isinstance(port, dict):
                continue
            if _s(port.get("state")).lower() != "open":
                continue
            n += 1
            port_num = _s(port.get("port"))
            service = _s(port.get("service")) or "unknown"
            product = _s(port.get("product"))
            out.append(RawFinding(
                id=f"NMAP-{n:03d}",
                scanner="Nmap",
                kind=f"Exposed service: {service}",
                url=f"{_s(host.get('address'))}:{port_num}",
                method="TCP",
                evidence=product or service,
                raw={"port": port_num, "version": _s(port.get("version"))},
            ))
    return out


def _detag(value: Any) -> str:
    """Normalize HTML fragments from scanner descriptions into clean plain text."""
    text = _s(value)
    if not text:
        return ""
    text = text.replace("<br>", " ").replace("<br/>", " ").replace("</p>", " ")
    return re.sub(r"\s+", " ", html.unescape(_TAGS.sub("", text))).strip()


def _burp_host(item: dict[str, Any]) -> str:
    """Extract host string safely, handling dict structures from XML converters."""
    host = item.get("origin") or item.get("host") or ""
    if isinstance(host, dict):
        host = host.get("#text") or host.get("value") or host.get("name") or ""
    return _s(host).rstrip("/")


def parse_burp(data: dict[str, Any]) -> list[RawFinding]:
    """Parse Burp Suite scanner issues from Professional or Enterprise exports."""
    if not isinstance(data, dict):
        raise ValueError("Burp data must be a JSON object.")

    issues = data.get("issues")
    if issues is None:
        events = data.get("issue_events")
        if isinstance(events, list):
            issues = [e.get("issue", e) if isinstance(e, dict) else e for e in events]

    if not isinstance(issues, list):
        return []

    out: list[RawFinding] = []
    for n, item in enumerate(issues, 1):
        if not isinstance(item, dict):
            continue
        detail = _detag(
            item.get("issue_detail") or item.get("issueDetail")
            or item.get("detail") or item.get("description")
        )
        background = _detag(item.get("issue_background") or item.get("issueBackground"))
        path = _s(item.get("path"))
        url = _burp_host(item) + path

        parameter = _s(item.get("parameter") or item.get("param"))
        if not parameter:
            match = _PARAM_RE.search(detail or "")
            parameter = match.group(1) if match else ""

        serial = (
            _s(item.get("serial_number"))
            or _s(item.get("serialNumber"))
            or _s(item.get("id"))
            or f"BURP-{n:03d}"
        )
        kind = _s(item.get("name") or item.get("issue_name") or "Unknown")

        raw_extra = {
            k: v for k, v in {
                "burp_severity": _s(item.get("severity")),
                "burp_confidence": _s(item.get("confidence")),
                "issue_background": background,
            }.items() if v
        }

        out.append(RawFinding(
            id=serial,
            scanner="Burp Suite",
            kind=kind,
            url=url,
            parameter=parameter,
            method=_s(item.get("method") or "GET").upper(),
            payload=_s(item.get("payload")),
            evidence=detail,
            raw=raw_extra,
        ))
    return out


PARSERS = {
    "vibescanner": parse_vibescanner,
    "burp": parse_burp,
    "zap": parse_zap,
    "nmap": parse_nmap,
}


def detect_format(data: dict[str, Any]) -> str:
    """Infer the scanner output format based on key payload markers."""
    if not isinstance(data, dict):
        return "vibescanner"
    if "site" in data:
        return "zap"
    if "hosts" in data:
        return "nmap"
    if "issues" in data or "issue_events" in data:
        return "burp"
    return "vibescanner"


def load(path: str | Path, fmt: str | None = None) -> list[RawFinding]:
    """Load and parse findings from a JSON scanner file."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Scanner file not found: {file_path}")

    raw_content = file_path.read_text(encoding="utf-8")
    data = json.loads(raw_content)

    if isinstance(data, list):
        data = {"findings": data}
    elif not isinstance(data, dict):
        raise ValueError(f"Expected a JSON object or array in {file_path}")

    fmt = fmt or detect_format(data)
    if fmt not in PARSERS:
        raise ValueError(f"Unknown scanner format {fmt!r}; supported formats: {sorted(PARSERS)}")

    findings = PARSERS[fmt](data)
    if not findings:
        raise ValueError(f"No findings parsed from {file_path} (detected format: {fmt})")
    return findings
