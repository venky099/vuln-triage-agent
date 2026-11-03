"""Command-line interface for vuln-triage-agent."""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import __version__
from .agent import TriageAgent
from .llm import get_backend
from .parsers import load
from .report import to_html, to_json, to_markdown

logger = logging.getLogger("vulntriage")


def _utf8_out() -> None:
    """Ensure standard output and error streams handle UTF-8 encoding on Windows."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for processing scanner results and generating reports."""
    _utf8_out()
    ap = argparse.ArgumentParser(
        prog="vulntriage",
        description="Convert automated security scanner output into a grounded, client-ready pentest report.",
    )
    ap.add_argument("scan", help="Path to scanner output JSON file")
    ap.add_argument("-o", "--out", help="Output report file path (default: stdout)")
    ap.add_argument(
        "-f", "--format",
        choices=["markdown", "html", "json"],
        default="markdown",
        help="Report output format (default: markdown)",
    )
    ap.add_argument(
        "--input-format",
        choices=["vibescanner", "burp", "zap", "nmap"],
        help="Explicitly specify scanner input format instead of auto-detecting",
    )
    ap.add_argument(
        "--backend",
        choices=["openai", "ollama", "mock"],
        help="LLM backend to use (default: auto-detected)",
    )
    ap.add_argument(
        "--no-grounding",
        action="store_true",
        help="Disable grounding verification (for evaluation comparison only)",
    )
    ap.add_argument(
        "--no-redact",
        action="store_true",
        help="Retain ungrounded claims in text while still applying warning flags",
    )
    ap.add_argument("--target", default="", help="Target identifier or URL for report header")
    ap.add_argument("--quiet", action="store_true", help="Suppress progress output")
    ap.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)

    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")

    # Load findings
    try:
        findings = load(args.scan, args.input_format)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Error reading scan: {exc}", file=sys.stderr)
        return 2

    target = args.target
    if not target:
        try:
            raw_scan_data = json.loads(Path(args.scan).read_text(encoding="utf-8"))
            if isinstance(raw_scan_data, dict):
                target = str(raw_scan_data.get("target", ""))
        except Exception:
            target = ""

    # Initialize backend and agent
    try:
        backend = get_backend(args.backend)
    except Exception as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    agent = TriageAgent(
        backend=backend,
        grounding=not args.no_grounding,
        redact=not args.no_redact,
    )

    def progress(i: int, total: int, raw_finding) -> None:
        if not args.quiet:
            print(f"  [{i}/{total}] {raw_finding.id} {raw_finding.kind}", file=sys.stderr)

    if not args.quiet:
        print(f"Backend: {agent.backend.name} | {len(findings)} findings loaded", file=sys.stderr)

    try:
        result = agent.run(findings, progress=progress)
    except Exception as exc:
        print(f"Triage execution failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    renderers = {"markdown": to_markdown, "html": to_html, "json": to_json}
    output = renderers[args.format](result, target)

    if args.out:
        try:
            Path(args.out).write_text(output, encoding="utf-8")
            if not args.quiet:
                print(f"Wrote report to {args.out}", file=sys.stderr)
        except OSError as exc:
            print(f"Error writing output file: {exc}", file=sys.stderr)
            return 2
    else:
        print(output)

    if not args.quiet:
        counts = result.counts()
        print(
            f"\n{len(result.findings)} findings ({result.duplicates_removed} duplicates merged) | "
            f"{counts['Critical']} critical, {counts['High']} high, {counts['Medium']} medium, {counts['Low']} low",
            file=sys.stderr,
        )
        if result.flagged:
            print(
                f"{len(result.flagged)} finding(s) contain ungrounded claims or discrepancies requiring human review",
                file=sys.stderr,
            )

    # Always report missing or failed findings to stderr, even when --quiet is active
    if result.errors:
        print(
            f"\n{len(result.errors)} finding(s) failed triage and are omitted from this report:",
            file=sys.stderr,
        )
        for source_id, reason in result.errors:
            print(f"  - {source_id}: {reason}", file=sys.stderr)

    # Return non-zero if human verification or errors occurred
    return 1 if (result.flagged or result.errors) else 0


if __name__ == "__main__":
    raise SystemExit(main())
