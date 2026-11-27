"""CLI entry point for marrow."""
from __future__ import annotations

import json
import sys

import click

from .payloads import prototype_pollution_payloads, server_side_payloads
from .prober import probe_url as _probe_url
from .scanner import scan_js_for_vulnerable_patterns


@click.group()
@click.version_option(package_name="marrow")
def cli() -> None:
    """marrow — prototype pollution payload generator and static JS scanner."""


@cli.command("generate")
@click.option("--key", default="polluted", show_default=True, help="Probe key to inject.")
@click.option("--value", default="1", show_default=True, help="Probe value to inject.")
@click.option("--server-side", is_flag=True, help="Include server-side Node.js payloads.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def generate(key: str, value: str, server_side: bool, as_json: bool) -> None:
    """Generate prototype pollution payloads."""
    payloads = prototype_pollution_payloads(key, value)
    if server_side:
        payloads += server_side_payloads(key, value)

    if as_json:
        click.echo(
            json.dumps(
                [
                    {
                        "technique": p.technique,
                        "param_name": p.param_name,
                        "param_value": p.param_value,
                        "description": p.description,
                    }
                    for p in payloads
                ],
                indent=2,
            )
        )
    else:
        for p in payloads:
            click.echo(f"[{p.technique}] {p.param_name}={p.param_value}")
            click.echo(f"  {p.description}")


@cli.command("scan-js")
@click.argument("file", type=click.Path(exists=True, readable=True))
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def scan_js(file: str, as_json: bool) -> None:
    """Statically scan a JS file for prototype pollution patterns."""
    with open(file, encoding="utf-8", errors="replace") as fh:
        content = fh.read()

    findings = scan_js_for_vulnerable_patterns(content)

    if not findings:
        click.echo("No vulnerable patterns found.")
        return

    if as_json:
        click.echo(
            json.dumps(
                [
                    {
                        "pattern_type": f.pattern_type,
                        "line_number": f.line_number,
                        "code_snippet": f.code_snippet,
                        "description": f.description,
                        "confidence": f.confidence,
                    }
                    for f in findings
                ],
                indent=2,
            )
        )
    else:
        for f in findings:
            click.echo(
                f"[{f.confidence.upper()}] line {f.line_number}: [{f.pattern_type}] {f.code_snippet}"
            )
            click.echo(f"  {f.description}")


@cli.command("probe")
@click.option("--url", required=True, help="Target URL to probe.")
@click.option("--key", default="polluted", show_default=True)
@click.option("--value", default="1", show_default=True)
@click.option("--method", default="GET", show_default=True, type=click.Choice(["GET", "POST"]))
@click.option("--server-side", is_flag=True, help="Include server-side payloads.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def probe(url: str, key: str, value: str, method: str, server_side: bool, as_json: bool) -> None:
    """Send prototype pollution payloads to a URL and report responses."""
    payloads = prototype_pollution_payloads(key, value)
    if server_side:
        payloads += server_side_payloads(key, value)

    results = _probe_url(url, payloads, method=method, probe_key=key)

    if as_json:
        click.echo(
            json.dumps(
                [
                    {
                        "technique": r["payload"].technique,
                        "response_code": r["response_code"],
                        "indicators": r["indicators"],
                        "error": r["error"],
                    }
                    for r in results
                ],
                indent=2,
            )
        )
    else:
        for r in results:
            status = r["response_code"] or "ERR"
            indicators = ", ".join(r["indicators"]) if r["indicators"] else "none"
            click.echo(
                f"[{r['payload'].technique}] HTTP {status} — indicators: {indicators}"
            )
            if r["error"]:
                click.echo(f"  error: {r['error']}")
