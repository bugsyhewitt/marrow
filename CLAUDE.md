# marrow — Worker Operating Manual

Part of the [necromancer](https://github.com/bugsyhewitt/necromancer) offensive-security suite.

## What this tool does

marrow is a prototype pollution payload generator and static JS vulnerability scanner.
It is pure Python with no headless browser dependency.

## Architecture

```
src/marrow/
  __init__.py      — version = "0.1.0"
  payloads.py      — ProtoPayload dataclass + payload generation functions
  scanner.py       — VulnerablePattern dataclass + regex-based JS static analysis
  prober.py        — HTTP probe via stdlib urllib (no requests dependency)
  cli.py           — Click CLI: generate / scan-js / probe subcommands
tests/
  test_payloads.py
  test_scanner.py
  test_prober.py
```

## Stack

- Python 3.11+
- click (CLI)
- stdlib only for HTTP (urllib) — no requests
- uv / pip for install; hatchling for build

## Running

```bash
pip install -e ".[dev]"
pytest -q
marrow --help
```

## v0.1 scope

Payload generation (10 techniques), static JS regex analysis, basic HTTP probing.

## Post-v0.1 directions

- AST-based JS analysis using `tree-sitter` for lower false-positive rate
- Headless browser probe (Playwright) for client-side prototype pollution testing
- Response diffing to detect pollution via behavioral change rather than just key presence
- Output formats: SARIF, JSON report, Markdown
- Integration with Pho3nix via `pho3nix_config/tool.yaml`

## Defining niche

marrow occupies the payload-generation + static-analysis slot in the suite.
It does NOT perform active exploitation, shell spawning, or dynamic runtime analysis.
Dynamic/browser-based testing is explicitly deferred to post-v0.1.

## Security note

marrow sends HTTP requests to targets. Only use against systems you own or have
written permission to test.
