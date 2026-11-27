"""HTTP probe: inject prototype pollution payloads and check responses."""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .payloads import ProtoPayload


def probe_url(
    url: str,
    payloads: list[ProtoPayload],
    method: str = "GET",
    timeout: int = 10,
    probe_key: str = "polluted",
) -> list[dict[str, Any]]:
    """Send prototype pollution payloads to a URL.

    For each payload, sends the request and checks whether probe_key
    appears in the response body (a crude server-side pollution indicator).
    Returns a list of result dicts with keys: payload, response_code, indicators, error.
    """
    results: list[dict[str, Any]] = []

    for payload in payloads:
        result: dict[str, Any] = {
            "payload": payload,
            "response_code": None,
            "indicators": [],
            "error": None,
        }

        try:
            if payload.technique in ("json-proto", "json-constructor", "nodejs-json-proto", "nodejs-json-constructor"):
                # Send as JSON body
                data = payload.param_value.encode()
                req = urllib.request.Request(
                    url,
                    data=data,
                    method="POST",
                    headers={"Content-Type": "application/json"},
                )
            elif method.upper() == "POST":
                body = urllib.parse.urlencode({payload.param_name: payload.param_value})
                req = urllib.request.Request(
                    url,
                    data=body.encode(),
                    method="POST",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            else:
                sep = "&" if "?" in url else "?"
                probe_url_full = f"{url}{sep}{urllib.parse.quote(payload.param_name)}={urllib.parse.quote(payload.param_value)}"
                req = urllib.request.Request(probe_url_full, method="GET")

            with urllib.request.urlopen(req, timeout=timeout) as resp:
                result["response_code"] = resp.status
                body_text = resp.read().decode(errors="replace")
                if probe_key in body_text:
                    result["indicators"].append(f"probe_key '{probe_key}' found in response body")
        except urllib.error.HTTPError as exc:
            result["response_code"] = exc.code
            try:
                body_text = exc.read().decode(errors="replace")
                if probe_key in body_text:
                    result["indicators"].append(f"probe_key '{probe_key}' found in error body")
            except Exception:
                pass
        except Exception as exc:
            result["error"] = str(exc)

        results.append(result)

    return results
