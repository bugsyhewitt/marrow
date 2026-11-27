"""Static JavaScript source analysis for prototype pollution vulnerabilities."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class VulnerablePattern:
    pattern_type: str
    line_number: int
    code_snippet: str
    description: str
    confidence: str  # "high" | "medium" | "low"


_PATTERNS: list[tuple[str, str, str, str]] = [
    # (pattern_type, regex, description, confidence)
    (
        "recursive-merge",
        r"(?:function\s+\w*merge\w*|function\s+\w*extend\w*|function\s+\w*assign\w*)"
        r"[^{]*\{[^}]*for\s*\([^)]*in\b",
        "Recursive merge/extend function with for-in loop — high risk of prototype pollution",
        "high",
    ),
    (
        "recursive-merge",
        r"for\s*\(\s*(?:const|let|var)?\s*\w+\s+in\s+\w+\s*\)[^{]*\n[^\n]*\[",
        "for-in loop with bracket assignment — potential unguarded prototype write",
        "high",
    ),
    (
        "lodash-merge",
        r"_\s*\.\s*merge\s*\(",
        "Lodash _.merge() call — vulnerable when any argument is user-controlled",
        "medium",
    ),
    (
        "lodash-merge",
        r"lodash\s*\.\s*merge\s*\(",
        "lodash.merge() call — vulnerable when any argument is user-controlled",
        "medium",
    ),
    (
        "object-assign",
        r"Object\s*\.\s*assign\s*\(",
        "Object.assign() call — vulnerable when merging user-supplied objects",
        "low",
    ),
    (
        "spread-merge",
        r"\{\s*\.\.\.\w+\s*,\s*\.\.\.\w+\s*\}",
        "Object spread merge — may propagate __proto__ from user-controlled input",
        "medium",
    ),
    (
        "spread-merge",
        r"\{\s*\.\.\.\w+\s*,\s*\.\.\.",
        "Multi-spread object merge — potential prototype pollution via user input",
        "low",
    ),
    (
        "jquery-extend",
        r"\$\s*\.\s*extend\s*\(\s*true\s*,",
        "jQuery.extend(true, ...) deep merge — vulnerable to prototype pollution",
        "high",
    ),
    (
        "jquery-extend",
        r"jQuery\s*\.\s*extend\s*\(\s*true\s*,",
        "jQuery.extend(true, ...) deep merge — vulnerable to prototype pollution",
        "high",
    ),
    (
        "for-in-assign",
        r"for\s*\(\s*(?:const|let|var)?\s*(\w+)\s+in\s+(\w+)\s*\)",
        "for-in enumeration — check if prototype properties are filtered with hasOwnProperty",
        "medium",
    ),
    (
        "defaults-assign",
        r"(?:_\s*\.\s*defaults|_\s*\.\s*defaultsDeep)\s*\(",
        "Lodash _.defaults / _.defaultsDeep — may be vulnerable with user-controlled objects",
        "medium",
    ),
]


def scan_js_for_vulnerable_patterns(js_content: str) -> list[VulnerablePattern]:
    """Statically find potentially vulnerable merge/assign patterns in JS source."""
    if not js_content or not js_content.strip():
        return []

    findings: list[VulnerablePattern] = []
    lines = js_content.splitlines()

    for pattern_type, pattern, description, confidence in _PATTERNS:
        regex = re.compile(pattern, re.MULTILINE | re.DOTALL)
        for match in regex.finditer(js_content):
            line_number = js_content[: match.start()].count("\n") + 1
            # Grab the matched line for the snippet
            snippet_line = lines[line_number - 1].strip() if line_number <= len(lines) else match.group(0)[:80]
            # Avoid duplicate findings on the same line+type
            already = any(
                f.line_number == line_number and f.pattern_type == pattern_type
                for f in findings
            )
            if not already:
                findings.append(
                    VulnerablePattern(
                        pattern_type=pattern_type,
                        line_number=line_number,
                        code_snippet=snippet_line,
                        description=description,
                        confidence=confidence,
                    )
                )

    return findings
