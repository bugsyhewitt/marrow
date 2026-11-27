"""Tests for static JS vulnerability scanner."""
import pytest

from marrow.scanner import VulnerablePattern, scan_js_for_vulnerable_patterns

JS_RECURSIVE_MERGE = """
function merge(target, source) {
    for (const key in source) {
        target[key] = source[key];
    }
    return target;
}
"""

JS_LODASH_MERGE = """
const result = _.merge(config, userSupplied);
"""

JS_OBJECT_ASSIGN = """
const merged = Object.assign(defaults, userInput);
"""

JS_SPREAD_MERGE = """
const config = {...defaults, ...userInput};
"""

JS_JQUERY_EXTEND = """
$.extend(true, target, userInput);
"""

JS_SAFE = """
var x = 1;
const greeting = "hello world";
function add(a, b) { return a + b; }
"""


def test_recursive_merge_returns_findings():
    findings = scan_js_for_vulnerable_patterns(JS_RECURSIVE_MERGE)
    assert findings, "Expected findings for recursive merge pattern"


def test_recursive_merge_confidence_high_or_medium():
    findings = scan_js_for_vulnerable_patterns(JS_RECURSIVE_MERGE)
    confidences = {f.confidence for f in findings}
    assert confidences & {"high", "medium"}, f"Expected high or medium confidence, got {confidences}"


def test_lodash_merge_returns_findings():
    findings = scan_js_for_vulnerable_patterns(JS_LODASH_MERGE)
    assert findings, "Expected findings for _.merge pattern"


def test_lodash_merge_pattern_type():
    findings = scan_js_for_vulnerable_patterns(JS_LODASH_MERGE)
    types = {f.pattern_type for f in findings}
    assert "lodash-merge" in types


def test_empty_string_returns_empty():
    assert scan_js_for_vulnerable_patterns("") == []


def test_safe_js_returns_empty():
    assert scan_js_for_vulnerable_patterns(JS_SAFE) == []


def test_object_assign_returns_findings():
    findings = scan_js_for_vulnerable_patterns(JS_OBJECT_ASSIGN)
    assert findings, "Expected findings for Object.assign"


def test_confidence_values_are_valid():
    all_js = JS_RECURSIVE_MERGE + JS_LODASH_MERGE + JS_OBJECT_ASSIGN + JS_SPREAD_MERGE
    findings = scan_js_for_vulnerable_patterns(all_js)
    for f in findings:
        assert f.confidence in {"high", "medium", "low"}, f"Invalid confidence: {f.confidence}"


def test_line_number_is_positive():
    findings = scan_js_for_vulnerable_patterns(JS_LODASH_MERGE)
    for f in findings:
        assert f.line_number >= 1


def test_code_snippet_non_empty():
    findings = scan_js_for_vulnerable_patterns(JS_LODASH_MERGE)
    for f in findings:
        assert f.code_snippet.strip()


def test_findings_are_vulnerable_pattern_instances():
    findings = scan_js_for_vulnerable_patterns(JS_RECURSIVE_MERGE)
    assert all(isinstance(f, VulnerablePattern) for f in findings)


def test_jquery_extend_returns_findings():
    findings = scan_js_for_vulnerable_patterns(JS_JQUERY_EXTEND)
    assert findings, "Expected findings for jQuery.extend"


def test_jquery_extend_pattern_type():
    findings = scan_js_for_vulnerable_patterns(JS_JQUERY_EXTEND)
    types = {f.pattern_type for f in findings}
    assert "jquery-extend" in types


def test_whitespace_only_returns_empty():
    assert scan_js_for_vulnerable_patterns("   \n\t  ") == []
