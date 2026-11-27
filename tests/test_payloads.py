"""Tests for payload generation."""
import json

import pytest

from marrow.payloads import ProtoPayload, prototype_pollution_payloads, server_side_payloads


def test_prototype_pollution_payloads_returns_at_least_8():
    payloads = prototype_pollution_payloads()
    assert len(payloads) >= 8


def test_first_payload_is_proto_bracket():
    payloads = prototype_pollution_payloads()
    assert "__proto__[polluted]" in payloads[0].param_name


def test_constructor_prototype_param_present():
    payloads = prototype_pollution_payloads()
    names = [p.param_name for p in payloads]
    assert any("constructor[prototype][polluted]" in n for n in names)


def test_url_encoded_variant_present():
    payloads = prototype_pollution_payloads()
    names = [p.param_name for p in payloads]
    assert any("%5F%5Fproto%5F%5F" in n for n in names)


def test_json_body_technique_produces_valid_json():
    payloads = prototype_pollution_payloads()
    json_payloads = [p for p in payloads if p.technique == "json-proto"]
    assert json_payloads, "json-proto technique not found"
    parsed = json.loads(json_payloads[0].param_value)
    assert "__proto__" in parsed


def test_json_constructor_technique_produces_valid_json():
    payloads = prototype_pollution_payloads()
    json_payloads = [p for p in payloads if p.technique == "json-constructor"]
    assert json_payloads, "json-constructor technique not found"
    parsed = json.loads(json_payloads[0].param_value)
    assert "constructor" in parsed
    assert "prototype" in parsed["constructor"]


def test_server_side_payloads_returns_at_least_3():
    payloads = server_side_payloads()
    assert len(payloads) >= 3


def test_probe_key_defaults_to_polluted():
    payloads = prototype_pollution_payloads()
    assert all("polluted" in p.param_name or "polluted" in p.param_value for p in payloads)


def test_probe_value_defaults_to_1():
    payloads = prototype_pollution_payloads()
    for p in payloads:
        if p.technique not in ("json-proto", "json-constructor"):
            assert p.param_value == "1"


def test_nested_technique_has_subkey_in_param_name():
    payloads = prototype_pollution_payloads()
    nested = [p for p in payloads if p.technique == "nested"]
    assert nested, "nested technique not found"
    assert "subkey" in nested[0].param_name


def test_each_payload_has_non_empty_description():
    payloads = prototype_pollution_payloads()
    for p in payloads:
        assert p.description.strip(), f"Empty description for technique={p.technique}"


def test_custom_probe_key_propagates():
    payloads = prototype_pollution_payloads(probe_key="xtest", probe_value="99")
    assert any("xtest" in p.param_name or "xtest" in p.param_value for p in payloads)


def test_all_payloads_are_proto_payload_instances():
    payloads = prototype_pollution_payloads()
    assert all(isinstance(p, ProtoPayload) for p in payloads)


def test_server_side_includes_nodejs_json_proto():
    payloads = server_side_payloads()
    techniques = {p.technique for p in payloads}
    assert "nodejs-json-proto" in techniques
