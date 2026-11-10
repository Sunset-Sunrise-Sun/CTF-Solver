"""Tests for :mod:`ctf_solver.mcp.schema` (Round 2 section 3.2).

The validator gates ``tools/call`` arguments *before* a handler runs, so the
negative cases matter more than the happy path: wrong payload types, nested
property types, additional properties, bounds, malformed schemas and the
"unknown keyword is ignored, never trusted" contract.
"""

from __future__ import annotations

import copy

import pytest

from ctf_solver.core.errors import ValidationError
from ctf_solver.mcp.schema import (
    JSON_TYPES,
    SchemaPayloadValidationError,
    SchemaValidationError,
    validate_or_raise,
    validate_schema,
)

CTF_EXEC_SCHEMA: dict = {
    "type": "object",
    "required": ["tool_name", "argv"],
    "additionalProperties": False,
    "properties": {
        "tool_name": {"type": "string", "minLength": 1},
        "argv": {
            "type": "array",
            "minItems": 1,
            "maxItems": 4096,
            "items": {"type": "string"},
        },
        "timeout_s": {"type": ["number", "null"], "minimum": 0.1, "maximum": 600},
    },
}
VALID_CTF_EXEC = {"tool_name": "internal.file_hash", "argv": ["README.md"], "timeout_s": 5}


def test_valid_ctf_exec_payload_passes() -> None:
    assert validate_schema(CTF_EXEC_SCHEMA, VALID_CTF_EXEC) == []


def test_ctf_exec_nested_wrong_argv_type_path() -> None:
    errors = validate_schema(CTF_EXEC_SCHEMA, {"tool_name": "x", "argv": ["ok", 7]})
    assert errors == [{"path": "$.argv[1]", "message": "expected type string, got integer"}]


def test_ctf_exec_additional_property_rejected() -> None:
    payload = dict(VALID_CTF_EXEC)
    payload["bypass"] = True
    errors = validate_schema(CTF_EXEC_SCHEMA, payload)
    assert errors == [
        {"path": "$.bypass", "message": "additional property 'bypass' is not allowed"}
    ]


def test_ctf_exec_missing_required_arguments() -> None:
    errors = validate_schema(CTF_EXEC_SCHEMA, {})
    paths = [error["path"] for error in errors]
    assert paths == ["$.tool_name", "$.argv"]
    assert all("required property" in error["message"] for error in errors)


def test_multiple_errors_are_all_returned() -> None:
    errors = validate_schema(
        CTF_EXEC_SCHEMA, {"tool_name": "", "argv": "not-an-array", "timeout_s": -1}
    )
    assert len(errors) == 3
    assert {error["path"] for error in errors} == {"$.tool_name", "$.argv", "$.timeout_s"}


# ---------------------------------------------------------------------------
# type
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "declared, accepted, rejected",
    [
        ("object", {"a": 1}, [1, "x", None, [], True]),
        ("array", [1, 2], ["x", {}, None, 5]),
        ("string", "x", [1, 1.5, None, [], {}]),
        ("integer", 3, [3.5, True, "3", None]),
        ("number", 3, [True, "3", None, []]),
        ("boolean", True, [1, 0, "true", None]),
        ("null", None, [0, "", False, []]),
    ],
)
def test_type_single(declared: str, accepted, rejected) -> None:
    schema = {"type": declared}
    assert validate_schema(schema, accepted) == []
    for value in rejected:
        errors = validate_schema(schema, value)
        assert len(errors) == 1
        assert errors[0]["path"] == "$"
        assert "expected type" in errors[0]["message"]


def test_number_accepts_integer_and_float_but_not_bool() -> None:
    assert validate_schema({"type": "number"}, 1) == []
    assert validate_schema({"type": "number"}, 1.5) == []
    assert validate_schema({"type": "number"}, True)[0]["path"] == "$"


def test_integer_is_python_int_only() -> None:
    assert validate_schema({"type": "integer"}, 2) == []
    assert validate_schema({"type": "integer"}, 2.0) != []
    assert validate_schema({"type": "integer"}, 2.5) != []


def test_type_list_accepts_each_branch() -> None:
    schema = {"type": ["string", "null"]}
    assert validate_schema(schema, "x") == []
    assert validate_schema(schema, None) == []
    errors = validate_schema(schema, 5)
    assert errors == [{"path": "$", "message": "expected type one of: string, null, got integer"}]


def test_type_list_rejects_bool_for_integer_branch() -> None:
    assert validate_schema({"type": ["integer", "null"]}, True) != []


# ---------------------------------------------------------------------------
# enum / const
# ---------------------------------------------------------------------------


def test_enum_matches_by_json_value() -> None:
    schema = {"enum": ["a", 1, None]}
    assert validate_schema(schema, "a") == []
    assert validate_schema(schema, 1) == []
    assert validate_schema(schema, None) == []
    assert validate_schema(schema, "b") == [
        {"path": "$", "message": "value is not one of the allowed enum values"}
    ]


def test_enum_keeps_boolean_distinct_from_integer() -> None:
    schema = {"enum": [1]}
    assert validate_schema(schema, True) != []
    assert validate_schema(schema, 1) == []
    schema_bool = {"enum": [True]}
    assert validate_schema(schema_bool, 1) != []
    assert validate_schema(schema_bool, True) == []


def test_enum_object_and_array_values() -> None:
    schema = {"enum": [{"mode": "fast"}, [1, 2]]}
    assert validate_schema(schema, {"mode": "fast"}) == []
    assert validate_schema(schema, [1, 2]) == []
    assert validate_schema(schema, {"mode": "slow"}) != []


def test_const() -> None:
    assert validate_schema({"const": "fixed"}, "fixed") == []
    assert validate_schema({"const": "fixed"}, "other") != []
    assert validate_schema({"const": None}, None) == []
    assert validate_schema({"const": None}, "null") != []


# ---------------------------------------------------------------------------
# required / properties / additionalProperties
# ---------------------------------------------------------------------------


def test_required_and_properties_nested_paths() -> None:
    schema = {
        "type": "object",
        "properties": {
            "a": {"type": "integer"},
            "nested": {
                "type": "object",
                "properties": {"b": {"type": "string"}},
            },
        },
    }
    errors = validate_schema(schema, {"a": "x", "nested": {"b": 5}})
    assert [error["path"] for error in errors] == ["$.a", "$.nested.b"]


def test_additional_properties_true_and_absent_allow_extras() -> None:
    assert validate_schema({"type": "object", "additionalProperties": True}, {"x": 1}) == []
    assert validate_schema({"type": "object"}, {"x": 1}) == []


def test_additional_properties_false_rejects_extras_only_for_objects() -> None:
    schema = {"type": "object", "properties": {"a": {"type": "integer"}}, "additionalProperties": False}
    assert validate_schema(schema, {"a": 1}) == []
    assert validate_schema(schema, {"a": 1, "b": 2}) == [
        {"path": "$.b", "message": "additional property 'b' is not allowed"}
    ]
    # The keyword applies to objects only; non-objects are governed by 'type'.
    assert validate_schema(schema, "not-an-object") != []


def test_required_ignored_for_non_object_values() -> None:
    schema = {"type": ["object", "null"], "required": ["a"]}
    assert validate_schema(schema, None) == []


# ---------------------------------------------------------------------------
# array constraints
# ---------------------------------------------------------------------------


def test_items_and_length_bounds() -> None:
    schema = {"type": "array", "minItems": 2, "maxItems": 3, "items": {"type": "integer"}}
    assert validate_schema(schema, [1, 2]) == []
    assert validate_schema(schema, [1, "x"]) == [
        {"path": "$[1]", "message": "expected type integer, got string"}
    ]
    errors = validate_schema(schema, [1])
    assert errors == [{"path": "$", "message": "array has fewer than the minimum 2 item(s)"}]
    errors = validate_schema(schema, [1, 2, 3, 4])
    assert errors == [{"path": "$", "message": "array has more than the maximum 3 item(s)"}]


def test_items_absent_allows_any_items() -> None:
    assert validate_schema({"type": "array", "minItems": 1}, [object()]) == []


def test_array_keywords_ignored_for_non_array() -> None:
    assert validate_schema({"type": "string", "minItems": 5}, "abc") == []


# ---------------------------------------------------------------------------
# string constraints
# ---------------------------------------------------------------------------


def test_string_length_constraints() -> None:
    schema = {"type": "string", "minLength": 2, "maxLength": 4}
    assert validate_schema(schema, "ab") == []
    assert validate_schema(schema, "abcde") == [
        {"path": "$", "message": "string is longer than the maximum length 4"}
    ]
    assert validate_schema(schema, "a") == [
        {"path": "$", "message": "string is shorter than the minimum length 2"}
    ]


def test_pattern_uses_search_semantics() -> None:
    schema = {"type": "string", "pattern": "[0-9]+"}
    assert validate_schema(schema, "abc123") == []
    assert validate_schema(schema, "abc") == [
        {"path": "$", "message": "string does not match the required pattern '[0-9]+'"}
    ]


# ---------------------------------------------------------------------------
# numeric constraints
# ---------------------------------------------------------------------------


def test_numeric_bounds() -> None:
    schema = {"type": "number", "minimum": 0, "maximum": 10}
    assert validate_schema(schema, 0) == []
    assert validate_schema(schema, 10) == []
    assert validate_schema(schema, -1) == [
        {"path": "$", "message": "number is less than the minimum 0"}
    ]
    assert validate_schema(schema, 11) == [
        {"path": "$", "message": "number is greater than the maximum 10"}
    ]


def test_exclusive_bounds() -> None:
    schema = {"type": "number", "exclusiveMinimum": 0, "exclusiveMaximum": 10}
    assert validate_schema(schema, 0) != []
    assert validate_schema(schema, 10) != []
    assert validate_schema(schema, 0.5) == []
    assert validate_schema(schema, 9.5) == []


def test_numeric_keywords_ignored_for_non_number() -> None:
    assert validate_schema({"type": "string", "minimum": 5}, "abc") == []


# ---------------------------------------------------------------------------
# anyOf
# ---------------------------------------------------------------------------


def test_any_of_accepts_matching_branch() -> None:
    schema = {"anyOf": [{"type": "string"}, {"type": "integer", "minimum": 1}]}
    assert validate_schema(schema, "x") == []
    assert validate_schema(schema, 3) == []


def test_any_of_rejects_when_no_branch_matches() -> None:
    schema = {"anyOf": [{"type": "string"}, {"type": "integer", "minimum": 1}]}
    errors = validate_schema(schema, 0)
    assert errors == [{"path": "$", "message": "value does not match any allowed 'anyOf' schema"}]
    assert validate_schema(schema, None) != []


def test_any_of_combines_with_other_keywords() -> None:
    schema = {
        "type": "object",
        "required": ["value"],
        "properties": {"value": {"anyOf": [{"type": "boolean"}, {"const": "auto"}]}},
    }
    assert validate_schema(schema, {"value": True}) == []
    assert validate_schema(schema, {"value": "auto"}) == []
    assert validate_schema(schema, {"value": "manual"}) == [
        {
            "path": "$.value",
            "message": "value does not match any allowed 'anyOf' schema",
        }
    ]


# ---------------------------------------------------------------------------
# unknown keywords, paths, custom root
# ---------------------------------------------------------------------------


def test_unknown_keywords_are_ignored_not_trusted() -> None:
    schema = {"type": "string", "format": "uri", "title": "x", "customKeyword": {"a": 1}}
    assert validate_schema(schema, "definitely-not-a-uri") == []


def test_unsupported_structural_keywords_are_ignored_by_contract() -> None:
    # The frozen interface says unknown keywords are ignored, not trusted: an
    # unsupported constraint must not be silently enforced as if it worked.
    assert validate_schema({"$ref": "#/definitions/anything"}, {"any": "value"}) == []
    assert validate_schema({"oneOf": [{"type": "string"}]}, 5) == []


def test_empty_schema_accepts_anything() -> None:
    for value in (None, 1, "x", [], {}, {"a": 1}, True):
        assert validate_schema({}, value) == []


def test_custom_root_path_is_used() -> None:
    errors = validate_schema({"type": "integer"}, "x", path="$.arguments")
    assert errors == [{"path": "$.arguments", "message": "expected type integer, got string"}]


def test_deep_nested_paths() -> None:
    schema = {
        "type": "object",
        "properties": {
            "requests": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"headers": {"type": "array", "items": {"type": "string"}}},
                },
            }
        },
    }
    errors = validate_schema(schema, {"requests": [{"headers": ["ok", 1]}]})
    assert errors == [{"path": "$.requests[0].headers[1]", "message": "expected type string, got integer"}]


def test_schema_is_not_mutated() -> None:
    schema = copy.deepcopy(CTF_EXEC_SCHEMA)
    validate_schema(schema, {})
    assert schema == CTF_EXEC_SCHEMA


# ---------------------------------------------------------------------------
# validate_or_raise
# ---------------------------------------------------------------------------


def test_validate_or_raise_passes_for_valid_payload() -> None:
    assert validate_or_raise(CTF_EXEC_SCHEMA, VALID_CTF_EXEC) is None


def test_validate_or_raise_raises_payload_error() -> None:
    with pytest.raises(SchemaPayloadValidationError) as info:
        validate_or_raise(CTF_EXEC_SCHEMA, {"tool_name": "x", "argv": [1]})
    error = info.value
    assert isinstance(error, ValidationError)  # CtfSolverError: MCP/IPC safe
    assert error.reason_code == "invalid_request"
    assert error.errors == [
        {"path": "$.argv[0]", "message": "expected type string, got integer"}
    ]
    assert error.details["errors"] == error.errors
    payload = error.to_dict()
    assert payload["reason_code"] == "invalid_request"


def test_validate_or_raise_does_not_mask_malformed_schema() -> None:
    with pytest.raises(SchemaValidationError):
        validate_or_raise({"type": "not-a-json-type"}, "x")
    # Payload failure is a distinct exception class from a malformed schema.
    with pytest.raises(SchemaPayloadValidationError):
        validate_or_raise({"type": "integer"}, "x")
    assert JSON_TYPES == {"object", "array", "string", "integer", "number", "boolean", "null"}


# ---------------------------------------------------------------------------
# Malformed schemas -> SchemaValidationError("invalid schema")
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "schema",
    [
        None,
        [],
        "a schema",
        42,
        True,
        {"type": "str"},
        {"type": []},
        {"type": ["string", 1]},
        {"type": 5},
        {"enum": "abc"},
        {"enum": []},
        {"required": "a"},
        {"required": [1]},
        {"required": [""]},
        {"properties": []},
        {"properties": {"a": "not-a-schema"}},
        {"properties": {"a": {"type": "bogus"}}},
        {"additionalProperties": "no"},
        {"items": [{"type": "string"}]},
        {"items": {"type": "bogus"}},
        {"minItems": -1},
        {"minItems": True},
        {"maxItems": 1.5},
        {"minLength": -2},
        {"maxLength": "3"},
        {"pattern": "["},
        {"pattern": 5},
        {"minimum": "5"},
        {"maximum": True},
        {"exclusiveMinimum": None},
        {"exclusiveMaximum": []},
        {"anyOf": []},
        {"anyOf": "x"},
        {"anyOf": [{"type": "bogus"}]},
        {"type": "object", "properties": {"a": {"type": "integer", "minimum": "x"}}},
    ],
)
def test_malformed_schema_raises(schema) -> None:
    with pytest.raises(SchemaValidationError) as info:
        validate_schema(schema, {"anything": 1})
    assert "invalid schema" in str(info.value)


def test_malformed_nested_schema_detected_even_when_unvisited_by_payload() -> None:
    schema = {
        "type": "object",
        "properties": {"never_present": {"type": "object", "required": "not-a-list"}},
    }
    # The payload does not contain "never_present"; the schema must still be
    # rejected up front instead of allowing the payload through.
    with pytest.raises(SchemaValidationError):
        validate_schema(schema, {})


def test_validate_schema_rejects_bad_validation_path() -> None:
    with pytest.raises(SchemaValidationError):
        validate_schema({"type": "string"}, "x", path="")
