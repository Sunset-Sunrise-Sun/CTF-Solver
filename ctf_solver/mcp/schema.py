"""Minimal, dependency-free JSON-Schema subset validator for MCP payloads.

Round 2 needs Worker-facing tool arguments validated against the declared
``inputSchema`` **before** they reach a handler. The audited Harness MCP client
sends ``tools/call`` with a JSON object; the Manager/ctf-exec surfaces must
reject a wrong *payload type*, not only missing ``required`` keys.

Supported keywords (docs/ROUND_2_INTERFACES.md section 3.2):

``type`` (single name or list), ``enum``, ``const``, ``required``,
``properties``, ``additionalProperties`` (boolean), ``items`` (single schema),
``minItems``, ``maxItems``, ``minLength``, ``maxLength``, ``pattern``,
``minimum``, ``maximum``, ``exclusiveMinimum``, ``exclusiveMaximum`` and a
minimal ``anyOf``.

Design:
* :func:`validate_schema` returns a list of ``{"path": ..., "message": ...}``
  error objects and never raises for a *payload* problem.
* A malformed/unsupported **schema** is a programming/configuration error and
  raises :class:`SchemaValidationError` ("invalid schema") before any payload
  verdict is produced. Validation is therefore never "fail open" because a
  schema is nonsense.
* Unknown schema keywords are ignored (untouched annotation keywords), never
  used as validation constraints. Callers must place security-relevant
  constraints in the supported set above.

The validator is deliberately a *subset*: it is a tool-argument gate, not a
general JSON-Schema implementation.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from ..core.errors import ValidationError

#: JSON-Schema type names supported by the validator.
JSON_TYPES = frozenset(
    {"object", "array", "string", "integer", "number", "boolean", "null"}
)


class SchemaValidationError(ValueError):
    """The schema itself is malformed or unsupported (not a payload verdict)."""

    def __init__(self, message: str = "invalid schema") -> None:
        super().__init__(message)


class SchemaPayloadValidationError(ValidationError):
    """A payload failed validation; ``errors`` holds the error dicts."""

    reason_code = "invalid_request"

    def __init__(self, errors: list[dict[str, Any]], *, path: str = "$") -> None:
        self.errors = [dict(error) for error in errors]
        super().__init__(
            f"schema validation failed at {path} ({len(self.errors)} error(s))",
            details={"errors": self.errors, "path": path},
        )


# ---------------------------------------------------------------------------
# Schema self-check (malformed schema => SchemaValidationError)
# ---------------------------------------------------------------------------


def _invalid(detail: str) -> SchemaValidationError:
    return SchemaValidationError(f"invalid schema: {detail}")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _require_non_negative_int(keyword: str, value: Any) -> int:
    if not _is_int(value) or value < 0:
        raise _invalid(f"{keyword!r} must be a non-negative integer")
    return value


def _require_number(keyword: str, value: Any) -> int | float:
    if not _is_number(value):
        raise _invalid(f"{keyword!r} must be a number")
    return value


def _check_schema(schema: Any, where: str) -> None:
    """Recursively reject a schema that the validator cannot enforce safely."""

    if not isinstance(schema, dict):
        raise _invalid(f"{where} must be an object schema")
    check = dict(schema)  # copy: never mutate caller state

    if "type" in check:
        declared = check["type"]
        if isinstance(declared, str):
            if declared not in JSON_TYPES:
                raise _invalid(f"{where}.type is not a supported JSON type: {declared!r}")
        elif isinstance(declared, list):
            if not declared:
                raise _invalid(f"{where}.type must not be an empty list")
            for item in declared:
                if not isinstance(item, str) or item not in JSON_TYPES:
                    raise _invalid(
                        f"{where}.type contains an unsupported JSON type: {item!r}"
                    )
        else:
            raise _invalid(f"{where}.type must be a string or a list of strings")

    if "enum" in check:
        enum = check["enum"]
        if not isinstance(enum, list) or not enum:
            raise _invalid(f"{where}.enum must be a non-empty list")

    if "required" in check:
        required = check["required"]
        if not isinstance(required, list):
            raise _invalid(f"{where}.required must be a list of property names")
        for name in required:
            if not isinstance(name, str) or not name:
                raise _invalid(f"{where}.required entries must be non-empty strings")

    if "properties" in check:
        properties = check["properties"]
        if not isinstance(properties, dict):
            raise _invalid(f"{where}.properties must be an object")
        for name, sub_schema in properties.items():
            if not isinstance(name, str):
                raise _invalid(f"{where}.properties keys must be strings")
            _check_schema(sub_schema, f"{where}.properties[{name!r}]")

    if "additionalProperties" in check:
        if not isinstance(check["additionalProperties"], bool):
            raise _invalid(f"{where}.additionalProperties must be a boolean")

    if "items" in check:
        items = check["items"]
        if not isinstance(items, dict):
            raise _invalid(f"{where}.items must be a single object schema")
        _check_schema(items, f"{where}.items")

    for keyword in ("minItems", "maxItems", "minLength", "maxLength"):
        if keyword in check:
            _require_non_negative_int(f"{where}.{keyword}", check[keyword])

    if "pattern" in check:
        pattern = check["pattern"]
        if not isinstance(pattern, str):
            raise _invalid(f"{where}.pattern must be a string")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise _invalid(f"{where}.pattern is not a valid regular expression: {exc}") from exc

    for keyword in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"):
        if keyword in check:
            _require_number(f"{where}.{keyword}", check[keyword])

    if "anyOf" in check:
        any_of = check["anyOf"]
        if not isinstance(any_of, list) or not any_of:
            raise _invalid(f"{where}.anyOf must be a non-empty list of schemas")
        for index, sub_schema in enumerate(any_of):
            _check_schema(sub_schema, f"{where}.anyOf[{index}]")


# ---------------------------------------------------------------------------
# JSON value helpers
# ---------------------------------------------------------------------------


def _json_equal(left: Any, right: Any) -> bool:
    """JSON-data equality that keeps ``True`` distinct from ``1``."""

    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if _is_number(left) and _is_number(right):
        return left == right
    if left is None or right is None:
        return left is None and right is None
    if isinstance(left, str) or isinstance(right, str):
        return isinstance(left, str) and isinstance(right, str) and left == right
    if isinstance(left, list) or isinstance(right, list):
        if not isinstance(left, list) or not isinstance(right, list):
            return False
        return len(left) == len(right) and all(
            _json_equal(a, b) for a, b in zip(left, right)
        )
    if isinstance(left, dict) or isinstance(right, dict):
        if not isinstance(left, dict) or not isinstance(right, dict):
            return False
        if set(left) != set(right):
            return False
        return all(_json_equal(left[key], right[key]) for key in left)
    return type(left) is type(right) and left == right


def _json_type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (list, tuple)):
        return "array"
    if isinstance(value, Mapping):
        return "object"
    return type(value).__name__


def _matches_type(value: Any, declared: str) -> bool:
    if declared == "null":
        return value is None
    if declared == "boolean":
        return isinstance(value, bool)
    if declared == "integer":
        return _is_int(value)
    if declared == "number":
        return _is_number(value)
    if declared == "string":
        return isinstance(value, str)
    if declared == "array":
        return isinstance(value, (list, tuple))
    if declared == "object":
        return isinstance(value, Mapping)
    return False  # pragma: no cover - schema check rejects unknown names first


def _property_path(path: str, key: str) -> str:
    if path == "$":
        return f"$.{key}"
    return f"{path}.{key}"


def _index_path(path: str, index: int) -> str:
    return f"{path}[{index}]"


# ---------------------------------------------------------------------------
# Payload validation
# ---------------------------------------------------------------------------


def _error(errors: list[dict[str, Any]], path: str, message: str) -> None:
    errors.append({"path": path, "message": message})


def _validate_type(schema: dict[str, Any], value: Any, path: str, errors: list[dict[str, Any]]) -> None:
    declared = schema.get("type")
    if declared is None:
        return
    names = [declared] if isinstance(declared, str) else list(declared)
    if not any(_matches_type(value, name) for name in names):
        expected = names[0] if len(names) == 1 else "one of: " + ", ".join(names)
        _error(
            errors,
            path,
            f"expected type {expected}, got {_json_type_name(value)}",
        )


def _validate_enum(schema: dict[str, Any], value: Any, path: str, errors: list[dict[str, Any]]) -> None:
    enum = schema.get("enum")
    if enum is not None and not any(_json_equal(value, allowed) for allowed in enum):
        _error(errors, path, "value is not one of the allowed enum values")


def _validate_const(schema: dict[str, Any], value: Any, path: str, errors: list[dict[str, Any]]) -> None:
    if "const" in schema and not _json_equal(value, schema["const"]):
        _error(errors, path, "value does not equal the required const value")


def _validate_string(schema: dict[str, Any], value: Any, path: str, errors: list[dict[str, Any]]) -> None:
    if not isinstance(value, str):
        return
    min_length = schema.get("minLength")
    if min_length is not None and len(value) < min_length:
        _error(errors, path, f"string is shorter than the minimum length {min_length}")
    max_length = schema.get("maxLength")
    if max_length is not None and len(value) > max_length:
        _error(errors, path, f"string is longer than the maximum length {max_length}")
    pattern = schema.get("pattern")
    if pattern is not None and re.search(pattern, value) is None:
        _error(errors, path, f"string does not match the required pattern {pattern!r}")


def _validate_number(schema: dict[str, Any], value: Any, path: str, errors: list[dict[str, Any]]) -> None:
    if not _is_number(value):
        return
    minimum = schema.get("minimum")
    if minimum is not None and value < minimum:
        _error(errors, path, f"number is less than the minimum {minimum}")
    maximum = schema.get("maximum")
    if maximum is not None and value > maximum:
        _error(errors, path, f"number is greater than the maximum {maximum}")
    exclusive_minimum = schema.get("exclusiveMinimum")
    if exclusive_minimum is not None and value <= exclusive_minimum:
        _error(errors, path, f"number must be greater than {exclusive_minimum}")
    exclusive_maximum = schema.get("exclusiveMaximum")
    if exclusive_maximum is not None and value >= exclusive_maximum:
        _error(errors, path, f"number must be less than {exclusive_maximum}")


def _validate_array(schema: dict[str, Any], value: Any, path: str, errors: list[dict[str, Any]]) -> None:
    if not isinstance(value, (list, tuple)):
        return
    min_items = schema.get("minItems")
    if min_items is not None and len(value) < min_items:
        _error(errors, path, f"array has fewer than the minimum {min_items} item(s)")
    max_items = schema.get("maxItems")
    if max_items is not None and len(value) > max_items:
        _error(errors, path, f"array has more than the maximum {max_items} item(s)")
    items = schema.get("items")
    if items is not None:
        for index, item in enumerate(value):
            _validate(items, item, _index_path(path, index), errors)


def _validate_object(schema: dict[str, Any], value: Any, path: str, errors: list[dict[str, Any]]) -> None:
    if not isinstance(value, Mapping):
        return
    required = schema.get("required") or []
    for name in required:
        if name not in value:
            _error(errors, _property_path(path, name), f"required property {name!r} is missing")

    properties = schema.get("properties") or {}
    for name, sub_schema in properties.items():
        if name in value:
            _validate(sub_schema, value[name], _property_path(path, name), errors)

    if schema.get("additionalProperties") is False:
        for name in value:
            if name not in properties:
                _error(
                    errors,
                    _property_path(path, str(name)),
                    f"additional property {name!r} is not allowed",
                )


def _validate_any_of(schema: dict[str, Any], value: Any, path: str, errors: list[dict[str, Any]]) -> None:
    any_of = schema.get("anyOf")
    if not any_of:
        return
    for sub_schema in any_of:
        branch_errors: list[dict[str, Any]] = []
        _validate(sub_schema, value, path, branch_errors)
        if not branch_errors:
            return
    _error(errors, path, "value does not match any allowed 'anyOf' schema")


def _validate(schema: dict[str, Any], value: Any, path: str, errors: list[dict[str, Any]]) -> None:
    """Validate ``value`` against an already self-checked schema."""

    _validate_type(schema, value, path, errors)
    _validate_enum(schema, value, path, errors)
    _validate_const(schema, value, path, errors)
    _validate_string(schema, value, path, errors)
    _validate_number(schema, value, path, errors)
    _validate_array(schema, value, path, errors)
    _validate_object(schema, value, path, errors)
    _validate_any_of(schema, value, path, errors)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def validate_schema(
    schema: dict[str, Any], value: Any, *, path: str = "$"
) -> list[dict[str, Any]]:
    """Validate ``value`` against ``schema``.

    Returns a list of ``{"path": ..., "message": ...}`` error objects (empty
    when the payload is valid). Raises :class:`SchemaValidationError` when the
    schema itself is malformed/unsupported.
    """

    if not isinstance(path, str) or not path:
        raise SchemaValidationError("invalid validation path")
    _check_schema(schema, path)
    errors: list[dict[str, Any]] = []
    _validate(schema, value, path, errors)
    return errors


def validate_or_raise(schema: dict[str, Any], value: Any, *, path: str = "$") -> None:
    """Validate and raise on the first failure class.

    * malformed schema -> :class:`SchemaValidationError` (never a payload verdict);
    * invalid payload -> :class:`SchemaPayloadValidationError` carrying every
      error dict in ``.errors`` / ``.details["errors"]``.
    """

    errors = validate_schema(schema, value, path=path)
    if errors:
        raise SchemaPayloadValidationError(errors, path=path)
