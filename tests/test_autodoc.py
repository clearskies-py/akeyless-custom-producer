from __future__ import annotations

import clearskies
from clearskies import columns

from clearskies_akeyless_custom_producer.endpoints import NoInput, WithInput


def _dummy_create(**kwargs):
    return {"id": "example", "response": kwargs}


def _dummy_revoke(**kwargs):
    return None


def _dummy_rotate(**kwargs):
    return {"payload": kwargs}


class _PayloadSchema(clearskies.Schema):
    client_id = columns.String()
    client_secret = columns.Uuid()
    allowed = columns.Boolean()
    maximum = columns.Float()
    count = columns.Integer()
    scopes = columns.List(value_type=str)


class _InputSchema(clearskies.Schema):
    requested_scopes = columns.List(value_type=str)


def _request_schema(request) -> dict:
    return request.root_properties["requestBody"]["content"]["application/json"]["schema"]


def _request_body(request) -> dict:
    return request.root_properties["requestBody"]


def test_no_input_documentation_includes_sync_paths() -> None:
    endpoint = NoInput(
        url="example",
        create_callable=_dummy_create,
        revoke_callable=_dummy_revoke,
        rotate_callable=_dummy_rotate,
        id_column_name="id",
    )

    relative_paths = {request.relative_path for request in endpoint.documentation()}

    assert "example/sync/create" in relative_paths
    assert "example/sync/revoke" in relative_paths
    assert "example/sync/rotate" in relative_paths


def test_no_input_documentation_request_body_includes_payload_schema_hints() -> None:
    endpoint = NoInput(
        url="example",
        create_callable=_dummy_create,
        payload_schema=_PayloadSchema,
        id_column_name="id",
    )

    docs_by_path = {request.relative_path: request for request in endpoint.documentation()}
    create_request = docs_by_path["example/sync/create"]
    create_request_schema = _request_schema(create_request)
    create_request_body = _request_body(create_request)

    payload_schema = create_request_schema["properties"]["payload"]
    assert create_request_body["required"] is True
    assert create_request_schema["required"] == ["payload"]
    assert payload_schema["oneOf"][0]["type"] == "string"
    assert payload_schema["oneOf"][1]["type"] == "object"
    assert set(payload_schema["oneOf"][1]["properties"].keys()) == {
        "client_id",
        "client_secret",
        "allowed",
        "maximum",
        "count",
        "scopes",
    }
    payload_properties = payload_schema["oneOf"][1]["properties"]
    assert payload_properties["client_id"]["type"] == "string"
    assert payload_properties["client_secret"]["type"] == "string"
    assert payload_properties["allowed"]["type"] == "boolean"
    assert payload_properties["maximum"]["type"] == "number"
    assert payload_properties["count"]["type"] == "integer"
    assert payload_properties["scopes"]["type"] == "array"
    assert payload_properties["scopes"]["items"]["type"] == "string"


def test_no_input_revoke_docs_require_ids() -> None:
    endpoint = NoInput(
        url="example",
        create_callable=_dummy_create,
        revoke_callable=_dummy_revoke,
        payload_schema=_PayloadSchema,
        id_column_name="id",
    )

    docs_by_path = {request.relative_path: request for request in endpoint.documentation()}
    revoke_request_schema = _request_schema(docs_by_path["example/sync/revoke"])
    ids_schema = revoke_request_schema["properties"]["ids"]

    assert revoke_request_schema["required"] == ["payload", "ids"]
    assert ids_schema["type"] == "array"
    assert ids_schema["items"]["type"] == "string"


def test_with_input_documentation_create_and_rotate_include_input_schema_hints() -> None:
    endpoint = WithInput(
        url="example",
        create_callable=_dummy_create,
        payload_schema=_PayloadSchema,
        input_schema=_InputSchema,
        id_column_name="id",
    )

    docs_by_path = {request.relative_path: request for request in endpoint.documentation()}

    create_request = docs_by_path["example/sync/create"]
    rotate_request = docs_by_path["example/sync/rotate"]
    create_schema = _request_schema(create_request)
    rotate_schema = _request_schema(rotate_request)
    create_request_body = _request_body(create_request)
    rotate_request_body = _request_body(rotate_request)

    create_input_schema = create_schema["properties"]["input"]
    rotate_input_schema = rotate_schema["properties"]["input"]

    assert create_request_body["required"] is True
    assert rotate_request_body["required"] is True
    assert create_schema["required"] == ["payload"]
    assert rotate_schema["required"] == ["payload"]
    assert create_input_schema["oneOf"][0]["type"] == "string"
    assert rotate_input_schema["oneOf"][0]["type"] == "string"
    assert create_input_schema["oneOf"][1]["type"] == "object"
    assert rotate_input_schema["oneOf"][1]["type"] == "object"
    assert set(create_input_schema["oneOf"][1]["properties"].keys()) == {"requested_scopes"}
    assert set(rotate_input_schema["oneOf"][1]["properties"].keys()) == {"requested_scopes"}
    assert create_input_schema["oneOf"][1]["properties"]["requested_scopes"]["type"] == "array"
    assert create_input_schema["oneOf"][1]["properties"]["requested_scopes"]["items"]["type"] == "string"
