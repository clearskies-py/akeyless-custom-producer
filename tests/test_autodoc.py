from __future__ import annotations

from clearskies_akeyless_custom_producer.endpoints import NoInput, WithInput


def _dummy_create(**kwargs):
    return {"id": "example", "response": kwargs}


def _dummy_revoke(**kwargs):
    return None


def _dummy_rotate(**kwargs):
    return {"payload": kwargs}


def _parameter_names(request) -> list[str]:
    names: list[str] = []
    for parameter in request.parameters:
        schema = getattr(parameter, "definition", None)
        name = getattr(schema, "name", None)
        if isinstance(name, str):
            names.append(name)
    return names


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


def test_with_input_documentation_create_and_rotate_include_input_parameter() -> None:
    endpoint = WithInput(
        url="example",
        create_callable=_dummy_create,
        id_column_name="id",
    )

    docs_by_path = {request.relative_path: request for request in endpoint.documentation()}

    create_request = docs_by_path["example/sync/create"]
    rotate_request = docs_by_path["example/sync/rotate"]

    assert "input" in _parameter_names(create_request)
    assert "input" in _parameter_names(rotate_request)
