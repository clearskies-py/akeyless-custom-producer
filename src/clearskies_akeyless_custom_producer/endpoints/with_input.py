from __future__ import annotations

import inspect
import json
from typing import Any, Callable

import clearskies.configs
import clearskies.exceptions
from clearskies.authentication import Authentication, Authorization, Public
from clearskies.input_outputs import InputOutput
from clearskies.schema import Schema

from .no_input import NoInput


class WithInput(NoInput):
    """
    The necessary endpoints for a custom producer (or rotator) that does accept input from the client.

    It's almost a copy of the NoInput endpoint but with the allowance of an input schema.

    For an example, consider a (fairly) common use case of an OAuth server as in the NoInput example.
    Only now it add's scopes to the request. And we want to the user to override the scope within the allowed scopes:

    ```
    #!/usr/bin/env python
    from clearskies import columns, validators
    import clearskies
    import clearskies_akeyless_custom_producer

    # a schema to describe what we expect the payload to look like:
    # it should contain client_id and client_secret, both of which are required
    class ClientCredentials(clearskies.Schema):
        client_id = columns.String(
            validators=[validators.Required()]
        )
        client_secret = columns.String(
            validators=[validators.Required()]
        )
        scopes = columns.String(
            validators=[validators.Required()]
        )
        allowed_scopes = columns.Json()

    # a schema to describe what we expect the payload to look like:
    # it should contain client_id and client_secret, both of which are required
    class ScopeRequired(clearskies.Schema):
        requested_scope = columns.String()

    def create(client_id, client_secret, scopes, allowed_scopes, requested_scope, requests):
        if requested_scope:
            if requested_scope not in allowed_scopes:
                raise clearskies.exceptions.ClientError(f"Requested scope `{requested_scope}` is not allowed.")
            scopes = requested_scope

        response = requests.post(
            'https://example.com/oauth/token',
            data={
                "grant_type": "client_credentials",
                "audience": "example.com",
                "client_id": client_id,
                "client_secret": client_secret,
                "scopes": scopes
            },
            headers={
                "content-type": "application/x-www-form-urlencoded",
            },
        )
        if response.status_code != 200:
            raise clearskies.exceptions.ClientError("Failed to fetch JWT from OAuth server. Response: " + response.content.decode('utf-8'))
        return response.json()

    def rotate(client_id, client_secret, requests):
        jwt = create(client_id, client_secret, requests)["access_token"]

        # of course, the details of a rotate request vary wildly from vendor-to-vendor, so this is just
        # a basic placeholder.
        rotate_response = requests.patch(
            f"https://example.com/oauth/rotate",
            headers={
                "content-type": "application/json",
                "Authorization": f"Bearer ${jwt}",
            }
        )

        if rotate_response.status_code != 200:
            raise clearskies.exceptions.ClientError("Rotate request rejected by OAuth Serve.  Response: " + rotate_response.content.decode('utf-8'))
        new_client_secret = rotate_response.json().get("client_secret")
        if not new_client_secret:
            raise clearskies.exceptions.ClientError("Huh, I did not understand the response from the OAuth server after my rotate request.  I could not find my new client secret :(")

        return {
            "client_id": client_id,
            "client_secret": new_client_secret,
        }

    # Finally, just wrap it all up in the Endpoint and attach it to the appropriate context
    wsgi = clearskies.contexts.WsgiRef(
        clearskies_akeyless_custom_producer.endpoints.NoInput(
            create_callable=create,
            rotate_callable=rotate,
            payload_schema=ClientCredentials,
            input_schema=ScopeRequired,
        ),
    )
    wsgi()
    ```
    """

    """
    A schema to describe the allowed input payload.

    While optional, this is strongly encouraged.  When the endpoints are invoked they will check the
    provided payload against this schema and returned a detailed error message if they don't match.
    When you first create a custom producer in Akeyless, it will always do a "dry run" against
    the create endpoint, which means that you will immediately find out if you have made a mistake
    when configuring your payload.  Hence, setting this makes debugging much easier and finds mistakes
    immediately, rather than when you try to use the producer.
    """
    input_schema = clearskies.configs.Schema(default=None)

    def __init__(
        self,
        url: str = "",
        create_callable: Callable | None = None,
        revoke_callable: Callable | None = None,
        rotate_callable: Callable | None = None,
        payload_schema: type[Schema] | None = None,
        input_schema: type[Schema] | None = None,
        id_column_name: str = "",
        authentication: Authentication = Public(),
        authorization: Authorization = Authorization(),
    ):
        super().__init__(
            url=url,
            create_callable=create_callable,
            revoke_callable=revoke_callable,
            rotate_callable=rotate_callable,
            payload_schema=payload_schema,
            id_column_name=id_column_name,
            authentication=authentication,
            authorization=authorization,
        )
        if input_schema:
            self.input_schema = input_schema

    def create(self, input_output: InputOutput, payload: dict[str, Any]) -> Any:
        try:
            input = self.get_input(input_output)
        except clearskies.exceptions.ClientError as e:
            return input_output.respond(str(e), 400)

        if self.input_schema:
            # The top-level error handler will wrap things in a standard clearskies response, but we just want
            # to return plain text, so well catch expected exceptions
            try:
                self.writeable_column_names = list(self.input_schema.get_columns().keys())
                self.validate_input_against_schema(
                    input,
                    input_output,
                    self.input_schema,
                )
            except clearskies.exceptions.InputErrors as e:
                return input_output.respond(", ".join([f"{key}: {value}" for (key, value) in e.errors.items()]), 400)

        payload = {**payload, **input}
        return super().create(input_output, payload)

    def get_input(self, input_output: InputOutput) -> dict[str, Any]:
        request_json = self.get_request_data(input_output, required=True)
        if "input" not in request_json or not request_json["input"]:
            return {}
        if not isinstance(request_json["input"], dict):
            raise clearskies.exceptions.ClientError(f"'input' in the JSON POST body was not a JSON object")
        return request_json["input"]
