from __future__ import annotations

import json
import inspect
from typing import TYPE_CHECKING, Any, Callable, Type

import clearskies.configs
import clearskies.exceptions
import clearskies.decorators
from clearskies import authentication, autodoc, typing
from clearskies.authentication import Authentication, Authorization, Public
from clearskies.endpoint import Endpoint
from clearskies.input_outputs import InputOutput
from clearskies.functional import routing

if TYPE_CHECKING:
    from clearskies import Column, Schema, SecurityHeader
    from clearskies.model import Model
    from clearskies.schema import Schema

class NoInput(Endpoint):
    """
    The necessary endpoints for a custom producer (or rotator) that does not accept any input from the client.

    First and foremost, the corresponding Akeyless docs:

     * https://docs.akeyless.io/docs/custom-producer
     * https://docs.akeyless.io/docs/create-a-custom-rotated-secret

    The overall idea is that Akeyless manages the storage of your "root" credentials, and reaches out to
    these custom producer endpoints to facilitate the creation/revocation of temporary credentials, as well
    as the rotation of your root credentials.  Akeyless always provides the necessary credentials (which it
    stores in the `payload` of your producer/rotator) to these endpoints on every call.  Therefore, you don't
    have to (and in fact you **shouldn't!**) store any access credentials or other sensitive data for use
    by these endpoints.  The expectation is that the actual custom producer webhooks you manage with this
    module are fully stateless.  This simplifies both management and security - since they have no access on
    their own and rely exclusively on credentials provided by Akeyless when called, there's no risk of
    escalation of privileges or AuthN/AuthZ bypass.  In fact, AuthN/AuthZ become substantially less important
    all together.

    Managing producers and rotators boils down to three actions: creating new credentials, revoking old ones,
    and rotating current ones.  This endpoint supports that by allowing you to provide a callable for each action.
    Note though that not all vendors support all actions.  Some credentials can't be revoked (e.g. JWTs), and
    not all vendors support credential rotation (for example, AWS access keys). Hoewver, even in the latter
    case, rotation is still typically possible by issuing a new credential and revoking the old one (which
    is how access key rotation works for AWS).  The following table shows what functionality is supported
    depending on which callables you provide:

    | Create | Rotate | Revoke | Custom Producer Support | Custom Rotator Support | Notes                                                                              |
    |:------:|:------:|:------:|:-----------------------:|:----------------------:|------------------------------------------------------------------------------------|
    |    ✓   |    ✓   |    ✓   |            ✓            |            ✓           | Creation, Rotation, and Revocation are all fully supported.                        |
    |    ✓   |        |    ✓   |            ✓            |            ✓           | Rotation happens by creating a new credential/revoking the old one.                |
    |    ✓   |    ✓   |        |            ✓            |            ✓           | Issued credentials are assumed to expire on their own.                             |
    |    ✓   |        |        |            ✓            |                        | Issued credentials are assumed to expire on their own.  Rotation is not supported. |
    |        |    ✓   |        |                         |            ✓           | Only supports custom rotators, not custom producers.                               |

    So in short, you implement the create/revoke/rotate callables depending on vendor capabilities,
    and then the above table shows what capabilities you can make use of.  This endpoint will expose the
    necessary `/sync/create`, `/sync/rotate`, and `/sync/revoke` endpoints.  When those are called, the provided
    payload (which is assumed to be in JSON format) is checked against the `payload_schema` you provide,
    with the request rejected (with a clear error message) if it doesn't match.  Finally, the appropriate
    create/revoke/rotate callable is invoked with the data from the provided payload.  Again, keep in mind
    that there isn't a simple 1:1 correspondance.  If you don't define a rotate callable, but do provide
    create and revoke, then a call to `/sync/rotate` will result in a call first to the create callable,
    followed by a call to the revoke callable.

    For an example, consider a (fairly) common use case of an OAuth server which allows for the generation
    of JWTs from `client_id` and `client_secret`, and which also has an endpoint to rotate the client secret.
    Therefore, the vendor supports create and rotate (but not revoke), which would look something like this:

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

    def create(client_id, client_secret, requests):
        response = requests.post(
            'https://example.com/oauth/token',
            data={
                "grant_type": "client_credentials",
                "audience": "example.com",
                "client_id": client_id,
                "client_secret": client_secret,
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
        ),
    )
    wsgi()
    ```
    """

    """
    A base URL for these endpoints.

    Note that the standard Akeyless URLs (`/sync/create`, `/sync/rotate`, `/sync/revoke`) are always used by
    this endpoint.  By setting a URL you add a prefix, which can be helpful if you want to host multiple
    custom producers/rotators on the same infrastructure:

    ```
    import clearskies
    import clearskies_akeyless_custom_producer

    my_producers = clearskies.EndpointGroup([
        clearskies_akeyless_custom_producer.endpoints.NoInput(
            url="/vendor_1",
            create=some_callable,
            revoke=some_other_callable,
        ),
        clearskies_akeyless_custom_producer.endpoints.NoInput(
            url="/vendor_2",
            create=next_callable,
            rotate=another_callable,,
        ),
    ])
    ```

    In which case your application ends up with all the applicable endpoints:

     * `/vendor_1/sync/create`
     * `/vendor_1/sync/revoke`
     * `/vendor_1/sync/rotate`
     * `/vendor_2/sync/create`
     * `/vendor_2/sync/rotate`
    """
    url = clearskies.configs.String(default="")

    """
    A function to call to create a new credential.  If omited, then this will only be useable as a rotator.

    This should accept a `payload` arg, which will be the decoded json from the payload stored in the
    custom producer.  It should return the details of the new credential as a dictionary.  If you have specified
    `id_column_name` then you must ensure that the returned credential includes a key/value pair that corresponds
    to the id column name.  This is used by Akeyless to track credentials and comes back to the revoke callable
    so you can properly revoke the credential.

    Note though that credential revocation is optional, as not all credentials (e.g. JWTs) can be revoked.
    Therefore, you don't have to set the `id_column_name` on the endpoint.  In this case the revoke callable
    will never be called.  Note that leaving out the id_column_name also has implications for auditing,
    but not all temporary credentials have an option for providing a unique id, so :shrug:.

    Finally, this may get called during a rotation operation.  Not all vendors directly support credential
    rotation, in which case the endpoint will still make a rotation happen by creating a new credential
    and deleteing the old one.  If necessary, your create callable can differentiate between
    "create-new-credential-for-temporary-user" and "create-new-credential-for-rotation" by requesting the
    `for_rotate` kwarg, which will be set to either True or False depending on the context.
    """
    create_callable = clearskies.configs.Callable(default=None)

    """
    A function to call to rotate the root credentials.

    This function will be executed when the `/sync/rotate` endpoint is called.  It should accept an argument
    called `payload` which will be a dicationary containing the payload stored in the producer/rotator.  The
    callable should then return the new payload.

    Note that not all vendors support credential rotation, but you can still create a rotator for them.
    The custom producer endpoint will still expose and manage a `/sync/rotate` endpoint even if you don't
    have a `rotate_callable` set.  If `/sync/rotate` is invoked without a rotate callable, then this
    endpoint will instead call the create callable and return a new credential (and, if the revoke_callable
    is set, it will call that for the old root credentials).
    """
    rotate_callable = clearskies.configs.Callable(default=None)

    """
    A function that will be called when a credential needs to be revoked.

    The callable should accept two args: one named `payload` and one named `id_to_delete`.  The former is the payload
    stored in the producer/rotator, and the latter is the id of the credential to be revoked.

    In order for this to work, you have to set `id_column_name` and return a matching dictionary key
    from your create callable.  Akeyless then uses this id to track each credential so that, when it is
    time to revoke it, Akeyless can provide that id back to you and ensure you revoke the correct
    credential.  Note that revocation is optional.  Not all credentials can be revoked (e.g. JWTs),
    in which case you don't have to provide anything for `revoke_callable`.
    """
    revoke_callable = clearskies.configs.Callable(default=None)

    """
    A schema to describe the expected payload.

    While optional, this is strongly encouraged.  When the endpoints are invoked they will check the
    provided payload against this schema and returned a detailed error message if they don't match.
    When you first create a custom producer in Akeyless, it will always do a "dry run" against
    the create endpoint, which means that you will immediately find out if you have made a mistake
    when configuring your payload.  Hence, setting this makes debugging much easier and finds mistakes
    immediately, rather than when you try to use the proudcer.
    """
    payload_schema = clearskies.configs.Schema(default=None)

    """
    The key, in the newly returned credential, that can be used to uniquely identify that credential.

    This is used for credential revocation and auditing.  When a credential is created, a dictionary
    is returned that contains the full credential details.  The `id_column_name` must correspond to
    one of the keys in that dictionary.  The corresponding value will then be tracked by Akeyless,
    show up in the audit logs, and also will be passed back to the revoke function when it is time
    to revoke the credentials.

    The exact value to use simply depends on the credential source.  For example, if you were
    working with a database, the `id_column_name` would typically correspond to the username of
    the newly created credential.  If working with some 3rd party servce and generating something
    like an API key, it might correspond to the id of the API key (presuming the vendor has one).

    This is optional, as not all vendors and credentials have something that can be used as a
    unique id.  If you omit this though, it implicitly disables credential revocation.  This is
    normal and expected in cases where credentials automatically expire on their own (sessions,
    JWTs, etc...).
    """
    id_column_name = clearskies.configs.String(default="")

    request_methods = ["POST"]

    @clearskies.decorators.parameters_to_properties
    def __init__(
        self,
        url: str = "",
        create_callable: Callable | None = None,
        revoke_callable: Callable | None = None,
        rotate_callable: Callable | None = None,
        payload_schema: Schema | None = None,
        id_column_name: str = "",
        authentication: Authentication = Public(),
        authorization: Authorization = Authorization(),
    ):
        super().__init__()

        # if revoke_callable is set and id_column_name isn't, then we have a problem.
        if revoke_callable and not id_column_name:
            raise ValueError("A revoke callable was provided but id_column_name is not set.  Without an id_column_name, revocation is disabled, so you should not set a revoke callable")

    def handle(self, input_output: InputOutput):
        # figure out if we are creating, revoking, or rotating
        base_url = self.url.strip('/')
        incoming_url = input_output.get_full_path().strip("/")
        expected_endpoints = {
            f"{base_url}/sync/create".strip("/"): self.create,
            f"{base_url}/sync/rotate".strip("/"): self.rotate,
            f"{base_url}/sync/revoke".strip("/"): self.revoke,
        }

        method_to_execute = None
        for (expected_url, method) in expected_endpoints.items():
            (matches, routing_data) = routing.match_route(expected_url, incoming_url, allow_partial=False)
            if not matches:
                continue

            method_to_execute = method
            break

        if not method_to_execute:
            raise clearskies.exceptions.NotFound()

        try:
            payload = self.get_payload(input_output)
        except clearskies.exceptions.ClientError as e:
            return input_output.respond(str(e), 400)

        if self.payload_schema:
            # The top-level error handler will wrap things in a standard clearskies response, but we just want
            # to return plain text, so well catch expected exceptions
            try:
                self.writeable_column_names = list(self.payload_schema.get_columns().keys())
                self.validate_input_against_schema(
                    payload,
                    input_output,
                    self.payload_schema,
                )
            except clearskies.exceptions.InputErrors as e:
                return input_output.respond(
                    ", ".join([f"{key}: {value}" for (key, value) in e.errors.items()]),
                    400
                )

        try:
            return method_to_execute(input_output, payload)
        except clearskies.exceptions.ClientError as e:
            return input_output.respond(str(e), 400)
        except clearskies.exceptions.InputErrors as e:
            return input_output.respond(
                ", ".join([f"{key}: {value}" for (key, value) in e.errors.items()]),
                400
            )

    def create(self, input_output: InputOutput, payload: dict[str, Any]) -> Any:
        if not self.create_callable:
            raise clearskies.exceptions.ClientError("Creating credentials is not available because not create_callable is configured.")

        credentials = self.di.call_function(
            self.create_callable,
            **payload,
            payload=payload,
            for_rotate=False,
        )

        credential_id = "i_dont_need_an_id"
        if self.id_column_name:
            if self.id_column_name not in credentials:
                raise ValueError(
                    f"Response from create callable did not include the required id column: '{self.id_column_name}'"
                )
            # akeyless will only accept strings as the id value - no integers/etc
            credential_id = str(credentials[id_column_name])

        return input_output.respond({
            'id': credential_id,
            'response': credentials,
        }, 200)

    def revoke(self, input_output: InputOutput, payload: dict[str, Any]) -> Any:
        try:
            ids = self.get_ids(input_output)
        except clearskies.exceptions.ClientError as e:
            return input_output.respond(str(e), 400)

        # if we don't have an id_column_name set then we can't revoke.  However, we still have to respond
        # with the same list of ids provided by Akeyless
        if not self.id_column_name:
            return input_output.respond({
                "revoked": ids,
                "message": "",
            }, 200)

        for id in ids:
            self._di.call_function(
                self.revoke_callable,
                **payload,
                payload=payload,
                id_to_delete=id,
            )

        return input_output.respond({
            "revoked": ids,
            "message": "",
        }, 200)

    def rotate(self, input_output: InputOutput, payload: dict[str, Any]) -> Any:
        # easy if we can actually rotate
        if self.rotate_callable:
            return input_output.respond({
                "payload": json.dumps(self.di.call_function(
                    self.rotate_callable,
                    **payload,
                    payload=payload,
                )),
            }, 200)

        # otherwise we have to create/revoke
        new_payload = self.di.call_function(
            self.create_callable,
            **payload,
            payload=payload,
            for_rotate=True,
        )
        if self.revoke_callable:
            self.di.call_function(
                self.revoke_callable,
                **new_payload,
                payload=new_payload,
                id_to_delete=payload.get(self.id_column_name),
            )

        return input_output.respond({
            "payload": json.dumps(new_payload)
        })

    def matches_request(self, input_output: InputOutput, allow_partial=False) -> bool:
        """
        Check if we match the incoming request

        We *always* do some internal routing so we need the allow_partial flag to be true.
        Otherwise, we can rely on the logic in our parent.  Therefore, we extend this method just to
        tweak the flag.
        """
        return super().matches_request(input_output, allow_partial=True)

    def get_payload(self, input_output: InputOutput) -> dict[str, Any]:
        request_json = self.get_request_data(input_output, required=True)
        if "payload" not in request_json:
            raise clearskies.exceptions.ClientError("Missing 'payload' in JSON POST body")
        if not request_json["payload"]:
            raise clearskies.exceptions.ClientError("Provided 'payload' in JSON POST body was empty")
        if not isinstance(request_json["payload"], str):
            if isinstance(request_json["payload"], dict):
                raise clearskies.exceptions.ClientError(
                    "'payload' in the JSON POST body was a JSON object, but it should be a serialized JSON string"
                )
            raise clearskies.exceptions.ClientError("'payload' in JSON POST must be a string containing JSON")
        try:
            payload = json.loads(request_json['payload'])
        except json.JSONDecodeError:
            raise clearskies.exceptions.ClientError("'payload' in JSON POST body was not a valid JSON string")
        return payload

    def get_ids(self, input_output: InputOutput) -> list[str]:
        request_json = self.get_request_data(input_output, required=True)
        if "ids" not in request_json:
            raise clearskies.exceptions.ClientError("Missing 'ids' in JSON POST body")
        if not isinstance(request_json["ids"], list):
            raise clearskies.exceptions.ClientError("'ids' in JSON POST body was not a list.")
        return request_json["ids"]  # type: ignore

    def populate_routing_data(self, input_output: InputOutput) -> Any:
        # N/A for these endpoints
        return None
