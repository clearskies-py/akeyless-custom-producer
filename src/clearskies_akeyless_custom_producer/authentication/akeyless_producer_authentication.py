"""Akeyless producer authentication for custom producer endpoints."""

from __future__ import annotations

import base64
import json
import logging
from typing import TYPE_CHECKING, Any, Callable

from clearskies import configs, decorators, di, loggable
from clearskies.authentication import Authentication
from clearskies.exceptions import Authentication as AuthenticationException

if TYPE_CHECKING:
    from clearskies.input_outputs.input_output import InputOutput

logger = logging.getLogger(__name__)


class AkeylessProducerAuthentication(Authentication, di.InjectableProperties, loggable.Loggable):
    """
    Authenticate requests from Akeyless using the AkeylessCreds header.

    When Akeyless Gateway calls your custom producer endpoints to create, revoke, or rotate
    credentials, it includes an AkeylessCreds header with a JWT token. This authentication
    class validates that token by:

    1. Extracting the access_id from the JWT payload (without verification)
    2. Calling Akeyless' validation endpoint to verify the token signature and claims
    3. Optionally enforcing an allowlist of permitted gateway access IDs

    ## Basic Usage

    ```python
    import clearskies
    import clearskies_akeyless_custom_producer

    app = clearskies.contexts.WsgiRef(
        clearskies.EndpointGroup(
            url="/api/v1",
            authentication=clearskies_akeyless_custom_producer.authentication.AkeylessProducerAuthentication(
                expected_item_name="/custom-producer-oauth",
            ),
            endpoints=[...],
        ),
    )
    ```

    ## Configuration Options

    - `expected_item_name` (str): The item name (path) of the custom producer in Akeyless.
      If set, included in the validation request for extra verification. Default: ""

    - `allowlist_access_ids` (list[str] or callable): Akeyless Gateway access IDs that are allowed.
      Can be a static list like `["p-prod-gateway"]` or a callable like `lambda: db.get_allowed_gateways()`.
      If callable, evaluated at request time for dynamic allowlists. If not set, any validated token
      from Akeyless is accepted. Default: []

    - `validate_url` (str): The Akeyless validation endpoint URL. For testing or on-premise
      deployments, you can override this. Default:
      "https://auth.akeyless.io/validate-producer-credentials"

    - `request_timeout_seconds` (float): HTTP request timeout (in seconds) for calls to the
      Akeyless validation endpoint. Default: 2.0 seconds

    - `allow_dry_run` (bool): Allow the special "p-custom" dry-run access ID that Akeyless
      uses when creating/testing the custom producer. When enabled, "p-custom" bypasses the
      allowlist (if configured). Default: True (recommended to keep enabled)

    ## Examples

    ### With static gateway allowlist (recommended for production):

    ```python
    authentication = clearskies_akeyless_custom_producer.authentication.AkeylessProducerAuthentication(
        expected_item_name="/custom-producer-oauth",
        allowlist_access_ids=["p-prod-gateway"],
    )
    ```

    ### With multiple allowed gateways:

    ```python
    authentication = clearskies_akeyless_custom_producer.authentication.AkeylessProducerAuthentication(
        expected_item_name="/custom-producer-oauth",
        allowlist_access_ids=["p-prod-gateway", "p-staging-gateway"],
    )
    ```

    ### With dynamic allowlist (callable):

    ```python
    import clearskies
    import clearskies_akeyless_custom_producer
    from my_app.services import gateway_service


    def get_allowed_gateways():
        # Fetch list of allowed gateways from database or cache.
        return gateway_service.get_allowed_access_ids()


    app = clearskies.contexts.WsgiRef(
        clearskies.EndpointGroup(
            url="/api/v1",
            authentication=clearskies_akeyless_custom_producer.authentication.AkeylessProducerAuthentication(
                expected_item_name="/custom-producer-oauth",
                allowlist_access_ids=get_allowed_gateways,  # Evaluated at request time
            ),
            endpoints=[...],
        ),
    )
    ```

    Benefits of callable allowlist:
    - **No restart required**: Update allowed gateways in database/cache
    - **Tenant isolation**: Different tenants can have different gateway allowlists
    - **Feature flags**: Disable gateways dynamically without redeployment
    - **Audit trail**: Track when allowlists change

    ### Without allowlist (accepts any validated gateway):

    ```python
    authentication = clearskies_akeyless_custom_producer.authentication.AkeylessProducerAuthentication(
        expected_item_name="/custom-producer-oauth",
    )
    ```

    ## Dry-run Mode

    When you first create a custom producer in Akeyless, the gateway performs a "dry-run"
    against your endpoints using the special access ID "p-custom". This is automatically
    allowed regardless of your allowlist configuration (if `allow_dry_run=True`).

    **Why it works**: The "p-custom" access ID is always whitelisted internally, so you don't
    need to include it in your allowlist. This makes initial setup simpler and safer—you can
    set a restrictive production allowlist immediately after creation.

    **If you need to disable it**: Set `allow_dry_run=False` to block dry-run requests (not
    recommended unless you have specific security requirements).
    """

    """
    The item name (path) of the custom producer in Akeyless.
    """
    expected_item_name = configs.String(default="")

    """
    List of Akeyless Gateway access IDs that are allowed.
    If not set, any validated token is accepted.
    """
    allowlist_access_ids = configs.StringListOrCallable(default=[])

    """
    The URL of the Akeyless validation endpoint.
    """
    validate_url = configs.String(default="https://auth.akeyless.io/validate-producer-credentials")

    """
    Timeout (in seconds) for HTTP requests to the validation endpoint.
    """
    request_timeout_seconds = configs.Float(default=2.0)

    """
    Allow dry-run mode using the special "p-custom" access ID.
    Akeyless uses this when creating/testing the custom producer.
    Default: True (recommended to keep enabled for initial setup).
    """
    allow_dry_run = configs.Boolean(default=True)

    """
    The requests object for making HTTP calls.
    """
    requests = di.inject.Requests()

    """
    The dependency injection container for calling functions with injection.
    """
    di = di.inject.Di()

    @decorators.parameters_to_properties
    def __init__(
        self,
        expected_item_name: str = "",
        allowlist_access_ids: list[str] | Callable[[], list[str]] | None = None,
        validate_url: str = "https://auth.akeyless.io/validate-producer-credentials",
        request_timeout_seconds: float = 2.0,
        allow_dry_run: bool = True,
    ) -> None:
        """Initialize Akeyless producer authentication."""
        self.finalize_and_validate_configuration()

    def _extract_access_id_from_jwt_payload(self, token: str) -> str:
        """
        Decode JWT payload (without verification) and extract access_id claim.

        Performs a base64url decode of the JWT payload segment (middle part between dots).
        Returns the `access_id` claim from the decoded payload.

        Raises `clearskies.exceptions.Authentication` if the token is malformed or the claim
        is not found.
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise AuthenticationException("Invalid token format: expected 3 JWT segments")
            # Decode the payload (second segment)
            payload_encoded = parts[1]
            # Add padding if needed
            padding = 4 - (len(payload_encoded) % 4)
            if padding and padding != 4:
                payload_encoded += "=" * padding
            payload_bytes = base64.urlsafe_b64decode(payload_encoded)
            payload = json.loads(payload_bytes.decode("utf-8"))
            self.logger.debug("Decoded JWT payload: %s", payload)
            # Try common claim names for access_id
            for key in ["access_id", "aid", "client_id", "sub"]:
                if key in payload:
                    return str(payload[key])
            raise AuthenticationException("Token payload missing access_id claim")
        except (ValueError, json.JSONDecodeError, AttributeError, IndexError) as e:
            raise AuthenticationException(f"Failed to decode token payload: {e}") from e

    def authenticate(self, input_output: InputOutput) -> bool:
        """
        Authenticate request using the AkeylessCreds header.

        Extracts the JWT token from the `AkeylessCreds` request header, validates it with
        Akeyless' validation endpoint, and enforces the allowlist if configured.

        Sets `input_output.authorization_data` on success with the validated `access_id` and
        `sub_claims` from Akeyless.

        Raises `clearskies.exceptions.Authentication` if the header is missing, the token is
        invalid, the validation endpoint fails, or the access ID is not in the allowlist.
        """
        # Extract token from header
        token = input_output.request_headers.get("AkeylessCreds")
        if not token:
            raise AuthenticationException("Missing AkeylessCreds header")

        # Extract access_id from token payload for the validation request
        # This will raise AuthenticationException if token is invalid
        extracted_access_id = self._extract_access_id_from_jwt_payload(token)

        # Validate with Akeyless
        try:
            auth_data = self._validate_with_akeyless(token, extracted_access_id)
        except Exception as e:
            logger.error("Akeyless validation failed: %s", str(e))
            raise AuthenticationException("Token validation failed") from e

        # Check allowlist if configured
        allowlist: Any = self.allowlist_access_ids
        if callable(allowlist):
            # Use DI to call the function so developers can inject dependencies
            allowlist = self.di.call_function(allowlist)

        validated_access_id = auth_data.get("access_id")

        # Check if this is a dry-run request (special "p-custom" access ID)
        is_dry_run = validated_access_id == "p-custom"

        # Handle dry-run access ID: allow if enabled, reject if disabled
        if is_dry_run:
            if not self.allow_dry_run:
                raise AuthenticationException("Dry-run access ID 'p-custom' is not allowed")
            # If allow_dry_run=True, bypass allowlist check and allow the request
        elif allowlist:
            # For non-dry-run requests, check allowlist if configured
            allowlist_set = set(allowlist)
            if validated_access_id not in allowlist_set:
                raise AuthenticationException(f"Access ID '{validated_access_id}' not in allowlist")

        # Set authorization data and return True
        input_output.authorization_data = auth_data
        return True

    def _validate_with_akeyless(self, token: str, access_id: str) -> dict[str, Any]:
        """
        Call Akeyless validation endpoint to verify the token.

        Makes a POST request to the configured validation endpoint with the token and extracted
        `access_id`. The endpoint verifies the token signature and claims.

        Returns a dict with the validated `access_id` and `sub_claims` from the response.

        Raises `clearskies.exceptions.Authentication` if the endpoint is unreachable, returns
        a non-200 status, or returns invalid JSON.
        """
        payload = {
            "creds": token,
            "expected_access_id": access_id,
        }
        if self.expected_item_name:
            payload["expected_item_name"] = self.expected_item_name

        try:
            response = self.requests.post(
                self.validate_url,
                json=payload,
                timeout=self.request_timeout_seconds,
                verify=True,
            )
        except Exception as e:
            raise AuthenticationException(f"Validation endpoint request failed: {e}") from e

        if response.status_code != 200:
            raise AuthenticationException(f"Validation endpoint returned status {response.status_code}")

        try:
            response_data = response.json()
        except json.JSONDecodeError as e:
            raise AuthenticationException("Validation endpoint returned invalid JSON") from e

        # Build authorization data from response
        # The response may include validated access_id, sub_claims, etc.
        auth_data = {
            "access_id": response_data.get("access_id", access_id),
            "sub_claims": response_data.get("sub_claims", {}),
        }
        return auth_data
