"""Unit tests for AkeylessProducerAuthentication."""

from __future__ import annotations

import base64
import json
import unittest
from typing import Callable
from unittest.mock import MagicMock

import clearskies
import requests
from clearskies.contexts import Context
from clearskies.exceptions import Authentication as AuthenticationException

from clearskies_akeyless_custom_producer.authentication.akeyless_producer_authentication import (
    AkeylessProducerAuthentication,
)

# Helper functions


def _base64url_encode(data: str) -> str:
    """Encode string to base64url format (JWT-style)."""
    return base64.urlsafe_b64encode(data.encode()).decode().rstrip("=")


def _create_test_jwt_token(access_id: str) -> str:
    """Create a test JWT token with the given access_id in payload."""
    header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"  # {}
    payload = json.dumps({"access_id": access_id})
    payload_encoded = _base64url_encode(payload)
    signature = "test_signature"
    return f"{header}.{payload_encoded}.{signature}"


class TestAkeylessProducerAuthentication(unittest.TestCase):
    """Test AkeylessProducerAuthentication class."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        # Create a mock requests object
        self.mock_requests = MagicMock()

        self.input_output = MagicMock()
        self.input_output.request_headers = MagicMock()

    def _create_auth_with_context(
        self,
        expected_item_name: str = "/test-producer",
        allowlist_access_ids: list[str] | Callable[[], list[str]] | None = None,
        allow_dry_run: bool = True,
    ) -> AkeylessProducerAuthentication:
        """Create an AkeylessProducerAuthentication instance with proper DI setup."""
        auth = AkeylessProducerAuthentication(
            expected_item_name=expected_item_name,
            allowlist_access_ids=allowlist_access_ids,
            allow_dry_run=allow_dry_run,
        )
        # Create a context to properly initialize DI
        # We use class_overrides to inject our mock requests
        context = Context(
            clearskies.endpoints.Callable(lambda: {}),
            class_overrides={requests.Session: self.mock_requests},
        )
        # Manually set the DI container on the auth instance
        auth.di = context.di
        return auth

    def test_authenticate_missing_header_raises(self) -> None:
        """Raise AuthenticationException if AkeylessCreds header is missing."""
        auth = self._create_auth_with_context()
        self.input_output.request_headers.get.return_value = None

        with self.assertRaises(AuthenticationException) as ctx:
            auth.authenticate(self.input_output)

        assert "Missing AkeylessCreds header" in str(ctx.exception)

    def test_authenticate_invalid_token_format_raises(self) -> None:
        """Raise AuthenticationException if token format is invalid."""
        auth = self._create_auth_with_context()
        self.input_output.request_headers.get.return_value = "invalid.token"

        with self.assertRaises(AuthenticationException) as ctx:
            auth.authenticate(self.input_output)

        assert "Invalid token format" in str(ctx.exception)

    def test_authenticate_success_returns_true(self) -> None:
        """Successfully authenticate and return True on valid token."""
        auth = self._create_auth_with_context()
        auth.requests = self.mock_requests
        token = _create_test_jwt_token("p-gateway123")
        self.input_output.request_headers.get.return_value = token

        self.mock_requests.post.return_value.status_code = 200
        self.mock_requests.post.return_value.json.return_value = {
            "access_id": "p-gateway123",
            "sub_claims": {"role": ["admin"]},
        }

        result = auth.authenticate(self.input_output)

        assert result is True
        assert self.input_output.authorization_data["access_id"] == "p-gateway123"
        assert self.input_output.authorization_data["sub_claims"] == {"role": ["admin"]}

    def test_authenticate_calls_validate_endpoint(self) -> None:
        """Verify that the validation endpoint is called with correct payload."""
        auth = self._create_auth_with_context()
        auth.requests = self.mock_requests
        token = _create_test_jwt_token("p-gw456")
        self.input_output.request_headers.get.return_value = token

        self.mock_requests.post.return_value.status_code = 200
        self.mock_requests.post.return_value.json.return_value = {
            "access_id": "p-gw456",
            "sub_claims": {},
        }

        auth.authenticate(self.input_output)

        # Verify the endpoint was called with the token and extracted access_id
        self.mock_requests.post.assert_called_once()
        call_args = self.mock_requests.post.call_args
        assert call_args[1]["json"]["creds"] == token
        assert call_args[1]["json"]["expected_access_id"] == "p-gw456"
        assert call_args[1]["json"]["expected_item_name"] == "/test-producer"
        assert call_args[1]["timeout"] == 2.0

    def test_authenticate_validation_failure_raises(self) -> None:
        """Raise AuthenticationException if validation endpoint returns non-200."""
        auth = self._create_auth_with_context()
        auth.requests = self.mock_requests
        token = _create_test_jwt_token("p-bad")
        self.input_output.request_headers.get.return_value = token

        self.mock_requests.post.return_value.status_code = 401

        with self.assertRaises(AuthenticationException) as ctx:
            auth.authenticate(self.input_output)

        assert "Token validation failed" in str(ctx.exception)

    def test_authenticate_network_error_raises(self) -> None:
        """Raise AuthenticationException on network failure (fail-closed)."""
        auth = self._create_auth_with_context()
        auth.requests = self.mock_requests
        token = _create_test_jwt_token("p-net")
        self.input_output.request_headers.get.return_value = token

        self.mock_requests.post.side_effect = requests.RequestException("Connection timeout")

        with self.assertRaises(AuthenticationException) as ctx:
            auth.authenticate(self.input_output)

        assert "Token validation failed" in str(ctx.exception)

    def test_authenticate_invalid_json_response_raises(self) -> None:
        """Raise AuthenticationException if validation endpoint returns invalid JSON."""
        auth = self._create_auth_with_context()
        auth.requests = self.mock_requests
        token = _create_test_jwt_token("p-invalid-json")
        self.input_output.request_headers.get.return_value = token

        self.mock_requests.post.return_value.status_code = 200
        self.mock_requests.post.return_value.json.side_effect = json.JSONDecodeError("msg", "doc", 0)

        with self.assertRaises(AuthenticationException) as ctx:
            auth.authenticate(self.input_output)

        assert "Token validation failed" in str(ctx.exception)

    def test_authenticate_allowlist_enforced(self) -> None:
        """Reject token if access_id is not in configured allowlist."""
        auth_with_allowlist = self._create_auth_with_context(allowlist_access_ids=["p-allowed1", "p-allowed2"])
        auth_with_allowlist.requests = self.mock_requests
        token = _create_test_jwt_token("p-notallowed")
        self.input_output.request_headers.get.return_value = token

        self.mock_requests.post.return_value.status_code = 200
        self.mock_requests.post.return_value.json.return_value = {
            "access_id": "p-notallowed",
            "sub_claims": {},
        }

        with self.assertRaises(AuthenticationException) as ctx:
            auth_with_allowlist.authenticate(self.input_output)

        assert "not in allowlist" in str(ctx.exception)

    def test_authenticate_allowlist_accepted(self) -> None:
        """Accept token if access_id is in configured allowlist."""
        auth_with_allowlist = self._create_auth_with_context(allowlist_access_ids=["p-allowed1", "p-allowed2"])
        auth_with_allowlist.requests = self.mock_requests
        token = _create_test_jwt_token("p-allowed1")
        self.input_output.request_headers.get.return_value = token

        self.mock_requests.post.return_value.status_code = 200
        self.mock_requests.post.return_value.json.return_value = {
            "access_id": "p-allowed1",
            "sub_claims": {},
        }

        result = auth_with_allowlist.authenticate(self.input_output)

        assert result is True
        assert self.input_output.authorization_data["access_id"] == "p-allowed1"

    def test_authenticate_without_expected_item_name(self) -> None:
        """Verify request is valid when expected_item_name is not configured."""
        auth_no_item = self._create_auth_with_context(expected_item_name="")
        auth_no_item.requests = self.mock_requests
        token = _create_test_jwt_token("p-test")
        self.input_output.request_headers.get.return_value = token

        self.mock_requests.post.return_value.status_code = 200
        self.mock_requests.post.return_value.json.return_value = {
            "access_id": "p-test",
            "sub_claims": {},
        }

        auth_no_item.authenticate(self.input_output)

        call_args = self.mock_requests.post.call_args
        assert "expected_item_name" not in call_args[1]["json"]

    def test_authenticate_custom_timeout(self) -> None:
        """Verify custom request timeout is used."""
        auth_custom = AkeylessProducerAuthentication(request_timeout_seconds=5.0)
        auth_custom.di = Context(clearskies.endpoints.Callable(lambda: {})).di
        auth_custom.requests = self.mock_requests
        token = _create_test_jwt_token("p-timeout")
        self.input_output.request_headers.get.return_value = token

        self.mock_requests.post.return_value.status_code = 200
        self.mock_requests.post.return_value.json.return_value = {
            "access_id": "p-timeout",
            "sub_claims": {},
        }

        auth_custom.authenticate(self.input_output)

        call_args = self.mock_requests.post.call_args
        assert call_args[1]["timeout"] == 5.0

    def test_dry_run_token_accepted_without_allowlist(self) -> None:
        """Accept dry-run tokens (p-custom) when no allowlist is configured."""
        auth = self._create_auth_with_context()
        auth.requests = self.mock_requests
        token = _create_test_jwt_token("p-custom")
        self.input_output.request_headers.get.return_value = token

        self.mock_requests.post.return_value.status_code = 200
        self.mock_requests.post.return_value.json.return_value = {
            "access_id": "p-custom",
            "sub_claims": {},
        }

        result = auth.authenticate(self.input_output)

        assert result is True
        assert self.input_output.authorization_data["access_id"] == "p-custom"

    def test_authenticate_with_callable_allowlist(self) -> None:
        """Accept token when access_id is returned by callable allowlist."""

        def get_allowed_ids() -> list[str]:
            return ["p-dynamic1", "p-dynamic2"]

        auth_with_callable = self._create_auth_with_context(allowlist_access_ids=get_allowed_ids)
        auth_with_callable.requests = self.mock_requests
        token = _create_test_jwt_token("p-dynamic1")
        self.input_output.request_headers.get.return_value = token

        self.mock_requests.post.return_value.status_code = 200
        self.mock_requests.post.return_value.json.return_value = {
            "access_id": "p-dynamic1",
            "sub_claims": {},
        }

        result = auth_with_callable.authenticate(self.input_output)

        assert result is True
        assert self.input_output.authorization_data["access_id"] == "p-dynamic1"

    def test_authenticate_callable_allowlist_rejected(self) -> None:
        """Reject token when access_id is not in callable allowlist."""

        def get_allowed_ids() -> list[str]:
            return ["p-dynamic1", "p-dynamic2"]

        auth_with_callable = self._create_auth_with_context(allowlist_access_ids=get_allowed_ids)
        auth_with_callable.requests = self.mock_requests
        token = _create_test_jwt_token("p-notinlist")
        self.input_output.request_headers.get.return_value = token

        self.mock_requests.post.return_value.status_code = 200
        self.mock_requests.post.return_value.json.return_value = {
            "access_id": "p-notinlist",
            "sub_claims": {},
        }

        with self.assertRaises(AuthenticationException) as ctx:
            auth_with_callable.authenticate(self.input_output)

        assert "not in allowlist" in str(ctx.exception)

    def test_dry_run_always_allowed_with_allowlist(self) -> None:
        """Allow p-custom dry-run even when allowlist is configured."""
        auth_with_allowlist = self._create_auth_with_context(allowlist_access_ids=["p-prod-gateway"])
        auth_with_allowlist.requests = self.mock_requests
        token = _create_test_jwt_token("p-custom")
        self.input_output.request_headers.get.return_value = token

        self.mock_requests.post.return_value.status_code = 200
        self.mock_requests.post.return_value.json.return_value = {
            "access_id": "p-custom",
            "sub_claims": {},
        }

        result = auth_with_allowlist.authenticate(self.input_output)

        assert result is True
        assert self.input_output.authorization_data["access_id"] == "p-custom"

    def test_dry_run_disabled_rejects_p_custom(self) -> None:
        """Reject p-custom when allow_dry_run=False."""
        auth_no_dry_run = self._create_auth_with_context(allowlist_access_ids=["p-prod-gateway"], allow_dry_run=False)
        auth_no_dry_run.requests = self.mock_requests
        token = _create_test_jwt_token("p-custom")
        self.input_output.request_headers.get.return_value = token

        self.mock_requests.post.return_value.status_code = 200
        self.mock_requests.post.return_value.json.return_value = {
            "access_id": "p-custom",
            "sub_claims": {},
        }

        with self.assertRaises(AuthenticationException) as ctx:
            auth_no_dry_run.authenticate(self.input_output)

        assert "not allowed" in str(ctx.exception)

    def test_dry_run_disabled_without_allowlist_rejects_p_custom(self) -> None:
        """Reject p-custom when allow_dry_run=False, even without an allowlist (logic gap fix)."""
        auth_no_dry_run = self._create_auth_with_context(allow_dry_run=False)
        auth_no_dry_run.requests = self.mock_requests
        token = _create_test_jwt_token("p-custom")
        self.input_output.request_headers.get.return_value = token

        self.mock_requests.post.return_value.status_code = 200
        self.mock_requests.post.return_value.json.return_value = {
            "access_id": "p-custom",
            "sub_claims": {},
        }

        with self.assertRaises(AuthenticationException) as ctx:
            auth_no_dry_run.authenticate(self.input_output)

        assert "not allowed" in str(ctx.exception)


if __name__ == "__main__":
    unittest.main()
