import json
import unittest
from unittest.mock import MagicMock, patch

import clearskies

from clearskies_akeyless_custom_producer.authentication import AkeylessProducerAuthentication


def _create_test_jwt_token(access_id: str, sub_claims: dict | None = None) -> str:
    """Create a test JWT token with the given access_id and sub_claims."""
    if sub_claims is None:
        sub_claims = {}

    payload = {"access_id": access_id, "sub_claims": sub_claims}
    # Simple base64 encoding (not real JWT - just for testing token structure)
    import base64

    payload_bytes = json.dumps(payload).encode("utf-8")
    return base64.b64encode(payload_bytes).decode("utf-8")


class MockJWSToken:
    """Mock jwcrypto.jws.JWS token."""

    def __init__(self, token: str):
        self.token = token
        self.objects = {}

    def deserialize(self, token: str) -> None:
        """Simulate deserializing a token."""
        import base64

        self.token = token
        # Extract payload from our test token format
        try:
            payload_bytes = base64.b64decode(token)
            self.objects["payload"] = payload_bytes
        except Exception:
            self.objects["payload"] = None


class MockJWSModule:
    """Mock jwcrypto.jws module."""

    def __init__(self):
        self.token_instance = MockJWSToken("")

    def JWS(self):
        return self.token_instance


class TestAkeylessProducerAuthentication(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_jws_module = MockJWSModule()
        self.mock_requests = MagicMock()

    def test_real_jwcrypto_imports_through_di_without_binding(self) -> None:
        """Use real jwcrypto module through DI without explicit binding."""
        # Prebuilt compact JWS with payload:
        # {"access_id":"p-producer1","sub_claims":{"client_id":"client123"}}
        # The test itself does not import jwcrypto; only DI must resolve `jwcrypto.jws`.
        token = (
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJhY2Nlc3NfaWQiOiJwLXByb2R1Y2VyMSIsInN1Yl9jbGFpbXMiOnsiY2xpZW50X2lkIjoiY2xpZW50MTIzIn19."
            "c2ln"
        )

        with patch("requests.Session", return_value=self.mock_requests):
            context = clearskies.contexts.Context(
                clearskies.endpoints.Callable(
                    lambda: {"hello": "world"},
                    authentication=AkeylessProducerAuthentication(
                        expected_item_name="/my-producer",
                    ),
                ),
            )

            self.mock_requests.post.return_value.status_code = 200
            self.mock_requests.post.return_value.json.return_value = {
                "access_id": "p-producer1",
                "sub_claims": {"client_id": "client123"},
            }

            status_code, _, _ = context(request_headers={"AkeylessCreds": token})

            assert status_code == 200
            self.mock_requests.post.assert_called_once()

    def test_successful_authentication_extracts_access_id(self) -> None:
        """Successfully authenticate when Akeyless returns validated access_id."""
        token = _create_test_jwt_token("p-producer1")

        with patch("requests.Session", return_value=self.mock_requests):
            context = clearskies.contexts.Context(
                clearskies.endpoints.Callable(
                    lambda: {"hello": "world"},
                    authentication=AkeylessProducerAuthentication(
                        expected_item_name="/my-producer",
                    ),
                ),
                bindings={
                    "jwcrypto.jws": self.mock_jws_module,
                },
            )

            self.mock_requests.post.return_value.status_code = 200
            self.mock_requests.post.return_value.json.return_value = {
                "access_id": "p-producer1",
                "sub_claims": {"client_id": "client123"},
            }

            status_code, response_data, _ = context(request_headers={"AkeylessCreds": token})

            assert status_code == 200
            self.mock_requests.post.assert_called_once()

    def test_missing_akeyless_creds_header_returns_401(self) -> None:
        """Return 401 when AkeylessCreds header is missing."""
        with patch("requests.Session", return_value=self.mock_requests):
            context = clearskies.contexts.Context(
                clearskies.endpoints.Callable(
                    lambda: {"hello": "world"},
                    authentication=AkeylessProducerAuthentication(
                        expected_item_name="/my-producer",
                    ),
                ),
                bindings={
                    "jwcrypto.jws": self.mock_jws_module,
                },
            )

            status_code, _, _ = context(request_headers={})
            assert status_code == 401

    def test_validate_endpoint_called_with_correct_params(self) -> None:
        """Verify validate endpoint is called with expected parameters."""
        token = _create_test_jwt_token("p-producer1")
        validate_url = "https://custom.akeyless.io/validate"

        with patch("requests.Session", return_value=self.mock_requests):
            context = clearskies.contexts.Context(
                clearskies.endpoints.Callable(
                    lambda: {"hello": "world"},
                    authentication=AkeylessProducerAuthentication(
                        expected_item_name="/custom-producer",
                        validate_url=validate_url,
                        request_timeout_seconds=3.0,
                    ),
                ),
                bindings={
                    "jwcrypto.jws": self.mock_jws_module,
                },
            )

            self.mock_requests.post.return_value.status_code = 200
            self.mock_requests.post.return_value.json.return_value = {
                "access_id": "p-producer1",
                "sub_claims": {},
            }

            context(request_headers={"AkeylessCreds": token})

            call_args = self.mock_requests.post.call_args
            assert call_args[0][0] == validate_url
            assert call_args[1]["timeout"] == 3.0
            assert call_args[1]["json"]["expected_item_name"] == "/custom-producer"

    def test_validation_endpoint_error_returns_401(self) -> None:
        """Return 401 when validation endpoint returns error."""
        token = _create_test_jwt_token("p-producer1")

        with patch("requests.Session", return_value=self.mock_requests):
            context = clearskies.contexts.Context(
                clearskies.endpoints.Callable(
                    lambda: {"hello": "world"},
                    authentication=AkeylessProducerAuthentication(
                        expected_item_name="/my-producer",
                    ),
                ),
                bindings={
                    "jwcrypto.jws": self.mock_jws_module,
                },
            )

            self.mock_requests.post.return_value.status_code = 401

            status_code, _, _ = context(request_headers={"AkeylessCreds": token})
            assert status_code == 401

    def test_allowlist_rejects_unlisted_access_id(self) -> None:
        """Return 401 when access_id is not in allowlist."""
        token = _create_test_jwt_token("p-unlisted")

        with patch("requests.Session", return_value=self.mock_requests):
            context = clearskies.contexts.Context(
                clearskies.endpoints.Callable(
                    lambda: {"hello": "world"},
                    authentication=AkeylessProducerAuthentication(
                        expected_item_name="/my-producer",
                        allowlist_access_ids=["p-allowed1", "p-allowed2"],
                    ),
                ),
                bindings={
                    "jwcrypto.jws": self.mock_jws_module,
                },
            )

            self.mock_requests.post.return_value.status_code = 200
            self.mock_requests.post.return_value.json.return_value = {
                "access_id": "p-unlisted",
                "sub_claims": {},
            }

            status_code, _, _ = context(request_headers={"AkeylessCreds": token})
            assert status_code == 401

    def test_allowlist_accepts_listed_access_id(self) -> None:
        """Accept token when access_id is in allowlist."""
        token = _create_test_jwt_token("p-allowed1")

        with patch("requests.Session", return_value=self.mock_requests):
            context = clearskies.contexts.Context(
                clearskies.endpoints.Callable(
                    lambda: {"hello": "world"},
                    authentication=AkeylessProducerAuthentication(
                        expected_item_name="/my-producer",
                        allowlist_access_ids=["p-allowed1", "p-allowed2"],
                    ),
                ),
                bindings={
                    "jwcrypto.jws": self.mock_jws_module,
                },
            )

            self.mock_requests.post.return_value.status_code = 200
            self.mock_requests.post.return_value.json.return_value = {
                "access_id": "p-allowed1",
                "sub_claims": {},
            }

            status_code, response_data, _ = context(request_headers={"AkeylessCreds": token})
            assert status_code == 200

    def test_callable_allowlist_accepted(self) -> None:
        """Accept token when access_id is returned by callable allowlist."""

        def get_allowed_ids() -> list[str]:
            return ["p-dynamic1", "p-dynamic2"]

        token = _create_test_jwt_token("p-dynamic1")

        with patch("requests.Session", return_value=self.mock_requests):
            context = clearskies.contexts.Context(
                clearskies.endpoints.Callable(
                    lambda: {"hello": "world"},
                    authentication=AkeylessProducerAuthentication(
                        expected_item_name="/my-producer",
                        allowlist_access_ids=get_allowed_ids,
                    ),
                ),
                bindings={
                    "jwcrypto.jws": self.mock_jws_module,
                },
            )

            self.mock_requests.post.return_value.status_code = 200
            self.mock_requests.post.return_value.json.return_value = {
                "access_id": "p-dynamic1",
                "sub_claims": {},
            }

            status_code, _, _ = context(request_headers={"AkeylessCreds": token})
            assert status_code == 200

    def test_callable_allowlist_rejected(self) -> None:
        """Reject token when access_id not in callable allowlist."""

        def get_allowed_ids() -> list[str]:
            return ["p-dynamic1", "p-dynamic2"]

        token = _create_test_jwt_token("p-notallowed")

        with patch("requests.Session", return_value=self.mock_requests):
            context = clearskies.contexts.Context(
                clearskies.endpoints.Callable(
                    lambda: {"hello": "world"},
                    authentication=AkeylessProducerAuthentication(
                        expected_item_name="/my-producer",
                        allowlist_access_ids=get_allowed_ids,
                    ),
                ),
                bindings={
                    "jwcrypto.jws": self.mock_jws_module,
                },
            )

            self.mock_requests.post.return_value.status_code = 200
            self.mock_requests.post.return_value.json.return_value = {
                "access_id": "p-notallowed",
                "sub_claims": {},
            }

            status_code, _, _ = context(request_headers={"AkeylessCreds": token})
            assert status_code == 401

    def test_dry_run_access_id_allowed_by_default(self) -> None:
        """Accept dry-run access_id 'p-custom' by default."""
        token = _create_test_jwt_token("p-custom")

        with patch("requests.Session", return_value=self.mock_requests):
            context = clearskies.contexts.Context(
                clearskies.endpoints.Callable(
                    lambda: {"hello": "world"},
                    authentication=AkeylessProducerAuthentication(
                        expected_item_name="/my-producer",
                    ),
                ),
                bindings={
                    "jwcrypto.jws": self.mock_jws_module,
                },
            )

            self.mock_requests.post.return_value.status_code = 200
            self.mock_requests.post.return_value.json.return_value = {
                "access_id": "p-custom",
                "sub_claims": {},
            }

            status_code, _, _ = context(request_headers={"AkeylessCreds": token})
            assert status_code == 200

    def test_dry_run_access_id_rejected_when_disabled(self) -> None:
        """Reject dry-run access_id 'p-custom' when allow_dry_run=False."""
        token = _create_test_jwt_token("p-custom")

        with patch("requests.Session", return_value=self.mock_requests):
            context = clearskies.contexts.Context(
                clearskies.endpoints.Callable(
                    lambda: {"hello": "world"},
                    authentication=AkeylessProducerAuthentication(
                        expected_item_name="/my-producer",
                        allow_dry_run=False,
                    ),
                ),
                bindings={
                    "jwcrypto.jws": self.mock_jws_module,
                },
            )

            self.mock_requests.post.return_value.status_code = 200
            self.mock_requests.post.return_value.json.return_value = {
                "access_id": "p-custom",
                "sub_claims": {},
            }

            status_code, _, _ = context(request_headers={"AkeylessCreds": token})
            assert status_code == 401

    def test_invalid_token_returns_401(self) -> None:
        """Return 401 for invalid token format."""
        invalid_token = "not-a-valid-token!!!"

        with patch("requests.Session", return_value=self.mock_requests):
            context = clearskies.contexts.Context(
                clearskies.endpoints.Callable(
                    lambda: {"hello": "world"},
                    authentication=AkeylessProducerAuthentication(
                        expected_item_name="/my-producer",
                    ),
                ),
                bindings={
                    "jwcrypto.jws": self.mock_jws_module,
                },
            )

            status_code, _, _ = context(request_headers={"AkeylessCreds": invalid_token})
            assert status_code == 401

    def test_validation_endpoint_network_error_returns_401(self) -> None:
        """Return 401 when validation endpoint is unreachable."""
        token = _create_test_jwt_token("p-producer1")

        with patch("requests.Session", return_value=self.mock_requests):
            context = clearskies.contexts.Context(
                clearskies.endpoints.Callable(
                    lambda: {"hello": "world"},
                    authentication=AkeylessProducerAuthentication(
                        expected_item_name="/my-producer",
                    ),
                ),
                bindings={
                    "jwcrypto.jws": self.mock_jws_module,
                },
            )

            self.mock_requests.post.side_effect = Exception("Connection failed")

            status_code, _, _ = context(request_headers={"AkeylessCreds": token})
            assert status_code == 401

    def test_validation_endpoint_json_error_returns_401(self) -> None:
        """Return 401 when validation endpoint response is invalid JSON."""
        token = _create_test_jwt_token("p-producer1")

        with patch("requests.Session", return_value=self.mock_requests):
            context = clearskies.contexts.Context(
                clearskies.endpoints.Callable(
                    lambda: {"hello": "world"},
                    authentication=AkeylessProducerAuthentication(
                        expected_item_name="/my-producer",
                    ),
                ),
                bindings={
                    "jwcrypto.jws": self.mock_jws_module,
                },
            )

            self.mock_requests.post.return_value.status_code = 200
            self.mock_requests.post.return_value.json.side_effect = ValueError("Invalid JSON")

            status_code, _, _ = context(request_headers={"AkeylessCreds": token})
            assert status_code == 401
