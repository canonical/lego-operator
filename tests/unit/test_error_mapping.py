# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.

"""Unit tests for LEGOError to CertificateError mapping."""

from unittest.mock import patch

from pytest import fixture
from scenario import Context, State

from charmlibs.interfaces.tls_certificates import CertificateRequestErrorCode
from charm import LegoCharm


class MockLEGOError:
    """Mock LEGOError for testing without importing the full pylego library."""

    def __init__(
        self,
        detail: str,
        *,
        type: str = "lego",
        code: str = "",
        acme_type: str = "",
        info: dict | None = None,
    ):
        """Initialize mock LEGOError with attributes used by the mapper.

        Args:
            detail: Human-readable error message
            type: "acme" for CA server errors, "lego" for client/provider errors
            code: Machine-readable error code
            acme_type: Full ACME problem type URN (ACME errors only)
            info: Raw error dictionary (may include HTTP status for ACME)
        """
        self.detail = detail
        self.type = type
        self.code = code
        self.acme_type = acme_type
        self.info = info or {}
        # Extract subproblems from info if present
        self.subproblems = self.info.get("subproblems", [])


class TestLegoCharmMapError:
    """Test _map_lego_error_to_certificate_error mapping logic."""

    @fixture(scope="function", autouse=True)
    def context(self):
        self.ctx = Context(LegoCharm)

    @patch("charm.LegoCharm._on_config_changed")
    def test_given_acme_rate_limited_when_map_error_then_server_not_available(self, _):
        """Test ACME rate limit errors are treated as transient."""
        state = State()
        with self.ctx(self.ctx.on.config_changed(), state) as manager:
            charm = manager.charm
            error = MockLEGOError(
                detail="Rate limit exceeded",
                type="acme",
                code="rateLimited",
                acme_type="urn:ietf:params:acme:error:rateLimited",
                info={"status": 429},
            )
            code = charm._map_lego_error_to_certificate_error(error)
            assert code == CertificateRequestErrorCode.SERVER_NOT_AVAILABLE

    @patch("charm.LegoCharm._on_config_changed")
    def test_given_acme_dns_error_when_map_error_then_server_not_available(self, _):
        """Test ACME DNS errors are treated as transient (DNS propagation delays)."""
        state = State()
        with self.ctx(self.ctx.on.config_changed(), state) as manager:
            charm = manager.charm
            error = MockLEGOError(
                detail="DNS problem: NXDOMAIN looking up TXT for _acme-challenge.example.com",
                type="acme",
                code="dns",
                acme_type="urn:ietf:params:acme:error:dns",
                info={"status": 400},
            )
            code = charm._map_lego_error_to_certificate_error(error)
            assert code == CertificateRequestErrorCode.SERVER_NOT_AVAILABLE

    @patch("charm.LegoCharm._on_config_changed")
    def test_given_acme_unauthorized_when_map_error_then_domain_not_allowed(self, _):
        """Test ACME authorization failures map to domain not allowed."""
        state = State()
        with self.ctx(self.ctx.on.config_changed(), state) as manager:
            charm = manager.charm
            error = MockLEGOError(
                detail="Authorization failed for domain",
                type="acme",
                code="unauthorized",
                acme_type="urn:ietf:params:acme:error:unauthorized",
                info={"status": 403},
            )
            code = charm._map_lego_error_to_certificate_error(error)
            assert code == CertificateRequestErrorCode.DOMAIN_NOT_ALLOWED

    @patch("charm.LegoCharm._on_config_changed")
    def test_given_acme_rejected_identifier_ip_when_map_error_then_ip_not_allowed(self, _):
        """Test IP address rejection detected via subproblems."""
        state = State()
        with self.ctx(self.ctx.on.config_changed(), state) as manager:
            charm = manager.charm
            error = MockLEGOError(
                detail="IP address rejected",
                type="acme",
                code="rejectedIdentifier",
                acme_type="urn:ietf:params:acme:error:rejectedIdentifier",
                info={
                    "status": 400,
                    "subproblems": [
                        {
                            "type": "rejectedIdentifier",
                            "detail": "IP addresses are not allowed",
                            "identifier": {"type": "ip", "value": "192.168.1.1"},
                        }
                    ],
                },
            )
            code = charm._map_lego_error_to_certificate_error(error)
            assert code == CertificateRequestErrorCode.IP_NOT_ALLOWED

    @patch("charm.LegoCharm._on_config_changed")
    def test_given_acme_rejected_identifier_ip_from_detail_when_map_error_then_ip_not_allowed(
        self, _
    ):
        """Test IP address rejection detected via detail message (fallback)."""
        state = State()
        with self.ctx(self.ctx.on.config_changed(), state) as manager:
            charm = manager.charm
            error = MockLEGOError(
                detail="Error creating new order :: Cannot issue for IP address",
                type="acme",
                code="rejectedIdentifier",
                acme_type="urn:ietf:params:acme:error:rejectedIdentifier",
                info={"status": 400},
            )
            code = charm._map_lego_error_to_certificate_error(error)
            assert code == CertificateRequestErrorCode.IP_NOT_ALLOWED

    @patch("charm.LegoCharm._on_config_changed")
    def test_given_acme_rejected_wildcard_when_map_error_then_wildcard_not_allowed(self, _):
        """Test wildcard domain rejection is properly identified."""
        state = State()
        with self.ctx(self.ctx.on.config_changed(), state) as manager:
            charm = manager.charm
            error = MockLEGOError(
                detail="Error creating new order :: Wildcard domains not supported",
                type="acme",
                code="rejectedIdentifier",
                acme_type="urn:ietf:params:acme:error:rejectedIdentifier",
                info={"status": 400},
            )
            code = charm._map_lego_error_to_certificate_error(error)
            assert code == CertificateRequestErrorCode.WILDCARD_NOT_ALLOWED

    @patch("charm.LegoCharm._on_config_changed")
    def test_given_lego_network_error_when_map_error_then_server_not_available(self, _):
        """Test lego network errors are treated as transient."""
        state = State()
        with self.ctx(self.ctx.on.config_changed(), state) as manager:
            charm = manager.charm
            error = MockLEGOError(
                detail="dial tcp 127.0.0.1:443: connect: connection refused",
                type="lego",
                code="network_error",
            )
            code = charm._map_lego_error_to_certificate_error(error)
            assert code == CertificateRequestErrorCode.SERVER_NOT_AVAILABLE

    @patch("charm.LegoCharm._on_config_changed")
    def test_given_lego_other_error_when_map_error_then_other(self, _):
        """Test non-network lego errors map to OTHER."""
        state = State()
        with self.ctx(self.ctx.on.config_changed(), state) as manager:
            charm = manager.charm
            error = MockLEGOError(
                detail="DNS provider authentication failed",
                type="lego",
                code="dns_provider_failed",
            )
            code = charm._map_lego_error_to_certificate_error(error)
            assert code == CertificateRequestErrorCode.OTHER

    @patch("charm.LegoCharm._on_config_changed")
    def test_given_acme_unknown_error_when_map_error_then_other(self, _):
        """Test unrecognized ACME errors default to OTHER."""
        state = State()
        with self.ctx(self.ctx.on.config_changed(), state) as manager:
            charm = manager.charm
            error = MockLEGOError(
                detail="Unknown ACME error",
                type="acme",
                code="unknownError",
                acme_type="urn:ietf:params:acme:error:unknownError",
                info={"status": 500},
            )
            code = charm._map_lego_error_to_certificate_error(error)
            assert code == CertificateRequestErrorCode.OTHER
