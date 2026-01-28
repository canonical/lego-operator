# Copyright 2026 Ubuntu
# See LICENSE file for licensing details.

"""Unit tests for LEGOError to CertificateError mapping."""

from charmlibs.interfaces.tls_certificates import CertificateRequestErrorCode
from pylego import LEGOError
from pytest import fixture
from scenario import Context, State

from charm import LegoCharm


class TestLegoCharmMapError:
    """Test _map_lego_error_to_certificate_error mapping logic."""

    @fixture(scope="function", autouse=True)
    def context(self):
        self.ctx = Context(LegoCharm)

    def test_given_acme_rate_limited_when_map_error_then_other(self):
        state = State()
        with self.ctx(self.ctx.on.config_changed(), state) as manager:
            charm = manager.charm
            error = LEGOError(
                detail="Rate limit exceeded",
                type="acme",
                code="rateLimited",
                acme_type="urn:ietf:params:acme:error:rateLimited",
                info={"status": 429},
            )
            code = charm._map_lego_error_to_certificate_error(error)
            assert code == CertificateRequestErrorCode.OTHER

    def test_given_acme_dns_error_when_map_error_then_other(self):
        state = State()
        with self.ctx(self.ctx.on.config_changed(), state) as manager:
            charm = manager.charm
            error = LEGOError(
                detail="DNS problem: NXDOMAIN looking up TXT for _acme-challenge.example.com",
                type="acme",
                code="dns",
                acme_type="urn:ietf:params:acme:error:dns",
                info={"status": 400},
            )
            code = charm._map_lego_error_to_certificate_error(error)
            assert code == CertificateRequestErrorCode.OTHER

    def test_given_acme_unauthorized_when_map_error_then_other(self):
        state = State()
        with self.ctx(self.ctx.on.config_changed(), state) as manager:
            charm = manager.charm
            error = LEGOError(
                detail="Authorization failed for domain",
                type="acme",
                code="unauthorized",
                acme_type="urn:ietf:params:acme:error:unauthorized",
                info={"status": 403},
            )
            code = charm._map_lego_error_to_certificate_error(error)
            assert code == CertificateRequestErrorCode.OTHER

    def test_given_acme_rejected_identifier_ip_when_map_error_then_ip_not_allowed(self):
        state = State()
        with self.ctx(self.ctx.on.config_changed(), state) as manager:
            charm = manager.charm
            error = LEGOError(
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

    def test_given_acme_rejected_identifier_ip_from_detail_when_map_error_then_ip_not_allowed(
        self,
    ):
        state = State()
        with self.ctx(self.ctx.on.config_changed(), state) as manager:
            charm = manager.charm
            error = LEGOError(
                detail="Error creating new order :: Cannot issue for IP address",
                type="acme",
                code="rejectedIdentifier",
                acme_type="urn:ietf:params:acme:error:rejectedIdentifier",
                info={"status": 400},
            )
            code = charm._map_lego_error_to_certificate_error(error)
            assert code == CertificateRequestErrorCode.IP_NOT_ALLOWED

    def test_given_acme_rejected_wildcard_when_map_error_then_wildcard_not_allowed(self):
        state = State()
        with self.ctx(self.ctx.on.config_changed(), state) as manager:
            charm = manager.charm
            error = LEGOError(
                detail="Error creating new order :: Wildcard domains not supported",
                type="acme",
                code="rejectedIdentifier",
                acme_type="urn:ietf:params:acme:error:rejectedIdentifier",
                info={"status": 400},
            )
            code = charm._map_lego_error_to_certificate_error(error)
            assert code == CertificateRequestErrorCode.WILDCARD_NOT_ALLOWED

    def test_given_lego_network_error_when_map_error_then_server_not_available(self):
        state = State()
        with self.ctx(self.ctx.on.config_changed(), state) as manager:
            charm = manager.charm
            error = LEGOError(
                detail="dial tcp 127.0.0.1:443: connect: connection refused",
                type="lego",
                code="network_error",
            )
            code = charm._map_lego_error_to_certificate_error(error)
            assert code == CertificateRequestErrorCode.SERVER_NOT_AVAILABLE

    def test_given_lego_other_error_when_map_error_then_other(self):
        state = State()
        with self.ctx(self.ctx.on.config_changed(), state) as manager:
            charm = manager.charm
            error = LEGOError(
                detail="DNS provider authentication failed",
                type="lego",
                code="dns_provider_failed",
            )
            code = charm._map_lego_error_to_certificate_error(error)
            assert code == CertificateRequestErrorCode.OTHER

    def test_given_acme_unknown_error_when_map_error_then_other(self):
        state = State()
        with self.ctx(self.ctx.on.config_changed(), state) as manager:
            charm = manager.charm
            error = LEGOError(
                detail="Unknown ACME error",
                type="acme",
                code="unknownError",
                acme_type="urn:ietf:params:acme:error:unknownError",
                info={"status": 500},
            )
            code = charm._map_lego_error_to_certificate_error(error)
            assert code == CertificateRequestErrorCode.OTHER
