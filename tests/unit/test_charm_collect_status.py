# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

from datetime import timedelta
from unittest.mock import MagicMock, Mock, patch

from charmlibs.interfaces.tls_certificates import (
    ProviderCertificate,
    RequirerCertificateRequest,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from ops.model import ActiveStatus, BlockedStatus
from pytest import fixture
from scenario import Context, Relation, Secret, State

from charm import LegoCharm

TLS_LIB_PATH = "charmlibs.interfaces.tls_certificates"
CERTIFICATES_RELATION_NAME = "certificates"
INGRESS_RELATION_NAME = "ingress"


class TestLegoOperatorCharmCollectStatus:
    @fixture(scope="function", autouse=True)
    def context(self):
        self.ctx = Context(LegoCharm)

    def test_given_not_leader_when_update_status_then_status_is_blocked(self):
        state = State(leader=False)
        out = self.ctx.run(self.ctx.on.collect_unit_status(), state)
        assert out.unit_status == BlockedStatus(
            "this charm does not scale, only the leader unit manages certificates."
        )

    def test_given_email_address_not_provided_when_update_config_then_status_is_blocked(self):
        state = State(
            leader=True,
            config={
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            },
        )
        out = self.ctx.run(self.ctx.on.collect_unit_status(), state)
        assert out.unit_status == BlockedStatus("email address was not provided")

    def test_given_server_not_provided_when_update_config_then_status_is_blocked(self):
        state = State(
            leader=True,
            config={"email": "banana@gmail.com", "server": ""},
        )
        out = self.ctx.run(self.ctx.on.collect_unit_status(), state)
        assert out.unit_status == BlockedStatus("acme server was not provided")

    def test_given_secret_id_not_provided_when_update_config_then_status_is_blocked(self):
        state = State(
            leader=True,
            config={
                "email": "banana@gmail.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            },
        )
        out = self.ctx.run(self.ctx.on.collect_unit_status(), state)
        assert out.unit_status == BlockedStatus("plugin configuration secret is not available")

    def test_given_plugin_not_provided_when_update_config_then_status_is_blocked(self):
        state = State(
            leader=True,
            secrets=[Secret({"wrong-key": "wrong-value"}, id="1")],
            config={
                "email": "banana@gmail.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "plugin-config-secret-id": "1",
            },
        )
        out = self.ctx.run(self.ctx.on.collect_unit_status(), state)
        assert out.unit_status == BlockedStatus("plugin was not provided")

    def test_given_invalid_email_when_update_config_then_status_is_blocked(self):
        state = State(
            leader=True,
            secrets=[Secret({"api-key": "apikey123"}, id="1")],
            config={
                "email": "invalid email",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "plugin": "httpreq",
                "plugin-config-secret-id": "1",
            },
        )
        out = self.ctx.run(self.ctx.on.collect_unit_status(), state)
        assert out.unit_status == BlockedStatus("invalid email address")

    def test_given_invalid_server_when_update_config_then_status_is_blocked(self):
        state = State(
            leader=True,
            secrets=[Secret({"api-key": "apikey123"}, id="1")],
            config={
                "email": "example@email.com",
                "server": "Invalid ACME server",
                "plugin": "httpreq",
                "plugin-config-secret-id": "1",
            },
        )
        out = self.ctx.run(self.ctx.on.collect_unit_status(), state)
        assert out.unit_status == BlockedStatus("invalid ACME server")

    def test_given_no_plugin_name_when_update_status_then_status_is_blocked(self):
        state = State(
            leader=True,
            secrets=[Secret({"wrong-api-key": "apikey123"}, id="1")],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "plugin-config-secret-id": "1",
            },
        )
        out = self.ctx.run(self.ctx.on.collect_unit_status(), state)
        assert out.unit_status == BlockedStatus("plugin was not provided")

    def test_given_invalid_plugin_config_when_update_status_then_status_is_blocked(self):
        state = State(
            leader=True,
            secrets=[Secret({"wrong-api-key": "apikey123"}, id="1")],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "plugin": "namecheap",
                "plugin-config-secret-id": "1",
            },
        )
        out = self.ctx.run(self.ctx.on.collect_unit_status(), state)
        assert out.unit_status == BlockedStatus(
            "namecheap-api-key and namecheap-api-user must be set"
        )

    def test_given_invalid_acme_ca_certificate_when_update_status_then_status_is_blocked(self):
        state = State(
            leader=True,
            secrets=[
                Secret({"namecheap-api-key": "apikey123", "namecheap-api-user": "a"}, id="1")
            ],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "plugin": "namecheap",
                "plugin-config-secret-id": "1",
                "acme-ca-certificates": "not a valid PEM certificate",
            },
        )
        out = self.ctx.run(self.ctx.on.collect_unit_status(), state)
        assert out.unit_status.name == "blocked"
        assert "acme-ca-certificates contains invalid PEM data" in out.unit_status.message

    def test_given_empty_acme_ca_certificate_when_update_status_then_status_is_active(self):
        state = State(
            leader=True,
            secrets=[
                Secret({"namecheap-api-key": "apikey123", "namecheap-api-user": "a"}, id="1")
            ],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "plugin": "namecheap",
                "plugin-config-secret-id": "1",
            },
        )
        out = self.ctx.run(self.ctx.on.collect_unit_status(), state)
        assert out.unit_status == ActiveStatus("0/0 certificate requests are fulfilled")

    def test_given_negative_dns_propagation_timeout_when_update_status_then_status_is_blocked(
        self,
    ):
        state = State(
            leader=True,
            secrets=[
                Secret({"namecheap-api-key": "apikey123", "namecheap-api-user": "a"}, id="1")
            ],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "plugin": "namecheap",
                "plugin-config-secret-id": "1",
                "dns-propagation-timeout": -100,
            },
        )
        out = self.ctx.run(self.ctx.on.collect_unit_status(), state)
        assert out.unit_status == BlockedStatus(
            "dns-propagation-timeout must be greater than 0"
        )

    def test_given_zero_dns_propagation_timeout_when_update_status_then_status_is_blocked(self):
        state = State(
            leader=True,
            secrets=[
                Secret({"namecheap-api-key": "apikey123", "namecheap-api-user": "a"}, id="1")
            ],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "plugin": "namecheap",
                "plugin-config-secret-id": "1",
                "dns-propagation-timeout": 0,
            },
        )
        out = self.ctx.run(self.ctx.on.collect_unit_status(), state)
        assert out.unit_status == BlockedStatus(
            "dns-propagation-timeout must be greater than 0"
        )

    def test_given_valid_dns_propagation_timeout_when_update_status_then_status_is_active(self):
        state = State(
            leader=True,
            secrets=[
                Secret({"namecheap-api-key": "apikey123", "namecheap-api-user": "a"}, id="1")
            ],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "plugin": "namecheap",
                "plugin-config-secret-id": "1",
                "dns-propagation-timeout": 600,
            },
        )
        out = self.ctx.run(self.ctx.on.collect_unit_status(), state)
        assert out.unit_status == ActiveStatus("0/0 certificate requests are fulfilled")

    def test_given_unset_dns_propagation_timeout_when_update_status_then_status_is_active(self):
        state = State(
            leader=True,
            secrets=[
                Secret({"namecheap-api-key": "apikey123", "namecheap-api-user": "a"}, id="1")
            ],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "plugin": "namecheap",
                "plugin-config-secret-id": "1",
            },
        )
        out = self.ctx.run(self.ctx.on.collect_unit_status(), state)
        assert out.unit_status == ActiveStatus("0/0 certificate requests are fulfilled")

    def test_given_http01_plugin_and_no_ingress_when_update_status_then_status_is_blocked(self):
        state = State(
            leader=True,
            config={
                "email": "user@example.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "plugin": "http",
            },
        )
        out = self.ctx.run(self.ctx.on.collect_unit_status(), state)
        assert out.unit_status == BlockedStatus("ingress relation is required for http-01 plugin")

    def test_given_http01_plugin_and_ingress_without_url_when_update_status_then_blocked(self):
        state = State(
            leader=True,
            config={
                "email": "user@example.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "plugin": "http",
            },
            relations=[
                Relation(endpoint=INGRESS_RELATION_NAME),
            ],
        )
        out = self.ctx.run(self.ctx.on.collect_unit_status(), state)
        assert out.unit_status == BlockedStatus("ingress URL not available; waiting for provider")

    def test_given_valid_acme_ca_certificate_when_update_status_then_status_is_active(self):
        ca_pk = generate_private_key()
        ca_cert = generate_ca(ca_pk, common_name="Test CA", validity=timedelta(days=365))
        state = State(
            leader=True,
            secrets=[
                Secret({"namecheap-api-key": "apikey123", "namecheap-api-user": "a"}, id="1")
            ],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "plugin": "namecheap",
                "plugin-config-secret-id": "1",
                "acme-ca-certificates": str(ca_cert),
            },
        )
        out = self.ctx.run(self.ctx.on.collect_unit_status(), state)
        assert out.unit_status == ActiveStatus("0/0 certificate requests are fulfilled")

    def test_given_valid_plugin_config_when_update_status_then_status_is_active(self):
        state = State(
            leader=True,
            secrets=[
                Secret({"namecheap-api-key": "apikey123", "namecheap-api-user": "a"}, id="1")
            ],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "plugin": "namecheap",
                "plugin-config-secret-id": "1",
            },
        )
        out = self.ctx.run(self.ctx.on.collect_unit_status(), state)
        assert out.unit_status == ActiveStatus("0/0 certificate requests are fulfilled")

    @patch("charm.run_lego_command")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate", new=Mock)
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_provider_certificates")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    def test_given_valid_config_and_pending_requests_when_update_status_then_status_is_active(
        self,
        mock_get_certificate_requests: MagicMock,
        mock_get_provider_certificates: MagicMock,
        mock_pylego: MagicMock,
    ):
        csr_pk_1 = generate_private_key()
        csr_1 = generate_csr(csr_pk_1, "foo.com")

        csr_pk_2 = generate_private_key()
        csr_2 = generate_csr(csr_pk_2, "bar.com")

        issuer_pk = generate_private_key()
        issuer = generate_ca(issuer_pk, common_name="ca", validity=timedelta(days=365))
        cert = generate_certificate(csr_1, issuer, issuer_pk, timedelta(days=365))
        chain = [cert, issuer]

        mock_get_certificate_requests.return_value = [
            RequirerCertificateRequest(
                relation_id=1, certificate_signing_request=csr_1, is_ca=False
            ),
            RequirerCertificateRequest(
                relation_id=1, certificate_signing_request=csr_2, is_ca=False
            ),
        ]
        mock_get_provider_certificates.return_value = [
            ProviderCertificate(
                relation_id=1,
                certificate_signing_request=csr_1,
                ca=issuer,
                certificate=cert,
                chain=chain,
            )
        ]

        state = State(
            leader=True,
            secrets=[Secret({"namecheap-api-key": "key", "namecheap-api-user": "a"}, id="1")],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "plugin": "namecheap",
                "plugin-config-secret-id": "1",
            },
            relations=[
                Relation(endpoint=CERTIFICATES_RELATION_NAME),
            ],
        )

        out = self.ctx.run(self.ctx.on.collect_unit_status(), state)
        assert out.unit_status == ActiveStatus(
            "1/2 certificate requests are fulfilled. please monitor logs for any errors"
        )
