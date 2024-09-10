# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

from unittest.mock import Mock, patch

from charms.tls_certificates_interface.v4.tls_certificates import (
    ProviderCertificate,
    RequirerCSR,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from ops.model import ActiveStatus, BlockedStatus
from pytest import fixture
from scenario import Context, Relation, Secret, State

from charm import LegoCharm

TLS_LIB_PATH = "charms.tls_certificates_interface.v4.tls_certificates"
CERTIFICATES_RELATION_NAME = "certificates"


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
        assert out.unit_status == BlockedStatus("plugin configuration secret was not provided")

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

    def test_given_invalid_plugin_config_when_update_status_then_status_is_blocked(self):
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

    def test_given_valid_specific_config_when_update_status_then_status_is_active(self):
        state = State(
            leader=True,
            secrets=[Secret({"api-key": "apikey123"}, id="1")],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "plugin": "example",
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
        self, mock_get_certificate_requests, mock_get_provider_certificates, mock_pylego
    ):
        csr_pk_1 = generate_private_key()
        csr_1 = generate_csr(csr_pk_1, "foo.com")

        csr_pk_2 = generate_private_key()
        csr_2 = generate_csr(csr_pk_2, "bar.com")

        issuer_pk = generate_private_key()
        issuer = generate_ca(issuer_pk, common_name="ca", validity=365)
        cert = generate_certificate(csr_1, issuer, issuer_pk, 365)
        chain = [cert, issuer]

        mock_get_certificate_requests.return_value = [
            RequirerCSR(relation_id=1, certificate_signing_request=csr_1, is_ca=False),
            RequirerCSR(relation_id=1, certificate_signing_request=csr_2, is_ca=False),
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
            secrets=[Secret({"api-key": "apikey123"}, id="1")],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "plugin": "example",
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
