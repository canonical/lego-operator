# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

from datetime import timedelta
from unittest.mock import MagicMock, Mock, patch

from charms.tls_certificates_interface.v4.tls_certificates import (
    ProviderCertificate,
    RequirerCertificateRequest,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from ops import ActiveStatus
from pylego import LEGOError, LEGOResponse
from pylego.pylego import Metadata
from pytest import fixture
from scenario import Context, Relation, Secret, State

from charm import LegoCharm

TLS_LIB_PATH = "charms.tls_certificates_interface.v4.tls_certificates"
CERT_TRANSFER_LIB_PATH = "charms.certificate_transfer_interface.v1.certificate_transfer"
CERTIFICATES_RELATION_NAME = "certificates"
CA_TRANSFER_RELATION_NAME = "send-ca-cert"


class TestLegoOperatorCharmConfigure:
    @fixture(scope="function", autouse=True)
    def context(self):
        self.ctx = Context(LegoCharm)

    @patch("charm.run_lego_command")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate")
    def test_given_cmd_when_certificate_creation_request_then_certificate_is_set_in_relation(
        self,
        mock_set_relation_certificate: MagicMock,
        mock_get_outstanding_certificate_requests: MagicMock,
        mock_pylego: MagicMock,
    ):
        csr_pk = generate_private_key()
        csr = generate_csr(csr_pk, "foo.com")
        issuer_pk = generate_private_key()
        issuer = generate_ca(issuer_pk, common_name="ca", validity=timedelta(days=365))
        cert = generate_certificate(csr, issuer, issuer_pk, validity=timedelta(days=365))
        chain = [cert, issuer]

        mock_get_outstanding_certificate_requests.return_value = [
            RequirerCertificateRequest(relation_id=1, certificate_signing_request=csr, is_ca=True)
        ]

        mock_pylego.return_value = LEGOResponse(
            csr=str(csr),
            private_key=str(generate_private_key()),
            certificate=str(cert),
            issuer_certificate=str(issuer),
            metadata=Metadata(stable_url="stable url", url="url", domain="domain.com"),
        )

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
            relations=[
                Relation(endpoint=CERTIFICATES_RELATION_NAME),
            ],
            unit_status=ActiveStatus(),  # type: ignore
        )

        self.ctx.run(self.ctx.on.update_status(), state)
        mock_pylego.assert_called_with(
            email="example@email.com",
            server="https://acme-v02.api.letsencrypt.org/directory",
            csr=str(csr).encode(),
            env={"NAMECHEAP_API_KEY": "apikey123", "NAMECHEAP_API_USER": "a"},
            plugin="namecheap",
        )
        mock_set_relation_certificate.assert_called_with(
            provider_certificate=ProviderCertificate(
                certificate=cert,
                certificate_signing_request=csr,
                ca=issuer,
                chain=chain,
                relation_id=1,
            ),
        )

    @patch("charm.run_lego_command")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate")
    def test_given_cmd_execution_fails_when_certificate_creation_request_then_request_fails(
        self,
        mock_set_relation_certificate: MagicMock,
        mock_get_certificate_requests: MagicMock,
        mock_pylego: MagicMock,
    ):
        csr_pk = generate_private_key()
        csr = generate_csr(csr_pk, "foo.com")

        mock_get_certificate_requests.return_value = [
            RequirerCertificateRequest(relation_id=1, certificate_signing_request=csr, is_ca=True)
        ]

        mock_pylego.side_effect = LEGOError("its bad")

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
            relations=[
                Relation(endpoint=CERTIFICATES_RELATION_NAME),
            ],
            unit_status=ActiveStatus(),  # type: ignore
        )

        self.ctx.run(self.ctx.on.update_status(), state)
        mock_pylego.assert_called_with(
            email="example@email.com",
            server="https://acme-v02.api.letsencrypt.org/directory",
            csr=str(csr).encode(),
            env={"NAMECHEAP_API_KEY": "apikey123", "NAMECHEAP_API_USER": "a"},
            plugin="namecheap",
        )
        assert not mock_set_relation_certificate.called

    @patch.dict(
        "os.environ",
        {
            "JUJU_CHARM_HTTP_PROXY": "Random proxy",
            "JUJU_CHARM_HTTPS_PROXY": "Random https proxy",
            "JUJU_CHARM_NO_PROXY": "No proxy",
        },
    )
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate", new=Mock)
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    @patch("charm.run_lego_command")
    def test_given_cmd_when_app_environment_variables_set_then_command_executed_with_environment_variables(  # noqa: E501
        self,
        mock_pylego: MagicMock,
        mock_get_certificate_requests: MagicMock,
    ):
        csr_pk = generate_private_key()
        csr = generate_csr(csr_pk, "foo.com")
        issuer_pk = generate_private_key()
        issuer = generate_ca(issuer_pk, common_name="ca", validity=timedelta(days=365))
        cert = generate_certificate(csr, issuer, issuer_pk, timedelta(days=365))

        mock_get_certificate_requests.return_value = [
            RequirerCertificateRequest(relation_id=1, certificate_signing_request=csr, is_ca=True)
        ]

        mock_pylego.return_value = LEGOResponse(
            csr=str(csr),
            private_key=str(generate_private_key()),
            certificate=str(cert),
            issuer_certificate=str(issuer),
            metadata=Metadata(stable_url="stable url", url="url", domain="domain.com"),
        )

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
            relations=[Relation(endpoint=CERTIFICATES_RELATION_NAME)],
            unit_status=ActiveStatus(),  # type: ignore
        )

        self.ctx.run(self.ctx.on.update_status(), state)

        mock_pylego.assert_called_with(
            email="example@email.com",
            server="https://acme-v02.api.letsencrypt.org/directory",
            csr=str(csr).encode(),
            env={
                "NAMECHEAP_API_KEY": "apikey123",
                "NAMECHEAP_API_USER": "a",
                "HTTP_PROXY": "Random proxy",
                "HTTPS_PROXY": "Random https proxy",
                "NO_PROXY": "No proxy",
            },
            plugin="namecheap",
        )

    @patch(f"{CERT_TRANSFER_LIB_PATH}.CertificateTransferProvides.add_certificates")
    def test_given_cert_transfer_relation_not_created_then_ca_certificates_not_added_in_relation_data(  # noqa: E501
        self, mock_add_certificates: MagicMock
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
            },
            relations=[Relation(endpoint=CERTIFICATES_RELATION_NAME)],
            unit_status=ActiveStatus(),  # type: ignore
        )

        self.ctx.run(self.ctx.on.update_status(), state)
        mock_add_certificates.assert_not_called()

    @patch(f"{CERT_TRANSFER_LIB_PATH}.CertificateTransferProvides.add_certificates")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_provider_certificates")
    def test_given_cert_transfer_relation_and_ca_certificates_then_ca_certificates_added_in_relation_data(  # noqa: E501
        self, mock_get_provider_certificates: MagicMock, mock_add_certificates: MagicMock
    ):
        private_key = generate_private_key()
        csr = generate_csr(private_key, "foo.com")

        server_private_key = generate_private_key()
        ca = generate_ca(server_private_key, timedelta(days=365), "ca.com")
        certificate = generate_certificate(csr, ca, server_private_key, timedelta(days=365))

        mock_get_provider_certificates.return_value = [
            ProviderCertificate(
                relation_id=1,
                certificate_signing_request=csr,
                certificate=certificate,
                ca=ca,
                chain=[ca],
                revoked=False,
            )
        ]

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
            relations=[
                Relation(id=1, endpoint=CERTIFICATES_RELATION_NAME),
                Relation(id=2, endpoint=CA_TRANSFER_RELATION_NAME),
            ],
            unit_status=ActiveStatus(),  # type: ignore
        )

        self.ctx.run(self.ctx.on.update_status(), state)

        mock_add_certificates.assert_called_with({str(ca)})
