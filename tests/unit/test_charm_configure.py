# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import os
import tempfile
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
from ops import ActiveStatus
from pylego import LEGOError, LEGOResponse
from pylego.pylego import Metadata
from pytest import fixture
from scenario import Context, Relation, Secret, State

from charm import LegoCharm

TLS_LIB_PATH = "charmlibs.interfaces.tls_certificates"
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
    @patch("charm.generate_private_key")
    def test_given_cmd_when_certificate_creation_request_then_certificate_is_set_in_relation(
        self,
        mock_generate_private_key: MagicMock,
        mock_set_relation_certificate: MagicMock,
        mock_get_outstanding_certificate_requests: MagicMock,
        mock_pylego: MagicMock,
    ):
        mock_account_pk = generate_private_key()
        mock_generate_private_key.return_value = mock_account_pk
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
            certificate=f"{str(cert)}\n{str(issuer)}",
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
                "dns-propagation-wait": 600,
            },
            relations=[
                Relation(endpoint=CERTIFICATES_RELATION_NAME),
            ],
            unit_status=ActiveStatus(),  # type: ignore
        )

        self.ctx.run(self.ctx.on.update_status(), state)
        mock_pylego.assert_called_with(
            email="example@email.com",
            private_key=str(mock_account_pk),
            server="https://acme-v02.api.letsencrypt.org/directory",
            csr=str(csr).encode(),
            env={"NAMECHEAP_API_KEY": "apikey123", "NAMECHEAP_API_USER": "a"},
            plugin="namecheap",
            dns_propagation_wait=600,
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
    @patch("charm.generate_private_key")
    def test_given_cmd_execution_fails_when_certificate_creation_request_then_request_fails(
        self,
        mock_generate_private_key: MagicMock,
        mock_set_relation_certificate: MagicMock,
        mock_get_certificate_requests: MagicMock,
        mock_pylego: MagicMock,
    ):
        mock_account_pk = generate_private_key()
        mock_generate_private_key.return_value = mock_account_pk
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
            private_key=str(mock_account_pk),
            server="https://acme-v02.api.letsencrypt.org/directory",
            csr=str(csr).encode(),
            env={"NAMECHEAP_API_KEY": "apikey123", "NAMECHEAP_API_USER": "a"},
            plugin="namecheap",
            dns_propagation_wait=None,
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
    @patch("charm.generate_private_key")
    def test_given_cmd_when_app_environment_variables_set_then_command_executed_with_environment_variables(  # noqa: E501
        self,
        mock_generate_private_key: MagicMock,
        mock_pylego: MagicMock,
        mock_get_certificate_requests: MagicMock,
    ):
        mock_account_pk = generate_private_key()
        mock_generate_private_key.return_value = mock_account_pk
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
            certificate=f"{str(cert)}\n{str(issuer)}",
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
            private_key=str(mock_account_pk),
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
            dns_propagation_wait=None,
        )

    @patch("charm.run_lego_command")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate", new=Mock)
    @patch("charm.generate_private_key")
    def test_given_http01_plugin_when_request_then_http01_env_and_plugin_used(
        self,
        mock_generate_private_key: MagicMock,
        mock_get_certificate_requests: MagicMock,
        mock_run_lego: MagicMock,
    ):
        mock_account_pk = generate_private_key()
        mock_generate_private_key.return_value = mock_account_pk
        csr_pk = generate_private_key()
        csr = generate_csr(csr_pk, "foo.example")
        issuer_pk = generate_private_key()
        issuer = generate_ca(issuer_pk, common_name="ca", validity=timedelta(days=365))
        cert = generate_certificate(csr, issuer, issuer_pk, validity=timedelta(days=365))

        mock_get_certificate_requests.return_value = [
            RequirerCertificateRequest(relation_id=1, certificate_signing_request=csr, is_ca=True)
        ]

        mock_run_lego.return_value = LEGOResponse(
            csr=str(csr),
            private_key=str(generate_private_key()),
            certificate=f"{str(cert)}\n{str(issuer)}",
            issuer_certificate=str(issuer),
            metadata=Metadata(stable_url="stable", url="tmp", domain="foo.example"),
        )

        state = State(
            leader=True,
            config={
                "email": "user@example.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "plugin": "http",
            },
            relations=[Relation(endpoint=CERTIFICATES_RELATION_NAME)],
            unit_status=ActiveStatus(),  # type: ignore
        )

        self.ctx.run(self.ctx.on.update_status(), state)

        kwargs = mock_run_lego.call_args.kwargs  # type: ignore[attr-defined]
        assert kwargs["plugin"] == "http"
        assert kwargs["env"]["HTTP01_PORT"] == "8080"
        assert kwargs["env"]["HTTP01_IFACE"] == ""

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

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate", new=Mock)
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    @patch("charm.run_lego_command")
    @patch("charm.generate_private_key")
    def test_given_valid_config_when_configure_then_private_key_is_generated_and_stored(
        self,
        mock_generate_private_key: MagicMock,
        mock_pylego: MagicMock,
        mock_get_certificate_requests: MagicMock,
    ):
        mock_account_pk = generate_private_key()
        mock_generate_private_key.return_value = mock_account_pk
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
            certificate=f"{str(cert)}\n{str(issuer)}",
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

        state_out = self.ctx.run(self.ctx.on.update_status(), state)
        assert "acme-account-details" in [s.label for s in state_out.secrets]
        assert {"private-key": str(mock_account_pk), "email": "example@email.com"} in [
            s.tracked_content for s in state_out.secrets
        ]

    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate", new=Mock)
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    @patch("charm.run_lego_command")
    @patch("charm.generate_private_key")
    def test_given_email_changed_when_configure_then_private_key_is_generated_and_stored(
        self,
        mock_generate_private_key: MagicMock,
        mock_pylego: MagicMock,
        mock_get_certificate_requests: MagicMock,
    ):
        mock_account_pk = generate_private_key()
        mock_generate_private_key.return_value = mock_account_pk
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
            certificate=f"{str(cert)}\n{str(issuer)}",
            issuer_certificate=str(issuer),
            metadata=Metadata(stable_url="stable url", url="url", domain="domain.com"),
        )

        state = State(
            leader=True,
            secrets=[
                Secret({"namecheap-api-key": "apikey123", "namecheap-api-user": "a"}, id="1"),
                Secret(
                    {"private-key": str(mock_account_pk), "email": "example@email.com"}, id="2"
                ),
            ],
            config={
                "email": "different@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "plugin": "namecheap",
                "plugin-config-secret-id": "1",
            },
            relations=[Relation(endpoint=CERTIFICATES_RELATION_NAME)],
            unit_status=ActiveStatus(),  # type: ignore
        )

        state_out = self.ctx.run(self.ctx.on.update_status(), state)
        assert "acme-account-details" in [s.label for s in state_out.secrets]
        assert {"private-key": str(mock_account_pk), "email": "different@email.com"} in [
            s.tracked_content for s in state_out.secrets
        ]

    @patch("charm.run_lego_command")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    @patch("charm.generate_private_key")
    def test_given_ca_cert_configured_when_certificate_request_then_lego_uses_ca_env_var(
        self,
        mock_generate_private_key: MagicMock,
        mock_get_certificate_requests: MagicMock,
        mock_run_lego: MagicMock,
    ):
        ca_pk = generate_private_key()
        ca_cert = generate_ca(ca_pk, common_name="Test CA", validity=timedelta(days=365))
        mock_account_pk = generate_private_key()
        mock_generate_private_key.return_value = mock_account_pk
        csr_pk = generate_private_key()
        csr = generate_csr(csr_pk, "foo.com")
        issuer_pk = generate_private_key()
        issuer = generate_ca(issuer_pk, common_name="ca", validity=timedelta(days=365))
        cert = generate_certificate(csr, issuer, issuer_pk, timedelta(days=365))

        mock_get_certificate_requests.return_value = [
            RequirerCertificateRequest(relation_id=1, certificate_signing_request=csr, is_ca=True)
        ]
        mock_run_lego.return_value = LEGOResponse(
            csr=str(csr),
            private_key=str(generate_private_key()),
            certificate=f"{str(cert)}\n{str(issuer)}",
            issuer_certificate=str(issuer),
            metadata=Metadata(stable_url="stable url", url="url", domain="domain.com"),
        )

        # Create a temporary file to simulate the CA bundle
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem") as f:
            f.write(str(ca_cert))
            ca_file_path = f.name

        try:
            with patch("charm.ACME_CA_CERTIFICATES_FILE_PATH", ca_file_path):
                state = State(
                    leader=True,
                    secrets=[
                        Secret(
                            {"namecheap-api-key": "apikey123", "namecheap-api-user": "a"}, id="1"
                        )
                    ],
                    config={
                        "email": "example@email.com",
                        "server": "https://acme-v02.api.letsencrypt.org/directory",
                        "plugin": "namecheap",
                        "plugin-config-secret-id": "1",
                        "acme-ca-certificates": str(ca_cert),
                    },
                    relations=[Relation(endpoint=CERTIFICATES_RELATION_NAME)],
                    unit_status=ActiveStatus(),  # type: ignore
                )

                self.ctx.run(self.ctx.on.config_changed(), state)

                mock_run_lego.assert_called_once()
                env_arg = mock_run_lego.call_args[1]["env"]
                assert "LEGO_CA_CERTIFICATES" in env_arg
                assert env_arg["LEGO_CA_CERTIFICATES"] == ca_file_path
        finally:
            os.unlink(ca_file_path)

    @patch("charm.run_lego_command")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_error")
    @patch("charm.generate_private_key")
    def test_given_ip_rejection_error_when_certificate_request_then_ip_not_allowed_error_set(
        self,
        mock_generate_private_key: MagicMock,
        mock_set_relation_error: MagicMock,
        mock_get_certificate_requests: MagicMock,
        mock_pylego: MagicMock,
    ):
        """Test that IP address rejections are correctly identified and mapped."""
        mock_account_pk = generate_private_key()
        mock_generate_private_key.return_value = mock_account_pk
        csr_pk = generate_private_key()
        csr = generate_csr(csr_pk, "192.168.1.1")

        mock_get_certificate_requests.return_value = [
            RequirerCertificateRequest(relation_id=1, certificate_signing_request=csr, is_ca=False)
        ]

        # Simulate ACME rejectedIdentifier error for IP address
        mock_pylego.side_effect = LEGOError(
            detail="Error creating new order :: Cannot issue for IP address",
            type="acme",
            code="rejectedIdentifier",
            acme_type="urn:ietf:params:acme:error:rejectedIdentifier",
            status=400,
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

        # Verify set_relation_error was called
        assert mock_set_relation_error.called
        call_args = mock_set_relation_error.call_args[1]
        provider_error = call_args["provider_error"]
        
        # Verify the error code and name are correct for IP rejection
        from charmlibs.interfaces.tls_certificates import CertificateRequestErrorCode
        assert provider_error.error.code == CertificateRequestErrorCode.IP_NOT_ALLOWED
        assert provider_error.error.name == "IP_NOT_ALLOWED"
        assert provider_error.relation_id == 1

    @patch("charm.run_lego_command")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_error")
    @patch("charm.generate_private_key")
    def test_given_domain_rejection_when_certificate_request_then_domain_not_allowed_error_set(
        self,
        mock_generate_private_key: MagicMock,
        mock_set_relation_error: MagicMock,
        mock_get_certificate_requests: MagicMock,
        mock_pylego: MagicMock,
    ):
        """Test that domain rejections (non-IP) are correctly mapped to DOMAIN_NOT_ALLOWED."""
        mock_account_pk = generate_private_key()
        mock_generate_private_key.return_value = mock_account_pk
        csr_pk = generate_private_key()
        csr = generate_csr(csr_pk, "example.com")

        mock_get_certificate_requests.return_value = [
            RequirerCertificateRequest(relation_id=1, certificate_signing_request=csr, is_ca=False)
        ]

        # Simulate ACME rejectedIdentifier error for domain (no IP keywords)
        mock_pylego.side_effect = LEGOError(
            detail="Domain example.com is not allowed",
            type="acme",
            code="rejectedIdentifier",
            acme_type="urn:ietf:params:acme:error:rejectedIdentifier",
            status=400,
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

        # Verify set_relation_error was called with DOMAIN_NOT_ALLOWED
        assert mock_set_relation_error.called
        call_args = mock_set_relation_error.call_args[1]
        provider_error = call_args["provider_error"]
        
        from charmlibs.interfaces.tls_certificates import CertificateRequestErrorCode
        assert provider_error.error.code == CertificateRequestErrorCode.DOMAIN_NOT_ALLOWED
        assert provider_error.error.name == "DOMAIN_NOT_ALLOWED"

    @patch("charm.run_lego_command")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_error")
    @patch("charm.generate_private_key")
    def test_given_network_error_when_certificate_request_then_server_not_available_error_set(
        self,
        mock_generate_private_key: MagicMock,
        mock_set_relation_error: MagicMock,
        mock_get_certificate_requests: MagicMock,
        mock_pylego: MagicMock,
    ):
        """Test that network errors are correctly mapped to SERVER_NOT_AVAILABLE."""
        mock_account_pk = generate_private_key()
        mock_generate_private_key.return_value = mock_account_pk
        csr_pk = generate_private_key()
        csr = generate_csr(csr_pk, "example.com")

        mock_get_certificate_requests.return_value = [
            RequirerCertificateRequest(relation_id=1, certificate_signing_request=csr, is_ca=False)
        ]

        # Simulate network error detected by Pylego
        mock_pylego.side_effect = LEGOError(
            detail="dial tcp 127.0.0.1:443: connect: connection refused",
            type="lego",
            code="network_error",
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

        # Verify set_relation_error was called with SERVER_NOT_AVAILABLE
        assert mock_set_relation_error.called
        call_args = mock_set_relation_error.call_args[1]
        provider_error = call_args["provider_error"]
        
        from charmlibs.interfaces.tls_certificates import CertificateRequestErrorCode
        assert provider_error.error.code == CertificateRequestErrorCode.SERVER_NOT_AVAILABLE.value
        assert provider_error.error.name == "SERVER_NOT_AVAILABLE"
