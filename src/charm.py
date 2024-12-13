#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Lego Operator Charm."""

import logging
import os
import re
from contextlib import contextmanager
from typing import Any, Dict
from urllib.parse import urlparse

from charms.certificate_transfer_interface.v1.certificate_transfer import (
    CertificateTransferProvides,
)
from charms.loki_k8s.v1.loki_push_api import LogForwarder
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateSigningRequest,
    ProviderCertificate,
    TLSCertificatesProvidesV4,
)
from ops import ModelError, Secret, SecretNotFoundError, main
from ops.charm import CharmBase, CollectStatusEvent
from ops.framework import EventBase
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus
from pylego import LEGOError, run_lego_command

import plugin_configs

logger = logging.getLogger(__name__)

CERTIFICATES_RELATION_NAME = "certificates"
CA_TRANSFER_RELATION_NAME = "send-ca-cert"


class LegoCharm(CharmBase):
    """Base charm for charms that use the ACME protocol to get certificates.

    This charm implements the tls_certificates interface as a provider.
    """

    def __init__(self, *args: Any):
        super().__init__(*args)
        self._logging = LogForwarder(self, relation_name="logging")
        self.tls_certificates = TLSCertificatesProvidesV4(self, CERTIFICATES_RELATION_NAME)
        self.cert_transfer = CertificateTransferProvides(self, CA_TRANSFER_RELATION_NAME)

        [
            self.framework.observe(event, self._configure)
            for event in [
                self.on[CA_TRANSFER_RELATION_NAME].relation_joined,
                self.on[CERTIFICATES_RELATION_NAME].relation_changed,
                self.on.secret_changed,
                self.on.config_changed,
                self.on.update_status,
            ]
        ]
        self.framework.observe(self.on.collect_unit_status, self._on_collect_status)

        self._plugin = str(self.model.config.get("plugin", ""))

    def _on_collect_status(self, event: CollectStatusEvent) -> None:
        """Handle the collect status event."""
        if not self.unit.is_leader():
            event.add_status(
                BlockedStatus(
                    "this charm does not scale, only the leader unit manages certificates."
                )
            )
            return
        if err := self._validate_charm_config_options():
            event.add_status(BlockedStatus(err))
            return
        if err := self._validate_plugin_config_options():
            event.add_status(BlockedStatus(err))
            return
        event.add_status(ActiveStatus(self._get_certificate_fulfillment_status()))

    def _configure(self, event: EventBase) -> None:
        """Configure the Lego provider."""
        if not self.unit.is_leader():
            logger.error("only the leader unit can handle certificate requests")
            return
        if err := self._validate_charm_config_options():
            logger.error("charm config validation failed: %s", err)
            return
        if err := self._validate_plugin_config_options():
            logger.error("plugin config validation failed: %s", err)
            return
        self._configure_certificates()
        self._configure_ca_certificates()

    def _configure_certificates(self):
        """Attempt to fulfill all certificate requests."""
        certificate_requests = self.tls_certificates.get_certificate_requests()
        provided_certificates = self.tls_certificates.get_provider_certificates()
        certificate_pair_map = {
            csr: list(
                filter(
                    lambda x: x.relation_id == csr.relation_id
                    and x.certificate_signing_request.raw == csr.certificate_signing_request.raw,
                    provided_certificates,
                )
            )
            for csr in certificate_requests
        }
        for certificate_request, assigned_certificates in certificate_pair_map.items():
            if not assigned_certificates:
                with self.maintenance_status(
                    f"processing certificate request for relation {certificate_request.certificate_signing_request.common_name}"
                ):
                    self._generate_signed_certificate(
                        csr=certificate_request.certificate_signing_request,
                        relation_id=certificate_request.relation_id,
                    )

    def _configure_ca_certificates(self):
        """Distribute all used issuer certificates to requirers."""
        if len(self.model.relations.get(CA_TRANSFER_RELATION_NAME, [])) > 0:
            self.cert_transfer.add_certificates(
                {
                    str(provider_certificate.ca)
                    for provider_certificate in self.tls_certificates.get_provider_certificates()
                }
            )

    def _generate_signed_certificate(self, csr: CertificateSigningRequest, relation_id: int):
        """Generate signed certificate from the ACME provider."""
        try:
            response = run_lego_command(
                email=self._email or "",
                server=self._server or "",
                csr=csr.raw.encode(),
                env=self._plugin_config | self._app_environment,
                plugin=self._plugin,
            )
        except LEGOError as e:
            logger.error(
                "An error occurred executing the lego command: %s. \
                will try again in during the next update status event.",
                e,
            )
            return
        self.tls_certificates.set_relation_certificate(
            provider_certificate=ProviderCertificate(
                certificate=Certificate.from_string(response.certificate),
                certificate_signing_request=CertificateSigningRequest.from_string(response.csr),
                ca=Certificate.from_string(response.issuer_certificate),
                chain=[
                    Certificate.from_string(cert)
                    for cert in [response.certificate, response.issuer_certificate]
                ],
                relation_id=relation_id,
            ),
        )
        logger.info("generated certificate for domain %s", response.metadata.domain)

    def _get_certificate_fulfillment_status(self) -> str:
        """Return the status message reflecting how many certificate requests are still pending."""
        outstanding_requests_num = len(
            self.tls_certificates.get_outstanding_certificate_requests()
        )
        total_requests_num = len(self.tls_certificates.get_certificate_requests())
        fulfilled_certs = total_requests_num - outstanding_requests_num
        message = f"{fulfilled_certs}/{total_requests_num} certificate requests are fulfilled"
        if fulfilled_certs != total_requests_num:
            message += ". please monitor logs for any errors"
        return message

    def _validate_charm_config_options(self) -> str:
        """Validate generic ACME config.

        Returns:
        str: Error message if invalid, otherwise an empty string.
        """
        if not self._email:
            return "email address was not provided"
        if not self._server:
            return "acme server was not provided"
        if not self._plugin_config:
            return "plugin configuration secret is not available"
        if not self._plugin:
            return "plugin was not provided"
        if not _email_is_valid(self._email):
            return "invalid email address"
        if not _server_is_valid(self._server):
            return "invalid ACME server"
        if not _plugin_is_valid(self._plugin):
            return "invalid plugin"
        return ""

    def _validate_plugin_config_options(self) -> str:
        """Validate the config options for the specific chosen plugins.

        Returns:
            str: Error message if invalid, otherwise an empty string.
        """
        try:
            plugin_validator = getattr(plugin_configs, self._plugin)
        except AttributeError:
            logger.warning("this plugin's config options are not validated by the charm.")
            return ""
        return plugin_validator.validate(self._plugin_config)

    @contextmanager
    def maintenance_status(self, message: str):
        """Context manager to set the charm status temporarily.

        Useful around long-running operations to indicate that the charm is
        busy.
        """
        previous_status = self.unit.status
        self.unit.status = MaintenanceStatus(message)
        yield
        self.unit.status = previous_status

    @property
    def _app_environment(self) -> Dict[str, str]:
        """Extract proxy model environment variables."""
        env = {}

        if http_proxy := get_env_var(env_var="JUJU_CHARM_HTTP_PROXY"):
            env["HTTP_PROXY"] = http_proxy
        if https_proxy := get_env_var(env_var="JUJU_CHARM_HTTPS_PROXY"):
            env["HTTPS_PROXY"] = https_proxy
        if no_proxy := get_env_var(env_var="JUJU_CHARM_NO_PROXY"):
            env["NO_PROXY"] = no_proxy
        return env

    @property
    def _plugin_config(self) -> Dict[str, str]:
        """Plugin specific additional configuration for the command.

        Will attempt to access the juju secret through the secret id given in
        the plugin-config-secret-id option, convert the keys from lowercase, kebab-style
        to uppercase, snake_case, and return all of them as a dictionary.
        Ex:

        namecheap-api-key: "APIKEY1"
        namecheap-api-user: "USER"

        will become

        NAMECHEAP_API_KEY: "APIKEY1"
        NAMECHEAP_API_USER: "USER"

        Returns:
            Dict[str,str]: Plugin specific configuration.
        """
        try:
            plugin_config_secret_id = str(self.model.config.get("plugin-config-secret-id", ""))
            if not plugin_config_secret_id:
                return {}
            plugin_config_secret: Secret = self.model.get_secret(id=plugin_config_secret_id)
            plugin_config = plugin_config_secret.get_content(refresh=True)
        except SecretNotFoundError:
            return {}
        except ModelError as e:
            logger.warning("unable to access the secret: %s", e)
            return {}
        return {key.upper().replace("-", "_"): value for key, value in plugin_config.items()}

    @property
    def _email(self) -> str | None:
        """Email address to use for the ACME account."""
        email = self.model.config.get("email", None)
        if not isinstance(email, str):
            return None
        return email

    @property
    def _server(self) -> str | None:
        """ACME server address."""
        server = self.model.config.get("server", None)
        if not isinstance(server, str):
            return None
        return server


def get_env_var(env_var: str) -> str | None:
    """Get the environment variable value.

    Looks for all upper-case and all low-case of the `env_var`.

    Args:
        env_var: Name of the environment variable.

    Returns:
        Value of the environment variable. None if not found.
    """
    return os.environ.get(env_var.upper(), os.environ.get(env_var.lower(), None))


def _plugin_is_valid(plugin: str) -> bool:
    """Validate the format of the plugin."""
    return bool(plugin)


def _email_is_valid(email: str) -> bool:
    """Validate the format of the email address."""
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return False
    return True


def _server_is_valid(server: str) -> bool:
    """Validate the format of the ACME server address."""
    urlparts = urlparse(server)
    if not all([urlparts.scheme, urlparts.netloc]):
        return False
    return True


if __name__ == "__main__":  # pragma: nocover
    main(LegoCharm)  # type: ignore
