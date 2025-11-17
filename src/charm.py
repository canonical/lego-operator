#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Lego Operator Charm."""

import logging
import os
import re
import subprocess
from contextlib import contextmanager
from typing import Any, Dict, Set
from urllib.parse import urlparse

from charms.certificate_transfer_interface.v1.certificate_transfer import (
    CertificateTransferProvides,
    CertificateTransferRequires,
)
from charms.loki_k8s.v1.loki_push_api import LogForwarder
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateSigningRequest,
    ProviderCertificate,
    TLSCertificatesProvidesV4,
    generate_private_key,
)
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from ops import ModelError, Secret, SecretNotFoundError, main
from ops.charm import CharmBase, CollectStatusEvent
from ops.framework import EventBase
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus
from pylego import LEGOError, run_lego_command

from charms.traefik_k8s.v2.ingress import IngressPerAppRequirer

import plugin_configs

logger = logging.getLogger(__name__)

CERTIFICATES_RELATION_NAME = "certificates"
SEND_CA_TRANSFER_RELATION_NAME = "send-ca-cert"
RECEIVE_CA_TRANSFER_RELATION_NAME = "receive-ca-cert"
ACCOUNT_SECRET_LABEL = "acme-account-details"
ACME_CA_CERTIFICATES_FILE_PATH = "/var/lib/acme-ca-certificates.pem"

HTTP01_IFACE_DEFAULT = ""


class LegoCharm(CharmBase):
    """Base charm for charms that use the ACME protocol to get certificates.

    This charm implements the tls_certificates interface as a provider.
    """

    def __init__(self, *args: Any):
        super().__init__(*args)
        self._logging = LogForwarder(self, relation_name="logging")
        self._tls_certificates = TLSCertificatesProvidesV4(self, CERTIFICATES_RELATION_NAME)
        self.cert_transfer = CertificateTransferProvides(self, SEND_CA_TRANSFER_RELATION_NAME)
        self.receive_ca_certificates = CertificateTransferRequires(
            self, RECEIVE_CA_TRANSFER_RELATION_NAME
        )

        [
            self.framework.observe(event, self._configure)
            for event in [
                self.on[SEND_CA_TRANSFER_RELATION_NAME].relation_joined,
                self.on[CERTIFICATES_RELATION_NAME].relation_changed,
                self.on.secret_changed,
                self.on.config_changed,
                self.on.update_status,
            ]
        ]
        self.framework.observe(
            self.receive_ca_certificates.on.certificate_set_updated, self._configure
        )
        self.framework.observe(
            self.receive_ca_certificates.on.certificates_removed, self._configure
        )
        self.framework.observe(self.on.collect_unit_status, self._on_collect_status)

        self._plugin = str(self.model.config.get("plugin", ""))

        # HTTP-01: setup ingress on configured port
        # LEGO's built-in HTTP server will handle serving challenges
        self._ingress = None
        if self._plugin in ("http-01", "http"):
            try:
                port = int(self.model.config.get("http-01-port", 8080))
            except Exception:
                port = 8080
            self._ingress = IngressPerAppRequirer(
                self,
                port=port,
                healthcheck_params={
                    "path": "/",
                    "interval": "10s",
                    "timeout": "5s",
                }
            )

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
        if self._plugin in ("http-01", "http"):
            if not self._ingress or not self._ingress.relation:
                event.add_status(BlockedStatus("http-01 requires `ingress` relation"))
                return
            if not self._ingress.url:
                event.add_status(
                    BlockedStatus(
                        "waiting for ingress URL from provider (ensure ingress provider is active)"
                    )
                )
                return
        event.add_status(ActiveStatus(self._get_certificate_fulfillment_status()))

    def _configure(self, event: EventBase) -> None:
        """Configure the Lego provider."""
        if not self.unit.is_leader():
            logger.error("only the leader unit can handle certificate requests")
            return
        
        # Publish ingress requirements early (before validation) to avoid empty databags
        # being read by the ingress provider during unrelated hooks
        if self._plugin in ("http-01", "http"):
            try:
                port = int(self.model.config.get("http-01-port", 8080))
            except Exception:
                port = 8080
            # Lazily initialize the ingress requirer if not yet created
            if not self._ingress:
                self._ingress = IngressPerAppRequirer(
                    self,
                    port=port,
                    healthcheck_params={
                        "path": "/",
                        "interval": "10s",
                        "timeout": "5s",
                    }
                )
            # Always try to publish requirements to avoid empty databags on the provider side
            self._ingress.provide_ingress_requirements(port=port)
        
        if err := self._validate_charm_config_options():
            logger.error("charm config validation failed: %s", err)
            return
        if err := self._validate_plugin_config_options():
            logger.error("plugin config validation failed: %s", err)
            return
        self._configure_acme_ca_certificates_bundle()
        self._configure_certificates()
        self._configure_send_ca_certificates()

    def _configure_acme_ca_certificates_bundle(self):
        """Configure the LEGO CA certificates."""
        config_certs = self._get_ca_certs_from_config()
        relation_certs: Set[str] = set()
        if len(self.model.relations.get(RECEIVE_CA_TRANSFER_RELATION_NAME, [])) > 0:
            relation_certs = self.receive_ca_certificates.get_all_certificates()
        combined_certs = list(config_certs | relation_certs)
        self._write_acme_ca_bundle_file(combined_certs)

    def _configure_certificates(self):
        """Attempt to fulfill all certificate requests."""
        certificate_requests = self._tls_certificates.get_certificate_requests()
        provided_certificates = self._tls_certificates.get_provider_certificates()
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

    def _configure_send_ca_certificates(self):
        """Distribute all used issuer certificates to requirers."""
        if len(self.model.relations.get(SEND_CA_TRANSFER_RELATION_NAME, [])) > 0:
            self.cert_transfer.add_certificates(
                {
                    str(provider_certificate.ca)
                    for provider_certificate in self._tls_certificates.get_provider_certificates()
                }
            )

    def _generate_signed_certificate(self, csr: CertificateSigningRequest, relation_id: int):
        """Generate signed certificate from the ACME provider."""
        try:
            private_key = self._get_or_create_acme_account_private_key()
            base_env = (
                self._plugin_config | self._app_environment | self._acme_ca_certificates_env
                if self._acme_ca_certificates_env
                else self._plugin_config | self._app_environment
            )
            # Configure LEGO HTTP-01 using built-in server (pylego doesn't support webroot)
            http01_env = {}
            if self._plugin in ("http-01", "http"):
                try:
                    port = int(self.model.config.get("http-01-port", 8080))
                except Exception:
                    port = 8080
                http01_env = {
                    "HTTP01_PORT": str(port),
                    "HTTP01_IFACE": HTTP01_IFACE_DEFAULT,
                }
                logger.debug("using HTTP-01 challenge with built-in server on port: %s", port)
            # For HTTP-01, use "http" plugin to trigger LEGO's built-in HTTP server
            plugin_to_use = "http" if self._plugin in ("http-01", "http") else self._plugin
            logger.debug("plugin: %s, plugin_to_use: %s, http01_env: %s", self._plugin, plugin_to_use, http01_env)
            response = run_lego_command(
                email=self._email or "",
                private_key=private_key,
                server=self._server or "",
                csr=csr.raw.encode(),
                env=base_env | http01_env,
                plugin=plugin_to_use,
            )
        except LEGOError as e:
            logger.error(
                "An error occurred executing the lego command: %s. \
                will try again in during the next update status event.",
                e,
            )
            return
        end_certificate = self._get_end_certificate(response.certificate)
        self._tls_certificates.set_relation_certificate(
            provider_certificate=ProviderCertificate(
                certificate=Certificate.from_string(end_certificate),
                certificate_signing_request=CertificateSigningRequest.from_string(response.csr),
                ca=Certificate.from_string(response.issuer_certificate),
                chain=[
                    Certificate.from_string(cert)
                    for cert in _get_chain_from_certificate_bundle(
                        response.certificate, response.issuer_certificate
                    )
                ],
                relation_id=relation_id,
            ),
        )
        logger.info("generated certificate for domain %s", response.metadata.domain)

    def _get_end_certificate(self, cert: str) -> str:
        """Get the end certificate from the ACME provider."""
        certs = x509.load_pem_x509_certificates(cert.encode())
        first_cert = certs[0].public_bytes(encoding=serialization.Encoding.PEM)
        return first_cert.decode()

    def _get_certificate_fulfillment_status(self) -> str:
        """Return the status message reflecting how many certificate requests are still pending."""
        outstanding_requests_num = len(
            self._tls_certificates.get_outstanding_certificate_requests()
        )
        total_requests_num = len(self._tls_certificates.get_certificate_requests())
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
        if self._plugin not in ("http-01", "http") and not self._plugin_config:
            return "plugin configuration secret is not available"
        if not self._plugin:
            return "plugin was not provided"
        if not _email_is_valid(self._email):
            return "invalid email address"
        if not _server_is_valid(self._server):
            return "invalid ACME server"
        if not _plugin_is_valid(self._plugin):
            return "invalid plugin"
        if err := self._validate_acme_ca_certificates_config_option():
            return err
        return ""

    def _validate_plugin_config_options(self) -> str:
        """Validate the config options for the specific chosen plugins.

        Returns:
            str: Error message if invalid, otherwise an empty string.
        """
        if self._plugin in ("http-01", "http"):
            try:
                _ = int(self.model.config.get("http-01-port", 8080))
            except Exception:
                return "invalid http-01-port"
            return ""
        try:
            plugin_validator = getattr(plugin_configs, self._plugin)
        except AttributeError:
            logger.warning("this plugin's config options are not validated by the charm.")
            return ""
        return plugin_validator.validate(self._plugin_config)

    def _validate_acme_ca_certificates_config_option(self) -> str:
        """Validate the acme-ca-certificates config option.

        Returns:
            str: Error message if invalid, otherwise an empty string.
        """
        ca_certificate = self.model.config.get("acme-ca-certificates", None)
        if not isinstance(ca_certificate, str) or not ca_certificate.strip():
            return ""

        try:
            x509.load_pem_x509_certificates(ca_certificate.encode())
        except Exception:
            return "acme-ca-certificates contains invalid PEM data"

        return ""

    def _get_or_create_acme_account_private_key(self) -> str:
        """Get the private key if it exists, create it and store it if it doesn't.

        Returns:
            str: The private key.
        """
        if not self._email:
            raise ValueError("email is required to store the private key")
        private_key, email = self._get_account_acme_account_details()
        if private_key and email == self._email:
            return private_key
        logger.info("ACME account details not valid, generating new private key")
        private_key = str(generate_private_key())
        self._store_account_acme_account_details(private_key, self._email)
        return private_key

    def _store_account_acme_account_details(self, private_key: str, email: str) -> None:
        """Store the private key in a juju secret.

        Args:
            private_key: The private key to store.
            email: The email to store.
        """
        try:
            secret = self.model.get_secret(label=ACCOUNT_SECRET_LABEL)
            secret.set_content({"private-key": private_key, "email": email})
            secret.get_content(refresh=True)
        except SecretNotFoundError:
            self.unit.add_secret(
                content={"private-key": private_key, "email": email},
                label=ACCOUNT_SECRET_LABEL,
            )

    def _get_account_acme_account_details(self) -> tuple[str | None, str | None]:
        """Get the private key and email if they exist.

        Returns:
            tuple[str | None, str | None]: The private key and email if they exist, None otherwise.
        """
        try:
            secret = self.model.get_secret(label=ACCOUNT_SECRET_LABEL)
            content = secret.get_content(refresh=True)
            return content["private-key"], content["email"]
        except SecretNotFoundError:
            return None, None

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

    @property
    def _acme_ca_certificates_env(self) -> Dict[str, str]:
        """CA certificates environment variable to use with LEGO."""
        path = ACME_CA_CERTIFICATES_FILE_PATH
        try:
            if os.path.isfile(path) and os.path.getsize(path) > 0:
                return {"LEGO_CA_CERTIFICATES": path}
        except OSError:
            return {}
        return {}

    def _get_ca_certs_from_config(self) -> Set[str]:
        """Return a set of PEM CA certificates provided via config.

        The config option may contain multiple concatenated PEM blocks.
        """
        ca_certificate = self.model.config.get("acme-ca-certificates", None)
        if not isinstance(ca_certificate, str) or not ca_certificate.strip():
            return set()
        certs = self._parse_pem_certificates(ca_certificate)
        return set(certs)

    def _parse_pem_certificates(self, raw_cert: str) -> list[str]:
        """Parse PEM certificates.

        Returns a list of PEM strings with standard formatting.
        """
        if not isinstance(raw_cert, str) or not raw_cert.strip():
            return []

        normalized: list[str] = []
        seen_bytes: set[bytes] = set()

        try:
            certs = x509.load_pem_x509_certificates(raw_cert.encode())
        except Exception:
            return []

        for cert in certs:
            pem_bytes = cert.public_bytes(encoding=serialization.Encoding.PEM)
            if pem_bytes in seen_bytes:
                continue
            seen_bytes.add(pem_bytes)
            normalized.append(pem_bytes.decode())

        return normalized

    def _write_acme_ca_bundle_file(self, pem_certs: list[str]) -> None:
        """Write the combined CA bundle to disk."""
        path = ACME_CA_CERTIFICATES_FILE_PATH
        directory = os.path.dirname(path)
        try:
            if not pem_certs:
                if os.path.isfile(path):
                    os.remove(path)
                return
            os.makedirs(directory, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(cert.strip() + "\n" for cert in pem_certs))
        except OSError as e:
            logger.warning("failed to write ACME CA bundle at %s: %s", path, e)


    # HTTP-01 helpers: Simple HTTP server process to serve webroot files
    def _is_http01_server_running(self) -> bool:
        """Check if HTTP-01 server process is running."""
        try:
            port = int(self.model.config.get("http-01-port", 8080))
        except Exception:
            port = 8080
        
        # Check if port is in use (server is likely running)
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            is_running = result == 0  # Port is in use
            if is_running:
                logger.debug("http-01 server detected on port %d", port)
            else:
                logger.debug("http-01 server NOT detected on port %d (result: %d)", port, result)
            return is_running
        except Exception as e:
            logger.warning("failed to check if http-01 server is running: %s", e)
            return False

    def _ensure_http01_webroot(self) -> bool:
        """Ensure the HTTP-01 webroot directory exists.
        
        Returns:
            bool: True if directory structure was created/modified, False if it already existed.
        """
        try:
            # Check if .well-known directory already exists
            acme_challenge_dir = os.path.join(HTTP01_WEBROOT_DIR, ".well-known", "acme-challenge")
            dir_existed = os.path.exists(acme_challenge_dir)
            
            os.makedirs(HTTP01_WEBROOT_DIR, exist_ok=True)
            
            # Create the .well-known/acme-challenge directory for LEGO
            os.makedirs(acme_challenge_dir, exist_ok=True)
            
            # Set proper permissions
            os.chmod(HTTP01_WEBROOT_DIR, 0o755)
            os.chmod(os.path.join(HTTP01_WEBROOT_DIR, ".well-known"), 0o755)
            os.chmod(acme_challenge_dir, 0o755)
            
            # Create test files for easy verification
            test_file_path = os.path.join(HTTP01_WEBROOT_DIR, "test.txt")
            with open(test_file_path, "w") as f:
                f.write("Hello from Lego HTTP-01 server!\n")
            
            # Create an index.html for root path testing
            index_file_path = os.path.join(HTTP01_WEBROOT_DIR, "index.html")
            with open(index_file_path, "w") as f:
                f.write("<html><body><h1>Lego HTTP-01 Server is Running!</h1></body></html>\n")
            
            if not dir_existed:
                logger.info("created ACME challenge directory structure at %s", HTTP01_WEBROOT_DIR)
            else:
                logger.debug("ACME challenge directory already exists at %s", HTTP01_WEBROOT_DIR)
            
            return not dir_existed  # Return True if we created new directories
        except OSError as e:
            logger.warning("failed to prepare http-01 webroot: %s", e)
            return False

    def _restart_http01_server(self) -> None:
        """Restart the HTTP-01 server.
        
        This is needed when the webroot directory structure changes, as Python's HTTP server
        doesn't dynamically reload directory listings.
        """
        try:
            port = int(self.model.config.get("http-01-port", 8080))
        except Exception:
            port = 8080
        
        try:
            # Kill existing HTTP server process
            subprocess.run(
                ["pkill", "-f", f"python3 -m http.server {port}"],
                check=False,  # Don't fail if process doesn't exist
                timeout=5,
            )
            logger.info("stopped existing http-01 server on port %d", port)
            
            # Wait a moment for the port to be released
            import time
            time.sleep(0.5)
        except Exception as e:
            logger.warning("failed to stop existing http-01 server: %s", e)
        
        # Start the server (let _ensure_http01_server handle this)
        self._start_http01_server()

    def _start_http01_server(self) -> None:
        """Start the HTTP-01 server."""
        try:
            port = int(self.model.config.get("http-01-port", 8080))
        except Exception:
            port = 8080
        
        try:
            # Log server startup attempt
            logger.info("starting http-01 server on port %d serving %s", port, HTTP01_WEBROOT_DIR)
            
            # Use Popen with start_new_session to completely detach from parent process
            process = subprocess.Popen(
                ["python3", "-m", "http.server", str(port), "--directory", HTTP01_WEBROOT_DIR, "--bind", "0.0.0.0"],
                start_new_session=True,  # Detach from parent process group
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
            )
            
            # Give it a moment to start
            import time
            time.sleep(0.5)
            
            # Verify it's running
            if self._is_http01_server_running():
                logger.info("http-01 server started successfully on port %d (PID: %s)", port, process.pid)
            else:
                logger.error("http-01 server failed to start on port %d - port not bound after launch", port)
        except Exception as e:
            logger.error("failed to start http-01 server: %s", e)

    def _ensure_http01_server(self, force_restart: bool = False) -> None:
        """Ensure HTTP-01 server is running for ACME challenge.
        
        This starts a detached subprocess that persists across charm hook executions.
        The subprocess is completely independent - it survives when the charm process exits.
        
        Technical details:
        - start_new_session=True creates a new process group, detaching from parent
        - When the charm process exits, this subprocess is adopted by init (PID 1)
        - The server continues running until manually stopped or the system reboots
        
        Args:
            force_restart: If True, restart the server even if it's already running.
        """
        try:
            port = int(self.model.config.get("http-01-port", 8080))
        except Exception:
            port = 8080

        # Check if server is already running
        if self._is_http01_server_running() and not force_restart:
            logger.info("http-01 server already running on port %d", port)
            return
        
        if force_restart:
            logger.info("restarting http-01 server on port %d", port)
            self._restart_http01_server()
        else:
            self._start_http01_server()

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


def _get_chain_from_certificate_bundle(cert: str, issuer: str | None) -> list[str]:
    """Get the chain from certificate bundle and add the issuer if it's not present."""
    certs = x509.load_pem_x509_certificates(cert.encode())
    if issuer:
        issuer_cert = x509.load_pem_x509_certificate(issuer.encode())
        issuer_in_chain = any(
            existing_cert.public_bytes(encoding=serialization.Encoding.PEM)
            == issuer_cert.public_bytes(encoding=serialization.Encoding.PEM)
            for existing_cert in certs
        )

        if not issuer_in_chain:
            certs.append(issuer_cert)

    return [cert.public_bytes(encoding=serialization.Encoding.PEM).decode() for cert in certs]


if __name__ == "__main__":  # pragma: nocover
    main(LegoCharm)  # type: ignore
