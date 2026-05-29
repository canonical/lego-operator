# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.lego.name
}

output "requires" {
  description = "Required integration endpoints."
  value = {
    logging = "logging"
  }
}

output "provides" {
  description = "Provided integration endpoints."
  value = {
    certificates = "certificates"
    send_ca_cert = "send-ca-cert"
  }
}

output "secret_id" {
  description = "ID of the LEGO credentials secret."
  value       = juju_secret.lego_credentials.secret_id
}
