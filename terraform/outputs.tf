# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "The Juju application name"
  value       = juju_application.application.name
}

output "requires" {
  description = "The Juju integrations that the charm requires"
  value = {
    receive-ca-cert = "receive-ca-cert"
    logging         = "logging"
  }
}

output "provides" {
  description = "The Juju integrations that the charm provides"
  value = {
    certificates = "certificates"
    send-ca-cert = "send-ca-cert"
  }
}
