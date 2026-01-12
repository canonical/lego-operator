# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

data "juju_model" "lego" {
  name = var.model
}

resource "juju_secret" "lego_credentials" {
  model = data.juju_model.lego.name
  name  = var.secret_name
  value = var.secret_value
  info  = "LEGO plugin configuration credentials"
}

resource "juju_application" "lego" {
  name  = var.app_name
  model = data.juju_model.lego.name

  charm {
    name     = "lego"
    channel  = var.channel
    revision = var.revision
    base     = var.base
  }

  config      = merge(var.config, { "plugin-config-secret-id" = juju_secret.lego_credentials.secret_id })
  constraints = var.constraints
  units       = var.units
}

resource "juju_access_secret" "lego_credentials_access" {
  model = data.juju_model.lego.name
  applications = [
    juju_application.lego.name
  ]
  secret_id = juju_secret.lego_credentials.secret_id
}
