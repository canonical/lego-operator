/**
 * # Terraform Module for Lego Operator
 *
 * This is a Terraform module facilitating the deployment of the Lego charm
 * using the Juju Terraform provider.
 */

resource "juju_application" "application" {
  name        = var.app_name
  model_uuid  = var.model
  trust       = true
  config      = var.config
  constraints = var.constraints
  units       = var.units

  charm {
    name     = "lego"
    base     = var.base
    channel  = var.channel
    revision = var.revision
  }
}
