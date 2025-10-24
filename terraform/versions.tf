# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

terraform {
  required_providers {
    juju = {
      source = "juju/juju"
      # update to 1.0.0 once it's ready
      # version = "~> 1.0.0"
      version = "1.0.0-beta4"
    }
  }

  required_version = ">= 1.5.0"
}
