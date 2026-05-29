# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

variable "app_name" {
  description = "Name of the application in the Juju model."
  type        = string
  default     = "lego"
}

variable "base" {
  description = "The operating system on which to deploy"
  type        = string
  default     = "ubuntu@22.04"
}

variable "channel" {
  description = "The channel to use when deploying a charm."
  type        = string
  default     = "latest/stable"
}

variable "config" {
  description = "Application config. Details about available options can be found at https://charmhub.io/lego/configure."
  type        = map(string)
  default     = {}
}

variable "constraints" {
  description = "Juju constraints to apply for this application."
  type        = string
  default     = ""
}

variable "model" {
  description = "Reference to the Juju model to deploy application to."
  type        = string
}

variable "revision" {
  description = "Revision number of the charm"
  type        = number
  default     = null
}

variable "secret_name" {
  description = "Name for the LEGO credentials secret."
  type        = string
  default     = "lego-credentials"
}

variable "secret_value" {
  description = "Secret values for LEGO plugin configuration. The keys depend on the plugin used."
  type        = map(string)
  sensitive   = true
}

variable "units" {
  description = "Number of units to deploy"
  type        = number
  default     = 1
}
