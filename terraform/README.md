<!-- vale Canonical.007-Headings-sentence-case = NO -->
# LEGO Terraform Module
<!-- vale Canonical.007-Headings-sentence-case = YES -->

This directory contains [Terraform][Terraform] module for deploying the [LEGO charm][LEGO charm].

The module uses the [Terraform Juju provider][Terraform Juju provider] to model
deployments onto any Kubernetes environment managed by [Juju][Juju].

## Module Structure

The Terraform module is located in `terraform/charm/` and provides a complete deployment solution that includes:
- The LEGO charm application
- Juju secrets for plugin credentials
- Secret access configuration

## Usage

```hcl
module "lego" {
  source = "git::https://github.com/canonical/lego-operator//terraform/charm"
  
  model = "my-model"
  
  secret_value = {
    httpreq-endpoint            = "https://lego-certs.example.com"
    httpreq-username            = "my-username"
    httpreq-password            = "my-password"
    httpreq-propagation-timeout = 600
  }
  
  channel = "4/stable"
  config = {
    email  = "admin@example.com"
    plugin = "httpreq"
  }
}
```

## Common Integration Patterns

### TLS Certificates Provider

The most common use case is providing TLS certificates to other charms:

```hcl
resource "juju_integration" "app_certificates" {
  model = "my-model"
  
  application {
    name     = module.lego.app_name
    endpoint = module.lego.provides.certificates
  }
  
  application {
    name     = "my-app"
    endpoint = "certificates"
  }
}
```

### Logging Integration

To send logs to Loki:

```hcl
resource "juju_integration" "lego_logging" {
  model = "my-model"
  
  application {
    name     = module.lego.app_name
    endpoint = module.lego.requires.logging
  }
  
  application {
    offer_url = "admin/cos.loki-logging"
  }
}
```

## Plugin Configuration

LEGO supports various DNS providers through plugins. The `secret_value` variable should contain the plugin-specific configuration. Common examples:

### HTTPReq Plugin

```hcl
secret_value = {
  httpreq-endpoint            = "https://lego-certs.example.com"
  httpreq-username            = "username"
  httpreq-password            = "password"
  httpreq-propagation-timeout = 600
}
```

### Route53 Plugin

```hcl
secret_value = {
  aws-access-key-id     = "your-access-key"
  aws-secret-access-key = "your-secret-key"
  aws-region            = "us-east-1"
}
```

### Cloudflare Plugin

```hcl
secret_value = {
  cloudflare-email   = "your-email@example.com"
  cloudflare-api-key = "your-api-key"
}
```

Refer to the [LEGO charm documentation](https://charmhub.io/lego) for the complete list of supported plugins and their configuration options.

## Available Integrations

According to [Charmhub integrations][lego-integrations]:

### Provides
- **certificates** - `tls-certificates` interface
- **send-ca-cert** - `certificate_transfer` interface

### Requires
- **logging** - `loki_push_api` interface

## Requirements

- Terraform >= 1.6.6
- Juju >= 3.1
- Juju Terraform Provider >= 0.21.1

[Terraform]: https://www.terraform.io/
[Terraform Juju provider]: https://registry.terraform.io/providers/juju/juju/latest
[Juju]: https://juju.is
[LEGO charm]: https://charmhub.io/lego
[lego-integrations]: https://charmhub.io/lego/integrations
