<!-- vale Canonical.007-Headings-sentence-case = NO -->
# LEGO Terraform module
<!-- vale Canonical.007-Headings-sentence-case = YES -->

This folder contains a [Terraform][Terraform] module for the LEGO charm that handles the complete deployment including secrets management.

The module uses the [Terraform Juju provider][Terraform Juju provider] to model the charm
deployment onto any Kubernetes environment managed by [Juju][Juju].

## Module structure

- **main.tf** - Defines the Juju application, secrets, and access configuration.
- **variables.tf** - Allows customization of the deployment including charm configuration and plugin credentials.
- **output.tf** - Integrates the module with other Terraform modules by defining integration endpoints.
- **versions.tf** - Defines the Terraform provider version.

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

### Creating integrations

```hcl
resource "juju_integration" "lego_certificates" {
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

The complete list of available integrations can be found [in the Integrations tab][lego-integrations].

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

[Terraform]: https://www.terraform.io/
[Terraform Juju provider]: https://registry.terraform.io/providers/juju/juju/latest
[Juju]: https://juju.is
[lego-integrations]: https://charmhub.io/lego/integrations

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_juju"></a> [juju](#requirement\_juju) | >= 0.21.1 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_juju"></a> [juju](#provider\_juju) | >= 0.21.1 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [juju_access_secret.lego_credentials_access](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/access_secret) | resource |
| [juju_application.lego](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/application) | resource |
| [juju_secret.lego_credentials](https://registry.terraform.io/providers/juju/juju/latest/docs/resources/secret) | resource |
| [juju_model.lego](https://registry.terraform.io/providers/juju/juju/latest/docs/data-sources/model) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_app_name"></a> [app\_name](#input\_app\_name) | Name of the application in the Juju model. | `string` | `"lego"` | no |
| <a name="input_base"></a> [base](#input\_base) | The operating system on which to deploy | `string` | `"ubuntu@22.04"` | no |
| <a name="input_channel"></a> [channel](#input\_channel) | The channel to use when deploying a charm. | `string` | `"latest/stable"` | no |
| <a name="input_config"></a> [config](#input\_config) | Application config. Details about available options can be found at https://charmhub.io/lego/configure. | `map(string)` | `{}` | no |
| <a name="input_constraints"></a> [constraints](#input\_constraints) | Juju constraints to apply for this application. | `string` | `""` | no |
| <a name="input_model"></a> [model](#input\_model) | Reference to the Juju model to deploy application to. | `string` | n/a | yes |
| <a name="input_revision"></a> [revision](#input\_revision) | Revision number of the charm | `number` | `null` | no |
| <a name="input_secret_name"></a> [secret\_name](#input\_secret\_name) | Name for the LEGO credentials secret. | `string` | `"lego-credentials"` | no |
| <a name="input_secret_value"></a> [secret\_value](#input\_secret\_value) | Secret values for LEGO plugin configuration. The keys depend on the plugin used. | `map(string)` | n/a | yes |
| <a name="input_units"></a> [units](#input\_units) | Number of units to deploy | `number` | `1` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_app_name"></a> [app\_name](#output\_app\_name) | Name of the deployed application. |
| <a name="output_provides"></a> [provides](#output\_provides) | Provided integration endpoints. |
| <a name="output_requires"></a> [requires](#output\_requires) | Required integration endpoints. |
| <a name="output_secret_id"></a> [secret\_id](#output\_secret\_id) | ID of the LEGO credentials secret. |
<!-- END_TF_DOCS -->
