"""Validation functions for each plugin."""

from urllib.parse import urlparse


class httpreq:  # noqa: N801
    """HTTPREQ Plugin Validator."""

    @staticmethod
    def validate(config: dict[str, str]) -> str:
        """Validate httpreq options."""
        if "HTTPREQ_ENDPOINT" not in config:
            return "HTTREQ_ENDPOINT must point to a valid DNS server."
        try:
            url = urlparse(config.get("HTTPREQ_ENDPOINT"))
            if url.scheme not in ["http", "https"]:
                return "HTTPREQ_ENDPOINT must be a valid HTTP or HTTPS URL."
        except ValueError:
            return "HTTPREQ_ENDPOINT must be a valid HTTP or HTTPS URL."
        if config.get("HTTPREQ_MODE") and config.get("HTTPREQ_MODE") != "RAW":
            return "HTTPREQ_MODE must be RAW or not provided."
        return ""


class route53:  # noqa: N801
    """AWS Route 53 Plugin Validator."""

    @staticmethod
    def validate(config: dict[str, str]) -> str:
        """Validate httpreq options."""
        required_config = [
            "AWS_REGION",
            "AWS_HOSTED_ZONE_ID",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
        ]
        if missing_config := [option for option in required_config if option not in config]:
            return f"The following config options must be set: {', '.join(missing_config)}"
        return ""


class namecheap:  # noqa: N801
    """Namecheap Plugin Validator."""

    @staticmethod
    def validate(config: dict[str, str]) -> str:
        """Validate httpreq options."""
        if "NAMECHEAP_API_KEY" not in config or "NAMECHEAP_API_USER" not in config:
            return "namecheap-api-key and namecheap-api-user must be set"
        return ""
