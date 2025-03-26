import plugin_configs


class TestHTTPReqValidator:
    def test_given_missing_config_options_then_error_msg_returned(self):
        config = {}
        out = plugin_configs.httpreq.validate(config)
        assert out == "HTTREQ_ENDPOINT must point to a valid DNS server."

    def test_given_bad_url_in_config_options_then_error_msg_returned(self):
        config = {"HTTPREQ_ENDPOINT": "not a url lol"}
        out = plugin_configs.httpreq.validate(config)
        assert out == "HTTPREQ_ENDPOINT must be a valid HTTP or HTTPS URL."

    def test_given_bad_mode_value_in_config_options_then_error_msg_returned(self):
        config = {"HTTPREQ_ENDPOINT": "https://canonical.com", "HTTPREQ_MODE": "NOT RAW"}
        out = plugin_configs.httpreq.validate(config)
        assert out == "HTTPREQ_MODE must be RAW or not provided."

    def test_given_valid_config_then_no_error_msg_returned(self):
        config = {"HTTPREQ_ENDPOINT": "https://canonical.com", "HTTPREQ_MODE": "RAW"}
        out = plugin_configs.httpreq.validate(config)
        assert out == ""


class TestRoute53Validator:
    def test_given_missing_value_in_config_then_error_msg_returned(self):
        config = {
            "AWS_REGION": "mars-olympus",
            "AWS_ACCESS_KEY_ID": "id12",
            "AWS_HOSTED_ZONE_ID": "123",
        }
        out = plugin_configs.route53.validate(config)
        assert out == "The following config options must be set: AWS_SECRET_ACCESS_KEY"

    def test_given_valid_config_then_no_error_msg_returned(self):
        config = {
            "AWS_REGION": "mars-olympus",
            "AWS_ACCESS_KEY_ID": "id12",
            "AWS_HOSTED_ZONE_ID": "123",
            "AWS_SECRET_ACCESS_KEY": "1234",
        }
        out = plugin_configs.route53.validate(config)
        assert out == ""


class TestNamecheapValidator:
    def test_given_missing_value_in_config_then_error_msg_returned(self):
        config = {
            "NAMECHEAP_API_USER": "me",
        }
        out = plugin_configs.namecheap.validate(config)
        assert out == "namecheap-api-key and namecheap-api-user must be set"

    def test_given_valid_config_then_no_error_msg_returned(self):
        config = {
            "NAMECHEAP_API_USER": "me",
            "NAMECHEAP_API_KEY": "apikey123",
        }
        out = plugin_configs.namecheap.validate(config)
        assert out == ""
