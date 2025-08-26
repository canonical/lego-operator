#!/usr/bin/env python3
# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.

import logging
import pathlib

import jubilant

logger = logging.getLogger(__name__)

APP_NAME = "lego-operator"


def test_deploy_lego(juju: jubilant.Juju, charm_path: pathlib.Path):
    def workload_status(status: jubilant.Status) -> str:
        return status.apps[APP_NAME].units[f"{APP_NAME}/0"].workload_status.current

    config = {
        "email": "example@gmail.com",
        "server": "https://acme-staging-v02.api.letsencrypt.org/directory",
        "plugin": "namecheap",
    }
    juju.deploy(charm_path, app=APP_NAME, config=config)
    juju.wait(lambda status: workload_status(status) == "blocked")

    secret_data = {"namecheap-api-key": "key1", "namecheap-api-user": "me"}
    secret_uri = juju.add_secret("plugin-credentials", secret_data)
    juju.grant_secret(secret_uri, app=APP_NAME)
    juju.config(APP_NAME, {"plugin-config-secret-id": secret_uri.unique_identifier})
    juju.wait(lambda status: jubilant.all_active(status, APP_NAME))

    assert workload_status(juju.status()) == "active"
