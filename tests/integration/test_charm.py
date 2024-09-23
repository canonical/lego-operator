#!/usr/bin/env python3
# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.

import logging
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

APP_NAME = "lego-operator"


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest, request: pytest.FixtureRequest):
    """Build the charm-under-test and deploy it together with related charms.

    Assert on the unit status before any relations/configurations take place.
    """
    assert ops_test.model
    # Build and deploy charm from local source folder
    charm = Path(request.config.getoption("--charm_path")).resolve()  # type: ignore

    await ops_test.model.deploy(
        entity_url=charm,
        application_name=APP_NAME,
        config={
            "email": "example@gmail.com",
            "server": "https://acme-staging-v02.api.letsencrypt.org/directory",
            "plugin": "namecheap",
        },
        series="jammy",
    )

    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="blocked",
        raise_on_error=True,
        timeout=1000,
    )
    secret = await ops_test.model.add_secret(
        "plugin-credentials", data_args=["namecheap-api-key=key1", "namecheap-api-user=me"]
    )
    await ops_test.model.grant_secret(secret_name="plugin-credentials", application=APP_NAME)
    await ops_test.model.applications[APP_NAME].set_config(  # type: ignore
        {"plugin-config-secret-id": secret.split(":")[-1]}
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        raise_on_error=True,
        timeout=1000,
    )
    assert ops_test.model.applications[APP_NAME].units[0].workload_status == "active"  # type: ignore
