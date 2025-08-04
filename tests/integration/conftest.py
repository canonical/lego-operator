#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import os
import pathlib
import typing

import jubilant
import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    """Add options to the pytest command line.

    This is a pytest hook that is called when the pytest command line is being parsed.

    Args:
      parser: The pytest command line parser.
    """
    parser.addoption(
        "--charm_path", action="store", default=None, help="Path to the charm under test"
    )
    parser.addoption(
        "--keep-models",
        action="store_true",
        default=False,
        help="keep temporarily-created models",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Validate the options provided by the user.

    This is a pytest hook that is called after command line options have been parsed.

    Args:
      config: The pytest configuration object.
    """
    charm_path = str(config.getoption("--charm_path"))
    if not charm_path:
        pytest.exit("The --charm_path option is required. Tests aborted.")
    if not os.path.exists(charm_path):
        pytest.exit(f"The path specified for the charm under test does not exist: {charm_path}")


@pytest.fixture(scope="session")
def charm_path(request: pytest.FixtureRequest) -> pathlib.Path:
    path: str = request.config.getoption("--charm_path")  # type: ignore
    return pathlib.Path(path).resolve()


@pytest.fixture(scope="module")
def juju(request: pytest.FixtureRequest) -> typing.Iterator[jubilant.Juju]:
    keep_models = bool(request.config.getoption("--keep-models"))

    juju = jubilant.Juju()
    juju.wait_timeout = 1000
    models = json.loads(juju.cli("models", "--format=json"))
    if not any(m["short-name"] == "model" for m in models["models"]):
        juju.add_model("model")
    try:
        yield juju
    finally:
        if request.session.testsfailed:
            log = juju.debug_log(limit=1000)
            print(log, end="")
        if not keep_models:
            assert juju.model is not None
            juju.destroy_model(juju.model, destroy_storage=True, force=True)
