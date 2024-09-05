#!/usr/bin/env python3
# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk

"""Charm the service.

Refer to the following tutorial that will help you
develop a new k8s charm using the Operator Framework:

https://juju.is/docs/sdk/create-a-minimal-kubernetes-charm
"""

import logging

import ops
from ops import ActiveStatus

logger = logging.getLogger(__name__)

VALID_LOG_LEVELS = ["info", "debug", "warning", "error", "critical"]


class LegoOperatorCharm(ops.CharmBase):
    """Charm the service."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        self.framework.observe(self.on.collect_unit_status, self._on_collect_unit_status)

    def _on_collect_unit_status(self, event: ops.CollectStatusEvent):
        event.add_status(ActiveStatus())


if __name__ == "__main__":  # pragma: nocover
    ops.main(LegoOperatorCharm)  # type: ignore
