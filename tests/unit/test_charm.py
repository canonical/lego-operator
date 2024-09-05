# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

from ops import ActiveStatus
from pytest import fixture
from scenario import Context, State

from charm import LegoOperatorCharm


class TestLegoOperatorCharm:
    @fixture(scope="function", autouse=True)
    def context(self):
        self.ctx = Context(LegoOperatorCharm)

    def test_given_collect_unit_status_then_status_is_active(self):
        state = State(leader=False)
        out = self.ctx.run("collect-unit-status", state)
        assert out.unit_status == ActiveStatus()
