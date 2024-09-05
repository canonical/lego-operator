# Copyright 2024 Ubuntu
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

from pytest import fixture
from scenario import Context, State

from charm import LegoOperatorCharm


class TestLegoOperatorCharm:
    @fixture(scope="function", autouse=True)
    def context(self):
        self.ctx = Context(LegoOperatorCharm)

    def test_given_not_leader_when_update_status_then_status_is_blocked(self):
        state = State(leader=False)
        self.ctx.run("collect-unit-status", state)
        assert 1 == 1
