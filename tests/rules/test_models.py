"""Unit tests for Rule model."""

import pytest

from home_net_analyzer.rules.models import Rule, RuleAction, RuleTarget


class TestRuleBasics:
    """Basic construction and validation."""

    def test_block_ip_rule(self) -> None:
        r = Rule(action=RuleAction.BLOCK, target=RuleTarget.IP, value="192.168.1.50")
        assert r.action == RuleAction.BLOCK
        assert r.target == RuleTarget.IP
        assert r.value == "192.168.1.50"
        assert r.enabled is True

    def test_allow_subnet_rule(self) -> None:
        r = Rule(action=RuleAction.ALLOW, target=RuleTarget.SUBNET, value="10.0.0.0/24")
        assert r.is_allow() is True
        assert r.targets_subnet() is True

    def test_block_port_rule(self) -> None:
        r = Rule(action=RuleAction.BLOCK, target=RuleTarget.PORT, value="22")
        assert r.targets_port() is True
        assert r.value == "22"

    def test_port_range(self) -> None:
        r = Rule(action=RuleAction.BLOCK, target=RuleTarget.PORT, value="80-443")
        assert r.value == "80-443"

    def test_block_protocol_ssh(self) -> None:
        r = Rule(action=RuleAction.BLOCK, target=RuleTarget.PROTOCOL, value="ssh")
        assert r.targets_protocol() is True
        assert r.value == "ssh"

    def test_invalid_ip_raises(self) -> None:
        with pytest.raises(ValueError):
            Rule(action=RuleAction.BLOCK, target=RuleTarget.IP, value="not-an-ip")

    def test_invalid_subnet_raises(self) -> None:
        with pytest.raises(ValueError):
            Rule(action=RuleAction.BLOCK, target=RuleTarget.SUBNET, value="10.0.0.0")

    def test_invalid_port_raises(self) -> None:
        with pytest.raises(ValueError):
            Rule(action=RuleAction.BLOCK, target=RuleTarget.PORT, value="abc")

    def test_to_dict(self) -> None:
        r = Rule(
            action=RuleAction.BLOCK,
            target=RuleTarget.PORT,
            value="22",
            protocol="tcp",
            direction="in",
            description="Block SSH",
        )
        d = r.to_dict()
        assert d["action"] == "block"
        assert d["target"] == "port"
        assert d["value"] == "22"
        assert d["protocol"] == "tcp"
        assert d["description"] == "Block SSH"


class TestRuleHelpers:
    """Helper methods on Rule."""

    def test_is_block(self) -> None:
        r = Rule(action=RuleAction.BLOCK, target=RuleTarget.IP, value="1.2.3.4")
        assert r.is_block() is True
        assert r.is_allow() is False

    def test_is_allow(self) -> None:
        r = Rule(action=RuleAction.ALLOW, target=RuleTarget.IP, value="1.2.3.4")
        assert r.is_allow() is True
        assert r.is_block() is False
