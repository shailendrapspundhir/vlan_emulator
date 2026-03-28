"""Tests for NftablesBackend rule generation and behavior."""

import pytest
from unittest.mock import patch, MagicMock

from home_net_analyzer.rules.models import Rule, RuleAction, RuleTarget
from home_net_analyzer.rules.backends.nftables import NftablesBackend


class TestNftablesRuleTranslation:
    """Test _rule_to_nft produces expected expressions."""

    @pytest.fixture()
    def backend(self) -> NftablesBackend:
        # Use noop init by patching _ensure_table_chain to avoid calling nft
        with patch.object(NftablesBackend, "_ensure_table_chain", lambda self: None):
            b = NftablesBackend()
        return b

    def test_block_ip_generates_drop(self, backend: NftablesBackend) -> None:
        r = Rule(action=RuleAction.BLOCK, target=RuleTarget.IP, value="192.168.1.50")
        expr = backend._rule_to_nft(r)
        assert expr is not None
        assert "drop" in expr
        assert "ip" in expr
        assert "saddr" in expr or "daddr" in expr

    def test_allow_subnet(self, backend: NftablesBackend) -> None:
        r = Rule(action=RuleAction.ALLOW, target=RuleTarget.SUBNET, value="10.0.0.0/24")
        expr = backend._rule_to_nft(r)
        assert expr is not None
        assert "accept" in expr
        assert "10.0.0.0/24" in expr

    def test_block_port_tcp(self, backend: NftablesBackend) -> None:
        r = Rule(
            action=RuleAction.BLOCK,
            target=RuleTarget.PORT,
            value="22",
            protocol="tcp",
        )
        expr = backend._rule_to_nft(r)
        assert expr is not None
        assert "tcp" in expr
        assert "dport" in expr
        assert "22" in expr
        assert "drop" in expr

    def test_block_protocol_ssh(self, backend: NftablesBackend) -> None:
        r = Rule(action=RuleAction.BLOCK, target=RuleTarget.PROTOCOL, value="ssh")
        expr = backend._rule_to_nft(r)
        assert expr is not None
        assert "tcp" in expr
        assert "dport" in expr
        assert "22" in expr

    def test_block_protocol_ping(self, backend: NftablesBackend) -> None:
        r = Rule(action=RuleAction.BLOCK, target=RuleTarget.PROTOCOL, value="ping")
        expr = backend._rule_to_nft(r)
        assert expr is not None
        assert "icmp" in expr
        assert "echo-request" in expr

    def test_block_protocol_dns(self, backend: NftablesBackend) -> None:
        r = Rule(action=RuleAction.BLOCK, target=RuleTarget.PROTOCOL, value="dns")
        expr = backend._rule_to_nft(r)
        assert expr is not None
        assert "udp" in expr
        assert "53" in expr

    def test_block_protocol_telnet(self, backend: NftablesBackend) -> None:
        r = Rule(action=RuleAction.BLOCK, target=RuleTarget.PROTOCOL, value="telnet")
        expr = backend._rule_to_nft(r)
        assert expr is not None
        assert "tcp" in expr
        assert "23" in expr

    def test_block_mac(self, backend: NftablesBackend) -> None:
        r = Rule(action=RuleAction.BLOCK, target=RuleTarget.MAC, value="aa:bb:cc:dd:ee:ff")
        expr = backend._rule_to_nft(r)
        assert expr is not None
        assert "ether" in expr
        assert "saddr" in expr
        assert "aa:bb:cc:dd:ee:ff" in expr

    def test_reject_action(self, backend: NftablesBackend) -> None:
        r = Rule(action=RuleAction.REJECT, target=RuleTarget.IP, value="1.1.1.1")
        expr = backend._rule_to_nft(r)
        assert expr is not None
        assert "reject" in expr

    def test_direction_out(self, backend: NftablesBackend) -> None:
        r = Rule(
            action=RuleAction.BLOCK,
            target=RuleTarget.IP,
            value="2.2.2.2",
            direction="out",
        )
        expr = backend._rule_to_nft(r)
        assert expr is not None
        # Out should use daddr
        assert "daddr" in expr

    def test_direction_both(self, backend: NftablesBackend) -> None:
        r = Rule(
            action=RuleAction.BLOCK,
            target=RuleTarget.IP,
            value="3.3.3.3",
            direction="both",
        )
        expr = backend._rule_to_nft(r)
        assert expr is not None
        # Both should include saddr and daddr
        assert "saddr" in expr
        assert "daddr" in expr


class TestNftablesApplyRemove:
    """Test apply/remove call nft commands (mocked)."""

    def test_apply_calls_nft_add_rule(self) -> None:
        with patch.object(NftablesBackend, "_ensure_table_chain", lambda self: None):
            b = NftablesBackend()
        with patch.object(b, "_run") as m_run:
            r = Rule(action=RuleAction.BLOCK, target=RuleTarget.IP, value="1.2.3.4")
            b.apply(r)
            # Should have called _run with an nft add rule command
            assert m_run.called
            cmd = m_run.call_args[0][0]
            assert "nft" in cmd
            assert "add" in cmd
            assert "rule" in cmd

    def test_remove_calls_flush(self) -> None:
        with patch.object(NftablesBackend, "_ensure_table_chain", lambda self: None):
            b = NftablesBackend()
        with patch.object(b, "_run") as m_run:
            r = Rule(action=RuleAction.BLOCK, target=RuleTarget.IP, value="1.2.3.4")
            b.remove(r)
            assert m_run.called
            cmd = m_run.call_args[0][0]
            assert "nft" in cmd
            assert "flush" in cmd

    def test_is_available_false_when_nft_missing(self) -> None:
        with patch.object(NftablesBackend, "_ensure_table_chain", lambda self: None):
            b = NftablesBackend()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert b.is_available() is False
