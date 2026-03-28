"""Unit tests for RulesEngine (with Noop backend)."""

from pathlib import Path

import pytest

from home_net_analyzer.rules.engine import RulesEngine, NoopBackend
from home_net_analyzer.rules.models import Rule, RuleAction, RuleTarget


@pytest.fixture()
def engine(tmp_path: Path) -> RulesEngine:
    # Use noop backend and temp persist path for isolated testing
    return RulesEngine(backend="noop", persist_path=tmp_path / "rules.json")


class TestRulesEngineCRUD:
    """Basic CRUD operations."""

    def test_add_rule_returns_id(self, engine: RulesEngine) -> None:
        rid = engine.add_rule(Rule(action=RuleAction.BLOCK, target=RuleTarget.IP, value="1.2.3.4"))
        assert isinstance(rid, int)
        assert rid >= 1

    def test_get_rule(self, engine: RulesEngine) -> None:
        rid = engine.block_ip("5.6.7.8")
        r = engine.get_rule(rid)
        assert r is not None
        assert r.value == "5.6.7.8"

    def test_list_rules_sorted(self, engine: RulesEngine) -> None:
        engine.block_ip("1.1.1.1", priority=50)
        engine.block_ip("2.2.2.2", priority=10)
        engine.allow_ip("3.3.3.3", priority=20)
        rules = engine.list_rules()
        priorities = [r.priority for r in rules]
        assert priorities == sorted(priorities)

    def test_remove_rule(self, engine: RulesEngine) -> None:
        rid = engine.block_ip("1.1.1.1")
        assert engine.get_rule(rid) is not None
        assert engine.remove_rule(rid) is True
        assert engine.get_rule(rid) is None

    def test_remove_missing(self, engine: RulesEngine) -> None:
        assert engine.remove_rule(9999) is False

    def test_enable_disable(self, engine: RulesEngine) -> None:
        rid = engine.block_ip("10.0.0.1")
        r = engine.get_rule(rid)
        assert r is not None
        assert r.enabled is True
        assert engine.disable_rule(rid) is True
        r = engine.get_rule(rid)
        assert r is not None
        assert r.enabled is False
        assert engine.enable_rule(rid) is True
        r = engine.get_rule(rid)
        assert r is not None
        assert r.enabled is True

    def test_clear_all(self, engine: RulesEngine) -> None:
        engine.block_ip("1.0.0.1")
        engine.block_ip("1.0.0.2")
        engine.block_ip("1.0.0.3")
        assert len(engine.list_rules()) == 3
        count = engine.clear_all()
        assert count == 3
        assert len(engine.list_rules()) == 0


class TestConvenienceMethods:
    """Convenience factory methods."""

    def test_block_ip(self, engine: RulesEngine) -> None:
        rid = engine.block_ip("192.168.1.1")
        r = engine.get_rule(rid)
        assert r is not None
        assert r.action == RuleAction.BLOCK
        assert r.target == RuleTarget.IP
        assert r.value == "192.168.1.1"

    def test_allow_ip(self, engine: RulesEngine) -> None:
        rid = engine.allow_ip("10.0.0.1")
        r = engine.get_rule(rid)
        assert r is not None
        assert r.is_allow() is True

    def test_block_subnet(self, engine: RulesEngine) -> None:
        rid = engine.block_subnet("10.0.0.0/24")
        r = engine.get_rule(rid)
        assert r is not None
        assert r.targets_subnet() is True

    def test_allow_subnet(self, engine: RulesEngine) -> None:
        rid = engine.allow_subnet("192.168.0.0/16")
        r = engine.get_rule(rid)
        assert r.is_allow() is True

    def test_block_port(self, engine: RulesEngine) -> None:
        rid = engine.block_port(22)
        r = engine.get_rule(rid)
        assert r is not None
        assert r.targets_port() is True
        assert r.value == "22"

    def test_allow_port(self, engine: RulesEngine) -> None:
        rid = engine.allow_port("80")
        r = engine.get_rule(rid)
        assert r.targets_port() is True

    def test_block_protocol(self, engine: RulesEngine) -> None:
        rid = engine.block_protocol("ssh")
        r = engine.get_rule(rid)
        assert r.targets_protocol() is True

    def test_allow_protocol(self, engine: RulesEngine) -> None:
        rid = engine.allow_protocol("ping")
        r = engine.get_rule(rid)
        assert r.is_allow() is True
