"""RulesEngine: manage and apply network firewall rules."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal

from home_net_analyzer.rules.models import Rule, RuleAction, RuleTarget

DEFAULT_PERSIST_PATH = Path("data/rules.json")


class RulesEngine:
    """Engine to manage firewall rules.

    Supports pluggable backends (iptables, nftables, or custom).
    Rules are persisted to a JSON file so they survive between CLI invocations.
    """

    def __init__(
        self,
        *,
        backend: Literal["nftables", "iptables", "noop"] = "nftables",
        backend_factory: Callable[[], "RuleBackend"] | None = None,
        persist_path: Path | str | None = None,
    ) -> None:
        self._rules: dict[int, Rule] = {}
        self._next_id = 1
        self._backend: RuleBackend
        self._persist_path = Path(persist_path) if persist_path else DEFAULT_PERSIST_PATH

        if backend_factory is not None:
            self._backend = backend_factory()
        elif backend == "iptables":
            from home_net_analyzer.rules.backends.iptables import IptablesBackend

            self._backend = IptablesBackend()
        elif backend == "nftables":
            from home_net_analyzer.rules.backends.nftables import NftablesBackend

            self._backend = NftablesBackend()
        else:
            self._backend = NoopBackend()

        # Load persisted rules
        self._load()

    # ------------------------------------------------------------------
    # Rule CRUD
    # ------------------------------------------------------------------

    def add_rule(self, rule: Rule) -> int:
        """Add a rule and apply it. Returns assigned id."""
        if rule.id is None:
            rule.id = self._next_id
            self._next_id += 1
        if rule.created_at is None:
            rule.created_at = datetime.now(timezone.utc).isoformat()
        self._rules[rule.id] = rule
        if rule.enabled:
            self._backend.apply(rule)
        self._save()
        return rule.id

    def get_rule(self, rule_id: int) -> Rule | None:
        return self._rules.get(rule_id)

    def list_rules(self) -> list[Rule]:
        return sorted(self._rules.values(), key=lambda r: (r.priority, r.id or 0))

    def remove_rule(self, rule_id: int) -> bool:
        """Remove a rule and un-apply it. Returns True if removed."""
        rule = self._rules.pop(rule_id, None)
        if rule is None:
            return False
        self._backend.remove(rule)
        self._save()
        return True

    def enable_rule(self, rule_id: int) -> bool:
        rule = self._rules.get(rule_id)
        if rule is None:
            return False
        if not rule.enabled:
            rule.enabled = True
            self._backend.apply(rule)
            self._save()
        return True

    def disable_rule(self, rule_id: int) -> bool:
        rule = self._rules.get(rule_id)
        if rule is None:
            return False
        if rule.enabled:
            rule.enabled = False
            self._backend.remove(rule)
            self._save()
        return True

    def clear_all(self) -> int:
        """Remove all rules. Returns count removed."""
        count = len(self._rules)
        for r in list(self._rules.values()):
            self._backend.remove(r)
        self._rules.clear()
        self._save()
        return count

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Load rules from persist file if it exists."""
        try:
            if self._persist_path.exists():
                data = json.loads(self._persist_path.read_text())
                for item in data.get("rules", []):
                    try:
                        rule = Rule(**item)
                        if rule.id is not None:
                            self._rules[rule.id] = rule
                            if rule.id >= self._next_id:
                                self._next_id = rule.id + 1
                    except Exception:
                        pass
        except Exception:
            pass  # Ignore load errors

    def _save(self) -> None:
        """Save rules to persist file."""
        try:
            self._persist_path.parent.mkdir(parents=True, exist_ok=True)
            data = {"rules": [r.to_dict() for r in self._rules.values()]}
            self._persist_path.write_text(json.dumps(data, indent=2))
        except Exception:
            pass  # Ignore save errors

    # ------------------------------------------------------------------
    # Convenience factory methods
    # ------------------------------------------------------------------

    def block_ip(self, ip: str, **kwargs: Any) -> int:
        return self.add_rule(Rule(action=RuleAction.BLOCK, target=RuleTarget.IP, value=ip, **kwargs))

    def allow_ip(self, ip: str, **kwargs: Any) -> int:
        return self.add_rule(Rule(action=RuleAction.ALLOW, target=RuleTarget.IP, value=ip, **kwargs))

    def block_subnet(self, subnet: str, **kwargs: Any) -> int:
        return self.add_rule(Rule(action=RuleAction.BLOCK, target=RuleTarget.SUBNET, value=subnet, **kwargs))

    def allow_subnet(self, subnet: str, **kwargs: Any) -> int:
        return self.add_rule(Rule(action=RuleAction.ALLOW, target=RuleTarget.SUBNET, value=subnet, **kwargs))

    def block_port(self, port: int | str, **kwargs: Any) -> int:
        return self.add_rule(Rule(action=RuleAction.BLOCK, target=RuleTarget.PORT, value=str(port), **kwargs))

    def allow_port(self, port: int | str, **kwargs: Any) -> int:
        return self.add_rule(Rule(action=RuleAction.ALLOW, target=RuleTarget.PORT, value=str(port), **kwargs))

    def block_protocol(self, proto: str, **kwargs: Any) -> int:
        return self.add_rule(Rule(action=RuleAction.BLOCK, target=RuleTarget.PROTOCOL, value=proto, **kwargs))

    def allow_protocol(self, proto: str, **kwargs: Any) -> int:
        return self.add_rule(Rule(action=RuleAction.ALLOW, target=RuleTarget.PROTOCOL, value=proto, **kwargs))


# ---------------------------------------------------------------------------
# Backend abstract and implementations
# ---------------------------------------------------------------------------


class RuleBackend:
    """Abstract base class for firewall backends."""

    def apply(self, rule: Rule) -> None:
        """Apply a rule to the actual firewall."""
        raise NotImplementedError

    def remove(self, rule: Rule) -> None:
        """Remove a rule from the actual firewall."""
        raise NotImplementedError

    def is_available(self) -> bool:
        """Check if backend tooling is available on this system."""
        return False


class NoopBackend(RuleBackend):
    """No-op backend for testing / unsupported environments."""

    def apply(self, rule: Rule) -> None:
        pass

    def remove(self, rule: Rule) -> None:
        pass

    def is_available(self) -> bool:
        return True


# Import concrete backends (defined in separate files)
try:
    from home_net_analyzer.rules.backends.nftables import NftablesBackend  # noqa: F401
except Exception:
    NftablesBackend = None  # type: ignore

try:
    from home_net_analyzer.rules.backends.iptables import IptablesBackend  # noqa: F401
except Exception:
    IptablesBackend = None  # type: ignore
