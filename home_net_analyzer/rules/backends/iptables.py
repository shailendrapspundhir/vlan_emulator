"""Iptables backend for RulesEngine.

This backend generates and runs `iptables` commands to apply/remove firewall rules.
It requires root privileges and the `iptables` tool installed.
"""

from __future__ import annotations

import subprocess
from typing import Any

from home_net_analyzer.rules.models import Rule, RuleAction, RuleTarget


class IptablesBackend:
    """Apply rules using iptables CLI."""

    def __init__(self, *, chain: str = "INPUT") -> None:
        self.chain = chain

    def apply(self, rule: Rule) -> None:
        """Apply a rule via iptables."""
        cmd = self._rule_to_iptables(rule)
        if cmd is None:
            return
        self._run(cmd, check=True)

    def remove(self, rule: Rule) -> None:
        """Remove a rule (best-effort: flush chain in simple impl)."""
        # Like nftables, a full implementation would track rule handles.
        # For simplicity, we flush the chain.
        self._run(["iptables", "-F", self.chain], check=False)

    def _rule_to_iptables(self, rule: Rule) -> list[str] | None:
        """Convert a Rule to iptables argv tokens (after 'iptables')."""
        # Action → -j TARGET
        if rule.action == RuleAction.BLOCK:
            target = "DROP"
        elif rule.action == RuleAction.ALLOW:
            target = "ACCEPT"
        elif rule.action == RuleAction.REJECT:
            target = "REJECT"
        else:
            return None

        parts: list[str] = ["-A", self.chain]

        # Target-specific
        if rule.target == RuleTarget.IP:
            if rule.direction in ("in", "both"):
                parts += ["-s", rule.value]
            if rule.direction in ("out", "both"):
                parts += ["-d", rule.value]

        elif rule.target == RuleTarget.SUBNET:
            if rule.direction in ("in", "both"):
                parts += ["-s", rule.value]
            if rule.direction in ("out", "both"):
                parts += ["-d", rule.value]

        elif rule.target == RuleTarget.PORT:
            proto = rule.protocol if rule.protocol != "any" else "tcp"
            parts += ["-p", proto, "--dport", rule.value]

        elif rule.target == RuleTarget.PROTOCOL:
            proto = rule.value.lower()
            if proto in ("tcp", "udp", "icmp"):
                parts += ["-p", proto]
            elif proto == "ping":
                parts += ["-p", "icmp", "--icmp-type", "echo-request"]
            elif proto == "ssh":
                parts += ["-p", "tcp", "--dport", "22"]
            elif proto == "telnet":
                parts += ["-p", "tcp", "--dport", "23"]
            elif proto == "dns":
                parts += ["-p", "udp", "--dport", "53"]
            else:
                parts += ["-p", proto]

        elif rule.target == RuleTarget.MAC:
            parts += ["-m", "mac", "--mac-source", rule.value]

        else:
            return None

        # Interface
        if rule.interface:
            parts += ["-i", rule.interface]

        # Verdict
        parts += ["-j", target]
        return parts

    def _run(self, cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

    def is_available(self) -> bool:
        try:
            res = subprocess.run(["iptables", "--version"], capture_output=True, text=True, check=False)
            return res.returncode == 0
        except FileNotFoundError:
            return False
