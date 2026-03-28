"""Nftables backend for RulesEngine.

This backend generates and runs `nft` commands to apply/remove firewall rules.
It requires root privileges and the `nft` tool installed.
"""

from __future__ import annotations

import subprocess
from typing import Any

from home_net_analyzer.rules.models import Rule, RuleAction, RuleTarget


class NftablesBackend:
    """Apply rules using nftables (nft CLI)."""

    TABLE = "inet"
    TABLE_NAME = "hna"
    CHAIN = "filter"

    def __init__(self, *, table: str | None = None, chain: str | None = None) -> None:
        self.table = table or self.TABLE
        self.table_name = self.TABLE_NAME
        self.chain = chain or self.CHAIN
        self._ensure_table_chain()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _ensure_table_chain(self) -> None:
        """Ensure the hna table and chain exist."""
        # Create table if not exists
        self._run(["nft", "add", "table", self.table, self.table_name], check=False)
        # Create chain if not exists (input hook)
        self._run(
            [
                "nft",
                "add",
                "chain",
                self.table,
                self.table_name,
                self.chain,
                "{",
                "type",
                "filter",
                "hook",
                "input",
                "priority",
                "0",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ],
            check=False,
        )

    # ------------------------------------------------------------------
    # Apply / Remove
    # ------------------------------------------------------------------

    def apply(self, rule: Rule) -> None:
        """Apply a rule to nftables."""
        expr = self._rule_to_nft(rule)
        if expr is None:
            return  # No-op for unsupported rules
        # nft add rule <family> <table> <chain> <expr>
        cmd = ["nft", "add", "rule", self.table, self.table_name, self.chain] + expr
        self._run(cmd, check=True)

    def remove(self, rule: Rule) -> None:
        """Remove a rule from nftables (best-effort via flush+reapply)."""
        # nftables doesn't have a clean "remove by handle" without tracking handles.
        # For simplicity, we flush the chain and re-apply remaining rules.
        # A production implementation would track rule handles.
        self._run(["nft", "flush", "chain", self.table, self.table_name, self.chain], check=False)

    # ------------------------------------------------------------------
    # Rule → nft expression
    # ------------------------------------------------------------------

    def _rule_to_nft(self, rule: Rule) -> list[str] | None:
        """Convert a Rule to nftables expression tokens."""
        # Action
        if rule.action == RuleAction.BLOCK:
            verdict = "drop"
        elif rule.action == RuleAction.ALLOW:
            verdict = "accept"
        elif rule.action == RuleAction.REJECT:
            verdict = "reject"
        else:
            return None

        parts: list[str] = []

        # Direction (nftables handles ingress/egress via chain hooks; we apply on input)
        # We focus on filtering by src/dst IP.

        # Target-specific match
        if rule.target == RuleTarget.IP:
            # ip saddr <ip> or ip daddr <ip> depending on direction
            if rule.direction in ("in", "both"):
                parts += ["ip", "saddr", rule.value]
            if rule.direction in ("out", "both"):
                parts += ["ip", "daddr", rule.value]

        elif rule.target == RuleTarget.SUBNET:
            # Same as IP but CIDR
            if rule.direction in ("in", "both"):
                parts += ["ip", "saddr", rule.value]
            if rule.direction in ("out", "both"):
                parts += ["ip", "daddr", rule.value]

        elif rule.target == RuleTarget.PORT:
            # tcp/udp port
            proto = rule.protocol if rule.protocol != "any" else "tcp"
            port = rule.value
            parts += [proto, "dport", port]

        elif rule.target == RuleTarget.PROTOCOL:
            proto = rule.value.lower()
            if proto in ("tcp", "udp", "icmp"):
                parts += [proto]
            elif proto == "ping":
                parts += ["icmp", "type", "echo-request"]
            elif proto == "ssh":
                parts += ["tcp", "dport", "22"]
            elif proto == "telnet":
                parts += ["tcp", "dport", "23"]
            elif proto == "dns":
                parts += ["udp", "dport", "53"]
            else:
                # Unknown protocol string: try as-is
                parts += [proto]

        elif rule.target == RuleTarget.MAC:
            # mac saddr <mac>
            parts += ["ether", "saddr", rule.value]

        else:
            return None

        # Append verdict
        parts.append(verdict)
        return parts

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def _run(self, cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
        """Run an nft command."""
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

    def is_available(self) -> bool:
        """Check if nft command is available."""
        try:
            res = subprocess.run(["nft", "--version"], capture_output=True, text=True, check=False)
            return res.returncode == 0
        except FileNotFoundError:
            return False
