"""Data models for firewall rules."""

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class RuleAction(str, Enum):
    """Possible actions for a rule."""

    BLOCK = "block"
    ALLOW = "allow"
    REJECT = "reject"  # Like block but sends ICMP/port-unreachable


class RuleTarget(str, Enum):
    """What the rule targets."""

    IP = "ip"
    SUBNET = "subnet"
    PORT = "port"
    PROTOCOL = "protocol"
    MAC = "mac"


class Rule(BaseModel):
    """A network firewall rule.

    Examples:
        - Block IP 192.168.1.50
        - Allow subnet 10.0.0.0/24
        - Block port 22
        - Allow protocol SSH
    """

    id: int | None = None

    # Core
    action: RuleAction
    target: RuleTarget

    # Target value (depends on target type)
    # - IP: "192.168.1.50"
    # - SUBNET: "10.0.0.0/24"
    # - PORT: "22" or "80-443"
    # - PROTOCOL: "tcp", "udp", "icmp", "ssh", "telnet", "ping", etc.
    # - MAC: "aa:bb:cc:dd:ee:ff"
    value: str

    # Optional scoping
    direction: Literal["in", "out", "both"] = "both"
    interface: str | None = None  # e.g., "eth0", "wlan0"

    # Protocol scoping (for IP/port rules)
    protocol: Literal["tcp", "udp", "icmp", "any"] = "any"

    # State
    enabled: bool = True
    priority: int = 100  # Lower = higher priority

    # Metadata
    description: str | None = None
    created_at: str | None = None  # ISO timestamp string (filled by engine)

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: str, info) -> str:
        target = info.data.get("target")
        if target == RuleTarget.PORT:
            # Allow single port or range like "80-443"
            if not (v.isdigit() or (v.count("-") == 1 and all(p.isdigit() for p in v.split("-")))):
                raise ValueError("Port must be a number or range like '80-443'")
        if target == RuleTarget.IP:
            # Basic IP check (not full validation)
            parts = v.split(".")
            if len(parts) != 4 or not all(p.isdigit() for p in parts):
                raise ValueError("IP must be like '192.168.1.50'")
        if target == RuleTarget.SUBNET:
            # Allow CIDR notation
            if "/" not in v:
                raise ValueError("Subnet must be CIDR notation like '10.0.0.0/24'")
        return v

    def is_block(self) -> bool:
        return self.action == RuleAction.BLOCK

    def is_allow(self) -> bool:
        return self.action == RuleAction.ALLOW

    def targets_ip(self) -> bool:
        return self.target == RuleTarget.IP

    def targets_subnet(self) -> bool:
        return self.target == RuleTarget.SUBNET

    def targets_port(self) -> bool:
        return self.target == RuleTarget.PORT

    def targets_protocol(self) -> bool:
        return self.target == RuleTarget.PROTOCOL

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "action": self.action.value,
            "target": self.target.value,
            "value": self.value,
            "direction": self.direction,
            "interface": self.interface,
            "protocol": self.protocol,
            "enabled": self.enabled,
            "priority": self.priority,
            "description": self.description,
            "created_at": self.created_at,
        }
