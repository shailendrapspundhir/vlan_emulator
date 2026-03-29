"""Data models for switch simulation: MAC table, frames, and forwarding decisions."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

from home_net_analyzer.capture.models import CapturedPacket


class MACTableEntry(BaseModel):
    """A single entry in the MAC address table.

    Example:
        entry = MACTableEntry(
            mac="aa:bb:cc:dd:ee:ff",
            vlan_id=10,
            port_id=1,
            entry_type="dynamic"
        )
    """

    mac: str = Field(..., description="MAC address (aa:bb:cc:dd:ee:ff)")
    vlan_id: int = Field(..., ge=1, le=4094, description="VLAN context")
    port_id: int = Field(..., ge=1, description="Associated switch port")
    entry_type: Literal["dynamic", "static", "sticky"] = Field(
        default="dynamic",
        description="How this entry was learned"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When entry was created"
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Last packet timestamp"
    )
    ttl: int = Field(default=300, ge=0, description="Time-to-live in seconds")

    def is_expired(self) -> bool:
        """Check if entry has aged out."""
        # Static entries never expire (ttl=0)
        if self.entry_type == "static" or self.ttl == 0:
            return False
        elapsed = (datetime.now(timezone.utc) - self.last_seen).total_seconds()
        return elapsed > self.ttl

    def touch(self) -> None:
        """Update last_seen timestamp to now."""
        self.last_seen = datetime.now(timezone.utc)

    def __hash__(self) -> int:
        """Make hashable for use in sets/dicts."""
        return hash((self.mac.lower(), self.vlan_id))

    def __eq__(self, other: object) -> bool:
        """Equality check for deduplication."""
        if not isinstance(other, MACTableEntry):
            return NotImplemented
        return self.mac.lower() == other.mac.lower() and self.vlan_id == other.vlan_id


class MACTable:
    """MAC address table for a switch with aging support.

    The MAC table maps (MAC address, VLAN) tuples to switch ports.
    It supports dynamic learning, static entries, and aging.

    Example:
        table = MACTable(max_entries=1024, default_ttl=300)
        table.learn("aa:bb:cc:dd:ee:ff", vlan_id=10, port_id=1)
        port = table.lookup("aa:bb:cc:dd:ee:ff", vlan_id=10)  # Returns 1
    """

    def __init__(self, max_entries: int = 1024, default_ttl: int = 300):
        """Initialize MAC table.

        Args:
            max_entries: Maximum number of entries before overflow
            default_ttl: Default time-to-live for dynamic entries in seconds
        """
        self._entries: dict[tuple[str, int], MACTableEntry] = {}
        self.max_entries = max_entries
        self.default_ttl = default_ttl
        self._stats = {
            "learned": 0,
            "aged_out": 0,
            "overflow": 0,
            "lookups": 0,
            "hits": 0,
            "misses": 0,
        }

    def learn(
        self,
        mac: str,
        vlan_id: int,
        port_id: int,
        entry_type: Literal["dynamic", "static", "sticky"] = "dynamic"
    ) -> MACTableEntry:
        """Learn or update a MAC address on a port.

        Args:
            mac: MAC address (will be normalized to lowercase)
            vlan_id: VLAN ID (1-4094)
            port_id: Switch port ID
            entry_type: Type of entry (dynamic, static, sticky)

        Returns:
            The created or updated MACTableEntry
        """
        mac = mac.lower()
        key = (mac, vlan_id)

        # Check if entry exists
        if key in self._entries:
            entry = self._entries[key]
            entry.port_id = port_id
            entry.touch()
            return entry

        # Check for overflow
        if len(self._entries) >= self.max_entries:
            self._handle_overflow()

        # Create new entry
        ttl = 0 if entry_type == "static" else self.default_ttl
        entry = MACTableEntry(
            mac=mac,
            vlan_id=vlan_id,
            port_id=port_id,
            entry_type=entry_type,
            ttl=ttl
        )
        self._entries[key] = entry
        self._stats["learned"] += 1
        return entry

    def lookup(self, mac: str, vlan_id: int) -> int | None:
        """Return port_id for MAC+VLAN, or None if unknown.

        Args:
            mac: MAC address to look up
            vlan_id: VLAN context

        Returns:
            Port ID if found, None otherwise
        """
        self._stats["lookups"] += 1
        mac = mac.lower()
        key = (mac, vlan_id)

        entry = self._entries.get(key)
        if entry is None:
            self._stats["misses"] += 1
            return None

        if entry.is_expired() and entry.entry_type == "dynamic":
            # Remove expired entry
            del self._entries[key]
            self._stats["misses"] += 1
            return None

        entry.touch()
        self._stats["hits"] += 1
        return entry.port_id

    def age_out(self) -> list[MACTableEntry]:
        """Remove expired entries and return what was removed.

        Returns:
            List of entries that were aged out
        """
        expired = []
        for key, entry in list(self._entries.items()):
            if entry.is_expired() and entry.entry_type == "dynamic":
                expired.append(entry)
                del self._entries[key]

        self._stats["aged_out"] += len(expired)
        return expired

    def flush_port(self, port_id: int) -> int:
        """Remove all entries for a port (e.g., link down).

        Args:
            port_id: Port ID to flush

        Returns:
            Number of entries removed
        """
        to_remove = [
            key for key, entry in self._entries.items()
            if entry.port_id == port_id
        ]
        for key in to_remove:
            del self._entries[key]
        return len(to_remove)

    def flush_vlan(self, vlan_id: int) -> int:
        """Remove all entries for a VLAN.

        Args:
            vlan_id: VLAN ID to flush

        Returns:
            Number of entries removed
        """
        to_remove = [
            key for key, entry in self._entries.items()
            if entry.vlan_id == vlan_id
        ]
        for key in to_remove:
            del self._entries[key]
        return len(to_remove)

    def add_static(self, mac: str, vlan_id: int, port_id: int) -> MACTableEntry:
        """Add a static MAC entry that doesn't age out.

        Args:
            mac: MAC address
            vlan_id: VLAN ID
            port_id: Port ID

        Returns:
            The created static entry
        """
        return self.learn(mac, vlan_id, port_id, entry_type="static")

    def get_entries(self) -> list[MACTableEntry]:
        """Get all current entries (for display/debugging).

        Returns:
            List of all MAC table entries
        """
        return list(self._entries.values())

    def get_entry_count(self) -> int:
        """Return current number of entries."""
        return len(self._entries)

    def get_stats(self) -> dict:
        """Return MAC table statistics."""
        return self._stats.copy()

    def _handle_overflow(self) -> None:
        """Handle table overflow by removing oldest dynamic entry."""
        # Find oldest dynamic entry
        oldest: MACTableEntry | None = None
        oldest_key: tuple[str, int] | None = None

        for key, entry in self._entries.items():
            if entry.entry_type != "static":
                if oldest is None or entry.last_seen < oldest.last_seen:
                    oldest = entry
                    oldest_key = key

        if oldest_key:
            del self._entries[oldest_key]
            self._stats["overflow"] += 1

    def clear(self) -> int:
        """Clear all entries from the table.

        Returns:
            Number of entries cleared
        """
        count = len(self._entries)
        self._entries.clear()
        return count


class SwitchFrame(BaseModel):
    """A frame as seen by a switch, with ingress port context.

    This wraps a CapturedPacket with switch-specific metadata
    for forwarding decisions.

    Example:
        frame = SwitchFrame(
            packet=captured_packet,
            ingress_port=1,
            ingress_switch="access-sw-01"
        )
        vlan = frame.get_vlan()
    """

    packet: CapturedPacket = Field(..., description="The captured packet")
    ingress_port: int = Field(..., ge=1, description="Ingress switch port ID")
    ingress_switch: str = Field(..., description="Name of ingress switch")

    # 802.1Q handling
    native_vlan: int = Field(default=1, ge=1, le=4094, description="Native VLAN for untagged frames")

    # Processing metadata
    received_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When frame was received"
    )

    def get_vlan(self) -> int:
        """Determine VLAN for this frame (tagged or native).

        Returns:
            VLAN ID (1-4094)
        """
        return self.packet.vlan_id or self.native_vlan

    def is_broadcast(self) -> bool:
        """Check if destination is broadcast MAC.

        Returns:
            True if destination is ff:ff:ff:ff:ff:ff
        """
        if not self.packet.dst_mac:
            return False
        return self.packet.dst_mac.lower() == "ff:ff:ff:ff:ff:ff"

    def is_multicast(self) -> bool:
        """Check if destination is multicast MAC.

        Multicast MACs have the least significant bit of the first
        octet set to 1.

        Returns:
            True if destination is multicast
        """
        if not self.packet.dst_mac:
            return False
        try:
            first_octet = int(self.packet.dst_mac.split(":")[0], 16)
            return (first_octet & 0x01) == 1
        except (ValueError, IndexError):
            return False

    def is_unknown_unicast(self) -> bool:
        """Check if this is unicast (not broadcast/multicast).

        Returns:
            True if destination is unicast
        """
        return not self.is_broadcast() and not self.is_multicast()


class VLANAction(str, Enum):
    """VLAN tag actions for frame egress."""
    TAG = "tag"           # Add/keep 802.1Q tag
    STRIP = "strip"       # Remove 802.1Q tag
    TRANSLATE = "translate"  # Translate VLAN ID (advanced)


class ForwardingDecision(BaseModel):
    """A forwarding decision for a frame.

    Represents the action to take for forwarding a frame
    out of a specific port.

    Example:
        decision = ForwardingDecision(
            port_id=5,
            vlan_action=VLANAction.TAG,
            egress_vlan=10
        )
        egress_packet = decision.apply_to_packet(packet)
    """

    port_id: int = Field(..., ge=1, description="Egress port ID")
    vlan_action: VLANAction = Field(..., description="VLAN tag action")
    egress_vlan: int | None = Field(
        default=None,
        ge=1,
        le=4094,
        description="VLAN to use on egress (for trunk ports)"
    )
    reason: str = Field(
        default="",
        description="Reason for this forwarding decision (for logging)"
    )

    def apply_to_packet(self, packet: CapturedPacket) -> CapturedPacket:
        """Apply VLAN action to create egress packet.

        Args:
            packet: Original packet

        Returns:
            Modified packet with VLAN action applied
        """
        new_packet = packet.model_copy()
        if self.vlan_action == VLANAction.TAG and self.egress_vlan:
            new_packet.vlan_id = self.egress_vlan
        elif self.vlan_action == VLANAction.STRIP:
            new_packet.vlan_id = None
        # TRANSLATE would handle VLAN translation here
        return new_packet

    def __str__(self) -> str:
        """String representation for logging."""
        vlan_info = f" VLAN:{self.egress_vlan}" if self.egress_vlan else ""
        return f"Port {self.port_id} ({self.vlan_action.value}){vlan_info}"
