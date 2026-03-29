"""Switch forwarding engine for VLAN-aware Layer 2 switching."""

from __future__ import annotations

from typing import Literal

from home_net_analyzer.capture.models import CapturedPacket
from home_net_analyzer.simulation.switch.models import (
    ForwardingDecision,
    MACTable,
    SwitchFrame,
    VLANAction,
)
from home_net_analyzer.topology.models import SwitchPort, VirtualSwitch


class SwitchStats:
    """Statistics for switch forwarding operations."""

    def __init__(self):
        self.frames_received: int = 0
        self.frames_forwarded: int = 0
        self.frames_flooded: int = 0
        self.frames_dropped: int = 0
        self.unicast_known: int = 0
        self.unicast_unknown: int = 0
        self.broadcast_received: int = 0
        self.multicast_received: int = 0
        self.vlan_errors: int = 0
        self.port_errors: int = 0

    def to_dict(self) -> dict:
        """Convert stats to dictionary."""
        return {
            "frames_received": self.frames_received,
            "frames_forwarded": self.frames_forwarded,
            "frames_flooded": self.frames_flooded,
            "frames_dropped": self.frames_dropped,
            "unicast_known": self.unicast_known,
            "unicast_unknown": self.unicast_unknown,
            "broadcast_received": self.broadcast_received,
            "multicast_received": self.multicast_received,
            "vlan_errors": self.vlan_errors,
            "port_errors": self.port_errors,
        }


class SwitchEngine:
    """VLAN-aware Layer 2 switch forwarding engine.

    This engine processes frames through a virtual switch, handling:
    - MAC address learning
    - VLAN-aware forwarding
    - Trunk port handling (tag/untag)
    - Broadcast/multicast flooding
    - Unknown unicast flooding

    Example:
        switch = VirtualSwitch(name="access-sw-01", ports=[...], vlans=[10, 20])
        engine = SwitchEngine(switch)

        frame = SwitchFrame(packet=packet, ingress_port=1, ingress_switch="access-sw-01")
        decisions = engine.process_frame(frame)
    """

    def __init__(
        self,
        switch: VirtualSwitch,
        mac_table: MACTable | None = None,
        *,
        native_vlan: int = 1,
        log_level: Literal["debug", "info", "warning", "error"] = "info"
    ):
        """Initialize switch engine.

        Args:
            switch: VirtualSwitch configuration
            mac_table: Optional MACTable (creates default if None)
            native_vlan: Native VLAN for untagged frames
            log_level: Logging verbosity
        """
        self.switch = switch
        self.mac_table = mac_table or MACTable()
        self.native_vlan = native_vlan
        self.log_level = log_level
        self.stats = SwitchStats()
        self._logs: list[dict] = []

    def process_frame(self, frame: SwitchFrame) -> list[ForwardingDecision]:
        """Process a frame through the switch.

        This is the main entry point for switch forwarding. It:
        1. Validates the ingress port
        2. Determines the VLAN for the frame
        3. Learns the source MAC address
        4. Makes forwarding decision based on destination

        Args:
            frame: The frame to process with ingress context

        Returns:
            List of forwarding decisions (ports to send on)
        """
        self.stats.frames_received += 1
        self._log("debug", f"Processing frame on port {frame.ingress_port}")

        # 1. Validate ingress port
        ingress_port = self.switch.get_port(frame.ingress_port)
        if not ingress_port:
            self._log("error", f"Invalid ingress port {frame.ingress_port}")
            self.stats.port_errors += 1
            self.stats.frames_dropped += 1
            return []

        # 2. Determine VLAN (handle native VLAN tagging)
        vlan_id = self._determine_vlan(frame, ingress_port)
        if vlan_id is None:
            self._log(
                "warning",
                f"VLAN not allowed on port {frame.ingress_port}, dropping frame"
            )
            self.stats.vlan_errors += 1
            self.stats.frames_dropped += 1
            return []

        self._log("debug", f"Frame assigned to VLAN {vlan_id}")

        # 3. Learn source MAC
        if frame.packet.src_mac:
            self.mac_table.learn(
                frame.packet.src_mac,
                vlan_id,
                frame.ingress_port
            )
            self._log(
                "debug",
                f"Learned MAC {frame.packet.src_mac} on port {frame.ingress_port}, VLAN {vlan_id}"
            )

        # 4. Make forwarding decision
        decisions = self._forward_frame(frame, vlan_id, ingress_port)

        # Update stats
        if frame.is_broadcast():
            self.stats.broadcast_received += 1
        elif frame.is_multicast():
            self.stats.multicast_received += 1
        elif len(decisions) == 1:
            self.stats.unicast_known += 1
        else:
            self.stats.unicast_unknown += 1

        if len(decisions) > 1:
            self.stats.frames_flooded += 1
        elif len(decisions) == 1:
            self.stats.frames_forwarded += 1

        return decisions

    def _determine_vlan(self, frame: SwitchFrame, port: SwitchPort) -> int | None:
        """Determine effective VLAN for frame based on port configuration.

        Args:
            frame: The incoming frame
            port: The ingress port configuration

        Returns:
            VLAN ID if valid, None if VLAN not allowed (frame should be dropped)
        """
        if port.is_access():
            # Access port: frame should be untagged, use access_vlan
            if frame.packet.vlan_id is not None:
                # Tagged frame on access port - drop (could configure to strip instead)
                self._log(
                    "warning",
                    f"Tagged frame received on access port {port.id}"
                )
                return None
            return port.access_vlan
        else:
            # Trunk port: check if VLAN is allowed
            frame_vlan = frame.packet.vlan_id or frame.native_vlan
            if frame_vlan not in port.allowed_vlans:
                self._log(
                    "warning",
                    f"VLAN {frame_vlan} not allowed on trunk port {port.id}"
                )
                return None
            return frame_vlan

    def _forward_frame(
        self,
        frame: SwitchFrame,
        vlan_id: int,
        ingress_port: SwitchPort
    ) -> list[ForwardingDecision]:
        """Forward frame based on destination MAC.

        Args:
            frame: The frame to forward
            vlan_id: Determined VLAN ID
            ingress_port: The ingress port

        Returns:
            List of forwarding decisions
        """
        # Broadcast or multicast - flood to all ports in VLAN
        if frame.is_broadcast() or frame.is_multicast():
            self._log("debug", "Broadcast/multicast frame, flooding")
            return self._flood(frame, vlan_id, exclude_port=frame.ingress_port)

        # Unicast - try MAC table lookup
        return self._unicast_forward(frame, vlan_id)

    def _unicast_forward(self, frame: SwitchFrame, vlan_id: int) -> list[ForwardingDecision]:
        """Forward unicast frame based on MAC table.

        Args:
            frame: The frame to forward
            vlan_id: VLAN ID

        Returns:
            List with single forwarding decision, or flood if unknown
        """
        if not frame.packet.dst_mac:
            self._log("warning", "Frame has no destination MAC, dropping")
            self.stats.frames_dropped += 1
            return []

        # Lookup destination in MAC table
        dst_port = self.mac_table.lookup(frame.packet.dst_mac, vlan_id)

        if dst_port is None:
            # Unknown unicast - flood to same VLAN
            self._log(
                "debug",
                f"Unknown destination {frame.packet.dst_mac}, flooding"
            )
            return self._flood(frame, vlan_id, exclude_port=frame.ingress_port)

        # Known unicast - forward to specific port
        egress_port = self.switch.get_port(dst_port)
        if not egress_port:
            self._log("error", f"MAC table references invalid port {dst_port}")
            self.stats.port_errors += 1
            return []

        # Check VLAN compatibility on egress
        if not self._can_egress(vlan_id, egress_port):
            self._log(
                "warning",
                f"VLAN {vlan_id} cannot egress on port {egress_port.id}"
            )
            self.stats.vlan_errors += 1
            return []

        # Don't forward back out the same port it came in on
        if dst_port == frame.ingress_port:
            self._log("debug", "Destination on same port as source, not forwarding")
            return []

        self._log(
            "debug",
            f"Forwarding to port {dst_port} (MAC: {frame.packet.dst_mac})"
        )

        return [ForwardingDecision(
            port_id=dst_port,
            vlan_action=self._determine_vlan_action(vlan_id, egress_port),
            egress_vlan=vlan_id if egress_port.is_trunk() else None,
            reason=f"Known unicast: {frame.packet.dst_mac}"
        )]

    def _flood(
        self,
        frame: SwitchFrame,
        vlan_id: int,
        exclude_port: int
    ) -> list[ForwardingDecision]:
        """Flood frame to all ports in VLAN except ingress.

        Args:
            frame: The frame to flood
            vlan_id: VLAN ID to flood within
            exclude_port: Port ID to exclude (ingress port)

        Returns:
            List of forwarding decisions for all egress ports
        """
        decisions = []
        for port in self.switch.ports:
            if port.id == exclude_port:
                continue
            if not self._can_egress(vlan_id, port):
                continue
            decisions.append(ForwardingDecision(
                port_id=port.id,
                vlan_action=self._determine_vlan_action(vlan_id, port),
                egress_vlan=vlan_id if port.is_trunk() else None,
                reason="Flooding"
            ))

        self._log("debug", f"Flooding to {len(decisions)} ports")
        return decisions

    def _can_egress(self, vlan_id: int, port: SwitchPort) -> bool:
        """Check if frame can egress on port.

        Args:
            vlan_id: VLAN ID to check
            port: Egress port

        Returns:
            True if frame can egress on this port
        """
        if port.is_access():
            return port.access_vlan == vlan_id
        else:
            return vlan_id in port.allowed_vlans

    def _determine_vlan_action(self, vlan_id: int, port: SwitchPort) -> VLANAction:
        """Determine VLAN tag action for egress.

        Args:
            vlan_id: VLAN ID of the frame
            port: Egress port

        Returns:
            VLANAction (TAG or STRIP)
        """
        if port.is_access():
            return VLANAction.STRIP  # Remove tag for access ports
        else:
            return VLANAction.TAG  # Keep/add tag for trunk ports

    def get_mac_table_entries(self) -> list[dict]:
        """Get MAC table entries formatted for display.

        Returns:
            List of MAC table entry dictionaries
        """
        return [
            {
                "mac": entry.mac,
                "vlan": entry.vlan_id,
                "port": entry.port_id,
                "type": entry.entry_type,
                "age": int(
                    (datetime.now(timezone.utc) - entry.last_seen).total_seconds()
                ),
            }
            for entry in self.mac_table.get_entries()
        ]

    def clear_mac_table(self) -> int:
        """Clear the MAC table.

        Returns:
            Number of entries cleared
        """
        return self.mac_table.clear()

    def get_stats(self) -> dict:
        """Get switch statistics.

        Returns:
            Dictionary of statistics
        """
        return {
            "switch_name": self.switch.name,
            **self.stats.to_dict(),
            "mac_table_stats": self.mac_table.get_stats(),
        }

    def get_logs(self, level: str | None = None) -> list[dict]:
        """Get processing logs.

        Args:
            level: Filter by log level (optional)

        Returns:
            List of log entries
        """
        if level:
            return [log for log in self._logs if log["level"] == level]
        return self._logs.copy()

    def clear_logs(self) -> None:
        """Clear processing logs."""
        self._logs.clear()

    def _log(self, level: str, message: str) -> None:
        """Add a log entry.

        Args:
            level: Log level (debug, info, warning, error)
            message: Log message
        """
        from datetime import datetime, timezone

        levels = ["debug", "info", "warning", "error"]
        if levels.index(level) >= levels.index(self.log_level):
            self._logs.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": level,
                "message": message,
            })


# Import needed for type hints
from datetime import datetime, timezone
