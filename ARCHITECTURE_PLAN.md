# VLAN Simulator Extension Architecture Plan

## Executive Summary

This document outlines the architecture for extending the Home Network Analyzer with comprehensive network simulation capabilities:

1. **Switch Simulator** - VLAN-aware Layer 2 switching with MAC learning, forwarding, flooding, and trunk handling
2. **Router Simulator** - Layer 3 routing with SVI gateways, routing tables, ARP resolution, and ACLs
3. **Virtual Network Simulator** - End-to-end packet flow simulation with logging, packet store integration, DHCP, STP, and security features

---

## Current State Analysis

### Existing Architecture

```
home_net_analyzer/
├── capture/          # Packet sniffing & parsing (CapturedPacket model)
├── storage/          # SQLite/DuckDB storage (PacketStore, Database)
├── rules/            # Firewall rules engine (RulesEngine, Rule models)
├── topology/         # Network topology models (VLAN, VirtualSwitch, Router, etc.)
├── simulation/       # Traffic generation (TrafficGenerator, TrafficScenario)
├── web/              # FastAPI dashboard
└── cli.py            # Typer CLI
```

### Existing Models (Strengths)

- **VLAN**: id, name, subnet, gateway - well defined
- **VirtualHost**: name, mac, ip, vlan_id, role - good foundation
- **SwitchPort**: access/trunk modes, VLAN handling - excellent starting point
- **VirtualSwitch**: ports, vlans - needs forwarding logic
- **Router**: interfaces, routing_table - needs packet processing
- **CapturedPacket**: Full L2/L3/L4 packet representation - excellent

### Gaps Identified

1. **No switch forwarding logic** - Topology exists but no packet forwarding simulation
2. **No MAC table management** - Essential for L2 switching
3. **No ARP table management** - Required for L3 gateway functionality
4. **No packet flow simulation** - Traffic generation exists but not topology-aware forwarding
5. **No ACL simulation at device level** - Rules engine is host-level, not per-device
6. **No DHCP simulation** - Static IPs only
7. **No STP simulation** - No loop prevention
8. **Limited logging** - No per-device or per-flow logging

---

## Part 1: Switch Simulator Architecture

### 1.1 Core Components

```
home_net_analyzer/simulation/switch/
├── __init__.py
├── models.py           # Switch state models (MACTable, etc.)
├── engine.py           # Switch forwarding engine
├── vlan_handler.py     # 802.1Q tag processing
├── trunk.py            # Trunk port handling
└── logging.py          # Switch event logging
```

### 1.2 Data Models

#### MACTableEntry
```python
class MACTableEntry(BaseModel):
    """A single entry in the MAC address table."""
    mac: str                          # MAC address (aa:bb:cc:dd:ee:ff)
    vlan_id: int                      # VLAN context
    port_id: int                      # Associated switch port
    entry_type: Literal["dynamic", "static", "sticky"]
    timestamp: datetime               # When learned
    last_seen: datetime               # Last packet timestamp
    ttl: int = 300                    # Time-to-live in seconds
    
    def is_expired(self) -> bool:
        """Check if entry has aged out."""
        return (datetime.now(timezone.utc) - self.last_seen).seconds > self.ttl
```

#### MACTable
```python
class MACTable:
    """MAC address table for a switch with aging support."""
    
    def __init__(self, max_entries: int = 1024, default_ttl: int = 300):
        self._entries: dict[tuple[str, int], MACTableEntry] = {}  # (mac, vlan) -> entry
        self.max_entries = max_entries
        self.default_ttl = default_ttl
    
    def learn(self, mac: str, vlan_id: int, port_id: int) -> None:
        """Learn or update a MAC address on a port."""
        
    def lookup(self, mac: str, vlan_id: int) -> int | None:
        """Return port_id for MAC+VLAN, or None if unknown."""
        
    def age_out(self) -> list[MACTableEntry]:
        """Remove expired entries, return what was removed."""
        
    def flush_port(self, port_id: int) -> None:
        """Remove all entries for a port (link down)."""
        
    def flush_vlan(self, vlan_id: int) -> None:
        """Remove all entries for a VLAN."""
```

#### SwitchFrame (Enhanced Packet for Switch Processing)
```python
class SwitchFrame(BaseModel):
    """A frame as seen by a switch, with ingress port context."""
    
    # Original packet data
    packet: CapturedPacket
    
    # Switch context
    ingress_port: int
    ingress_switch: str
    
    # 802.1Q handling
    native_vlan: int = 1  # Default native VLAN
    
    # Processing metadata
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    def get_vlan(self) -> int:
        """Determine VLAN for this frame (tagged or native)."""
        return self.packet.vlan_id or self.native_vlan
    
    def is_broadcast(self) -> bool:
        """Check if destination is broadcast."""
        return self.packet.dst_mac == "ff:ff:ff:ff:ff:ff" or self.packet.dst_mac.endswith(":ff")
    
    def is_multicast(self) -> bool:
        """Check if destination is multicast."""
        # Second least significant bit of first octet
        if not self.packet.dst_mac:
            return False
        first_octet = int(self.packet.dst_mac.split(":")[0], 16)
        return (first_octet & 0x01) == 1
```

### 1.3 Switch Forwarding Engine

```python
class SwitchEngine:
    """VLAN-aware Layer 2 switch forwarding engine."""
    
    def __init__(self, switch: VirtualSwitch, mac_table: MACTable | None = None):
        self.switch = switch
        self.mac_table = mac_table or MACTable()
        self.stats = SwitchStats()
        self.logger = SwitchLogger(switch.name)
    
    def process_frame(self, frame: SwitchFrame) -> list[ForwardingDecision]:
        """
        Process a frame through the switch.
        
        Returns list of forwarding decisions (ports to send on).
        """
        # 1. Validate ingress port
        ingress_port = self.switch.get_port(frame.ingress_port)
        if not ingress_port:
            self.logger.error(f"Invalid ingress port {frame.ingress_port}")
            return []
        
        # 2. Determine VLAN (handle native VLAN tagging)
        vlan_id = self._determine_vlan(frame, ingress_port)
        if vlan_id is None:
            self.logger.drop(frame, reason="vlan_not_allowed")
            return []
        
        # 3. Learn source MAC
        if frame.packet.src_mac:
            self.mac_table.learn(frame.packet.src_mac, vlan_id, frame.ingress_port)
        
        # 4. Make forwarding decision
        if frame.is_broadcast() or frame.is_multicast():
            decisions = self._flood(frame, vlan_id, exclude_port=frame.ingress_port)
        else:
            decisions = self._unicast_forward(frame, vlan_id)
        
        # 5. Log and return
        self.stats.record_forwarding(decisions)
        return decisions
    
    def _determine_vlan(self, frame: SwitchFrame, port: SwitchPort) -> int | None:
        """Determine effective VLAN for frame based on port configuration."""
        if port.is_access():
            # Access port: frame is untagged, use access_vlan
            if frame.packet.vlan_id is not None:
                # Tagged frame on access port - drop or strip (configurable)
                return None
            return port.access_vlan
        else:
            # Trunk port: check if VLAN is allowed
            frame_vlan = frame.packet.vlan_id or frame.native_vlan
            if frame_vlan not in port.allowed_vlans:
                return None
            return frame_vlan
    
    def _unicast_forward(self, frame: SwitchFrame, vlan_id: int) -> list[ForwardingDecision]:
        """Forward unicast frame based on MAC table."""
        dst_port = self.mac_table.lookup(frame.packet.dst_mac, vlan_id)
        
        if dst_port is None:
            # Unknown unicast - flood to same VLAN
            return self._flood(frame, vlan_id, exclude_port=frame.ingress_port)
        
        # Known unicast - forward to specific port
        egress_port = self.switch.get_port(dst_port)
        if not egress_port:
            return []
        
        # Check VLAN compatibility on egress
        if not self._can_egress(vlan_id, egress_port):
            return []
        
        return [ForwardingDecision(
            port_id=dst_port,
            vlan_action=self._determine_vlan_action(vlan_id, egress_port),
            egress_vlan=vlan_id if egress_port.is_trunk() else None
        )]
    
    def _flood(self, frame: SwitchFrame, vlan_id: int, exclude_port: int) -> list[ForwardingDecision]:
        """Flood frame to all ports in VLAN except ingress."""
        decisions = []
        for port in self.switch.ports:
            if port.id == exclude_port:
                continue
            if not self._can_egress(vlan_id, port):
                continue
            decisions.append(ForwardingDecision(
                port_id=port.id,
                vlan_action=self._determine_vlan_action(vlan_id, port),
                egress_vlan=vlan_id if port.is_trunk() else None
            ))
        return decisions
    
    def _can_egress(self, vlan_id: int, port: SwitchPort) -> bool:
        """Check if frame can egress on port."""
        if port.is_access():
            return port.access_vlan == vlan_id
        else:
            return vlan_id in port.allowed_vlans
    
    def _determine_vlan_action(self, vlan_id: int, port: SwitchPort) -> VLANAction:
        """Determine VLAN tag action for egress."""
        if port.is_access():
            return VLANAction.STRIP  # Remove tag for access ports
        else:
            return VLANAction.TAG  # Keep/add tag for trunk ports
```

### 1.4 VLAN Actions

```python
from enum import Enum

class VLANAction(str, Enum):
    """VLAN tag actions for frame egress."""
    TAG = "tag"           # Add/keep 802.1Q tag
    STRIP = "strip"       # Remove 802.1Q tag
    TRANSLATE = "translate"  # Translate VLAN ID (advanced)
```

### 1.5 Forwarding Decision

```python
class ForwardingDecision(BaseModel):
    """A forwarding decision for a frame."""
    port_id: int
    vlan_action: VLANAction
    egress_vlan: int | None = None  # VLAN to use on egress (for trunk ports)
    
    def apply_to_packet(self, packet: CapturedPacket) -> CapturedPacket:
        """Apply VLAN action to create egress packet."""
        new_packet = packet.model_copy()
        if self.vlan_action == VLANAction.TAG and self.egress_vlan:
            new_packet.vlan_id = self.egress_vlan
        elif self.vlan_action == VLANAction.STRIP:
            new_packet.vlan_id = None
        return new_packet
```

---

## Part 2: Router Simulator Architecture

### 2.1 Core Components

```
home_net_analyzer/simulation/router/
├── __init__.py
├── models.py           # Router state (ARP table, routing table, etc.)
├── engine.py           # Packet routing engine
├── arp.py              # ARP resolution and caching
├── svi.py              # Switched Virtual Interface handling
├── acl.py              # Access Control List processing
├── nat.py              # Network Address Translation (optional)
└── logging.py          # Router event logging
```

### 2.2 Data Models

#### ARPEntry
```python
class ARPEntry(BaseModel):
    """An entry in the ARP table."""
    ip: str
    mac: str | None = None  # None = incomplete
    interface: str          # Router interface name
    entry_type: Literal["dynamic", "static", "incomplete"]
    timestamp: datetime
    ttl: int = 300          # ARP cache timeout
    
    def is_complete(self) -> bool:
        return self.mac is not None
    
    def is_expired(self) -> bool:
        return (datetime.now(timezone.utc) - self.timestamp).seconds > self.ttl
```

#### ARPTable
```python
class ARPTable:
    """ARP cache for a router."""
    
    def __init__(self):
        self._entries: dict[str, ARPEntry] = {}  # ip -> entry
    
    def lookup(self, ip: str) -> ARPEntry | None:
        """Lookup MAC for IP address."""
        
    def add_entry(self, ip: str, mac: str, interface: str) -> None:
        """Add or update ARP entry."""
        
    def add_incomplete(self, ip: str, interface: str) -> None:
        """Mark ARP as pending resolution."""
        
    def age_out(self) -> list[ARPEntry]:
        """Remove expired entries."""
```

#### ACLRule
```python
class ACLRule(BaseModel):
    """A single ACL rule."""
    sequence: int
    action: Literal["permit", "deny"]
    
    # Match criteria (None = any)
    protocol: Literal["ip", "tcp", "udp", "icmp"] | None = None
    src_ip: str | None = None           # Can be IP or "any" or subnet
    src_wildcard: str | None = None     # For Cisco-style wildcards
    dst_ip: str | None = None
    dst_wildcard: str | None = None
    src_port: int | str | None = None   # Can be "eq 80" or range
    dst_port: int | str | None = None
    
    # Logging
    log: bool = False
    
    def matches(self, packet: CapturedPacket, direction: str) -> bool:
        """Check if packet matches this rule."""
```

#### ACL
```python
class ACL(BaseModel):
    """Access Control List for router interfaces."""
    name: str
    rules: list[ACLRule] = []
    
    def evaluate(self, packet: CapturedPacket, direction: Literal["in", "out"]) -> tuple[bool, ACLRule | None]:
        """
        Evaluate packet against ACL.
        Returns (permitted, matching_rule).
        """
        for rule in sorted(self.rules, key=lambda r: r.sequence):
            if rule.matches(packet, direction):
                return (rule.action == "permit", rule)
        # Implicit deny
        return (False, None)
```

#### RouterInterfaceState
```python
class RouterInterfaceState(BaseModel):
    """Runtime state for a router interface."""
    name: str
    enabled: bool = True
    
    # Layer 3 config
    ip: str | None = None
    subnet: str | None = None
    vlan_id: int | None = None  # For SVI
    
    # ACLs
    acl_in: str | None = None   # ACL name for ingress
    acl_out: str | None = None  # ACL name for egress
    
    # Stats
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    
    # Status
    line_protocol: Literal["up", "down", "admin_down"] = "up"
```

### 2.3 Routing Decision

```python
class RoutingDecision(BaseModel):
    """Result of a routing table lookup."""
    destination: str           # Original destination IP
    next_hop_ip: str | None    # None if directly connected
    interface: str             # Outgoing interface
    route_type: Literal["connected", "static", "dynamic"]
    metric: int = 0
    
    def is_directly_connected(self) -> bool:
        return self.next_hop_ip is None
```

### 2.4 Router Engine

```python
class RouterEngine:
    """Layer 3 routing engine with ACL and ARP support."""
    
    def __init__(
        self,
        router: Router,
        arp_table: ARPTable | None = None,
        acls: dict[str, ACL] | None = None
    ):
        self.router = router
        self.arp_table = arp_table or ARPTable()
        self.acls = acls or {}
        self.interfaces: dict[str, RouterInterfaceState] = {}
        self._init_interfaces()
        self.stats = RouterStats()
        self.logger = RouterLogger(router.name)
    
    def _init_interfaces(self) -> None:
        """Initialize interface states from router config."""
        for iface in self.router.interfaces:
            self.interfaces[iface.name] = RouterInterfaceState(
                name=iface.name,
                ip=iface.ip,
                subnet=iface.subnet,
                vlan_id=iface.vlan_id,
            )
    
    def route_packet(self, packet: CapturedPacket, ingress_iface: str) -> RouterProcessingResult:
        """
        Route a packet through the router.
        
        Returns result with forwarding decision or drop reason.
        """
        result = RouterProcessingResult(packet=packet)
        
        # 1. Validate ingress interface
        iface_state = self.interfaces.get(ingress_iface)
        if not iface_state or not iface_state.enabled:
            result.drop_reason = "invalid_ingress_interface"
            return result
        
        # 2. Check ingress ACL
        if iface_state.acl_in:
            acl = self.acls.get(iface_state.acl_in)
            if acl:
                permitted, rule = acl.evaluate(packet, "in")
                if not permitted:
                    result.drop_reason = "acl_deny"
                    result.acl_rule = rule
                    self.logger.drop(packet, reason="acl_in", acl=acl.name, rule=rule)
                    return result
        
        # 3. Route lookup
        route = self._lookup_route(packet.dst_ip)
        if not route:
            result.drop_reason = "no_route"
            self.logger.drop(packet, reason="no_route")
            return result
        
        result.route = route
        
        # 4. Check egress ACL
        egress_iface = self.interfaces.get(route.interface)
        if egress_iface and egress_iface.acl_out:
            acl = self.acls.get(egress_iface.acl_out)
            if acl:
                permitted, rule = acl.evaluate(packet, "out")
                if not permitted:
                    result.drop_reason = "acl_deny"
                    result.acl_rule = rule
                    self.logger.drop(packet, reason="acl_out", acl=acl.name, rule=rule)
                    return result
        
        # 5. ARP resolution
        target_ip = route.next_hop_ip or packet.dst_ip
        arp_entry = self.arp_table.lookup(target_ip)
        
        if arp_entry is None:
            # Need to ARP - queue packet and send ARP request
            result.requires_arp = True
            result.arp_target = target_ip
            result.arp_interface = route.interface
            self._send_arp_request(target_ip, route.interface)
            return result
        
        if not arp_entry.is_complete():
            # ARP pending - queue packet
            result.requires_arp = True
            result.arp_target = target_ip
            return result
        
        # 6. Prepare for forwarding
        result.next_hop_mac = arp_entry.mac
        result.egress_interface = route.interface
        result.forward = True
        
        # Decrement TTL
        if packet.ip_ttl:
            result.packet.ip_ttl = packet.ip_ttl - 1
            if result.packet.ip_ttl <= 0:
                result.drop_reason = "ttl_exceeded"
                self.logger.drop(packet, reason="ttl_exceeded")
                return result
        
        self.logger.forward(packet, route=route, next_hop_mac=arp_entry.mac)
        return result
    
    def _lookup_route(self, dst_ip: str) -> RoutingDecision | None:
        """Lookup route in routing table."""
        best_match: RouteEntry | None = None
        best_prefix_len = -1
        
        # Check connected networks first
        for iface_name, iface_state in self.interfaces.items():
            if iface_state.subnet and self._ip_in_subnet(dst_ip, iface_state.subnet):
                return RoutingDecision(
                    destination=dst_ip,
                    next_hop_ip=None,
                    interface=iface_name,
                    route_type="connected",
                    metric=0,
                )
        
        # Check static routes
        for route in self.router.routing_table:
            if self._ip_in_subnet(dst_ip, route.destination):
                prefix_len = int(route.destination.split("/")[1])
                if prefix_len > best_prefix_len:
                    best_prefix_len = prefix_len
                    best_match = route
        
        if best_match:
            return RoutingDecision(
                destination=dst_ip,
                next_hop_ip=best_match.next_hop,
                interface=best_match.interface,
                route_type="static",
                metric=1,
            )
        
        return None
    
    def _send_arp_request(self, target_ip: str, interface: str) -> None:
        """Generate ARP request packet."""
        # This would integrate with packet generator
        pass
    
    def handle_arp_reply(self, packet: CapturedPacket, interface: str) -> None:
        """Process incoming ARP reply."""
        # Extract sender IP/MAC and update ARP table
        pass
    
    def _ip_in_subnet(self, ip: str, subnet: str) -> bool:
        """Check if IP is in subnet."""
        import ipaddress
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet)
```

### 2.5 Router Processing Result

```python
class RouterProcessingResult(BaseModel):
    """Result of processing a packet through the router."""
    packet: CapturedPacket
    
    # Forwarding decision
    forward: bool = False
    egress_interface: str | None = None
    next_hop_mac: str | None = None
    
    # Routing info
    route: RoutingDecision | None = None
    
    # Drop info
    drop_reason: str | None = None
    acl_rule: ACLRule | None = None
    
    # ARP handling
    requires_arp: bool = False
    arp_target: str | None = None
    arp_interface: str | None = None
```

---

## Part 3: Virtual Network Simulator Architecture

### 3.1 Core Components

```
home_net_analyzer/simulation/network/
├── __init__.py
├── simulator.py        # Main simulation orchestrator
├── topology_manager.py # Manages network topology state
├── packet_flow.py      # End-to-end packet flow tracking
├── dhcp/               # DHCP server simulation
│   ├── __init__.py
│   ├── server.py
│   ├── lease.py
│   └── options.py
├── stp/                # Spanning Tree Protocol
│   ├── __init__.py
│   ├── bridge.py
│   ├── bpdu.py
│   └── state.py
├── logging/            # Comprehensive logging
│   ├── __init__.py
│   ├── flow_logger.py
│   ├── event_logger.py
│   └── packet_logger.py
└── security/           # Security features
    ├── __init__.py
    ├── port_security.py
    ├── dhcp_snooping.py
    └── dynamic_arp_inspection.py
```

### 3.2 Network Simulator

```python
class NetworkSimulator:
    """
    End-to-end network simulator orchestrating switches, routers, and hosts.
    """
    
    def __init__(self, topology: Topology):
        self.topology = topology
        
        # Device engines
        self.switch_engines: dict[str, SwitchEngine] = {}
        self.router_engines: dict[str, RouterEngine] = {}
        
        # Host state
        self.host_states: dict[str, HostState] = {}
        
        # Services
        self.dhcp_servers: dict[str, DHCPServer] = {}
        self.stp_instances: dict[str, STPBridge] = {}
        
        # Logging and storage
        self.flow_logger = FlowLogger()
        self.packet_store: PacketStore | None = None
        
        # Packet queue for async processing (ARP, etc.)
        self.packet_queue: list[QueuedPacket] = []
        
        self._initialize_devices()
    
    def _initialize_devices(self) -> None:
        """Initialize all device engines from topology."""
        for switch in self.topology.switches:
            self.switch_engines[switch.name] = SwitchEngine(switch)
        
        for router in self.topology.routers:
            self.router_engines[router.name] = RouterEngine(router)
        
        for host in self.topology.hosts:
            self.host_states[host.name] = HostState(
                host=host,
                ip=host.ip,
                mac=host.mac,
                gateway=self._find_gateway(host),
            )
    
    def simulate_packet_flow(
        self,
        src_host: str,
        dst_host: str,
        protocol: str = "icmp",
        count: int = 1,
    ) -> FlowResult:
        """
        Simulate end-to-end packet flow between two hosts.
        
        Traces the path through the network, handling:
        - L2 switching within VLAN
        - L3 routing between VLANs
        - ARP resolution
        - ACL filtering
        - Packet logging
        """
        src = self.host_states.get(src_host)
        dst = self.host_states.get(dst_host)
        
        if not src or not dst:
            raise ValueError(f"Unknown host: {src_host} or {dst_host}")
        
        flow = Flow(
            flow_id=self._generate_flow_id(),
            src_host=src_host,
            dst_host=dst_host,
            src_ip=src.ip,
            dst_ip=dst.ip,
            protocol=protocol,
        )
        
        packets = self._generate_flow_packets(src, dst, protocol, count)
        
        for packet in packets:
            hop_result = self._process_packet_through_network(packet, src)
            flow.add_hop(hop_result)
            
            # Store in packet store if configured
            if self.packet_store:
                self._store_packet_with_context(packet, hop_result)
        
        return FlowResult(flow=flow, success=flow.all_packets_delivered())
    
    def _process_packet_through_network(
        self,
        packet: CapturedPacket,
        src_host: HostState,
    ) -> HopResult:
        """
        Process a single packet through the network.
        
        Returns the hop-by-hop result showing the path taken.
        """
        hops: list[Hop] = []
        
        # 1. Source host ARP resolution
        next_hop_ip = self._determine_next_hop_ip(src_host, packet.dst_ip)
        dst_mac = self._resolve_arp(src_host, next_hop_ip)
        
        if not dst_mac:
            # Need to ARP - would queue in real implementation
            hops.append(Hop(
                device=src_host.host.name,
                action="arp_request",
                detail=f"Resolving {next_hop_ip}",
            ))
            return HopResult(hops=hops, delivered=False, drop_reason="arp_pending")
        
        packet.dst_mac = dst_mac
        packet.src_mac = src_host.mac
        
        # 2. Find connected switch and port
        connected_switch, ingress_port = self._find_host_connection(src_host)
        
        if not connected_switch:
            return HopResult(hops=hops, delivered=False, drop_reason="not_connected")
        
        # 3. Switch forwarding
        current_switch = connected_switch
        current_port = ingress_port
        
        while current_switch:
            frame = SwitchFrame(
                packet=packet,
                ingress_port=current_port,
                ingress_switch=current_switch.switch.name,
            )
            
            decisions = current_switch.process_frame(frame)
            
            hops.append(Hop(
                device=current_switch.switch.name,
                action="forward",
                detail=f"Decisions: {[d.port_id for d in decisions]}",
                vlan=frame.get_vlan(),
            ))
            
            if len(decisions) == 0:
                return HopResult(hops=hops, delivered=False, drop_reason="switch_drop")
            
            # Check if we're going to a router
            next_hop = self._determine_next_device(decisions, current_switch)
            
            if next_hop.type == "router":
                # Hand off to router
                router_result = self._process_through_router(packet, next_hop.router, next_hop.interface)
                hops.extend(router_result.hops)
                
                if not router_result.forward:
                    return HopResult(hops=hops, delivered=False, drop_reason=router_result.drop_reason)
                
                # Continue from router egress
                next_switch, next_port = self._find_router_connection(
                    router_result.egress_interface,
                    router_result.next_hop_mac,
                )
                
                current_switch = next_switch
                current_port = next_port
                packet = router_result.packet
                
            elif next_hop.type == "host":
                # Reached destination
                if next_hop.host.name == packet.dst_ip:
                    hops.append(Hop(
                        device=next_hop.host.name,
                        action="deliver",
                        detail="Packet delivered",
                    ))
                    return HopResult(hops=hops, delivered=True)
                else:
                    return HopResult(hops=hops, delivered=False, drop_reason="wrong_host")
            
            elif next_hop.type == "switch":
                # Continue to next switch
                current_switch = next_hop.switch
                current_port = next_hop.port
            else:
                break
        
        return HopResult(hops=hops, delivered=False, drop_reason="no_path")
    
    def _process_through_router(
        self,
        packet: CapturedPacket,
        router: RouterEngine,
        ingress_iface: str,
    ) -> RouterProcessingResult:
        """Process packet through a router."""
        return router.route_packet(packet, ingress_iface)
    
    def _find_host_connection(self, host: HostState) -> tuple[SwitchEngine | None, int]:
        """Find which switch and port a host is connected to."""
        for switch_name, engine in self.switch_engines.items():
            for port in engine.switch.ports:
                if port.connected_to == host.host.name:
                    return (engine, port.id)
        return (None, 0)
    
    def _determine_next_hop_ip(self, src: HostState, dst_ip: str) -> str:
        """Determine next hop IP for destination."""
        # Same subnet = direct
        if self._same_subnet(src.ip, dst_ip, src.subnet):
            return dst_ip
        # Different subnet = gateway
        return src.gateway
```

### 3.3 DHCP Simulation

```python
class DHCPServer:
    """Simulated DHCP server for automatic IP assignment."""
    
    def __init__(
        self,
        server_id: str,
        subnet: str,
        ip_range: tuple[str, str],
        gateway: str,
        dns_servers: list[str],
        lease_time: int = 3600,
    ):
        self.server_id = server_id
        self.subnet = subnet
        self.ip_range = ip_range
        self.gateway = gateway
        self.dns_servers = dns_servers
        self.lease_time = lease_time
        
        self.leases: dict[str, DHCPLease] = {}  # mac -> lease
        self.ip_pool: set[str] = self._generate_ip_pool()
        self.reservations: dict[str, str] = {}  # mac -> reserved_ip
    
    def handle_discover(self, packet: CapturedPacket) -> CapturedPacket | None:
        """Process DHCPDISCOVER, return DHCPOFFER."""
        
    def handle_request(self, packet: CapturedPacket) -> CapturedPacket | None:
        """Process DHCPREQUEST, return DHCPACK or DHCPNAK."""
        
    def release_lease(self, mac: str) -> None:
        """Release a DHCP lease."""
```

### 3.4 STP Simulation

```python
class STPBridge:
    """Spanning Tree Protocol bridge instance."""
    
    def __init__(self, switch_name: str, bridge_priority: int = 32768):
        self.switch_name = switch_name
        self.bridge_id = f"{bridge_priority:04x}.{self._generate_mac()}"
        self.root_bridge_id = self.bridge_id
        self.root_path_cost = 0
        self.root_port: int | None = None
        
        self.ports: dict[int, STPPortState] = {}
        
    def process_bpdu(self, bpdu: BPDU, port_id: int) -> None:
        """Process incoming BPDU and update STP state."""
        
    def generate_bpdu(self, port_id: int) -> BPDU:
        """Generate BPDU for transmission on port."""
        
    def get_forwarding_ports(self) -> list[int]:
        """Return list of ports in forwarding state."""
```

### 3.5 Security Features

#### Port Security
```python
class PortSecurity:
    """Switch port security feature."""
    
    def __init__(self, max_mac_addresses: int = 1, violation_mode: str = "shutdown"):
        self.max_mac_addresses = max_mac_addresses
        self.violation_mode = violation_mode  # protect, restrict, shutdown
        self.allowed_macs: set[str] = set()
        self.sticky_macs: set[str] = set()
        self.violation_count = 0
        self.port_shutdown = False
    
    def validate_mac(self, mac: str) -> bool:
        """Check if MAC is allowed on this port."""
        if self.port_shutdown:
            return False
        if mac in self.allowed_macs or mac in self.sticky_macs:
            return True
        if len(self.allowed_macs) + len(self.sticky_macs) < self.max_mac_addresses:
            if self.violation_mode == "sticky":
                self.sticky_macs.add(mac)
            return True
        self._handle_violation(mac)
        return False
    
    def _handle_violation(self, mac: str) -> None:
        """Handle security violation."""
        self.violation_count += 1
        if self.violation_mode == "shutdown":
            self.port_shutdown = True
```

#### DHCP Snooping
```python
class DHCPSnooping:
    """DHCP snooping security feature for switches."""
    
    def __init__(self):
        self.trusted_ports: set[int] = set()
        self.binding_table: dict[str, DHCPSnoopingBinding] = {}  # mac -> binding
    
    def validate_dhcp_packet(self, packet: CapturedPacket, port_id: int) -> bool:
        """Validate DHCP packet based on port trust state."""
        # Only trusted ports can send server responses
        if self._is_dhcp_server_packet(packet) and port_id not in self.trusted_ports:
            return False
        return True
    
    def learn_binding(self, packet: CapturedPacket) -> None:
        """Learn IP-MAC binding from DHCP ACK."""
```

---

## Part 4: Integration Architecture

### 4.1 Packet Store Integration

```python
class SimulatedPacketStore:
    """Extended packet store with simulation context."""
    
    def store_with_context(
        self,
        packet: CapturedPacket,
        context: SimulationContext,
    ) -> int:
        """
        Store packet with simulation metadata.
        
        Includes:
        - Flow ID
        - Path through network
        - Device decisions
        - Timing information
        """
        
    def query_by_flow(self, flow_id: str) -> list[PacketWithContext]:
        """Retrieve all packets for a specific flow."""
        
    def query_by_path(self, device_path: list[str]) -> list[PacketWithContext]:
        """Find packets that traversed a specific path."""
```

### 4.2 Logging Architecture

```python
class SimulationLogger:
    """Centralized logging for network simulation."""
    
    def __init__(self):
        self.event_log: list[SimulationEvent] = []
        self.flow_logs: dict[str, FlowLog] = {}
        
    def log_switch_event(
        self,
        switch: str,
        event_type: str,
        frame: SwitchFrame,
        details: dict,
    ) -> None:
        """Log a switch processing event."""
        
    def log_router_event(
        self,
        router: str,
        event_type: str,
        packet: CapturedPacket,
        details: dict,
    ) -> None:
        """Log a router processing event."""
        
    def log_flow_event(
        self,
        flow_id: str,
        event: str,
        hop: Hop,
    ) -> None:
        """Log a flow progression event."""
```

### 4.3 Web Dashboard Extensions

```python
# New API endpoints for simulation

@app.get("/api/simulation/topology")
def get_simulation_topology() -> dict:
    """Get current simulation topology with device states."""
    
@app.post("/api/simulation/flow")
def simulate_flow(payload: FlowSimulationRequest) -> FlowResult:
    """Run end-to-end flow simulation."""
    
@app.get("/api/simulation/switches/{switch_name}/mac-table")
def get_mac_table(switch_name: str) -> list[MACTableEntry]:
    """Get MAC table for a switch."""
    
@app.get("/api/simulation/routers/{router_name}/arp-table")
def get_arp_table(router_name: str) -> list[ARPEntry]:
    """Get ARP table for a router."""
    
@app.get("/api/simulation/flows/{flow_id}")
def get_flow_details(flow_id: str) -> FlowDetails:
    """Get detailed flow information with packet traces."""
    
@app.get("/api/simulation/visualization/packet-path")
def visualize_packet_path(flow_id: str) -> PathVisualization:
    """Get data for packet path visualization."""
```

---

## Part 5: Implementation Phases

### Phase 1: Switch Simulator (Weeks 1-2)

**Goals:**
- Basic MAC learning and forwarding
- VLAN-aware switching
- Trunk port support
- Unit tests

**Deliverables:**
- `simulation/switch/` module
- MACTable with aging
- SwitchEngine with forwarding logic
- Test coverage > 90%

### Phase 2: Router Simulator (Weeks 3-4)

**Goals:**
- Static routing
- ARP resolution
- Basic ACLs
- SVI support

**Deliverables:**
- `simulation/router/` module
- ARPTable with request/response
- RouterEngine with routing logic
- ACL evaluation

### Phase 3: Network Integration (Weeks 5-6)

**Goals:**
- End-to-end packet flow
- Multi-switch topologies
- Inter-VLAN routing
- Flow logging

**Deliverables:**
- `simulation/network/` module
- NetworkSimulator orchestration
- Flow tracking
- Integration tests

### Phase 4: Advanced Features (Weeks 7-8)

**Goals:**
- DHCP simulation
- STP simulation
- Security features
- Web dashboard integration

**Deliverables:**
- DHCP server/client simulation
- STP bridge simulation
- Port security, DHCP snooping
- Dashboard visualization

---

## Part 6: Testing Strategy

### Unit Tests

```python
# tests/simulation/switch/test_mac_table.py
def test_mac_learning():
    table = MACTable()
    table.learn("aa:bb:cc:dd:ee:ff", vlan_id=10, port_id=1)
    assert table.lookup("aa:bb:cc:dd:ee:ff", vlan_id=10) == 1

def test_mac_aging():
    table = MACTable(default_ttl=1)
    table.learn("aa:bb:cc:dd:ee:ff", vlan_id=10, port_id=1)
    time.sleep(2)
    aged = table.age_out()
    assert len(aged) == 1
```

### Integration Tests

```python
# tests/simulation/test_end_to_end.py
def test_inter_vlan_routing():
    topology = create_test_topology()
    sim = NetworkSimulator(topology)
    
    result = sim.simulate_packet_flow(
        src_host="pc-vlan10",
        dst_host="pc-vlan20",
        protocol="icmp",
    )
    
    assert result.success
    assert len(result.flow.hops) > 2  # Through switch, router, switch
```

### Scenario Tests

```python
# tests/simulation/scenarios/test_corporate_network.py
def test_full_corporate_scenario():
    """Test complex topology with multiple VLANs, switches, routers."""
    topology = load_topology("corporate_network.yaml")
    sim = NetworkSimulator(topology)
    
    # Test various flows
    scenarios = [
        ("pc-hr", "server-file", True),      # Same VLAN
        ("pc-hr", "pc-engineering", False),  # Different VLANs, need router
        ("pc-guest", "server-internal", False),  # ACL blocked
    ]
    
    for src, dst, expected in scenarios:
        result = sim.simulate_packet_flow(src, dst)
        assert result.success == expected
```

---

## Part 7: Configuration Schema Extensions

### Extended Topology YAML

```yaml
name: corporate_network
description: Multi-VLAN corporate network with security

vlans:
  - id: 10
    name: Management
    subnet: 10.0.10.0/24
    gateway: 10.0.10.1
  - id: 20
    name: Engineering
    subnet: 10.0.20.0/24
    gateway: 10.0.20.1
  - id: 30
    name: Guest
    subnet: 10.0.30.0/24
    gateway: 10.0.30.1

hosts:
  - name: pc-eng-01
    mac: aa:bb:cc:01:00:01
    ip: 10.0.20.101
    vlan_id: 20
    # DHCP alternative:
    # dhcp_client: true
    connected_to: access-sw-01/port/1

switches:
  - name: access-sw-01
    vlans: [10, 20, 30]
    stp:
      enabled: true
      priority: 32768
    ports:
      - id: 1
        name: Gi1/0/1
        mode: access
        access_vlan: 20
        connected_to: pc-eng-01
        port_security:
          enabled: true
          max_mac: 1
          violation: shutdown
      - id: 24
        name: Gi1/0/24
        mode: trunk
        allowed_vlans: [10, 20, 30]
        dhcp_snooping:
          trusted: true
    
  - name: core-sw-01
    vlans: [10, 20, 30]
    stp:
      enabled: true
      priority: 4096  # Root bridge
    ports:
      - id: 1
        name: Gi1/0/1
        mode: trunk
        allowed_vlans: [10, 20, 30]
        connected_to: access-sw-01/port/24
      - id: 2
        name: Gi1/0/2
        mode: trunk
        allowed_vlans: [10, 20, 30]
        connected_to: router-01/interface/gi0/0

routers:
  - name: router-01
    interfaces:
      - name: gi0/0
        type: trunk
        vlans: [10, 20, 30]
        connected_to: core-sw-01/port/2
      - name: gi0/1
        ip: 203.0.113.1
        subnet: 203.0.113.0/30
        connected_to: internet
    svis:
      - vlan: 10
        ip: 10.0.10.1
        subnet: 10.0.10.0/24
      - vlan: 20
        ip: 10.0.20.1
        subnet: 10.0.20.0/24
        acls:
          in: allow-engineering
          out: filter-engineering
      - vlan: 30
        ip: 10.0.30.1
        subnet: 10.0.30.0/24
        acls:
          in: restrict-guest
    routing_table:
      - destination: 0.0.0.0/0
        next_hop: 203.0.113.2
        interface: gi0/1
    acls:
      - name: allow-engineering
        rules:
          - sequence: 10
            action: permit
            protocol: ip
            src: 10.0.20.0/24
            dst: any
          - sequence: 20
            action: deny
            protocol: ip
            src: any
            dst: 10.0.10.0/24
      - name: restrict-guest
        rules:
          - sequence: 10
            action: permit
            protocol: tcp
            src: 10.0.30.0/24
            dst: any
            dst_port: 80
          - sequence: 20
            action: permit
            protocol: tcp
            src: 10.0.30.0/24
            dst: any
            dst_port: 443
          - sequence: 100
            action: deny
            protocol: ip
            src: any
            dst: any
            log: true

dhcp_servers:
  - name: dhcp-primary
    switch: core-sw-01
    vlan: 10
    ip_range: [10.0.10.100, 10.0.10.199]
    gateway: 10.0.10.1
    dns: [10.0.10.10, 8.8.8.8]
    lease_time: 3600
```

---

## Part 8: CLI Extensions

```bash
# Switch operations
hna switch mac-table <switch-name>           # Show MAC table
hna switch clear-mac <switch-name>           # Clear MAC table
hna switch port-status <switch-name>         # Show port status

# Router operations
hna router arp-table <router-name>           # Show ARP table
hna router route-table <router-name>         # Show routing table
hna router clear-arp <router-name>           # Clear ARP cache

# Simulation
hna simulate flow --src <host> --dst <host>  # Simulate packet flow
hna simulate ping --src <host> --dst <host>  # Simulate ping
hna simulate trace --src <host> --dst <host> # Trace route
hna simulate topology --file <yaml>          # Load and validate topology

# DHCP
hna dhcp leases                              # Show DHCP leases
hna dhcp release --mac <mac>                 # Release DHCP lease

# STP
hna stp status                               # Show STP topology
hna stp root-bridge                          # Show root bridge
```

---

## Summary

This architecture provides a comprehensive foundation for extending the Home Network Analyzer into a full-featured network simulation platform. Key design principles:

1. **Modularity**: Each component (switch, router, services) is self-contained
2. **Extensibility**: Clear interfaces allow adding new protocols/features
3. **Realism**: Models real network behaviors (MAC aging, ARP resolution, ACL evaluation)
4. **Observability**: Comprehensive logging and tracing at every step
5. **Integration**: Seamless connection to existing packet store and web dashboard

The implementation can proceed incrementally through the defined phases, with each phase delivering usable functionality while building toward the complete vision.
