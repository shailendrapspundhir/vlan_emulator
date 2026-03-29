# Extended Network Simulator Architecture
## Missing Components for Comprehensive Corporate/Server Network Simulation

---

## Summary by Priority

| Priority | Category | Components | Complexity |
|----------|----------|------------|------------|
| **P0** | Core Infrastructure | Gateway redundancy (HSRP/VRRP), LACP, ECMP | Medium |
| **P0** | Firewall/Security | Stateful firewall, zones, NAT, VPN | High |
| **P1** | Load Balancing | L4/L7 LB, health checks, SSL termination | High |
| **P1** | Advanced Routing | BGP, OSPF, route maps, policy-based routing | Very High |
| **P1** | DNS/DHCP | DNS server, DDNS, DHCP relay/options | Medium |
| **P2** | Wireless | WLAN, APs, controllers, roaming | Very High |
| **P2** | Overlay Networks | VXLAN, GRE, SD-WAN | High |
| **P2** | Virtualization | vSwitches, container networking, VPC | High |
| **P3** | Storage Network | iSCSI, NFS, storage ACLs | Medium |
| **P3** | Monitoring | SNMP, syslog, NetFlow, telemetry | Medium |
| **P3** | Identity/Access | 802.1X, RADIUS, NAC | High |

---

## P0: Essential Core Infrastructure

### 1. Gateway Redundancy Protocols

**Why needed:** First-hop redundancy for hosts when default gateway fails.

```python
class GatewayRedundancyProtocol(Enum):
    HSRP = "hsrp"      # Hot Standby Router Protocol (Cisco proprietary)
    VRRP = "vrrp"      # Virtual Router Redundancy Protocol (open standard)
    GLBP = "glbp"      # Gateway Load Balancing Protocol (Cisco)

class VirtualGateway(BaseModel):
    """Virtual gateway representing a redundant gateway group."""
    virtual_ip: str                    # Shared virtual IP (host's default gateway)
    virtual_mac: str                   # Virtual MAC address
    group_id: int                      # HSRP/VRRP group number
    protocol: GatewayRedundancyProtocol
    
    # Member routers
    members: list[GatewayMember]
    
    # State
    active_router: str | None = None   # Currently active router
    preempt: bool = True               # Allow preemption
    priority: int = 100                # Default priority
    hello_time: int = 3                # Seconds
    hold_time: int = 10                # Seconds

class GatewayMember(BaseModel):
    """A physical router participating in gateway redundancy."""
    router_name: str
    interface: str
    priority: int = 100
    state: Literal["init", "listen", "speak", "standby", "active"]
```

**Simulation behavior:**
- Track router states (active/standby)
- Failover on hello timeout
- Virtual MAC handling
- Preemption logic

---

### 2. Link Aggregation (LACP)

**Why needed:** Bundle multiple physical links for bandwidth and redundancy.

```python
class PortChannel(BaseModel):
    """Link aggregation group (LAG)."""
    name: str                          # e.g., "Port-channel1", "bond0"
    channel_id: int
    mode: Literal["active", "passive", "on"]  # LACP modes
    
    # Member ports
    member_ports: list[int]            # Physical port IDs
    
    # Load balancing algorithm
    load_balance: Literal[
        "src-dst-mac",      # Layer 2
        "src-dst-ip",       # Layer 3
        "src-dst-port",     # Layer 4
        "src-dst-mac-ip",   # Combined
    ] = "src-dst-mac"
    
    # State
    operational: bool = False
    member_count: int = 0

class LACPPDU(BaseModel):
    """LACP protocol data unit."""
    actor_system_id: str
    actor_port_id: int
    actor_state: LACPState
    partner_system_id: str
    partner_port_id: int
    partner_state: LACPState

class LACPState(BaseModel):
    """LACP state flags."""
    active: bool                       # Participating in LACP
    aggregation: bool                  # Link is aggregatable
    sync: bool                         # In sync with partner
    collecting: bool                   # Collecting frames
    distributing: bool                 # Distributing frames
```

**Simulation behavior:**
- Hash-based load distribution
- Port failure detection
- LACP PDU exchange
- Bundle bandwidth calculation

---

### 3. ECMP (Equal Cost Multi-Path)

**Why needed:** Use multiple paths for same destination for load balancing.

```python
class ECMPGroup(BaseModel):
    """Multiple equal-cost routes to same destination."""
    destination: str                   # Destination prefix
    next_hops: list[ECMPNextHop]
    
    # Load balancing method
    hash_algorithm: Literal[
        "per-packet",       # Round-robin (can cause reordering)
        "per-flow",         # Based on flow hash (recommended)
        "per-destination",  # Based on destination only
    ] = "per-flow"
    
    def select_next_hop(self, packet: CapturedPacket) -> ECMPNextHop:
        """Select next hop using hash of packet fields."""

class ECMPNextHop(BaseModel):
    """A single next hop in ECMP group."""
    next_hop_ip: str
    interface: str
    metric: int
    weight: int = 1
    packets_forwarded: int = 0
```

---

## P0: Firewall & Security Infrastructure

### 4. Stateful Firewall

**Why needed:** Connection-aware filtering beyond simple ACLs.

```python
class FirewallZone(BaseModel):
    """Security zone (e.g., trust, untrust, dmz)."""
    name: str
    interfaces: list[str]
    security_level: int                # 0-100 (higher = more trusted)
    
class FirewallPolicy(BaseModel):
    """Inter-zone security policy."""
    name: str
    source_zones: list[str]
    destination_zones: list[str]
    source_addresses: list[str]        # Can be "any" or specific
    destination_addresses: list[str]
    applications: list[str]            # App-aware (http, dns, etc.)
    services: list[str]                # Ports/protocols
    action: Literal["allow", "deny", "drop", "reject"]
    log: bool = False

class ConnectionState(Enum):
    NEW = "new"           # First packet of connection
    ESTABLISHED = "established"  # Return traffic allowed
    RELATED = "related"   # Related to existing (e.g., FTP data)
    INVALID = "invalid"   # Malformed/out-of-state

class ConnectionTableEntry(BaseModel):
    """Stateful connection tracking entry."""
    connection_id: str
    protocol: str
    
    # Original direction
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    
    # Reverse direction (for NAT)
    reply_src_ip: str
    reply_dst_ip: str
    reply_src_port: int
    reply_dst_port: int
    
    state: ConnectionState
    created_at: datetime
    last_activity: datetime
    timeout: int                       # Seconds until expiration
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0

class StatefulFirewall:
    """Stateful firewall with connection tracking."""
    
    def __init__(self):
        self.connection_table: dict[str, ConnectionTableEntry] = {}
        self.zones: dict[str, FirewallZone] = {}
        self.policies: list[FirewallPolicy] = []
    
    def process_packet(
        self,
        packet: CapturedPacket,
        ingress_zone: str,
        egress_zone: str
    ) -> FirewallDecision:
        """
        Process packet through stateful firewall.
        
        1. Check connection table for existing flow
        2. If new, evaluate against security policies
        3. Create connection entry if allowed
        4. Update counters
        """
        
    def is_return_traffic(self, packet: CapturedPacket) -> bool:
        """Check if packet is return traffic for existing connection."""
```

---

### 5. NAT (Network Address Translation)

**Why needed:** Critical for IPv4 conservation and network isolation.

```python
class NATType(Enum):
    STATIC = "static"      # 1:1 mapping
    DYNAMIC = "dynamic"    # Pool-based
    PAT = "pat"           # Port Address Translation (overload)

class NATRule(BaseModel):
    """NAT translation rule."""
    name: str
    nat_type: NATType
    
    # Match conditions
    source_addresses: list[str]
    destination_addresses: list[str]
    
    # Translation
    translated_source: str | None      # For source NAT
    translated_destination: str | None # For destination NAT (port forwarding)
    
    # PAT specific
    pat_pool: list[str] | None
    pat_interface: str | None          # Interface IP overload

class NATSession(BaseModel):
    """Active NAT translation entry."""
    original_src: str
    original_dst: str
    original_sport: int
    original_dport: int
    
    translated_src: str
    translated_dst: str
    translated_sport: int
    translated_dport: int
    
    protocol: str
    entry_type: Literal["static", "dynamic", "pat"]
    timeout: int

class NATEngine:
    """NAT processing engine."""
    
    def translate_outbound(self, packet: CapturedPacket) -> CapturedPacket:
        """Source NAT for outbound traffic."""
        
    def translate_inbound(self, packet: CapturedPacket) -> CapturedPacket:
        """Destination NAT for inbound traffic."""
        
    def create_port_forwarding(
        self,
        external_ip: str,
        external_port: int,
        internal_ip: str,
        internal_port: int,
        protocol: str
    ) -> None:
        """Create static NAT for port forwarding."""
```

---

### 6. VPN (Virtual Private Network)

**Why needed:** Secure remote access and site-to-site connectivity.

```python
class VPNType(Enum):
    IPSEC_SITE_TO_SITE = "ipsec_s2s"
    IPSEC_REMOTE_ACCESS = "ipsec_ra"
    SSL_VPN = "ssl_vpn"
    WIREGUARD = "wireguard"
    OPENVPN = "openvpn"

class IPsecSA(BaseModel):
    """IPsec Security Association."""
    spi: int                           # Security Parameter Index
    encryption_algorithm: str          # AES-256-GCM, etc.
    auth_algorithm: str                # SHA-256, etc.
    encryption_key: bytes
    auth_key: bytes
    lifetime: int                      # Seconds
    bytes_transferred: int = 0

class VPNTunnel(BaseModel):
    """VPN tunnel endpoint."""
    name: str
    vpn_type: VPNType
    local_gateway: str
    remote_gateway: str
    local_networks: list[str]
    remote_networks: list[str]
    
    # IPsec specific
    ike_version: Literal["v1", "v2"]
    ike_policy: IKEPolicy
    ipsec_policy: IPsecPolicy
    
    # State
    status: Literal["down", "init", "up"]
    phase1_status: str
    phase2_status: str
    
    # SAs
    inbound_sa: IPsecSA | None
    outbound_sa: IPsecSA | None

class VPNConcentrator:
    """VPN termination point."""
    
    def initiate_tunnel(self, remote_gateway: str) -> bool:
        """Initiate IKE negotiation."""
        
    def encapsulate(self, packet: CapturedPacket, tunnel: VPNTunnel) -> CapturedPacket:
        """Apply IPsec encapsulation (ESP)."""
        
    def decapsulate(self, packet: CapturedPacket) -> CapturedPacket | None:
        """Remove IPsec encapsulation and verify."""
```

---

## P1: Application Delivery & Services

### 7. Load Balancer (ADC)

**Why needed:** Distribute traffic across multiple servers.

```python
class LoadBalancerAlgorithm(Enum):
    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_conn"
    LEAST_RESPONSE_TIME = "least_response"
    IP_HASH = "ip_hash"
    WEIGHTED = "weighted"
    CONSISTENT_HASH = "consistent_hash"

class VirtualServer(BaseModel):
    """Frontend VIP configuration."""
    name: str
    vip_address: str
    vip_port: int
    protocol: Literal["tcp", "udp", "http", "https"]
    
    # SSL/TLS
    ssl_termination: bool = False
    certificate: str | None = None
    
    # Backend pool
    pool: BackendPool
    
    # Health monitoring
    health_check: HealthCheck
    
    # Persistence
    persistence: PersistenceProfile | None

class BackendPool(BaseModel):
    """Group of backend servers."""
    name: str
    algorithm: LoadBalancerAlgorithm
    members: list[PoolMember]

class PoolMember(BaseModel):
    """Individual backend server."""
    name: str
    ip: str
    port: int
    weight: int = 1
    priority: int = 1
    
    # State
    enabled: bool = True
    operational: bool = False          # Based on health checks
    current_connections: int = 0
    total_requests: int = 0

class HealthCheck(BaseModel):
    """Backend health monitoring."""
    type: Literal["tcp", "http", "https", "icmp", "custom"]
    interval: int = 10                 # Seconds
    timeout: int = 5                   # Seconds
    retries: int = 3
    
    # HTTP specific
    http_path: str = "/"
    http_expected: int = 200

class PersistenceProfile(BaseModel):
    """Session stickiness configuration."""
    method: Literal[
        "source-ip",        # Based on client IP
        "cookie",           # HTTP cookie insert
        "ssl-session-id",   # SSL session ID
        "application",      # Application-specific
    ]
    timeout: int = 3600
    
class LoadBalancer:
    """Application Delivery Controller simulation."""
    
    def __init__(self):
        self.virtual_servers: dict[str, VirtualServer] = {}
        self.persistence_table: dict[str, PoolMember] = {}  # session -> member
        
    def select_backend(self, packet: CapturedPacket, vs: VirtualServer) -> PoolMember:
        """Select backend server using configured algorithm."""
        
    def perform_health_check(self, member: PoolMember) -> bool:
        """Execute health check against backend."""
        
    def handle_ssl_termination(self, packet: CapturedPacket) -> CapturedPacket:
        """Decrypt SSL and forward as HTTP (or re-encrypt)."""
```

---

### 8. DNS Infrastructure

**Why needed:** Name resolution is critical for all network services.

```python
class DNSRecordType(Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    PTR = "PTR"
    SOA = "SOA"
    SRV = "SRV"
    TXT = "TXT"

class DNSRecord(BaseModel):
    """DNS resource record."""
    name: str                          # Domain name
    record_type: DNSRecordType
    ttl: int
    data: str                          # Record value
    priority: int | None = None        # For MX, SRV

class DNSZone(BaseModel):
    """DNS zone configuration."""
    name: str                          # e.g., "corp.example.com"
    zone_type: Literal["master", "slave", "stub", "forward"]
    
    # Records
    records: list[DNSRecord]
    
    # SOA
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int
    
    # Master/slave
    master_servers: list[str] | None

class DNSResolver:
    """DNS server/resolver simulation."""
    
    def __init__(self):
        self.zones: dict[str, DNSZone] = {}
        self.cache: DNSCache = DNSCache()
        self.forwarders: list[str] = []
        
    def resolve(self, query: DNSQuery) -> DNSResponse:
        """
        Resolve DNS query.
        
        1. Check cache
        2. Check authoritative zones
        3. Forward to upstream if recursive
        """
        
    def handle_reverse_lookup(self, ip: str) -> str | None:
        """PTR record lookup."""

class DNSQuery(BaseModel):
    """DNS query message."""
    query_id: int
    name: str
    record_type: DNSRecordType
    recursive: bool = True

class DNSServer:
    """Authoritative and recursive DNS server."""
    
    def add_zone(self, zone: DNSZone) -> None:
        """Add authoritative zone."""
        
    def configure_forwarding(self, upstream: list[str]) -> None:
        """Configure upstream forwarders."""
        
    def enable_dnssec(self) -> None:
        """Enable DNSSEC validation."""
```

---

### 9. Dynamic Routing Protocols

**Why needed:** Automatic route propagation in large networks.

```python
class RoutingProtocol(Enum):
    BGP = "bgp"           # Border Gateway Protocol (inter-AS)
    OSPF = "ospf"         # Open Shortest Path First (intra-AS)
    EIGRP = "eigrp"       # Enhanced Interior Gateway Routing Protocol (Cisco)
    ISIS = "is-is"        # Intermediate System to Intermediate System
    RIP = "rip"           # Routing Information Protocol (legacy)

class BGPPeer(BaseModel):
    """BGP neighbor configuration."""
    peer_ip: str
    remote_as: int
    local_as: int
    
    # BGP attributes
    peer_group: str | None
    route_map_in: str | None
    route_map_out: str | None
    prefix_list_in: str | None
    prefix_list_out: str | None
    
    # State
    state: Literal["idle", "connect", "active", "opensent", "openconfirm", "established"]
    
    # Capabilities
    multiprotocol: list[str] = []      # Address families (IPv4, IPv6, VPNv4)
    route_refresh: bool = True
    graceful_restart: bool = False

class BGPAdvertisement(BaseModel):
    """BGP route advertisement."""
    prefix: str
    next_hop: str
    as_path: list[int]                 # AS path
    local_pref: int = 100
    med: int = 0
    communities: list[str] = []
    origin: Literal["igp", "egp", "incomplete"]

class OSPFArea(BaseModel):
    """OSPF area configuration."""
    area_id: str                       # Can be decimal or dotted
    area_type: Literal["standard", "stub", "totally_stubby", "nssa", "totally_nssa"]
    
class OSPFInterface(BaseModel):
    """OSPF interface configuration."""
    interface: str
    area_id: str
    cost: int | None = None            # Auto-calculate if None
    priority: int = 1                  # For DR election
    network_type: Literal["broadcast", "point-to-point", "nbma", "point-to-multipoint"]
    
class RoutingProcess:
    """Dynamic routing protocol process."""
    
    protocol: RoutingProtocol
    router_id: str
    
    # BGP specific
    bgp_peers: dict[str, BGPPeer]
    bgp_rib: dict[str, BGPAdvertisement]  # BGP RIB
    
    # OSPF specific
    ospf_areas: dict[str, OSPFArea]
    ospf_interfaces: list[OSPFInterface]
    ospf_lsdb: list[LSA]               # Link State Database
    
    def advertise_route(self, prefix: str, attributes: dict) -> None:
        """Advertise route to peers."""
        
    def receive_update(self, peer: str, routes: list[BGPAdvertisement]) -> None:
        """Process route update from peer."""
        
    def select_best_path(self, prefix: str) -> BGPAdvertisement | None:
        """BGP best path selection algorithm."""
```

---

## P2: Modern Network Infrastructure

### 10. Overlay Networks (VXLAN/EVPN)

**Why needed:** Modern data center networking, network virtualization.

```python
class VXLANSegment(BaseModel):
    """VXLAN network segment."""
    vni: int                           # VXLAN Network Identifier (24-bit)
    name: str
    vlan_id: int | None = None         # Local VLAN mapping
    
    # Multicast or unicast mode
    replication_mode: Literal["multicast", "ingress_replication", "evpn"]
    multicast_group: str | None        # For multicast mode
    
class VTEP(BaseModel):
    """VXLAN Tunnel Endpoint."""
    name: str
    vtep_ip: str                       # VTEP source IP
    
    # Encapsulation
    udp_port: int = 4789
    
    # Segments
    segments: dict[int, VXLANSegment]  # VNI -> segment
    
    # Remote VTEPs (for ingress replication)
    remote_vteps: list[str]
    
    # MAC table per VNI
    mac_tables: dict[int, dict[str, str]]  # VNI -> {MAC -> remote VTEP}

class VXLANEncapsulation(BaseModel):
    """VXLAN header information."""
    vni: int
    flags: int = 0x08                  # I flag set
    reserved: int = 0

class OverlayNetwork:
    """VXLAN/overlay networking simulation."""
    
    def encapsulate(self, packet: CapturedPacket, vni: int, dst_vtep: str) -> CapturedPacket:
        """Encapsulate Ethernet frame in VXLAN."""
        # Outer: UDP dst_port 4789, inner: VXLAN header + original frame
        
    def decapsulate(self, packet: CapturedPacket) -> CapturedPacket:
        """Remove VXLAN encapsulation."""
        
    def learn_mac(self, vni: int, mac: str, vtep_ip: str) -> None:
        """Learn MAC address from VXLAN packet."""
        
    def lookup_mac(self, vni: int, mac: str) -> str | None:
        """Lookup remote VTEP for MAC address."""
```

---

### 11. Wireless LAN (WLAN)

**Why needed:** WiFi is ubiquitous in corporate networks.

```python
class WirelessStandard(Enum):
    WIFI4 = "802.11n"
    WIFI5 = "802.11ac"
    WIFI6 = "802.11ax"
    WIFI6E = "802.11ax-6e"
    WIFI7 = "802.11be"

class SSID(BaseModel):
    """Wireless network configuration."""
    name: str                          # SSID broadcast name
    vlan_id: int | None = None
    
    # Security
    security: Literal["open", "wep", "wpa2-psk", "wpa2-enterprise", "wpa3"]
    encryption: Literal["tkip", "aes", "gcmp"]
    
    # Enterprise auth
    radius_servers: list[str] = []
    
    # Band steering
    bands: list[Literal["2.4ghz", "5ghz", "6ghz"]] = ["2.4ghz", "5ghz"]
    
    # Advanced
    hidden: bool = False
    max_clients: int = 100
    bandwidth_limit: int | None = None  # Mbps

class AccessPoint(BaseModel):
    """Wireless access point."""
    name: str
    mac: str
    ip: str
    
    # Physical location
    location: str | None = None
    
    # Radio configuration
    radios: list[Radio]
    
    # Connected clients
    associated_clients: dict[str, WirelessClient]  # MAC -> client
    
    # Connection
    connected_switch: str
    connected_port: int
    
    # Controller
    controller: str | None = None       # If lightweight AP

class Radio(BaseModel):
    """AP radio interface."""
    band: Literal["2.4ghz", "5ghz", "6ghz"]
    channel: int
    channel_width: Literal["20mhz", "40mhz", "80mhz", "160mhz"]
    tx_power: int                      # dBm
    standard: WirelessStandard
    
class WirelessClient(BaseModel):
    """WiFi client device."""
    mac: str
    ip: str | None = None
    hostname: str | None = None
    
    # Connection info
    ssid: str
    ap: str                            # Connected AP
    radio_band: str
    
    # State
    signal_strength: int               # dBm
    data_rate: int                     # Mbps
    connected_at: datetime
    
    # Roaming
    session_id: str

class WLANController:
    """Centralized wireless controller."""
    
    def __init__(self):
        self.ssids: dict[str, SSID] = {}
        self.aps: dict[str, AccessPoint] = {}
        self.clients: dict[str, WirelessClient] = {}
        
    def client_association(self, client_mac: str, ap: str, ssid: str) -> bool:
        """Process client association request."""
        
    def client_roaming(self, client: WirelessClient, new_ap: str) -> None:
        """Handle client roam between APs."""
        
    def radius_authentication(self, client: WirelessClient) -> bool:
        """802.1X authentication via RADIUS."""
```

---

### 12. Virtualization & Container Networking

**Why needed:** Modern infrastructure is highly virtualized.

```python
class VirtualSwitch(BaseModel):
    """Hypervisor virtual switch (vSwitch)."""
    name: str
    host: str                          # Physical host
    
    # Uplinks
    uplinks: list[str]                 # Physical NICs
    
    # Port groups
    port_groups: list[PortGroup]
    
    # Features
    promiscuous_mode: bool = False
    mac_changes: bool = False
    forged_transmits: bool = False

class PortGroup(BaseModel):
    """Port group (VLAN configuration for VMs)."""
    name: str
    vlan_id: int | None = None
    vlan_trunk: bool = False
    allowed_vlans: list[int] = []
    
class VirtualMachine(BaseModel):
    """Virtual machine network interface."""
    name: str
    host: str
    
    # Network interfaces
    vnics: list[VirtualNIC]
    
    # Connected switch
    vswitch: str
    port_group: str

class VirtualNIC(BaseModel):
    """VM network interface."""
    mac: str
    ip: str | None = None
    connected: bool = True

class ContainerNetwork(BaseModel):
    """Container networking (CNI)."""
    name: str
    cni_type: Literal["bridge", "macvlan", "ipvlan", "overlay", "host"]
    
    # IPAM
    subnet: str
    gateway: str
    ip_range: tuple[str, str] | None = None
    
    # Options
    parent_interface: str | None = None  # For macvlan/ipvlan
    
class Container(BaseModel):
    """Container instance."""
    id: str
    name: str
    image: str
    
    # Network
    networks: list[str]                 # Connected networks
    ip_addresses: dict[str, str]        # network -> IP
    exposed_ports: list[int]
    port_mappings: list[PortMapping]

class PortMapping(BaseModel):
    """Docker-style port mapping."""
    host_ip: str
    host_port: int
    container_port: int
    protocol: Literal["tcp", "udp"]

class VirtualizationPlatform:
    """Hypervisor/container platform simulation."""
    
    def __init__(self):
        self.vswitches: dict[str, VirtualSwitch] = {}
        self.vms: dict[str, VirtualMachine] = {}
        self.container_networks: dict[str, ContainerNetwork] = {}
        self.containers: dict[str, Container] = {}
        
    def vm_packet_flow(self, vm: VirtualMachine, packet: CapturedPacket) -> None:
        """Process packet from VM through vSwitch."""
        
    def container_nat(self, container: Container, packet: CapturedPacket) -> CapturedPacket:
        """Apply container port mapping NAT."""
```

---

## P3: Specialized & Advanced

### 13. Network Access Control (NAC)

**Why needed:** Zero-trust network access, device authentication.

```python
class AuthenticationMethod(Enum):
    DOT1X = "802.1x"
    MAC_AUTH = "mac-auth"
    WEB_AUTH = "web-auth"
    MAB = "mab"           # MAC Authentication Bypass

class RADIUSServer(BaseModel):
    """RADIUS authentication server."""
    name: str
    ip: str
    auth_port: int = 1812
    acct_port: int = 1813
    secret: str
    
    # State
    reachable: bool = True
    response_time: float = 0.0

class AuthenticationProfile(BaseModel):
    """Port authentication configuration."""
    method: AuthenticationMethod
    
    # 802.1X
    eap_methods: list[str] = ["peap", "ttls", "tls"]
    
    # VLAN assignment
    auth_vlan: int | None = None       # VLAN after auth
    unauth_vlan: int | None = None     # Guest/Deny VLAN
    
    # CoA (Change of Authorization)
    dynamic_vlan: bool = True
    dynamic_acl: bool = True

class NACPolicy(BaseModel):
    """Posture and compliance checking."""
    name: str
    
    # Device profiling
    device_types: list[str] = []
    os_requirements: list[str] = []
    
    # Compliance
    av_required: bool = False
    patches_required: bool = False
    
    # Actions
    compliant_action: Literal["permit", "quarantine", "deny"]
    non_compliant_action: Literal["quarantine", "deny"]

class NACSystem:
    """Network Access Control system."""
    
    def __init__(self):
        self.radius_servers: list[RADIUSServer] = []
        self.auth_profiles: dict[str, AuthenticationProfile] = {}
        self.policies: list[NACPolicy] = []
        
    def authenticate_client(
        self,
        client_mac: str,
        method: AuthenticationMethod,
        credentials: dict
    ) -> AuthResult:
        """
        Authenticate client via RADIUS.
        
        Returns assigned VLAN, ACLs, etc.
        """
        
    def check_compliance(self, client: dict) -> ComplianceResult:
        """Check device posture/compliance."""
        
    def send_coa(self, client_mac: str, action: str) -> bool:
        """Send Change of Authorization (disconnect, reauth, etc.)."""
```

---

### 14. Network Monitoring & Telemetry

**Why needed:** Observability, troubleshooting, capacity planning.

```python
class SNMPVersion(Enum):
    V1 = "v1"
    V2C = "v2c"
    V3 = "v3"

class SNMPAgent(BaseModel):
    """SNMP agent on network device."""
    device: str
    version: SNMPVersion
    community: str | None = None       # v1/v2c
    
    # v3 security
    username: str | None = None
    auth_protocol: str | None = None
    priv_protocol: str | None = None
    
    # Traps
    trap_receivers: list[str] = []
    
    # MIBs
    supported_mibs: list[str] = []

class FlowRecord(BaseModel):
    """NetFlow/IPFIX flow record."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    
    # Counters
    packet_count: int
    byte_count: int
    
    # Timing
    start_time: datetime
    end_time: datetime
    
    # Additional fields
    tcp_flags: int | None = None
    src_as: int | None = None          # Autonomous System
    dst_as: int | None = None
    next_hop: str | None = None

class FlowCollector:
    """NetFlow/sFlow collector."""
    
    def __init__(self):
        self.flows: list[FlowRecord] = []
        self.templates: dict[int, FlowTemplate] = {}  # NetFlow v9
        
    def receive_flow(self, export_packet: bytes) -> list[FlowRecord]:
        """Parse NetFlow/sFlow export packet."""
        
    def query_flows(
        self,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        time_range: tuple[datetime, datetime] | None = None
    ) -> list[FlowRecord]:
        """Query flow records."""

class StreamingTelemetry(BaseModel):
    """Model-driven telemetry (gRPC/NETCONF)."""
    device: str
    sensor_path: str                   # YANG path
    interval: int                      # Seconds
    data: dict                         # Collected data

class NetworkMonitor:
    """Centralized network monitoring."""
    
    def __init__(self):
        self.snmp_agents: dict[str, SNMPAgent] = {}
        self.flow_collector = FlowCollector()
        self.syslog_server: SyslogServer | None = None
        self.telemetry_subscriptions: list[StreamingTelemetry] = []
        
    def poll_snmp(self, device: str, oid: str) -> SNMPValue:
        """Poll SNMP OID from device."""
        
    def receive_syslog(self, message: SyslogMessage) -> None:
        """Receive and store syslog message."""
        
    def analyze_flows(self, criteria: FlowAnalysisCriteria) -> FlowAnalysis:
        """Analyze flow data for top talkers, anomalies, etc."""
```

---

### 15. Storage Networking

**Why needed:** SAN/NAS connectivity in server networks.

```python
class StorageProtocol(Enum):
    ISCSI = "iscsi"
    FCOE = "fcoe"           # Fibre Channel over Ethernet
    NFS = "nfs"
    SMB = "smb"
    NVME_OF = "nvme-of"     # NVMe over Fabrics

class iSCSITarget(BaseModel):
    """iSCSI storage target."""
    iqn: str                           # iSCSI Qualified Name
    ip: str
    port: int = 3260
    
    # LUNs
    luns: list[LUN]
    
    # Authentication
    chap_enabled: bool = False
    chap_username: str | None = None

class iSCSIInitiator(BaseModel):
    """iSCSI client."""
    iqn: str
    ip: str
    
    # Connections
    sessions: list[iSCSISession]

class iSCSISession(BaseModel):
    """Active iSCSI session."""
    target_iqn: str
    initiator_iqn: str
    
    # Paths (multipath)
    connections: list[iSCSIConnection]
    
    # State
    is_discovery: bool = False

class StorageArray:
    """Storage array simulation."""
    
    def __init__(self):
        self.iscsi_targets: dict[str, iSCSITarget] = {}
        self.nfs_exports: dict[str, NFSExport] = {}
        
    def iscsi_login(self, initiator: iSCSIInitiator, target_iqn: str) -> bool:
        """Process iSCSI login request."""
        
    def iscsi_logout(self, session: iSCSISession) -> None:
        """Terminate iSCSI session."""
        
    def nfs_mount(self, client_ip: str, export_path: str) -> NFSHandle:
        """Process NFS mount request."""
```

---

### 16. IPv6 & Dual-Stack

**Why needed:** Modern networks are increasingly IPv6.

```python
class IPv6Config(BaseModel):
    """IPv6 interface configuration."""
    address: str                       # Full IPv6 address
    prefix_len: int = 64
    
    # Auto-configuration
    autoconf: bool = False             # SLAAC
    dhcpv6: bool = False
    
    # Router advertisement
    send_ra: bool = False
    ra_prefixes: list[str] = []
    
    # Privacy extensions
    privacy_addresses: bool = True

class NDPTableEntry(BaseModel):
    """Neighbor Discovery Protocol entry (ARP for IPv6)."""
    ipv6: str
    mac: str
    state: Literal["incomplete", "reachable", "stale", "delay", "probe", "failed"]
    is_router: bool = False
    last_seen: datetime

class DHCPv6Server:
    """DHCPv6 server for IPv6 address assignment."""
    
    def __init__(self):
        self.prefixes: dict[str, DHCPv6Prefix] = {}
        self.leases: dict[str, DHCPv6Lease] = {}
        
    def handle_solicit(self, packet: CapturedPacket) -> CapturedPacket:
        """Process DHCPv6 SOLICIT message."""
        
    def handle_request(self, packet: CapturedPacket) -> CapturedPacket:
        """Process DHCPv6 REQUEST message."""

class DualStackHost:
    """Host with both IPv4 and IPv6."""
    
    ipv4: str | None = None
    ipv6: str | None = None
    ipv6_link_local: str | None = None
    
    dns_preference: Literal["v4", "v6", "both"] = "both"
    
    def resolve_destination(self, hostname: str) -> tuple[str | None, str | None]:
        """Resolve to both A and AAAA records."""
        
    def select_source_address(self, dst: str) -> str:
        """Select appropriate source address for destination."""
```

---

### 17. Multicast

**Why needed:** Video streaming, financial data, routing protocols.

```python
class MulticastGroup(BaseModel):
    """IP multicast group."""
    group_address: str                 # 224.0.0.0/4 or ff00::/8
    sources: list[str] = []            # For SSM (Source Specific Multicast)
    
    # Receivers
    igmp_members: dict[str, IGMPMembership]  # host -> membership
    
class IGMPMembership(BaseModel):
    """IGMP group membership."""
    host: str
    group: str
    version: Literal["v1", "v2", "v3"]
    mode: Literal["include", "exclude"]  # v3 only
    sources: list[str] = []            # v3 only
    last_report: datetime

class IGMPQuerier:
    """IGMP querier (typically router)."""
    
    def send_query(self, group: str | None = None) -> None:
        """Send IGMP general or group-specific query."""
        
    def process_report(self, packet: CapturedPacket) -> None:
        """Process IGMP membership report."""
        
    def process_leave(self, packet: CapturedPacket) -> None:
        """Process IGMP leave group message."""

class MulticastRouter:
    """Multicast routing (PIM)."""
    
    def __init__(self):
        self.mroute_table: dict[str, MRoute] = {}  # group -> route
        self.pim_neighbors: dict[str, PIMNeighbor] = {}
        
    def pim_hello(self, interface: str) -> None:
        """Send PIM Hello on interface."""
        
    def pim_join_prune(self, group: str, sources: list[str], join: bool) -> None:
        """Send PIM Join/Prune message."""
        
    def rpf_check(self, source: str, incoming_iface: str) -> bool:
        """Reverse Path Forwarding check."""
```

---

### 18. Quality of Service (QoS)

**Why needed:** Traffic prioritization, bandwidth guarantees.

```python
class DSCPValue(Enum):
    """Differentiated Services Code Point values."""
    CS0 = 0      # Best effort
    CS1 = 8      # Scavenger
    CS2 = 16     # OAM
    CS3 = 24     # Call signaling
    CS4 = 32     # Streaming video
    CS5 = 40     # Voice
    CS6 = 48     # Network control
    CS7 = 56     # Reserved
    EF = 46      # Expedited Forwarding (voice)
    AF11 = 10    # Assured Forwarding classes
    AF12 = 12
    AF13 = 14
    AF21 = 18
    AF22 = 20
    AF23 = 22
    AF31 = 26
    AF32 = 28
    AF33 = 30
    AF41 = 34
    AF42 = 36
    AF43 = 38

class TrafficClass(BaseModel):
    """Traffic classification."""
    name: str
    match_criteria: list[MatchCriterion]
    
class MatchCriterion(BaseModel):
    """Traffic matching condition."""
    type: Literal[
        "dscp", "cos", "precedence", "protocol",
        "src-ip", "dst-ip", "src-port", "dst-port",
        "vlan", "input-interface"
    ]
    value: str | int

class QoSPolicy(BaseModel):
    """QoS policy-map configuration."""
    name: str
    classes: list[ClassPolicy]

class ClassPolicy(BaseModel):
    """Policy for a traffic class."""
    class_name: str
    
    # Actions
    police_rate: int | None = None     # bps
    police_burst: int | None = None    # bytes
    
    shape_rate: int | None = None      # bps
    
    bandwidth_percent: int | None = None
    bandwidth_absolute: int | None = None  # bps
    
    priority: bool = False             # Strict priority queue
    
    dscp_mark: DSCPValue | None = None
    cos_mark: int | None = None        # 802.1p
    
    queue_limit: int | None = None     # packets

class QoSEngine:
    """QoS processing engine."""
    
    def classify_packet(self, packet: CapturedPacket) -> str:
        """Determine traffic class for packet."""
        
    def apply_policy(self, packet: CapturedPacket, policy: QoSPolicy) -> QoSAction:
        """Apply QoS policy actions."""
        
    def enqueue(self, packet: CapturedPacket, queue: int) -> bool:
        """Add packet to queue, check for drops."""
        
    def schedule(self) -> CapturedPacket | None:
        """Dequeue packet based on scheduling algorithm."""
```

---

## Implementation Priority Matrix

| Component | Complexity | Value | Dependencies | Suggested Phase |
|-----------|------------|-------|--------------|-----------------|
| **Gateway Redundancy** | Medium | High | Router simulator | Phase 2 |
| **LACP** | Medium | High | Switch simulator | Phase 2 |
| **Stateful Firewall** | High | High | ACLs, NAT | Phase 3 |
| **NAT** | Medium | High | Router simulator | Phase 2 |
| **Load Balancer** | High | High | Health checks | Phase 3 |
| **DNS Server** | Medium | Medium | - | Phase 2 |
| **BGP/OSPF** | Very High | Medium | Router simulator | Phase 4 |
| **VXLAN** | High | Medium | Switch, Router | Phase 4 |
| **Wireless** | Very High | Medium | Switch, Security | Phase 4 |
| **Container Networking** | High | Medium | NAT, vSwitch | Phase 3 |
| **NAC/802.1X** | High | Medium | RADIUS, VLANs | Phase 4 |
| **QoS** | Medium | Low | Switch, Router | Phase 5 |
| **Multicast** | High | Low | Router simulator | Phase 5 |
| **IPv6** | High | Medium | Router, NDP | Phase 3 |
| **SNMP/Monitoring** | Medium | Low | All devices | Phase 3 |
| **Storage Networking** | Medium | Low | iSCSI, ACLs | Phase 5 |

---

## Summary

For an **exhaustive** corporate/server network simulator, the architecture should eventually include:

### Core L2/L3 (Must Have)
- ✅ VLANs, STP
- ✅ Static routing, ARP
- ✅ ACLs
- 🔄 Gateway redundancy (HSRP/VRRP)
- 🔄 Link aggregation (LACP)
- 🔄 ECMP

### Security (Must Have)
- 🔄 Stateful firewall
- 🔄 NAT (PAT, static)
- 🔄 VPN (IPsec, SSL)
- 🔄 Zones

### Application Delivery (Should Have)
- 🔄 Load balancer
- 🔄 DNS infrastructure
- �Reverse proxy/WAF

### Dynamic & Scalable (Should Have)
- 🔄 Dynamic routing (BGP, OSPF)
- 🔄 VXLAN/Overlay networking
- 🔄 DHCP advanced features

### Modern Infrastructure (Nice to Have)
- 🔄 Wireless (WLAN)
- 🔄 Container networking
- 🔄 Virtualization (vSwitches)

### Enterprise Features (Nice to Have)
- 🔄 NAC/802.1X
- 🔄 QoS/CoS
- 🔄 IPv6 dual-stack
- 🔄 Multicast

### Operations (Nice to Have)
- 🔄 SNMP/Monitoring
- 🔄 NetFlow/sFlow
- 🔄 Syslog

This extended architecture would make the simulator suitable for:
- Network architecture design validation
- Security policy testing
- Change management simulation
- Training and certification prep
- Troubleshooting scenario recreation
