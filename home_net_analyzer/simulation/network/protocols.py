"""Protocol simulators for network simulation.

Provides simulated implementations of common network protocols:
- DHCP: IP address assignment
- DNS: Name resolution
- ICMP: Ping functionality
- HTTP: Web server/client simulation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class DHCPState(str, Enum):
    """DHCP client states."""
    INIT = "INIT"
    SELECTING = "SELECTING"
    REQUESTING = "REQUESTING"
    BOUND = "BOUND"
    RENEWING = "RENEWING"
    REBINDING = "REBINDING"


@dataclass
class DHCPTransaction:
    """A DHCP transaction simulation.

    Simulates the 4-step DORA process:
    1. Discover (broadcast)
    2. Offer (unicast/broadcast)
    3. Request (broadcast)
    4. Ack (unicast/broadcast)

    Example:
        dhcp = DHCPTransaction(client_mac="aa:bb:cc:dd:ee:01")
        result = dhcp.simulate_dhcp(
            subnet="192.168.1.0/24",
            gateway="192.168.1.1",
            dns_servers=["8.8.8.8"]
        )
    """

    client_mac: str
    state: DHCPState = field(default=DHCPState.INIT)
    offered_ip: str | None = field(default=None)
    assigned_ip: str | None = field(default=None)
    subnet_mask: str | None = field(default=None)
    gateway: str | None = field(default=None)
    dns_servers: list[str] = field(default_factory=list)
    lease_time: int = field(default=3600)
    transaction_id: int = field(default_factory=lambda: __import__('random').randint(1, 0xFFFFFFFF))
    steps: list[dict] = field(default_factory=list)

    def simulate_dhcp(
        self,
        subnet: str,
        gateway: str,
        dns_servers: list[str] | None = None,
        lease_time: int = 3600
    ) -> dict[str, Any]:
        """Simulate complete DHCP DORA process.

        Args:
            subnet: Subnet in CIDR notation (e.g., "192.168.1.0/24")
            gateway: Default gateway IP
            dns_servers: List of DNS server IPs
            lease_time: Lease time in seconds

        Returns:
            Dict with assigned IP and configuration
        """
        import ipaddress

        self.steps = []
        network = ipaddress.ip_network(subnet)

        # Step 1: DHCP Discover (broadcast)
        self.state = DHCPState.SELECTING
        self.steps.append({
            "step": 1,
            "message": "DHCPDISCOVER",
            "src": "0.0.0.0",
            "dst": "255.255.255.255",
            "mac": self.client_mac,
            "details": f"Client {self.client_mac} broadcasting DHCPDISCOVER"
        })

        # Step 2: DHCP Offer
        # Assign IP from subnet (skip network and broadcast addresses)
        hosts = list(network.hosts())
        if len(hosts) > 2:
            offered = str(hosts[2])  # Skip .1 (usually gateway)
        else:
            offered = str(hosts[0])

        self.offered_ip = offered
        self.steps.append({
            "step": 2,
            "message": "DHCPOFFER",
            "src": gateway,
            "dst": offered,
            "mac": self.client_mac,
            "details": f"Server offering {offered} to {self.client_mac}"
        })

        # Step 3: DHCP Request
        self.state = DHCPState.REQUESTING
        self.steps.append({
            "step": 3,
            "message": "DHCPREQUEST",
            "src": "0.0.0.0",
            "dst": "255.255.255.255",
            "mac": self.client_mac,
            "details": f"Client requesting {offered}"
        })

        # Step 4: DHCP Ack
        self.state = DHCPState.BOUND
        self.assigned_ip = offered
        self.subnet_mask = str(network.netmask)
        self.gateway = gateway
        self.dns_servers = dns_servers or ["8.8.8.8"]
        self.lease_time = lease_time

        self.steps.append({
            "step": 4,
            "message": "DHCPACK",
            "src": gateway,
            "dst": offered,
            "mac": self.client_mac,
            "details": f"Server acknowledging lease of {offered}"
        })

        return {
            "success": True,
            "ip": self.assigned_ip,
            "subnet_mask": self.subnet_mask,
            "gateway": self.gateway,
            "dns_servers": self.dns_servers,
            "lease_time": self.lease_time,
            "steps": self.steps
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "client_mac": self.client_mac,
            "state": self.state.value,
            "assigned_ip": self.assigned_ip,
            "gateway": self.gateway,
            "dns_servers": self.dns_servers,
            "steps": self.steps
        }


@dataclass
class DNSEntry:
    """DNS cache entry."""
    name: str
    record_type: str  # A, AAAA, CNAME, MX, etc.
    value: str
    ttl: int = 300


@dataclass
class DNSQuery:
    """A DNS query simulation."""
    query_name: str
    query_type: str = "A"
    client_ip: str = "0.0.0.0"
    server_ip: str = "8.8.8.8"
    steps: list[dict] = field(default_factory=list)
    response: list[DNSEntry] = field(default_factory=list)

    def simulate_query(self, resolver: DNSResolver) -> dict[str, Any]:
        """Simulate DNS query process."""
        self.steps = []

        # Step 1: Query to resolver
        self.steps.append({
            "step": 1,
            "message": "DNS Query",
            "src": self.client_ip,
            "dst": self.server_ip,
            "details": f"Query: {self.query_name} ({self.query_type})"
        })

        # Step 2: Resolver lookup
        entries = resolver.resolve(self.query_name, self.query_type)

        if entries:
            self.response = entries
            self.steps.append({
                "step": 2,
                "message": "DNS Response",
                "src": self.server_ip,
                "dst": self.client_ip,
                "details": f"Found {len(entries)} record(s): "
                           f"{', '.join(e.value for e in entries)}"
            })
            return {
                "success": True,
                "answers": [{"name": e.name, "type": e.record_type, "value": e.value}
                           for e in entries],
                "steps": self.steps
            }
        else:
            self.steps.append({
                "step": 2,
                "message": "DNS Response (NXDOMAIN)",
                "src": self.server_ip,
                "dst": self.client_ip,
                "details": f"No records found for {self.query_name}"
            })
            return {
                "success": False,
                "error": "NXDOMAIN",
                "steps": self.steps
            }


class DNSResolver:
    """Simulated DNS resolver with local zone data."""

    def __init__(self) -> None:
        """Initialize resolver with default zones."""
        self.zones: dict[str, list[DNSEntry]] = {}
        self.cache: dict[tuple[str, str], DNSEntry] = {}

        # Add common public DNS entries
        self.add_record("google.com", "A", "142.250.80.46")
        self.add_record("cloudflare.com", "A", "104.16.132.229")
        self.add_record("github.com", "A", "140.82.121.4")
        self.add_record("example.com", "A", "93.184.216.34")

    def add_record(self, name: str, record_type: str, value: str, ttl: int = 300) -> None:
        """Add a DNS record to the zone."""
        key = name.lower()
        if key not in self.zones:
            self.zones[key] = []
        self.zones[key].append(DNSEntry(name, record_type, value, ttl))

    def resolve(self, name: str, record_type: str = "A") -> list[DNSEntry]:
        """Resolve a DNS query."""
        key = name.lower()
        if key in self.zones:
            return [e for e in self.zones[key] if e.record_type == record_type]
        return []

    def add_local_zone(self, domain: str, records: dict[str, str]) -> None:
        """Add a local zone with A records."""
        for hostname, ip in records.items():
            fqdn = f"{hostname}.{domain}" if hostname != "@" else domain
            self.add_record(fqdn, "A", ip)


@dataclass
class ICMPPing:
    """ICMP ping simulation."""

    source_ip: str
    dest_ip: str
    count: int = 4
    ttl: int = 64
    timeout: float = 2.0

    results: list[dict] = field(default_factory=list)
    packets_sent: int = 0
    packets_received: int = 0
    min_time: float = 0.0
    max_time: float = 0.0
    avg_time: float = 0.0

    def simulate(
        self,
        reachable: bool = True,
        latency_base: float = 1.0,
        packet_loss_rate: float = 0.0
    ) -> dict[str, Any]:
        """Simulate ping operation.

        Args:
            reachable: Whether destination is reachable
            latency_base: Base latency in ms
            packet_loss_rate: Probability of packet loss (0.0-1.0)

        Returns:
            Ping results dict
        """
        import random

        self.results = []
        self.packets_sent = self.count
        self.packets_received = 0

        times = []

        for seq in range(1, self.count + 1):
            # Simulate packet loss
            if random.random() < packet_loss_rate:
                self.results.append({
                    "seq": seq,
                    "status": "timeout",
                    "time_ms": None,
                    "ttl": None
                })
                continue

            if reachable:
                # Simulate latency with some variance
                latency = latency_base + random.uniform(-0.5, 0.5)
                latency = max(0.1, latency)  # Minimum 0.1ms
                times.append(latency)

                self.results.append({
                    "seq": seq,
                    "status": "reply",
                    "time_ms": round(latency, 2),
                    "ttl": max(1, self.ttl - seq)  # Decrement TTL
                })
                self.packets_received += 1
            else:
                self.results.append({
                    "seq": seq,
                    "status": "unreachable",
                    "time_ms": None,
                    "ttl": None
                })

        if times:
            self.min_time = min(times)
            self.max_time = max(times)
            self.avg_time = sum(times) / len(times)

        loss_percent = ((self.packets_sent - self.packets_received)
                       / self.packets_sent * 100)

        return {
            "success": self.packets_received > 0,
            "destination": self.dest_ip,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "packet_loss_percent": round(loss_percent, 1),
            "min_time_ms": round(self.min_time, 2) if times else None,
            "max_time_ms": round(self.max_time, 2) if times else None,
            "avg_time_ms": round(self.avg_time, 2) if times else None,
            "results": self.results
        }


@dataclass
class HTTPEndpoint:
    """HTTP endpoint definition."""
    path: str
    method: str = "GET"
    status_code: int = 200
    response_body: str = ""
    content_type: str = "text/html"


@dataclass
class HTTPServer:
    """Simulated HTTP server."""

    server_ip: str
    server_name: str = "nginx/1.18.0"
    port: int = 80

    endpoints: dict[tuple[str, str], HTTPEndpoint] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Add default endpoints."""
        self.add_endpoint(HTTPEndpoint("/", "GET", 200, "<h1>Welcome</h1>"))
        self.add_endpoint(HTTPEndpoint("/health", "GET", 200, '{"status": "ok"}',
                                      content_type="application/json"))

    def add_endpoint(self, endpoint: HTTPEndpoint) -> None:
        """Add an endpoint."""
        key = (endpoint.path, endpoint.method)
        self.endpoints[key] = endpoint

    def handle_request(self, path: str, method: str = "GET") -> dict[str, Any]:
        """Handle an HTTP request."""
        key = (path, method)

        if key in self.endpoints:
            endpoint = self.endpoints[key]
            return {
                "success": True,
                "status_code": endpoint.status_code,
                "headers": {
                    "Content-Type": endpoint.content_type,
                    "Server": self.server_name
                },
                "body": endpoint.response_body,
                "server_ip": self.server_ip
            }
        else:
            return {
                "success": False,
                "status_code": 404,
                "headers": {"Content-Type": "text/plain"},
                "body": "404 Not Found",
                "server_ip": self.server_ip
            }


class ProtocolSimulator:
    """High-level protocol simulator for network testing.

    Combines all protocol simulators for easy use in scenarios.

    Example:
        sim = ProtocolSimulator()

        # DHCP
        dhcp_result = sim.dhcp_request("aa:bb:cc:dd:ee:01", "192.168.1.0/24")

        # DNS
        dns_result = sim.dns_query("google.com")

        # Ping
        ping_result = sim.ping("192.168.1.1", "8.8.8.8")

        # HTTP
        http_result = sim.http_get("http://example.com/")
    """

    def __init__(self) -> None:
        """Initialize protocol simulator."""
        self.dns_resolver = DNSResolver()
        self.http_servers: dict[str, HTTPServer] = {}

        # Add default HTTP servers
        self.add_http_server("93.184.216.34", "example.com")
        self.add_http_server("142.250.80.46", "google.com")

    def add_http_server(self, ip: str, name: str = "") -> HTTPServer:
        """Add an HTTP server."""
        server = HTTPServer(server_ip=ip, server_name=name)
        self.http_servers[ip] = server
        return server

    def dhcp_request(
        self,
        client_mac: str,
        subnet: str,
        gateway: str = "",
        dns_servers: list[str] | None = None
    ) -> dict[str, Any]:
        """Simulate DHCP request.

        Args:
            client_mac: Client MAC address
            subnet: Subnet in CIDR notation
            gateway: Gateway IP (auto-detected if empty)
            dns_servers: DNS servers to provide

        Returns:
            DHCP result dict
        """
        import ipaddress

        network = ipaddress.ip_network(subnet)
        if not gateway:
            gateway = str(next(network.hosts()))

        dhcp = DHCPTransaction(client_mac=client_mac)
        return dhcp.simulate_dhcp(
            subnet=subnet,
            gateway=gateway,
            dns_servers=dns_servers or ["8.8.8.8"]
        )

    def dns_query(self, name: str, query_type: str = "A") -> dict[str, Any]:
        """Simulate DNS query."""
        query = DNSQuery(query_name=name, query_type=query_type)
        return query.simulate_query(self.dns_resolver)

    def ping(
        self,
        source_ip: str,
        dest_ip: str,
        count: int = 4,
        reachable: bool = True,
        latency_ms: float = 1.0
    ) -> dict[str, Any]:
        """Simulate ping."""
        ping_sim = ICMPPing(
            source_ip=source_ip,
            dest_ip=dest_ip,
            count=count
        )
        return ping_sim.simulate(reachable=reachable, latency_base=latency_ms)

    def http_get(self, url: str) -> dict[str, Any]:
        """Simulate HTTP GET request.

        Args:
            url: URL to request (e.g., "http://192.168.1.1/")

        Returns:
            HTTP response dict
        """
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or "/"

        # Resolve hostname if needed
        if host and not self._is_ip(host):
            dns_result = self.dns_query(host)
            if dns_result["success"] and dns_result["answers"]:
                host = dns_result["answers"][0]["value"]
            else:
                return {
                    "success": False,
                    "error": f"Could not resolve {host}",
                    "status_code": 0
                }

        if host in self.http_servers:
            server = self.http_servers[host]
            result = server.handle_request(path, "GET")
            result["dns_resolution"] = None if self._is_ip(parsed.hostname or "") else dns_result
            return result

        return {
            "success": False,
            "error": f"No server at {host}",
            "status_code": 0
        }

    def _is_ip(self, addr: str) -> bool:
        """Check if string is an IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(addr)
            return True
        except ValueError:
            return False
