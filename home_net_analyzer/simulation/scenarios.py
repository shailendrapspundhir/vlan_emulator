"""Pre-built traffic scenarios for common network activities.

These scenarios can be used with TrafficGenerator to produce realistic
synthetic traffic for testing, debugging, and simulation.
"""

from home_net_analyzer.simulation.traffic import TrafficFlow, TrafficScenario

# ---------------------------------------------------------------------------
# Individual flows (reusable building blocks)
# ---------------------------------------------------------------------------

DNS_QUERY = TrafficFlow(
    src="client",
    dst="dns-server",
    protocol="udp",
    src_port=54321,
    dst_port=53,
    count=1,
    app="DNS",
    length=64,
)

DNS_RESPONSE = TrafficFlow(
    src="dns-server",
    dst="client",
    protocol="udp",
    src_port=53,
    dst_port=54321,
    count=1,
    app="DNS",
    length=128,
)

HTTP_GET = TrafficFlow(
    src="client",
    dst="web-server",
    protocol="tcp",
    dst_port=80,
    count=5,
    app="HTTP",
    length=512,
)

HTTPS_TLS = TrafficFlow(
    src="client",
    dst="secure-server",
    protocol="tcp",
    dst_port=443,
    count=10,
    app="HTTPS",
    length=800,
)

ICMP_PING = TrafficFlow(
    src="client",
    dst="server",
    protocol="icmp",
    count=4,
    length=84,
)

SSH_SESSION = TrafficFlow(
    src="admin-pc",
    dst="mgmt-server",
    protocol="tcp",
    dst_port=22,
    count=20,
    app="SSH",
    length=256,
)

# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

SCENARIOS: dict[str, TrafficScenario] = {
    "web_browsing": TrafficScenario(
        name="web_browsing",
        description="Typical web browsing: DNS lookup + HTTP requests",
        flows=[
            TrafficFlow(src="client", dst="dns-server", protocol="udp", dst_port=53, count=2, app="DNS"),
            TrafficFlow(src="client", dst="web-server", protocol="tcp", dst_port=80, count=8, app="HTTP"),
        ],
    ),
    "dns_resolution": TrafficScenario(
        name="dns_resolution",
        description="DNS query and response exchange",
        flows=[
            DNS_QUERY,
            DNS_RESPONSE,
        ],
    ),
    "inter_vlan_ping": TrafficScenario(
        name="inter_vlan_ping",
        description="ICMP echo across VLANs (4 pings)",
        flows=[
            TrafficFlow(src="vlan10-host", dst="vlan20-host", protocol="icmp", count=4, vlan_id=10, length=84),
            TrafficFlow(src="vlan20-host", dst="vlan10-host", protocol="icmp", count=4, vlan_id=20, length=84),
        ],
    ),
    "port_scan": TrafficScenario(
        name="port_scan",
        description="TCP SYN port scan (common ports)",
        flows=[
            TrafficFlow(src="attacker", dst="target", protocol="tcp", dst_port=22, count=1),
            TrafficFlow(src="attacker", dst="target", protocol="tcp", dst_port=80, count=1),
            TrafficFlow(src="attacker", dst="target", protocol="tcp", dst_port=443, count=1),
            TrafficFlow(src="attacker", dst="target", protocol="tcp", dst_port=3389, count=1),
            TrafficFlow(src="attacker", dst="target", protocol="tcp", dst_port=21, count=1),
            TrafficFlow(src="attacker", dst="target", protocol="tcp", dst_port=25, count=1),
        ],
    ),
    "file_transfer": TrafficScenario(
        name="file_transfer",
        description="Large TCP file transfer simulation",
        flows=[
            TrafficFlow(src="client", dst="file-server", protocol="tcp", dst_port=21, count=50, app="FTP", length=1400),
        ],
    ),
    "ssh_admin": TrafficScenario(
        name="ssh_admin",
        description="SSH session to management server",
        flows=[
            SSH_SESSION,
        ],
    ),
    "https_browsing": TrafficScenario(
        name="https_browsing",
        description="Secure HTTPS browsing",
        flows=[
            TrafficFlow(src="client", dst="dns-server", protocol="udp", dst_port=53, count=1, app="DNS"),
            HTTPS_TLS,
        ],
    ),
    "full_corporate": TrafficScenario(
        name="full_corporate",
        description="Mixed corporate traffic: DNS, HTTP, HTTPS, ICMP, SSH",
        flows=[
            TrafficFlow(src="pc-01", dst="dns-server", protocol="udp", dst_port=53, count=3, app="DNS"),
            TrafficFlow(src="pc-01", dst="web-server", protocol="tcp", dst_port=80, count=10, app="HTTP"),
            TrafficFlow(src="pc-01", dst="secure-server", protocol="tcp", dst_port=443, count=8, app="HTTPS"),
            TrafficFlow(src="admin-pc", dst="mgmt-server", protocol="tcp", dst_port=22, count=15, app="SSH"),
            TrafficFlow(src="pc-02", dst="server", protocol="icmp", count=2),
        ],
    ),
}


def get_scenario(name: str) -> TrafficScenario:
    """Get a scenario by name. Raises KeyError if not found."""
    if name not in SCENARIOS:
        raise KeyError(f"Unknown scenario: {name}. Available: {list(SCENARIOS.keys())}")
    return SCENARIOS[name]


def list_scenarios() -> list[str]:
    """List all available scenario names."""
    return list(SCENARIOS.keys())
