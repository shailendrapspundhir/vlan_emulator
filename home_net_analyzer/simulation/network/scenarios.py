"""Pre-built network scenarios for simulation."""

from home_net_analyzer.simulation.network.engine import NetworkSimulationEngine
from home_net_analyzer.simulation.router.engine import RouterEngine
from home_net_analyzer.simulation.router.models import RouteEntry, RouterInterface, SVI
from home_net_analyzer.simulation.switch.engine import SwitchEngine
from home_net_analyzer.topology.models import SwitchPort


class ScenarioBuilder:
    """Builder for creating complex network scenarios.

    Provides pre-built scenarios for common network topologies.
    """

    @staticmethod
    def create_single_switch_vlan(
        sim: NetworkSimulationEngine,
        name: str = "single-switch-vlan"
    ) -> NetworkSimulationEngine:
        """Create a simple single switch with VLANs scenario.

        Topology:
            [PC1 VLAN10]--[SW1]--[PC2 VLAN20]
        """
        sim.create_topology(name)

        # Create switch
        switch = SwitchEngine(
            switch=type('obj', (object,), {
                'name': 'sw1',
                'ports': [
                    SwitchPort(id=1, name="Gi1/0/1", mode="access", access_vlan=10),
                    SwitchPort(id=2, name="Gi1/0/2", mode="access", access_vlan=20),
                    SwitchPort(id=3, name="Gi1/0/3", mode="access", access_vlan=10),
                    SwitchPort(id=4, name="Gi1/0/4", mode="access", access_vlan=20),
                ],
                'vlans': [10, 20],
                'get_port': lambda self, pid: next((p for p in self.ports if p.id == pid), None)
            })()
        )

        sim.add_switch("sw1", "Access Switch", switch)

        # Add hosts
        sim.add_host(
            host_id="pc1",
            name="Alice PC",
            mac="aa:bb:cc:10:00:01",
            ip="192.168.10.10",
            connected_switch="sw1",
            connected_port=1,
            vlan_id=10
        )

        sim.add_host(
            host_id="pc2",
            name="Bob PC",
            mac="aa:bb:cc:20:00:01",
            ip="192.168.20.10",
            connected_switch="sw1",
            connected_port=2,
            vlan_id=20
        )

        sim.add_host(
            host_id="pc3",
            name="Charlie PC",
            mac="aa:bb:cc:10:00:02",
            ip="192.168.10.20",
            connected_switch="sw1",
            connected_port=3,
            vlan_id=10
        )

        return sim

    @staticmethod
    def create_multi_switch_trunk(
        sim: NetworkSimulationEngine,
        name: str = "multi-switch-trunk"
    ) -> NetworkSimulationEngine:
        """Create multi-switch scenario with trunk links.

        Topology:
            [PC1]--[SW1]====[SW2]--[PC2]
                      trunk
        """
        sim.create_topology(name)

        # Create switches
        sw1 = SwitchEngine(
            switch=type('obj', (object,), {
                'name': 'sw1',
                'ports': [
                    SwitchPort(id=1, name="Gi1/0/1", mode="access", access_vlan=10),
                    SwitchPort(id=2, name="Gi1/0/2", mode="access", access_vlan=20),
                    SwitchPort(id=24, name="Gi1/0/24", mode="trunk", allowed_vlans=[10, 20]),
                ],
                'vlans': [10, 20],
                'get_port': lambda self, pid: next((p for p in self.ports if p.id == pid), None)
            })()
        )

        sw2 = SwitchEngine(
            switch=type('obj', (object,), {
                'name': 'sw2',
                'ports': [
                    SwitchPort(id=1, name="Gi1/0/1", mode="access", access_vlan=10),
                    SwitchPort(id=2, name="Gi1/0/2", mode="access", access_vlan=20),
                    SwitchPort(id=24, name="Gi1/0/24", mode="trunk", allowed_vlans=[10, 20]),
                ],
                'vlans': [10, 20],
                'get_port': lambda self, pid: next((p for p in self.ports if p.id == pid), None)
            })()
        )

        sim.add_switch("sw1", "Building A Switch", sw1)
        sim.add_switch("sw2", "Building B Switch", sw2)

        # Connect switches with trunk
        sim.connect_devices("sw1", "sw2", 24, 24, link_type="trunk", vlans=[10, 20])

        # Add hosts
        sim.add_host(
            host_id="pc1",
            name="Alice PC",
            mac="aa:bb:cc:10:00:01",
            ip="192.168.10.10",
            connected_switch="sw1",
            connected_port=1,
            vlan_id=10
        )

        sim.add_host(
            host_id="pc2",
            name="Bob PC",
            mac="aa:bb:cc:20:00:01",
            ip="192.168.20.10",
            connected_switch="sw1",
            connected_port=2,
            vlan_id=20
        )

        sim.add_host(
            host_id="pc3",
            name="Charlie PC",
            mac="aa:bb:cc:10:00:02",
            ip="192.168.10.20",
            connected_switch="sw2",
            connected_port=1,
            vlan_id=10
        )

        sim.add_host(
            host_id="pc4",
            name="Diana PC",
            mac="aa:bb:cc:20:00:02",
            ip="192.168.20.20",
            connected_switch="sw2",
            connected_port=2,
            vlan_id=20
        )

        return sim

    @staticmethod
    def create_router_on_stick(
        sim: NetworkSimulationEngine,
        name: str = "router-on-stick"
    ) -> NetworkSimulationEngine:
        """Create router-on-a-stick scenario for inter-VLAN routing.

        Topology:
            [PC1 VLAN10]--[SW1]--[Router]
            [PC2 VLAN20]--/      (trunk)
        """
        sim.create_topology(name)

        # Create switch
        sw1 = SwitchEngine(
            switch=type('obj', (object,), {
                'name': 'sw1',
                'ports': [
                    SwitchPort(id=1, name="Gi1/0/1", mode="access", access_vlan=10),
                    SwitchPort(id=2, name="Gi1/0/2", mode="access", access_vlan=20),
                    SwitchPort(id=3, name="Gi1/0/3", mode="access", access_vlan=10),
                    SwitchPort(id=24, name="Gi1/0/24", mode="trunk", allowed_vlans=[10, 20]),
                ],
                'vlans': [10, 20],
                'get_port': lambda self, pid: next((p for p in self.ports if p.id == pid), None)
            })()
        )

        sim.add_switch("sw1", "Access Switch", sw1)

        # Create router with SVIs
        router = RouterEngine(name="r1")
        router.add_svi(SVI(
            vlan_id=10,
            ip_address="192.168.10.1",
            subnet_mask="255.255.255.0",
            mac_address="aa:bb:cc:00:10:01"
        ))
        router.add_svi(SVI(
            vlan_id=20,
            ip_address="192.168.20.1",
            subnet_mask="255.255.255.0",
            mac_address="aa:bb:cc:00:20:01"
        ))

        sim.add_router("r1", "Core Router", router)

        # Connect switch to router (trunk)
        sim.connect_devices("sw1", "r1", 24, "eth0", link_type="trunk", vlans=[10, 20])

        # Add hosts
        sim.add_host(
            host_id="pc1",
            name="Alice PC",
            mac="aa:bb:cc:10:00:01",
            ip="192.168.10.10",
            connected_switch="sw1",
            connected_port=1,
            vlan_id=10,
            gateway="192.168.10.1"
        )

        sim.add_host(
            host_id="pc2",
            name="Bob PC",
            mac="aa:bb:cc:20:00:01",
            ip="192.168.20.10",
            connected_switch="sw1",
            connected_port=2,
            vlan_id=20,
            gateway="192.168.20.1"
        )

        sim.add_host(
            host_id="pc3",
            name="Charlie PC",
            mac="aa:bb:cc:10:00:02",
            ip="192.168.10.20",
            connected_switch="sw1",
            connected_port=3,
            vlan_id=10,
            gateway="192.168.10.1"
        )

        return sim

    @staticmethod
    def create_multi_site_network(
        sim: NetworkSimulationEngine,
        name: str = "multi-site"
    ) -> NetworkSimulationEngine:
        """Create complex multi-site network with multiple routers.

        Topology:
            Site A: [PCs]--[SW1]--[R1]--[WAN]--[R2]--[SW2]--[PCs] :Site B
        """
        sim.create_topology(name)

        # Site A Switch
        sw1 = SwitchEngine(
            switch=type('obj', (object,), {
                'name': 'sw1',
                'ports': [
                    SwitchPort(id=1, name="Gi1/0/1", mode="access", access_vlan=10),
                    SwitchPort(id=2, name="Gi1/0/2", mode="access", access_vlan=20),
                    SwitchPort(id=24, name="Gi1/0/24", mode="trunk", allowed_vlans=[10, 20]),
                ],
                'vlans': [10, 20],
                'get_port': lambda self, pid: next((p for p in self.ports if p.id == pid), None)
            })()
        )

        # Site B Switch
        sw2 = SwitchEngine(
            switch=type('obj', (object,), {
                'name': 'sw2',
                'ports': [
                    SwitchPort(id=1, name="Gi1/0/1", mode="access", access_vlan=10),
                    SwitchPort(id=2, name="Gi1/0/2", mode="access", access_vlan=20),
                    SwitchPort(id=24, name="Gi1/0/24", mode="trunk", allowed_vlans=[10, 20]),
                ],
                'vlans': [10, 20],
                'get_port': lambda self, pid: next((p for p in self.ports if p.id == pid), None)
            })()
        )

        sim.add_switch("sw1", "Site A Switch", sw1)
        sim.add_switch("sw2", "Site B Switch", sw2)

        # Site A Router
        r1 = RouterEngine(name="r1")
        r1.add_svi(SVI(vlan_id=10, ip_address="10.1.10.1", subnet_mask="255.255.255.0", mac_address="aa:bb:cc:01:10:01"))
        r1.add_svi(SVI(vlan_id=20, ip_address="10.1.20.1", subnet_mask="255.255.255.0", mac_address="aa:bb:cc:01:20:01"))
        r1.add_physical_interface(RouterInterface(
            name="eth1", ip_address="10.255.1.1", subnet_mask="255.255.255.252", mac_address="aa:bb:cc:01:00:01"
        ))
        r1.add_route(RouteEntry(
            destination="10.2.0.0/16", next_hop="10.255.1.2", interface="eth1", metric=10
        ))

        # Site B Router
        r2 = RouterEngine(name="r2")
        r2.add_svi(SVI(vlan_id=10, ip_address="10.2.10.1", subnet_mask="255.255.255.0", mac_address="aa:bb:cc:02:10:01"))
        r2.add_svi(SVI(vlan_id=20, ip_address="10.2.20.1", subnet_mask="255.255.255.0", mac_address="aa:bb:cc:02:20:01"))
        r2.add_physical_interface(RouterInterface(
            name="eth1", ip_address="10.255.1.2", subnet_mask="255.255.255.252", mac_address="aa:bb:cc:02:00:01"
        ))
        r2.add_route(RouteEntry(
            destination="10.1.0.0/16", next_hop="10.255.1.1", interface="eth1", metric=10
        ))

        sim.add_router("r1", "Site A Router", r1)
        sim.add_router("r2", "Site B Router", r2)

        # Connect devices
        sim.connect_devices("sw1", "r1", 24, "eth0", link_type="trunk", vlans=[10, 20])
        sim.connect_devices("sw2", "r2", 24, "eth0", link_type="trunk", vlans=[10, 20])
        sim.connect_devices("r1", "r2", "eth1", "eth1")

        # Site A Hosts
        sim.add_host("pc1", "Alice (Site A)", "aa:bb:cc:11:00:01", "10.1.10.10", "sw1", 1, "10.1.10.1", 10)
        sim.add_host("pc2", "Bob (Site A)", "aa:bb:cc:12:00:01", "10.1.20.10", "sw1", 2, "10.1.20.1", 20)

        # Site B Hosts
        sim.add_host("pc3", "Charlie (Site B)", "aa:bb:cc:21:00:01", "10.2.10.10", "sw2", 1, "10.2.10.1", 10)
        sim.add_host("pc4", "Diana (Site B)", "aa:bb:cc:22:00:01", "10.2.20.10", "sw2", 2, "10.2.20.1", 20)

        return sim

    @staticmethod
    def create_campus_network(
        sim: NetworkSimulationEngine,
        name: str = "campus"
    ) -> NetworkSimulationEngine:
        """Create a campus network with core, distribution, and access layers.

        Topology:
                               [Core Router]
                              /           \\
                    [Dist SW1]             [Dist SW2]
                    /        \\             /        \\
              [Acc SW1]  [Acc SW2]  [Acc SW3]  [Acc SW4]
        """
        sim.create_topology(name)

        # Core router
        core = RouterEngine(name="core")
        core.add_physical_interface(RouterInterface(
            name="eth0", ip_address="10.0.1.1", subnet_mask="255.255.255.0", mac_address="aa:bb:cc:00:01:01"
        ))
        core.add_physical_interface(RouterInterface(
            name="eth1", ip_address="10.0.2.1", subnet_mask="255.255.255.0", mac_address="aa:bb:cc:00:02:01"
        ))
        sim.add_router("core", "Core Router", core)

        # Distribution switches
        for i, dist_id in enumerate(["dist1", "dist2"], 1):
            dist = SwitchEngine(
                switch=type('obj', (object,), {
                    'name': dist_id,
                    'ports': [
                        SwitchPort(id=1, name="Gi1/0/1", mode="access", access_vlan=10),
                        SwitchPort(id=2, name="Gi1/0/2", mode="access", access_vlan=20),
                        SwitchPort(id=3, name="Gi1/0/3", mode="access", access_vlan=30),
                        SwitchPort(id=24, name="Gi1/0/24", mode="trunk", allowed_vlans=[10, 20, 30]),
                        SwitchPort(id=25, name="Gi1/0/25", mode="trunk", allowed_vlans=[10, 20, 30]),
                    ],
                    'vlans': [10, 20, 30],
                    'get_port': lambda self, pid: next((p for p in self.ports if p.id == pid), None)
                })()
            )
            sim.add_switch(dist_id, f"Distribution Switch {i}", dist)

            # Connect to core
            sim.connect_devices(dist_id, "core", 24, f"eth{i-1}", link_type="trunk", vlans=[10, 20, 30])

        # Access switches
        access_configs = [
            ("access1", "dist1", 25, "Building A"),
            ("access2", "dist1", 25, "Building B"),
            ("access3", "dist2", 25, "Building C"),
            ("access4", "dist2", 25, "Building D"),
        ]

        host_counter = 1
        for access_id, dist_id, dist_port, building in access_configs:
            access = SwitchEngine(
                switch=type('obj', (object,), {
                    'name': access_id,
                    'ports': [
                        SwitchPort(id=1, name="Gi1/0/1", mode="access", access_vlan=10),
                        SwitchPort(id=2, name="Gi1/0/2", mode="access", access_vlan=20),
                        SwitchPort(id=3, name="Gi1/0/3", mode="access", access_vlan=10),
                        SwitchPort(id=4, name="Gi1/0/4", mode="access", access_vlan=20),
                        SwitchPort(id=24, name="Gi1/0/24", mode="trunk", allowed_vlans=[10, 20]),
                    ],
                    'vlans': [10, 20],
                    'get_port': lambda self, pid: next((p for p in self.ports if p.id == pid), None)
                })()
            )
            sim.add_switch(access_id, f"{building} Access Switch", access)

            # Connect to distribution
            sim.connect_devices(access_id, dist_id, 24, dist_port, link_type="trunk", vlans=[10, 20])

            # Add hosts
            for port, vlan in [(1, 10), (2, 20), (3, 10), (4, 20)]:
                sim.add_host(
                    host_id=f"pc{host_counter}",
                    name=f"Host {host_counter} ({building})",
                    mac=f"aa:bb:cc:{host_counter:02x}:00:01",
                    ip=f"10.{i}.{vlan}.{10 + port}",
                    connected_switch=access_id,
                    connected_port=port,
                    vlan_id=vlan
                )
                host_counter += 1

        return sim
