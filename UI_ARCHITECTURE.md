# Desktop UI Architecture for VLAN Emulator
## Flet-Based User-Friendly Interface for Network Simulation

---

## Executive Summary

This document outlines the architecture for extending the VLAN Emulator project with a **desktop GUI** using Python's **Flet** package. The goal is to provide a user-friendly, visual interface for creating, configuring, running, and debugging network simulations (switches, routers, networks, firewalls) — replacing or complementing the current terminal-based CLI and web dashboard.

**Target Users:** Network engineers, students, educators, and anyone learning or testing network concepts without needing deep CLI knowledge.

---

## 1. Current Project State Analysis

### 1.1 Existing Architecture Overview

```
home_net_analyzer/
├── capture/          # Packet sniffing & parsing (CapturedPacket model)
├── storage/          # SQLite/DuckDB storage (PacketStore, Database)
├── rules/            # Firewall rules engine (RulesEngine, Rule models)
│   └── backends/     # iptables, nftables, noop
├── topology/         # Network topology models (VLAN, VirtualHost, VirtualSwitch, Router)
├── simulation/       # Simulation engines
│   ├── switch/       # VLAN-aware L2 switching (MAC learning, forwarding)
│   ├── router/       # L3 routing (ARP, ACLs, SVIs, static routes)
│   ├── network/      # Multi-device orchestration, hop-by-hop tracing
│   ├── scenarios.py  # Predefined scenarios
│   └── traffic.py    # Traffic generation
├── web/              # FastAPI web dashboard (HTML + JS)
├── cli.py            # Typer CLI with interactive menus
└── config.py         # Pydantic settings
```

### 1.2 Existing Operations (CLI + Web API)

| Category | Operations | Current Interface |
|----------|------------|-------------------|
| **Packets** | Count, recent, query, store | CLI + Web API |
| **Rules** | List, add, remove, enable, disable | CLI + Web API + Interactive |
| **Switches** | Create, list, status, MAC table, simulate, stats, delete | CLI + Interactive |
| **Routers** | Create, list, status, routes, ARP, simulate, stats, delete | CLI + Interactive |
| **Networks** | Run predefined scenarios, simulate flows, hop-by-hop trace | CLI + Interactive |
| **Dashboard** | Web UI for packets/rules | FastAPI + Jinja2 templates |

### 1.3 Key Existing Models

- **VLAN**: id, name, subnet, gateway
- **VirtualHost**: name, mac, ip, vlan_id, role
- **SwitchPort**: id, name, mode (access/trunk), access_vlan, allowed_vlans, connected_to
- **VirtualSwitch**: name, ports, vlans
- **RouterInterface / SVI**: name, ip, subnet, mac, enabled
- **RouteEntry**: destination, next_hop, interface, metric
- **CapturedPacket**: Full L2/L3/L4 representation
- **SwitchEngine / RouterEngine / NetworkSimulationEngine**: Core simulation logic

### 1.4 Identified Strengths

1. **Rich Simulation Logic**: Switch forwarding, router routing, ARP, ACLs, multi-device tracing — all implemented.
2. **Predefined Scenarios**: Single-switch, multi-switch, router-on-stick, campus, multi-site.
3. **Modular Engines**: SwitchEngine, RouterEngine, NetworkSimulationEngine are well-isolated.
4. **Data Persistence**: JSON-based switch/router configs; SQLite/DuckDB for packets.
5. **Existing Web API**: RESTful API for packets and rules — can be extended.

---

## 2. Identified Gaps for Desktop UI

### 2.1 Missing UI Infrastructure

| Gap | Impact | Priority |
|-----|--------|----------|
| No Flet integration | Must add new dependency and structure | P0 |
| No visual topology builder | Users must use CLI/JSON to define topologies | P0 |
| No live network diagram | Hard to visualize device connections | P0 |
| No real-time simulation progress | Users can't see step-by-step flow | P1 |
| No unified state management | UI and simulation engines not synchronized | P0 |
| No drag-and-drop device placement | Poor UX for topology creation | P1 |
| Limited error visualization | Errors shown as text, not highlighted in diagram | P2 |

### 2.2 Missing UI Features vs. CLI

| Feature | CLI Has It? | UI Needs |
|---------|-------------|----------|
| Create switch with ports | ✅ | Need visual form + diagram update |
| View MAC table | ✅ (table) | Need searchable table + live updates |
| Simulate frame through switch | ✅ (prompts) | Need form + animated trace |
| Create router with SVIs | ✅ | Need visual form |
| View ARP table | ✅ | Need table view |
| Simulate packet routing | ✅ | Need form + animated path |
| Run network scenario | ✅ | Need scenario picker + visual topology |
| Trace packet flow | ✅ (hop table) | Need animated hop-by-hop + timeline |
| Manage firewall rules | ✅ | Need CRUD forms + toggle switches |
| View stored packets | ✅ | Need filterable table |

### 2.3 Architectural Gaps

1. **No Separation of UI Logic from Simulation Logic**
   - CLI mixes prompts with engine calls.
   - UI needs a clean service/API layer to call engines.

2. **No Reactive State for Simulation**
   - Engines return results synchronously; no live updates.
   - UI needs event hooks or polling for progress.

3. **No Topology Serialization for UI**
   - Topologies are built programmatically or via ScenarioBuilder.
   - UI needs to save/load topologies (JSON) and render them.

4. **No Multi-Tab / Multi-View Concept**
   - CLI is linear; UI needs tabs: Topology, Switches, Routers, Simulations, Packets, Rules.

5. **No Undo / History**
   - CLI has no undo; UI should support undo for config changes.

---

## 3. Proposed Desktop UI Architecture (Flet-Based)

### 3.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Flet Desktop Application                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │   Sidebar    │  │   Main View  │  │   Inspector  │  │   Log Panel  │   │
│  │  Navigation  │  │  (Dynamic)   │  │  (Context)   │  │  (Events)    │   │
│  ├──────────────┤  ├──────────────┤  ├──────────────┤  ├──────────────┤   │
│  │ • Dashboard  │  │              │  │              │  │              │   │
│  │ • Topology   │  │  Content     │  │  Properties  │  │  Simulation  │   │
│  │ • Switches   │  │  changes     │  │  of selected │  │  logs,       │   │
│  │ • Routers    │  │  per view    │  │  device or   │  │  errors,     │   │
│  │ • Hosts      │  │              │  │  flow        │  │  traces      │   │
│  │ • Simulations│  │              │  │              │  │              │   │
│  │ • Packets    │  │              │  │              │  │              │   │
│  │ • Firewall   │  │              │  │              │  │              │   │
│  │ • Settings   │  │              │  │              │  │              │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           UI State Manager (Flet State / Provider)          │
│  • Current topology                                                         │
│  • Selected device                                                          │
│  • Active simulation                                                        │
│  • Recent logs                                                              │
│  • UI preferences                                                           │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Service Layer (Bridge to Engines)                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │
│  │ SwitchService   │  │ RouterService   │  │ NetworkService  │              │
│  │ • create()      │  │ • create()      │  │ • load_scenario │              │
│  │ • simulate()    │  │ • simulate()    │  │ • simulate_flow │              │
│  │ • get_mac_table │  │ • get_arp_table │  │ • get_trace     │              │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │
│  │ PacketService   │  │ RulesService    │  │ StorageService  │              │
│  │ • query()       │  │ • list/add/...  │  │ • save/load     │              │
│  │ • recent()      │  │ • enable/disable│  │ • export        │              │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘              │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Existing Simulation Engines (Unchanged)                  │
│  • SwitchEngine, RouterEngine, NetworkSimulationEngine                      │
│  • RulesEngine, PacketStore, Topology models                                │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Directory Structure (New UI Module)

```
home_net_analyzer/
├── ui/                          # NEW: Flet desktop application
│   ├── __init__.py
│   ├── app.py                   # Main Flet app entry point
│   ├── main.py                  # CLI command: hna gui  (launches Flet)
│   │
│   ├── state/                   # UI state management
│   │   ├── __init__.py
│   │   ├── app_state.py         # Global AppState dataclass / provider
│   │   ├── topology_state.py    # Current topology being edited
│   │   └── simulation_state.py  # Active simulation + trace
│   │
│   ├── views/                   # UI pages / tabs
│   │   ├── __init__.py
│   │   ├── dashboard_view.py    # Overview: stats, quick actions
│   │   ├── topology_view.py     # Visual network diagram (nodes + edges)
│   │   ├── switch_view.py       # Switch list, create, configure, simulate
│   │   ├── router_view.py       # Router list, create, configure, simulate
│   │   ├── host_view.py         # Host/endpoint management
│   │   ├── simulation_view.py   # Run scenarios, custom flows, traces
│   │   ├── packet_view.py       # Stored packets: table, filters, export
│   │   ├── firewall_view.py     # Rules CRUD, enable/disable
│   │   └── settings_view.py     # App settings, DB path, backend
│   │
│   ├── components/              # Reusable UI widgets
│   │   ├── __init__.py
│   │   ├── device_card.py       # Card showing a device (switch/router/host)
│   │   ├── port_editor.py       # Form to edit switch ports
│   │   ├── svi_editor.py        # Form to edit router SVIs
│   │   ├── route_editor.py      # Form to edit static routes
│   │   ├── trace_viewer.py      # Hop-by-hop trace display (table + animation)
│   │   ├── topology_canvas.py   # Visual diagram (using Flet Canvas or graph lib)
│   │   ├── log_panel.py         # Scrollable log output
│   │   ├── table_view.py        # Generic sortable/filterable table
│   │   └── dialogs/             # Modal dialogs
│   │       ├── __init__.py
│   │       ├── create_switch_dialog.py
│   │       ├── create_router_dialog.py
│   │       ├── simulate_flow_dialog.py
│   │       └── confirm_dialog.py
│   │
│   ├── services/                # Service layer bridging UI ↔ engines
│   │   ├── __init__.py
│   │   ├── switch_service.py
│   │   ├── router_service.py
│   │   ├── network_service.py
│   │   ├── packet_service.py
│   │   ├── rules_service.py
│   │   └── storage_service.py
│   │
│   └── assets/                  # Icons, images (if any)
│       └── icons/
│
├── cli.py                       # EXISTING: Add "gui" command
└── ... (existing modules unchanged)
```

### 3.3 Technology Stack

| Component | Technology | Rationale |
|-----------|------------|-----------|
| UI Framework | **Flet** (Python) | Cross-platform desktop (Windows/macOS/Linux), Flutter-based, Python-native, no web server needed |
| State Management | Flet `Ref`, custom `AppState` class, or simple pub/sub | Lightweight; no heavy framework needed |
| Diagrams | Flet `Canvas` + custom drawing, or integrate `networkx` + matplotlib for graph | Flet Canvas supports lines, shapes, text |
| Tables | Flet `DataTable` | Built-in, sortable |
| Forms | Flet `TextField`, `Dropdown`, `Checkbox`, `Button` | Standard widgets |
| Dialogs | Flet `AlertDialog`, `BottomSheet` | Built-in |
| Logging | Flet `Text` in scrollable container | Real-time append |
| Persistence | Reuse existing JSON + SQLite | No new DB needed |

### 3.4 Dependency Additions (pyproject.toml)

```toml
dependencies = [
    # ... existing ...
    "flet>=0.21.0",   # Desktop UI framework
]
```

---

## 4. Detailed UI Views & Operations

### 4.1 Dashboard View

**Purpose:** Landing page with overview and quick actions.

**Contents:**
- Stats cards: Packet count, Rule count, Active switches, Active routers, Last simulation
- Quick actions buttons:
  - "Create New Switch"
  - "Create New Router"
  - "Run Scenario"
  - "Open Packet Viewer"
  - "Manage Firewall Rules"
- Recent activity log (last 10 events)

**Interactions:**
- Clicking a stat card navigates to the respective view.
- Quick action buttons open dialogs or navigate.

---

### 4.2 Topology View

**Purpose:** Visual network diagram editor.

**Contents:**
- Canvas area showing devices as nodes (switch=🔲, router=⬡, host=💻)
- Edges representing links (solid for access, dashed for trunk/WAN)
- Toolbar: Add Device, Add Link, Delete, Zoom, Auto-layout
- Sidebar: Device list (click to select/highlight on canvas)

**Operations:**
| Action | UI Control | Backend Call |
|--------|------------|--------------|
| Add switch | Toolbar → Add → Switch | `SwitchService.create()` |
| Add router | Toolbar → Add → Router | `RouterService.create()` |
| Add host | Toolbar → Add → Host | `NetworkService.add_host()` |
| Connect devices | Drag from port to port | `NetworkService.connect()` |
| Move device | Drag node | UI-only (update positions) |
| Delete device | Select + Delete key | `SwitchService.delete()` / `RouterService.delete()` |
| Edit device | Double-click node | Open editor dialog |
| Save topology | File → Save | Serialize to JSON file |
| Load topology | File → Open | Deserialize from JSON |

**Gaps to Fill:**
- **Topology serialization format** — define JSON schema for saving/loading full topologies (devices, links, positions).
- **Auto-layout algorithm** — simple force-directed or hierarchical layout for initial placement.
- **Link validation** — prevent invalid connections (e.g., two access ports on different VLANs).

---

### 4.3 Switch View

**Purpose:** Manage virtual switches.

**Contents:**
- Table of switches: Name, #Ports, VLANs, MAC Table Size, Status
- Toolbar: Create, Delete, Refresh
- When a switch is selected:
  - Port configuration table (ID, Name, Mode, VLAN/Allowed, Connected To)
  - Buttons: Edit Port, Add Port
  - MAC Table: searchable table (MAC, VLAN, Port, Age)
  - Stats panel: frames received/forwarded/dropped
  - Simulate button → opens Simulate Frame dialog

**Simulate Frame Dialog:**
- Inputs: Source MAC, Dest MAC, Ingress Port, VLAN (optional)
- Button: Run Simulation
- Output: Forwarding decisions list + updated MAC table

**Interactions:**
- Create switch → `SwitchService.create(name, ports, vlans)`
- Edit port → `SwitchService.update_port(switch, port_id, new_config)`
- Simulate → `SwitchService.simulate_frame(switch, frame)` → returns decisions

---

### 4.4 Router View

**Purpose:** Manage virtual routers.

**Contents:**
- Table of routers: Name, #SVIs, #Interfaces, #Routes, ARP Entries
- Toolbar: Create, Delete, Refresh
- When a router is selected:
  - SVI table (VLAN, IP, Subnet, MAC, Enabled)
  - Physical Interfaces table (Name, IP, Subnet, MAC, Enabled)
  - Routing Table: searchable (Destination, Next Hop, Interface, Type, Metric)
  - ARP Table: searchable (IP, MAC, Interface, Age)
  - Stats panel
  - Simulate button → opens Simulate Packet dialog

**Simulate Packet Dialog:**
- Inputs: Source IP, Dest IP, Ingress Interface
- Button: Run Simulation
- Output: Routing decision (forward/deliver/drop) + next-hop info + updated ARP

**Interactions:**
- Create router → `RouterService.create(name, svis, interfaces, routes)`
- Add SVI → `RouterService.add_svi(router, svi)`
- Simulate → `RouterService.simulate_packet(router, packet, ingress)`

---

### 4.5 Simulation View (Network Flows)

**Purpose:** Run multi-device simulations and view traces.

**Contents:**
- Scenario picker: Dropdown of predefined scenarios (single-switch, router-on-stick, campus, etc.)
- "Load Scenario" button → populates topology view + runs sample flows
- Custom Flow panel:
  - Source Host dropdown
  - Dest Host dropdown
  - Protocol dropdown (ICMP, TCP, UDP)
  - Count
  - "Simulate Flow" button
- Trace viewer (when a flow completes):
  - Hop-by-hop table: Hop #, Device, Type, Action, Ingress, Egress, Details
  - Timeline visualization (horizontal bars per hop)
  - Success/Failure badge
- Logs panel: Real-time simulation events

**Interactions:**
- Load scenario → `NetworkService.load_scenario(name)` → updates topology state
- Simulate flow → `NetworkService.simulate_flow(src, dst, proto)` → returns `PacketFlow` with hops
- Display trace → populate `TraceViewer` component

**Gaps to Fill:**
- **Flow animation**: Step through hops with delays (UI can animate table row highlights).
- **Pause/Resume**: For long simulations.
- **Export trace**: Save hop log to CSV/JSON.

---

### 4.6 Packet View

**Purpose:** Browse and query stored packets.

**Contents:**
- Stats: Total packets, by protocol breakdown
- Filter bar: Source IP, Dest IP, Protocol, App Protocol, Date range
- Packet table: ID, Timestamp, Src, Dst, Proto, App, Length, VLAN
- Pagination or infinite scroll
- Export button: CSV / JSON

**Interactions:**
- Query → `PacketService.query(filters)` → returns list
- Export → `PacketService.export(format)` → file save dialog

---

### 4.7 Firewall View

**Purpose:** Manage firewall rules.

**Contents:**
- Rules table: ID, Action (block/allow/reject), Target, Value, Proto, Direction, Enabled (toggle)
- Toolbar: Add Rule, Delete Selected, Enable All, Disable All
- Add Rule dialog:
  - Action dropdown
  - Target dropdown (IP, Subnet, Port, Protocol, MAC)
  - Value input
  - Protocol dropdown
  - Direction dropdown
  - Description

**Interactions:**
- List → `RulesService.list()`
- Add → `RulesService.add(rule)`
- Toggle enable → `RulesService.enable(id)` / `disable(id)`
- Delete → `RulesService.remove(id)`

**Backend Note:** Rules engine already supports "noop" backend for safe UI testing. UI should default to noop unless user explicitly enables nftables/iptables.

---

### 4.8 Settings View

**Purpose:** Configure application behavior.

**Contents:**
- Database path (file picker or text input)
- Database type (SQLite / DuckDB)
- Rules backend (noop / nftables / iptables) — with warning for root requirement
- Capture interface (dropdown of available NICs)
- Log level (DEBUG/INFO/WARNING/ERROR)
- Theme (Light/Dark — Flet supports both)
- "Save Settings" button

**Interactions:**
- Load from `Settings` (Pydantic)
- Save → persist to `.env` or config file

---

## 5. Service Layer Design

### 5.1 Purpose

The service layer decouples UI from simulation engines. Each service:
- Wraps one or more engine classes
- Provides simple, UI-friendly method signatures
- Handles errors and returns structured results
- Can emit events for real-time UI updates (optional)

### 5.2 Example: SwitchService

```python
# home_net_analyzer/ui/services/switch_service.py

from dataclasses import dataclass
from typing import Optional, List, Dict, Any

from home_net_analyzer.simulation.switch import SwitchEngine, SwitchFrame
from home_net_analyzer.topology.models import SwitchPort, VirtualSwitch
from home_net_analyzer.capture.models import CapturedPacket


@dataclass
class SimulationResult:
    success: bool
    decisions: List[Dict[str, Any]]  # port_id, vlan_action, egress_vlan
    mac_table: List[Dict[str, Any]]
    stats: Dict[str, Any]
    error: Optional[str] = None


class SwitchService:
    """Service for switch operations from UI."""

    def __init__(self):
        # Could hold in-memory engines or delegate to a global store
        self._engines: Dict[str, SwitchEngine] = {}
        # Optionally load persisted configs on init

    def list_switches(self) -> List[str]:
        """Return names of all configured switches."""
        # Could delegate to _switch_store from cli.py
        ...

    def create(
        self,
        name: str,
        ports: List[SwitchPort],
        vlans: List[int],
        native_vlan: int = 1
    ) -> SwitchEngine:
        """Create a new switch and persist."""
        ...

    def get(self, name: str) -> Optional[SwitchEngine]:
        """Get switch engine by name."""
        ...

    def delete(self, name: str) -> bool:
        """Delete a switch."""
        ...

    def simulate_frame(
        self,
        switch_name: str,
        src_mac: str,
        dst_mac: str,
        ingress_port: int,
        vlan_id: Optional[int] = None
    ) -> SimulationResult:
        """Simulate a frame through the switch."""
        engine = self.get(switch_name)
        if not engine:
            return SimulationResult(False, [], [], {}, error="Switch not found")

        packet = CapturedPacket(src_mac=src_mac, dst_mac=dst_mac, vlan_id=vlan_id)
        frame = SwitchFrame(packet=packet, ingress_port=ingress_port, ingress_switch=switch_name)
        decisions = engine.process_frame(frame)

        return SimulationResult(
            success=len(decisions) > 0 or True,  # even floods are "success"
            decisions=[d.model_dump() for d in decisions],
            mac_table=engine.get_mac_table_entries(),
            stats=engine.get_stats(),
        )

    def get_mac_table(self, switch_name: str) -> List[Dict[str, Any]]:
        engine = self.get(switch_name)
        return engine.get_mac_table_entries() if engine else []

    def get_stats(self, switch_name: str) -> Dict[str, Any]:
        engine = self.get(switch_name)
        return engine.get_stats() if engine else {}
```

### 5.3 Similar Services

- **RouterService**: create, get, delete, add_svi, add_route, simulate_packet, get_arp_table, get_routes, get_stats
- **NetworkService**: load_scenario, create_topology, add_device, connect_devices, simulate_flow, get_trace
- **PacketService**: count, recent, query, export
- **RulesService**: list, add, remove, enable, disable, get
- **StorageService**: save_topology, load_topology (JSON files for topologies)

### 5.4 Event Bus (Optional but Recommended)

For real-time UI updates during simulations:

```python
# home_net_analyzer/ui/state/event_bus.py

from typing import Callable, Dict, List

class EventBus:
    def __init__(self):
        self._listeners: Dict[str, List[Callable]] = {}

    def subscribe(self, event: str, handler: Callable):
        self._listeners.setdefault(event, []).append(handler)

    def publish(self, event: str, data: Any):
        for h in self._listeners.get(event, []):
            h(data)


# Events:
#   "switch:frame_processed" -> {switch, decisions}
#   "router:packet_routed"   -> {router, decision}
#   "network:hop"            -> {flow_id, hop}
#   "log:message"            -> {level, message}
```

UI components subscribe; services publish.

---

## 6. Topology Serialization Schema

### 6.1 JSON Format for Saving/Loading Topologies

```json
{
  "version": "1.0",
  "name": "MyCampusNet",
  "created_at": "2024-01-15T10:00:00Z",
  "devices": {
    "sw1": {
      "type": "switch",
      "name": "Core-Switch-1",
      "vlans": [10, 20, 30],
      "native_vlan": 1,
      "ports": [
        {"id": 1, "name": "Gi1/0/1", "mode": "access", "access_vlan": 10, "connected_to": "pc1"},
        {"id": 2, "name": "Gi1/0/2", "mode": "trunk", "allowed_vlans": [10, 20]}
      ],
      "ui_position": {"x": 100, "y": 200}
    },
    "r1": {
      "type": "router",
      "name": "Gateway-Router",
      "svis": [
        {"vlan_id": 10, "ip": "10.0.10.1", "subnet": "255.255.255.0"}
      ],
      "physical_interfaces": [
        {"name": "eth0", "ip": "203.0.113.1", "subnet": "255.255.255.0"}
      ],
      "static_routes": [
        {"destination": "0.0.0.0/0", "next_hop": "203.0.113.254", "interface": "eth0"}
      ],
      "ui_position": {"x": 400, "y": 200}
    }
  },
  "hosts": {
    "pc1": {
      "name": "pc1",
      "mac": "aa:bb:cc:01:00:01",
      "ip": "10.0.10.101",
      "vlan_id": 10,
      "connected_switch": "sw1",
      "connected_port": 1,
      "gateway": "10.0.10.1",
      "ui_position": {"x": 50, "y": 300}
    }
  },
  "links": [
    {"from": "sw1", "from_port": 2, "to": "r1", "to_port": "eth0", "type": "trunk"}
  ]
}
```

### 6.2 Service Methods

```python
class StorageService:
    def save_topology(self, topology: dict, path: str) -> None:
        with open(path, "w") as f:
            json.dump(topology, f, indent=2)

    def load_topology(self, path: str) -> dict:
        with open(path) as f:
            return json.load(f)
```

---

## 7. Implementation Suggestions (Non-Code)

### 7.1 Recommended Implementation Phases

| Phase | Focus | Deliverables |
|-------|-------|--------------|
| **Phase 1** | Foundation | Add Flet dependency; create `ui/` package skeleton; implement `app.py` with sidebar navigation and placeholder views |
| **Phase 2** | Dashboard + Settings | Dashboard view with stats; Settings view with persistence |
| **Phase 3** | Switch Management | Switch view: list, create, port editor, MAC table, simulate frame |
| **Phase 4** | Router Management | Router view: list, create, SVI editor, routing table, ARP table, simulate packet |
| **Phase 5** | Network Simulation | Scenario loader; custom flow dialog; trace viewer (table) |
| **Phase 6** | Visual Topology | Topology view with canvas; device nodes; link drawing; drag-and-drop |
| **Phase 7** | Packet + Rules | Packet viewer (table + filters); Firewall rules CRUD |
| **Phase 8** | Polish | Animations, logs panel, export, error handling, theming |

### 7.2 Integration with Existing CLI

Add a new CLI command in `cli.py`:

```python
@app.command("gui")
def cmd_gui() -> None:
    """Launch the Flet desktop GUI."""
    from home_net_analyzer.ui.app import run_app
    run_app()
```

Users run: `hna gui`

### 7.3 State Synchronization

- UI reads from engines via services (read-only or controlled writes).
- Engines already persist configs (JSON files for switches/routers).
- UI can call the same `SwitchStore` / `RouterStore` classes from `cli.py` or refactor into shared services.
- **Recommendation:** Move `SwitchStore` and `RouterStore` to a shared module (e.g., `home_net_analyzer/persistence/`) so both CLI and UI use them.

### 7.4 Error Handling in UI

- All service calls should return a `Result` type or raise structured exceptions.
- UI catches and shows in:
  - A toast/snackbar (Flet `SnackBar`)
  - The log panel
  - Inline form validation errors

### 7.5 Theming

Flet supports light/dark themes. Add a setting:

```python
# In settings_view.py
theme_mode = ft.ThemeMode.DARK  # or LIGHT, SYSTEM
page.theme_mode = theme_mode
```

---

## 8. Gaps Summary & Recommendations

| Gap | Recommendation |
|-----|----------------|
| No Flet integration | Add `flet>=0.21.0` to dependencies; create `ui/` package |
| No visual topology | Implement `TopologyView` with Flet Canvas; define JSON schema |
| No live simulation updates | Add `EventBus`; publish events from services |
| CLI mixes concerns | Refactor `SwitchStore`/`RouterStore` to shared `persistence/` module |
| No undo | Add a simple command stack in `AppState` for config changes |
| No export/import | Add `StorageService.save_topology/load_topology` |
| Limited error display | Use SnackBar + LogPanel for all errors |
| No multi-tab state | Use Flet navigation rail + view switching; keep state per view |

---

## 9. Non-Functional Considerations

| Aspect | Suggestion |
|--------|------------|
| **Performance** | Simulations are CPU-bound; run in thread to keep UI responsive (`threading` or `asyncio`) |
| **Security** | Default rules backend to "noop" in UI; warn before enabling nftables/iptables |
| **Accessibility** | Use semantic labels on buttons; ensure keyboard navigation works |
| **Cross-platform** | Flet runs on Windows/macOS/Linux; test on all three |
| **Packaging** | Use PyInstaller to bundle as single executable: `pyinstaller --onefile --name vlan-emulator-gui -m home_net_analyzer.ui.app` |

---

## 10. Open Questions for Product Decisions

1. **Should the GUI replace the CLI, or coexist?**
   - Recommendation: Coexist. Keep `hna` CLI for scripting/automation; `hna gui` for interactive use.

2. **Should the GUI embed the web dashboard or be standalone?**
   - Recommendation: Standalone Flet app. Optionally keep web dashboard for remote access.

3. **How to handle root-required operations (packet capture, firewall)?**
   - Recommendation: GUI warns and gracefully degrades; packet capture can be simulated-only in GUI unless run as root.

4. **Should topologies be auto-saved?**
   - Recommendation: Auto-save to a default file on each change; offer "Save As" for named files.

5. **Should there be a "replay" mode for past simulations?**
   - Future enhancement: Store flow traces and allow replay in the trace viewer.

---

## Appendix A: Existing CLI Commands Reference

| Command | Description |
|---------|-------------|
| `hna count` | Show packet count |
| `hna recent -n 20` | Show recent packets |
| `hna query --src X --proto TCP` | Query packets |
| `hna rules list/add/remove/enable/disable` | Manage firewall rules |
| `hna dashboard` | Start web dashboard |
| `hna switch create/list/status/mac-table/simulate/stats/delete` | Switch operations |
| `hna router create/list/status/routes/arp/simulate/stats/delete` | Router operations |
| `hna network simulate/scenario` | Network flow simulation |
| `hna interactive` | Menu-driven interactive CLI |
| `hna gui` *(proposed)* | Launch Flet desktop GUI |

---

## Appendix B: Suggested Flet UI Component Mapping

| UI Element | Flet Widget |
|------------|-------------|
| Sidebar navigation | `ft.NavigationRail` |
| Main content area | `ft.Container` with dynamic `content` |
| Tables | `ft.DataTable` |
| Forms | `ft.TextField`, `ft.Dropdown`, `ft.Checkbox` |
| Buttons | `ft.ElevatedButton`, `ft.FilledButton` |
| Dialogs | `ft.AlertDialog` |
| Canvas for topology | `ft.Canvas` with `ft.Paint` shapes |
| Logs | `ft.ListView` of `ft.Text` |
| Tabs | `ft.Tabs` |
| SnackBar (toasts) | `ft.SnackBar` |
| File picker | `ft.FilePicker` |

---

*End of Architecture Document*
