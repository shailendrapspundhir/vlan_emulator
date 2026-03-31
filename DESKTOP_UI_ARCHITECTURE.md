# VLAN Emulator - Desktop UI Architecture Specification
## Flet-Based Visual Network Simulation Platform

**Version:** 1.0  
**Status:** Architecture Design Document  
**Date:** 2026-03-31

---

## Table of Contents

1. [Part 1: Current State & Gap Analysis](#part-1-current-state--gap-analysis)
2. [Part 2: Flet UI Architecture](#part-2-flet-ui-architecture)
3. [Part 3: Service Layer](#part-3-service-layer)
4. [Part 4: Event Bus](#part-4-event-bus)
5. [Part 5: State Management](#part-5-state-management)
6. [Part 6: View Designs](#part-6-view-designs)
7. [Part 7: Implementation Roadmap](#part-7-implementation-roadmap)
8. [Part 8: Technical Considerations](#part-8-technical-considerations)
9. [Part 9: UI/UX Guidelines](#part-9-uiux-guidelines)
10. [Part 10: Gap Resolution Summary](#part-10-gap-resolution-summary)

---

# Part 1: Current State & Gap Analysis

## 1.1 Existing Implementation Summary

The VLAN Emulator (`home_net_analyzer`) is a Python-based network simulation platform with:

| Module | Capability |
|--------|------------|
| `simulation/switch/` | VLAN-aware L2 forwarding, MAC learning, trunk/access ports |
| `simulation/router/` | L3 routing, SVIs, ARP, static routes, ACLs |
| `simulation/network/` | Multi-device orchestration, hop-by-hop flow tracing |
| `topology/` | VLAN, VirtualHost, SwitchPort, VirtualSwitch, Router models |
| `storage/` | PacketStore (SQLite/DuckDB), JSON persistence |
| `rules/` | Firewall rules with nftables/iptables/noop backends |
| `cli.py` | Typer CLI with interactive menus |
| `web/api.py` | FastAPI REST endpoints for packets/rules |

## 1.2 Identified Gaps (10+)

| # | Gap | Category | Impact | Priority |
|---|-----|----------|--------|----------|
| 1 | **No graphical topology** | Visualization | Users cannot see network layout | P0 |
| 2 | **No real-time updates** | UX | Stale data after simulations | P0 |
| 3 | **CLI-only device creation** | Usability | Requires terminal knowledge | P0 |
| 4 | **No packet animation** | Visualization | Hard to trace packet paths | P1 |
| 5 | **No unified state management** | Architecture | UI/Engine desync | P0 |
| 6 | **No undo/redo** | UX | Mistakes are irreversible | P1 |
| 7 | **No simulation control (pause/resume)** | Control | Cannot step through flows | P1 |
| 8 | **No visual MAC/ARP table inspection** | Debugging | Tables shown as text only | P2 |
| 9 | **No drag-and-drop editing** | UX | Manual JSON editing required | P1 |
| 10 | **No live flow tracing** | Visualization | Hop logs are static tables | P1 |
| 11 | **No topology persistence** | Data | Cannot save/load visual layouts | P1 |
| 12 | **No error highlighting in diagram** | Debugging | Errors buried in logs | P2 |

## 1.3 Gap Categories

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        GAP CATEGORIES                                   │
├─────────────────────────────────────────────────────────────────────────┤
│  VISUALIZATION (P0)                                                     │
│    • No graphical topology (Gap #1)                                     │
│    • No packet animation (Gap #4)                                       │
│    • No live flow tracing (Gap #10)                                     │
│                                                                         │
│  STATE MANAGEMENT (P0)                                                  │
│    • No unified state (Gap #5)                                          │
│    • No real-time updates (Gap #2)                                      │
│    • No topology persistence (Gap #11)                                  │
│                                                                         │
│  USABILITY (P0/P1)                                                      │
│    • CLI-only creation (Gap #3)                                         │
│    • No drag-and-drop (Gap #9)                                          │
│    • No undo/redo (Gap #6)                                              │
│                                                                         │
│  CONTROL (P1)                                                           │
│    • No simulation pause/resume (Gap #7)                                │
│                                                                         │
│  DEBUGGING (P2)                                                         │
│    • No visual MAC/ARP tables (Gap #8)                                  │
│    • No error highlighting (Gap #12)                                    │
└─────────────────────────────────────────────────────────────────────────┘
```

## 1.4 Current vs. Desired State

| Aspect | Current State | Desired State |
|--------|---------------|---------------|
| Topology creation | CLI commands + JSON | Visual drag-and-drop canvas |
| Device configuration | Text prompts | Modal dialogs with forms |
| Simulation execution | CLI `hna network simulate` | UI "Run" button with progress |
| Packet flow viewing | Table of hops | Animated path through diagram |
| MAC/ARP tables | CLI table output | Live-updating data grids |
| State persistence | Per-component JSON files | Unified AppState with save/load |
| User feedback | Terminal output | Visual notifications + log panel |

---

# Part 2: Flet UI Architecture

## 2.1 High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        FLET DESKTOP APPLICATION                                 │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │  Main Window (ft.Page)                                                    │  │
│  │  ┌─────────────┐  ┌─────────────────────────────────────────────────────┐ │  │
│  │  │  NAV RAIL   │  │                    MAIN CONTENT                     │ │  │
│  │  │  (Sidebar)  │  │  ┌───────────────────────────────────────────────┐  │ │  │
│  │  │             │  │  │              Current View                     │  │ │  │
│  │  │ • Dashboard │  │  │  (Dashboard / Topology / FlowTrace / Detail)  │  │ │  │
│  │  │ • Topology  │  │  │                                               │  │ │  │
│  │  │ • Devices   │  │  │  ┌──────────────┐  ┌───────────────────────┐  │  │ │  │
│  │  │ • Simulations│ │  │  │ NetworkCanvas│  │  Inspector / Details  │  │  │ │  │
│  │  │ • Packets   │  │  │  │              │  │                       │  │  │ │  │
│  │  │ • Rules     │  │  │  │  [Devices]   │  │  MAC Table            │  │  │ │  │
│  │  │ • Settings  │  │  │  │  [Links]     │  │  ARP Table            │  │  │ │  │
│  │  │             │  │  │  │  [Flows]     │  │  Routing Table        │  │  │ │  │
│  │  └─────────────┘  │  │  └──────────────┘  │  Stats                │  │  │ │  │
│  │                   │  │                    └───────────────────────┘  │  │ │  │
│  │                   │  └─────────────────────────────────────────────────┘  │ │  │
│  │                   │  ┌─────────────────────────────────────────────────┐  │ │  │
│  │                   │  │              LOG PANEL (bottom)                 │  │ │  │
│  │                   │  │  [timestamp] Event: device added                │  │ │  │
│  │                   │  │  [timestamp] Simulation: hop 3 completed        │  │ │  │
│  │                   │  └─────────────────────────────────────────────────┘  │ │  │
│  └───────────────────┴────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼ (Bridge via Services)
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        SERVICE LAYER (ASYNC)                                    │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐    │
│  │TopologyService│  │DeviceService  │  │SimulationSvc  │  │FlowService    │    │
│  │ • create()    │  │ • add_switch()│  │ • run()       │  │ • trace()     │    │
│  │ • load()      │  │ • add_router()│  │ • pause()     │  │ • animate()   │    │
│  │ • save()      │  │ • connect()   │  │ • step()      │  │ • export()    │    │
│  └───────────────┘  └───────────────┘  └───────────────┘  └───────────────┘    │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼ (ThreadPoolExecutor)
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    EXISTING SYNC ENGINES (Unchanged)                            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐                  │
│  │ SwitchEngine    │  │ RouterEngine    │  │ NetworkSimEngine│                  │
│  │ (process_frame) │  │ (route_packet)  │  │ (simulate_flow) │                  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 2.2 Proposed Module Structure

```
home_net_analyzer/
│
├── desktop/                          # NEW: Flet desktop application
│   │
│   ├── __init__.py
│   ├── main.py                       # Entry point: python -m home_net_analyzer.desktop
│   ├── app.py                        # Main Flet app, routing, theme application
│   │
│   ├── theme.py                      # Color schemes, typography, component styles
│   ├── state.py                      # AppState dataclass + persistence
│   ├── events.py                     # EventBus implementation
│   │
│   ├── services/                     # Async service layer
│   │   ├── __init__.py
│   │   ├── topology_service.py       # Topology CRUD, persistence
│   │   ├── device_service.py         # Switch/Router/Host management
│   │   ├── simulation_service.py     # Run/pause/resume/step simulations
│   │   └── flow_service.py           # Packet flow tracing & animation
│   │
│   ├── views/                        # Page views (one per nav item)
│   │   ├── __init__.py
│   │   ├── dashboard_view.py         # Overview, quick stats, recent activity
│   │   ├── topology_view.py          # Visual topology builder
│   │   ├── device_detail_view.py     # MAC/ARP/Routing tables for selected device
│   │   ├── simulation_view.py        # Run scenarios, control simulation
│   │   ├── flow_trace_view.py        # Animated packet flow visualization
│   │   ├── packet_view.py            # Stored packets browser
│   │   ├── rules_view.py             # Firewall rules management
│   │   └── settings_view.py          # App configuration
│   │
│   ├── components/                   # Reusable UI components
│   │   ├── __init__.py
│   │   ├── network_canvas.py         # Drag-and-drop device diagram
│   │   ├── packet_animator.py        # Animated packet traveling on links
│   │   ├── mac_table_grid.py         # DataTable for MAC addresses
│   │   ├── arp_table_grid.py         # DataTable for ARP cache
│   │   ├── routing_table_grid.py     # DataTable for routes
│   │   ├── hop_trace_table.py        # Step-by-step flow hops
│   │   ├── log_panel.py              # Scrollable event log
│   │   ├── device_card.py            # Summary card for a device
│   │   ├── toolbar.py                # Common action buttons
│   │   └── dialogs/                  # Modal dialogs
│   │       ├── __init__.py
│   │       ├── create_switch_dialog.py
│   │       ├── create_router_dialog.py
│   │       ├── create_host_dialog.py
│   │       ├── connect_devices_dialog.py
│   │       ├── simulate_frame_dialog.py
│   │       ├── simulate_flow_dialog.py
│   │       └── confirm_dialog.py
│   │
│   └── assets/                       # Icons, images (optional)
│       └── icons/
│
├── simulation/                       # EXISTING (unchanged)
├── topology/                         # EXISTING (unchanged)
├── storage/                          # EXISTING (unchanged)
├── rules/                            # EXISTING (unchanged)
├── cli.py                            # EXISTING: Add "desktop" command
└── pyproject.toml                    # Add flet dependency
```

## 2.3 Key Component Designs

### 2.3.1 NetworkCanvas Component

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  NetworkCanvas (ft.Canvas-based)                                            │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  Toolbar: [Add Switch] [Add Router] [Add Host] [Connect] [Delete]   │  │
│  ├───────────────────────────────────────────────────────────────────────┤  │
│  │                                                                       │  │
│  │      ┌─────────┐                              ┌─────────┐            │  │
│  │      │  SW1    │◄════════════════════════════►│  R1     │            │  │
│  │      │ Switch  │         (trunk link)         │ Router  │            │  │
│  │      └────┬────┘                              └────┬────┘            │  │
│  │           │                                        │                  │  │
│  │           │ (access)                               │ (access)         │  │
│  │           ▼                                        ▼                  │  │
│  │      ┌─────────┐                              ┌─────────┐            │  │
│  │      │  PC1    │                              │  SRV1   │            │  │
│  │      │  Host   │                              │  Host   │            │  │
│  │      └─────────┘                              └─────────┘            │  │
│  │                                                                       │  │
│  │  Legend: ▢ Switch  ⬡ Router  💻 Host   ── access   ══ trunk         │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│  Interactions:                                                              │
│    • Drag nodes to reposition                                               │
│    • Double-click node → open detail view                                   │
│    • Drag from port to port → create link                                   │
│    • Right-click → context menu (edit, delete)                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Responsibilities:**
- Render devices as draggable shapes with labels
- Render links as lines/arrows between ports
- Handle mouse events (drag, click, double-click)
- Notify parent of selection/changes via callbacks
- Support zoom and pan

### 2.3.2 PacketAnimator Component

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  PacketAnimator                                                             │
│                                                                             │
│  When a flow is simulated:                                                  │
│                                                                             │
│  1. Highlight source host (PC1)                                             │
│  2. Draw animated packet icon moving along link to SW1                      │
│  3. Highlight SW1, show "MAC learning" label briefly                        │
│  4. Packet continues to R1 (router)                                         │
│  5. Highlight R1, show "Routing decision"                                   │
│  6. Packet continues to destination (SRV1)                                  │
│  7. Highlight destination, show "Delivered"                                 │
│                                                                             │
│  Visual: Small colored circle or icon traveling along path                  │
│  Speed: Configurable (e.g., 500ms per hop)                                  │
│  Controls: [▶ Play] [⏸ Pause] [Step] [Reset]                                │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Responsibilities:**
- Accept a `PacketFlow` (sequence of hops)
- Animate a visual indicator along the canvas links
- Synchronize with hop trace table highlighting
- Support pause/resume/step controls
- Emit events on hop completion

---

# Part 3: Service Layer

## 3.1 Purpose

The service layer provides an **async bridge** between the Flet UI (event-driven, responsive) and the existing **synchronous simulation engines** (CPU-bound, blocking).

```
┌─────────────┐     calls      ┌──────────────────┐     wraps      ┌─────────────┐
│   Flet UI   │ ─────────────► │  Async Service   │ ─────────────► │ Sync Engine │
│  (EventLoop)│                │  (ThreadPoolExec)│                │  (blocking) │
└─────────────┘                └──────────────────┘                └─────────────┘
```

## 3.2 Service Interfaces

### 3.2.1 TopologyService

```python
# Conceptual interface (NOT implementation)

class TopologyService:
    """
    Async service for topology CRUD and persistence.
    Wraps existing topology models + adds UI-specific concerns.
    """

    async def create_topology(self, name: str) -> TopologyState:
        """Create a new empty topology."""
        ...

    async def load_topology(self, path: str) -> TopologyState:
        """Load topology from JSON file."""
        ...

    async def save_topology(self, topology: TopologyState, path: str) -> None:
        """Persist topology to JSON file."""
        ...

    async def add_device(self, topology: TopologyState, device: DeviceSpec) -> DeviceState:
        """Add a switch/router/host to the topology."""
        ...

    async def remove_device(self, topology: TopologyState, device_id: str) -> None:
        """Remove a device and its links."""
        ...

    async def connect_devices(
        self,
        topology: TopologyState,
        from_device: str,
        to_device: str,
        from_port: str,
        to_port: str,
        link_type: str = "access"
    ) -> LinkState:
        """Create a link between two devices."""
        ...

    async def auto_layout(self, topology: TopologyState) -> TopologyState:
        """Apply automatic layout algorithm."""
        ...
```

### 3.2.2 DeviceService

```python
class DeviceService:
    """
    Async service for device configuration and inspection.
    """

    async def get_switch_config(self, switch_id: str) -> SwitchConfig:
        """Get full switch configuration (ports, VLANs, stats)."""
        ...

    async def get_mac_table(self, switch_id: str) -> List[MACEntry]:
        """Get current MAC address table."""
        ...

    async def get_router_config(self, router_id: str) -> RouterConfig:
        """Get full router configuration (SVIs, interfaces, routes)."""
        ...

    async def get_arp_table(self, router_id: str) -> List[ARPEntry]:
        """Get current ARP cache."""
        ...

    async def get_routing_table(self, router_id: str) -> List[RouteEntry]:
        """Get routing table."""
        ...

    async def update_port(self, switch_id: str, port_id: int, config: PortUpdate) -> None:
        """Update a switch port configuration."""
        ...
```

### 3.2.3 SimulationService

```python
class SimulationService:
    """
    Async service for running and controlling simulations.
    """

    async def run_scenario(self, scenario_name: str) -> SimulationResult:
        """Load and execute a predefined scenario."""
        ...

    async def simulate_frame(
        self,
        switch_id: str,
        src_mac: str,
        dst_mac: str,
        ingress_port: int
    ) -> FrameResult:
        """Simulate a single frame through a switch."""
        ...

    async def simulate_packet(
        self,
        router_id: str,
        src_ip: str,
        dst_ip: str,
        ingress_interface: str
    ) -> RoutingResult:
        """Simulate a packet through a router."""
        ...

    async def start_flow(
        self,
        topology_id: str,
        src_host: str,
        dst_host: str,
        protocol: str
    ) -> FlowHandle:
        """Begin a multi-hop flow simulation (returns handle for control)."""
        ...

    async def pause_flow(self, flow_handle: str) -> None:
        """Pause an active flow."""
        ...

    async def resume_flow(self, flow_handle: str) -> None:
        """Resume a paused flow."""
        ...

    async def step_flow(self, flow_handle: str) -> Optional[HopResult]:
        """Advance flow by one hop (for step-through mode)."""
        ...
```

### 3.2.4 FlowService

```python
class FlowService:
    """
    Async service for packet flow tracing and animation.
    """

    async def trace_flow(
        self,
        src_host: str,
        dst_host: str,
        protocol: str,
        count: int = 1
    ) -> PacketFlow:
        """Generate and trace a packet flow; return full trace."""
        ...

    async def animate_flow(
        self,
        flow: PacketFlow,
        canvas: NetworkCanvas,
        on_hop: Callable[[Hop], None]
    ) -> None:
        """Animate the given flow on the canvas."""
        ...

    async def export_trace(self, flow: PacketFlow, format: str) -> str:
        """Export trace to CSV/JSON file path."""
        ...
```

## 3.3 Async Bridge Pattern

```python
# Conceptual pattern (NOT runnable code)

import asyncio
from concurrent.futures import ThreadPoolExecutor

executor = ThreadPoolExecutor(max_workers=4)

async def run_sync_in_thread(func, *args):
    """Run a synchronous function in a thread pool."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(executor, func, *args)

# Usage in service:
async def simulate_frame(self, switch_id, ...):
    # Get the sync engine (from existing code)
    engine = self._get_switch_engine(switch_id)
    
    # Wrap the blocking call
    result = await run_sync_in_thread(
        engine.process_frame,
        frame
    )
    return result
```

---

# Part 4: Event Bus

## 4.1 Purpose

Decouples components so that:
- Views react to state changes without direct coupling
- Services emit events without knowing who listens
- Multiple listeners can respond to the same event

## 4.2 EventBus Design

```
┌──────────────┐                    ┌──────────────┐
│   Publisher  │── publish(event) ─►│   EventBus   │
│  (Service)   │                    │  (Singleton) │
└──────────────┘                    └──────┬───────┘
                                           │
                           ┌───────────────┼───────────────┐
                           ▼               ▼               ▼
                    ┌──────────┐    ┌──────────┐    ┌──────────┐
                    │ Listener │    │ Listener │    │ Listener │
                    │ (View)   │    │ (Canvas) │    │ (Log)    │
                    └──────────┘    └──────────┘    └──────────┘
```

## 4.3 Event Types

| Event Name | Payload | Emitted By | Consumed By |
|------------|---------|------------|-------------|
| `topology:loaded` | `{topology: TopologyState}` | TopologyService | TopologyView, Canvas |
| `device:added` | `{device: DeviceState}` | DeviceService | Canvas, LogPanel |
| `device:selected` | `{device_id: str}` | Canvas | Inspector, DetailView |
| `link:created` | `{link: LinkState}` | DeviceService | Canvas |
| `simulation:started` | `{flow_id: str}` | SimulationService | FlowTraceView, Animator |
| `simulation:hop` | `{hop: Hop}` | SimulationService | HopTraceTable, Animator |
| `simulation:completed` | `{flow: PacketFlow, success: bool}` | SimulationService | FlowTraceView |
| `mac_table:updated` | `{switch_id: str, entries: List[MACEntry]}` | DeviceService | MACTableGrid |
| `arp_table:updated` | `{router_id: str, entries: List[ARPEntry]}` | DeviceService | ARPTableGrid |
| `log:message` | `{level: str, message: str}` | Any | LogPanel |
| `error:occurred` | `{error: str, context: dict}` | Any | LogPanel, SnackBar |

## 4.4 EventBus Interface

```python
# Conceptual interface (NOT implementation)

from typing import Callable, Dict, List, Any
from dataclasses import dataclass

@dataclass
class Event:
    name: str
    payload: Any
    timestamp: float

class EventBus:
    def __init__(self):
        self._listeners: Dict[str, List[Callable]] = {}

    def subscribe(self, event_name: str, handler: Callable[[Event], None]) -> None:
        """Register a handler for an event type."""
        self._listeners.setdefault(event_name, []).append(handler)

    def unsubscribe(self, event_name: str, handler: Callable) -> None:
        """Remove a handler."""
        if event_name in self._listeners:
            try:
                self._listeners[event_name].remove(handler)
            except ValueError:
                pass

    def publish(self, event_name: str, payload: Any = None) -> None:
        """Emit an event to all subscribers."""
        event = Event(name=event_name, payload=payload, timestamp=time.time())
        for handler in self._listeners.get(event_name, []):
            try:
                handler(event)
            except Exception as e:
                # Log but don't crash other handlers
                print(f"Event handler error: {e}")
```

## 4.5 Usage Example

```python
# Service emits event after adding device
async def add_device(self, ...):
    device = await self._create_device(...)
    self.event_bus.publish("device:added", {"device": device})
    return device

# View subscribes on init
def __init__(self, event_bus: EventBus):
    self.event_bus = event_bus
    self.event_bus.subscribe("device:added", self._on_device_added)

def _on_device_added(self, event: Event):
    device = event.payload["device"]
    self.canvas.add_node(device)
    self.log_panel.append(f"Added device: {device.name}")
```

---

# Part 5: State Management

## 5.1 AppState Overview

Centralized, serializable state for the entire application.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AppState                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  current_topology: Optional[TopologyState]                            │  │
│  │  selected_device_id: Optional[str]                                    │  │
│  │  active_simulation: Optional[SimulationState]                         │  │
│  │  recent_logs: List[LogEntry]                                          │  │
│  │  ui_preferences: UIPreferences                                        │  │
│  │    • theme_mode: "light" | "dark" | "system"                          │  │
│  │    • canvas_zoom: float                                               │  │
│  │    • log_level: str                                                   │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  Methods:                                                                   │
│    • load() -> load from JSON file                                          │
│    • save() -> persist to JSON file                                         │
│    • reset() -> factory defaults                                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 5.2 State Persistence

```python
# Conceptual (NOT implementation)

import json
from dataclasses import dataclass, asdict
from pathlib import Path

STATE_FILE = Path.home() / ".vlan_emulator" / "app_state.json"

@dataclass
class AppState:
    current_topology_id: Optional[str] = None
    selected_device_id: Optional[str] = None
    theme_mode: str = "dark"
    canvas_zoom: float = 1.0
    # ... other fields

    @classmethod
    def load(cls) -> "AppState":
        if STATE_FILE.exists():
            data = json.loads(STATE_FILE.read_text())
            return cls(**data)
        return cls()

    def save(self) -> None:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(asdict(self), indent=2))
```

## 5.3 State Reactivity

State changes trigger UI updates:

```
User Action → Service Call → State Update → EventBus.publish → View re-renders
```

Views observe state either by:
- Subscribing to EventBus events
- Polling AppState periodically (simpler but less efficient)
- Using Flet's `Ref` bindings

---

# Part 6: View Designs

## 6.1 Dashboard View (ASCII Mockup)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  🏠 Dashboard                                          [Settings] [Profile] │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │
│  │  42         │  │  3          │  │  2          │  │  7          │       │
│  │  Packets    │  │  Switches   │  │  Routers    │  │  Rules      │       │
│  │  Stored     │  │  Active     │  │  Active     │  │  Enabled    │       │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘       │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Quick Actions                                                      │   │
│  │  [➕ New Switch] [➕ New Router] [▶ Run Scenario] [📊 View Packets]  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Recent Activity                                                    │   │
│  │  • 10:15 - Simulation "router-on-stick" completed (success)         │   │
│  │  • 10:14 - Added host "web-server" to topology "CampusNet"          │   │
│  │  • 10:12 - MAC table updated on switch "Core-SW1" (3 new entries)   │   │
│  │  • 10:10 - Created switch "Edge-SW2" with 8 ports                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 6.2 Topology Builder View (ASCII Mockup)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  🗺️ Topology: CampusNet                              [Save] [Load] [Export]│
├──────────────┬──────────────────────────────────────┬──────────────────────┤
│  TOOLBAR     │           CANVAS                     │   INSPECTOR          │
│              │                                      │                      │
│ [Add Switch] │     ┌─────────┐                      │  Selected: Core-SW1  │
│ [Add Router] │     │ Core-SW1│◄══════►┌─────────┐  │                      │
│ [Add Host]   │     │ Switch  │        │Gateway-R│  │  Type: Switch        │
│              │     └────┬────┘        │ Router  │  │  VLANs: 10, 20, 30   │
│ [Connect]    │          │             └────┬────┘  │  Ports: 24           │
│ [Delete]     │          │ (trunk)          │       │  MAC Entries: 12     │
│              │          │                  │       │                      │
│ [Zoom +]     │     ┌────┴────┐        ┌────┴────┐│  [View MAC Table]    │
│ [Zoom -]     │     │ PC-Eng  │        │ SRV-Web ││  [Edit Ports]        │
│ [Auto Layout]│     │ Host    │        │ Host    ││  [Simulate Frame]    │
│              │     └─────────┘        └─────────┘│                      │
│              │                                      │                      │
│              │  Legend: ▢ Switch  ⬡ Router  💻 Host│                      │
│              │          ── access   ══ trunk       │                      │
└──────────────┴──────────────────────────────────────┴──────────────────────┘
│  LOG: Added link Core-SW1 ↔ Gateway-R (trunk)                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 6.3 Flow Trace View (ASCII Mockup)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  🔄 Flow Trace: PC-Eng → SRV-Web (ICMP)                    [▶] [⏸] [Step] │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  HOP-BY-HOP TRACE                                                   │   │
│  │  ┌───┬────────────┬─────────┬─────────────┬────────┬────────┐      │   │
│  │  │ # │ Device     │ Type    │ Action      │ Ingress│ Egress │      │   │
│  │  ├───┼────────────┼─────────┼─────────────┼────────┼────────┤      │   │
│  │  │ 1 │ PC-Eng     │ Host    │ Send        │ -      │ Gi1/0/1│ ◄────│   │
│  │  │ 2 │ Core-SW1   │ Switch  │ Forward     │ 1      │ 24     │ ◄────│   │
│  │  │ 3 │ Gateway-R  │ Router  │ Route       │ Vlan20 │ Vlan30 │ ◄────│   │
│  │  │ 4 │ Core-SW1   │ Switch  │ Forward     │ 24     │ 3      │ ◄────│   │
│  │  │ 5 │ SRV-Web    │ Host    │ Deliver     │ Gi1/0/3│ -      │ ◄────│   │
│  │  └───┴────────────┴─────────┴─────────────┴────────┴────────┘      │   │
│  │                                                                     │   │
│  │  Status: ✅ Success - 5 hops, 12ms total                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  ANIMATION                                                           │   │
│  │                                                                      │   │
│  │   PC-Eng ●━━━━━━━━━━► Core-SW1 ●━━━━━━━► Gateway-R ●━━━━━► SRV-Web  │   │
│  │           (animated dot traveling along path)                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

# Part 7: Implementation Roadmap

## 7.1 6-Phase, 12-Week Plan

| Phase | Weeks | Focus | Deliverable | Acceptance Criteria |
|-------|-------|-------|-------------|---------------------|
| **1. Foundation** | 1-2 | Project setup, navigation | App launches with sidebar | `hna desktop` opens window; 8 nav items visible; theme applied |
| **2. Topology Management** | 3-4 | Visual topology builder | Drag-and-drop canvas | Add/remove devices; create links; save/load JSON topology |
| **3. Device Details** | 5-6 | Live inspection | MAC/ARP/Routing tables | Select device → see live tables; tables update after simulation |
| **4. Simulation Control** | 7-8 | Run simulations | Scenario runner + controls | Run predefined scenario; pause/resume/step; view progress |
| **5. Flow Visualization** | 9-10 | Packet animation | Animated trace | Flow trace view; animated packets on canvas; hop highlighting |
| **6. Polish** | 11-12 | UX, packaging | Production-ready app | All views functional; error handling; `flet pack` works |

## 7.2 Phase Details

### Phase 1: Foundation (Weeks 1-2)

**Goals:**
- Add `flet` dependency
- Create `desktop/` package structure
- Implement main app with navigation rail
- Apply initial theme

**Deliverables:**
- `pyproject.toml` updated with `flet>=0.21.0`
- `desktop/app.py` with `ft.Page` and `ft.NavigationRail`
- Placeholder views for all 8 sections
- Basic routing between views

**Tasks:**
1. Update `pyproject.toml`
2. Create `desktop/` directory and `__init__.py`
3. Implement `app.py` with page setup
4. Create 8 stub view files
5. Implement navigation rail switching
6. Add `theme.py` with color constants
7. Test: `python -m home_net_analyzer.desktop` opens window

---

### Phase 2: Topology Management (Weeks 3-4)

**Goals:**
- Implement `NetworkCanvas` component
- Implement `TopologyService`
- Add device creation dialogs
- Enable save/load of topologies

**Deliverables:**
- Draggable nodes on canvas (switch, router, host)
- Link drawing between nodes
- Create device dialogs
- JSON topology persistence

**Tasks:**
1. Implement `components/network_canvas.py` using `ft.Canvas`
2. Implement `services/topology_service.py`
3. Create `dialogs/create_switch_dialog.py`
4. Create `dialogs/create_router_dialog.py`
5. Create `dialogs/create_host_dialog.py`
6. Wire save/load via `StorageService`
7. Test: Create topology, save, reload, see same layout

---

### Phase 3: Device Details (Weeks 5-6)

**Goals:**
- Implement device detail view
- Show live MAC, ARP, routing tables
- Auto-refresh after simulations

**Deliverables:**
- `device_detail_view.py` with tabs (Config / MAC / ARP / Routes)
- `components/mac_table_grid.py`
- `components/arp_table_grid.py`
- `components/routing_table_grid.py`
- Event-driven table updates

**Tasks:**
1. Implement detail view with tabs
2. Implement table grid components
3. Wire `DeviceService` to fetch tables
4. Subscribe to `mac_table:updated` etc. events
5. Test: Select switch → see MAC table; simulate frame → table grows

---

### Phase 4: Simulation Control (Weeks 7-8)

**Goals:**
- Implement `SimulationService`
- Add scenario picker
- Add simulation controls (Run, Pause, Resume, Step)
- Show simulation progress

**Deliverables:**
- `simulation_view.py` with scenario dropdown
- Simulation controls UI
- Progress indicator
- Integration with existing `NetworkSimulationEngine`

**Tasks:**
1. Implement `services/simulation_service.py` with async bridge
2. Create scenario picker dropdown
3. Add [Run], [Pause], [Step], [Reset] buttons
4. Show progress bar or hop counter
5. Emit events on hop completion
6. Test: Run "router-on-stick"; pause mid-flow; resume

---

### Phase 5: Flow Visualization (Weeks 9-10)

**Goals:**
- Implement `PacketAnimator`
- Integrate animation with `NetworkCanvas`
- Highlight hops in trace table
- Export trace to file

**Deliverables:**
- Animated packet indicator on canvas links
- Synchronized hop table highlighting
- `flow_trace_view.py`
- Export button (CSV/JSON)

**Tasks:**
1. Implement `components/packet_animator.py`
2. Wire animator to canvas (draw moving dot)
3. Synchronize with `hop_trace_table.py`
4. Add speed control slider
5. Implement export via `FlowService`
6. Test: Simulate flow → see animated path + table sync

---

### Phase 6: Polish (Weeks 11-12)

**Goals:**
- Error handling and user feedback
- Theming (light/dark toggle)
- Packaging with `flet pack`
- Documentation and final testing

**Deliverables:**
- SnackBar notifications for errors
- Theme toggle in Settings
- `flet pack` produces standalone executable
- README section for desktop app

**Tasks:**
1. Add try/except + SnackBar in all service calls
2. Implement theme toggle (ft.ThemeMode)
3. Test packaging: `flet pack home_net_analyzer/desktop/main.py`
4. Write user guide section
5. Cross-platform smoke test (Linux/macOS/Windows if possible)
6. Final bug fixes

---

# Part 8: Technical Considerations

## 8.1 Async Integration

**Challenge:** Flet runs on an asyncio event loop; existing simulation engines are synchronous and potentially slow.

**Solution:** Use `concurrent.futures.ThreadPoolExecutor`:

```python
# Pattern (conceptual)
import asyncio
from concurrent.futures import ThreadPoolExecutor

_executor = ThreadPoolExecutor(max_workers=4)

async def call_sync(func, *args):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_executor, func, *args)

# In service:
async def simulate(self, ...):
    engine = self._engines[switch_id]
    result = await call_sync(engine.process_frame, frame)
    return result
```

**Guidelines:**
- Never block the main thread with long-running calls
- Use `await` for all service methods from UI
- Limit thread pool size to avoid resource exhaustion

## 8.2 Performance Optimization

| Area | Strategy |
|------|----------|
| Canvas rendering | Limit redraws; only re-render on state change |
| Large topologies | Virtualize or paginate device lists if >100 nodes |
| Table updates | Batch updates; use `DataTable.update()` not full rebuild |
| Animation | Use `ft.Animation` or timer-based; target 60fps for smooth motion |
| Memory | Dispose old simulation results; cap log entries at 1000 |

## 8.3 Testing Strategy

| Level | What to Test | Tool |
|-------|--------------|------|
| Unit | Service methods (mock engines) | pytest |
| Component | View renders correctly | pytest + flet testing utils |
| Integration | Service ↔ Engine calls | pytest with real engines |
| E2E | User workflows (add device, run sim) | Manual + scripted flet tests |
| Packaging | `flet pack` produces runnable binary | CI smoke test |

## 8.4 Packaging

```bash
# Build standalone executable
pip install flet
flet pack home_net_analyzer/desktop/main.py \
    --name vlan-emulator \
    --icon assets/icon.png \
    --product-name "VLAN Emulator" \
    --product-version "1.0.0"

# Output: dist/vlan-emulator (Linux) or vlan-emulator.exe (Windows)
```

**Notes:**
- `flet pack` bundles Python + Flutter runtime
- Final binary ~50-100MB
- Supports Windows, macOS, Linux

---

# Part 9: UI/UX Guidelines

## 9.1 Color Schemes

### Dark Mode (Default)

```
┌─────────────────────────────────────────────────────────────────┐
│  Background      #0F172A  (slate-900)                           │
│  Surface         #1E293B  (slate-800)                           │
│  Primary         #22C55E  (green-500)                           │
│  Accent          #3B82F6  (blue-500)                            │
│  Text Primary    #E2E8F0  (slate-200)                           │
│  Text Muted      #94A3B8  (slate-400)                           │
│  Danger          #EF4444  (red-500)                             │
│  Border          #334155  (slate-700)                           │
└─────────────────────────────────────────────────────────────────┘
```

### Light Mode

```
┌─────────────────────────────────────────────────────────────────┐
│  Background      #F8FAFC  (slate-50)                            │
│  Surface         #FFFFFF  (white)                               │
│  Primary         #16A34A  (green-600)                           │
│  Accent          #2563EB  (blue-600)                            │
│  Text Primary    #0F172A  (slate-900)                           │
│  Text Muted      #64748B  (slate-500)                           │
│  Danger          #DC2626  (red-600)                             │
│  Border          #E2E8F0  (slate-200)                           │
└─────────────────────────────────────────────────────────────────┘
```

## 9.2 Iconography

| Concept | Icon Suggestion | Flet Widget |
|---------|-----------------|-------------|
| Switch | `⬛` or network switch emoji | Text or SVG |
| Router | `⬡` hexagon | Text or SVG |
| Host | `💻` or computer | Text or SVG |
| Link | `─` / `═` | Canvas line |
| Play | `▶` | Button text |
| Pause | `⏸` | Button text |
| Step | `⏭` | Button text |
| Add | `➕` | Button text |
| Delete | `🗑️` | Button text |
| Save | `💾` | Button text |

Flet supports:
- Unicode emoji directly in `ft.Text`
- Material Icons via `ft.Icon`
- Custom SVGs via `ft.Svg`

## 9.3 Layout Principles

1. **Navigation Rail (Left):** 72px wide; icons + labels; persistent
2. **Main Content:** Flexible width; scrollable if needed
3. **Inspector (Right):** 280px fixed; collapsible
4. **Log Panel (Bottom):** 120px height; collapsible
5. **Spacing:** 16px between major sections; 8px between related items
6. **Typography:** System sans-serif; 14px body, 18px headings
7. **Buttons:** 36px height minimum; rounded 8px corners
8. **Tables:** Striped rows; hover highlight; sortable headers

## 9.4 Interaction Patterns

| Action | Feedback |
|--------|----------|
| Button click | Brief press animation; disabled state while processing |
| Form validation error | Red border + inline message below field |
| Long operation | Spinner overlay or progress bar |
| Success | Green SnackBar: "Device added" |
| Error | Red SnackBar: "Failed: <message>" |
| Selection | Highlighted border or background color change |

---

# Part 10: Gap Resolution Summary

## 10.1 Gap → Solution Mapping

| # | Gap | Solution | Location |
|---|-----|----------|----------|
| 1 | No graphical topology | `NetworkCanvas` with drag-and-drop | `components/network_canvas.py` |
| 2 | No real-time updates | `EventBus` pub/sub | `events.py` |
| 3 | CLI-only creation | `TopologyService` + dialogs | `services/`, `dialogs/` |
| 4 | No packet animation | `PacketAnimator` | `components/packet_animator.py` |
| 5 | No unified state | `AppState` dataclass + persistence | `state.py` |
| 6 | No undo/redo | Command pattern (future) | `state.py` (extensible) |
| 7 | No simulation control | `SimulationService` with pause/resume/step | `services/simulation_service.py` |
| 8 | No visual MAC/ARP tables | `MACTableGrid`, `ARPTableGrid` | `components/` |
| 9 | No drag-and-drop | `NetworkCanvas` node dragging | `components/network_canvas.py` |
| 10 | No live flow tracing | `FlowTraceView` + `HopTraceTable` | `views/`, `components/` |
| 11 | No topology persistence | `TopologyService.save/load` | `services/topology_service.py` |
| 12 | No error highlighting | Event `error:occurred` → SnackBar + Log | `events.py`, views |

## 10.2 Architecture Completeness Checklist

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  ✓ Part 1: Current State & Gap Analysis    (10+ gaps identified)          │
│  ✓ Part 2: Flet UI Architecture            (diagram, structure, components)│
│  ✓ Part 3: Service Layer                   (4 services, async bridge)     │
│  ✓ Part 4: Event Bus                       (pub/sub, 12 event types)      │
│  ✓ Part 5: State Management                (AppState, persistence)        │
│  ✓ Part 6: View Designs                    (3 ASCII mockups)              │
│  ✓ Part 7: Implementation Roadmap          (6 phases, 12 weeks)           │
│  ✓ Part 8: Technical Considerations        (async, perf, testing, pack)   │
│  ✓ Part 9: UI/UX Guidelines                (colors, icons, layout)        │
│  ✓ Part 10: Gap Resolution                 (12 gaps → 12 solutions)       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Appendix A: Dependencies

Add to `pyproject.toml`:

```toml
dependencies = [
    # ... existing dependencies ...
    "flet>=0.21.0",   # Desktop UI framework
]
```

## Appendix B: CLI Integration

Add to `cli.py`:

```python
@app.command("desktop")
def cmd_desktop() -> None:
    """Launch the Flet desktop GUI application."""
    from home_net_analyzer.desktop.app import run_app
    run_app()
```

Users run: `hna desktop`

## Appendix C: File Count Estimate

| Category | Files | Notes |
|----------|-------|-------|
| Core | 4 | `main.py`, `app.py`, `theme.py`, `state.py`, `events.py` |
| Services | 5 | 4 services + `__init__.py` |
| Views | 9 | 8 views + `__init__.py` |
| Components | 12 | 8 components + 4 dialogs + `__init__.py` |
| Tests | 10 | Unit + integration |
| **Total** | **~40** | New files in `desktop/` |

---

*End of Architecture Specification Document*
