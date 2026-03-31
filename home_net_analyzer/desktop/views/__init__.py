"""Views (pages) for the Flet desktop application."""

from home_net_analyzer.desktop.views.dashboard_view import build_dashboard_view
from home_net_analyzer.desktop.views.topology_view import build_topology_view
from home_net_analyzer.desktop.views.device_detail_view import build_device_detail_view
from home_net_analyzer.desktop.views.simulation_view import build_simulation_view
from home_net_analyzer.desktop.views.flow_trace_view import build_flow_trace_view
from home_net_analyzer.desktop.views.packet_view import build_packet_view
from home_net_analyzer.desktop.views.rules_view import build_rules_view
from home_net_analyzer.desktop.views.settings_view import build_settings_view

__all__ = [
    "build_dashboard_view",
    "build_topology_view",
    "build_device_detail_view",
    "build_simulation_view",
    "build_flow_trace_view",
    "build_packet_view",
    "build_rules_view",
    "build_settings_view",
]
