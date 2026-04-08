from __future__ import annotations

from typing import TYPE_CHECKING

from ..country_flags import CountryResolver, detect_country
from ..link_parser import repair_node_outbound_from_link, validate_node_outbound

if TYPE_CHECKING:
    from ..app_controller import AppController
    from ..models import Node


def detect_countries_sync(controller: AppController) -> None:
    changed = False
    for node in controller.state.nodes:
        if not node.country_code:
            code = detect_country(node.name, node.server)
            if code:
                node.country_code = code
                changed = True
    if changed:
        controller.save()


def start_country_ip_resolution(controller: AppController) -> None:
    needs = [(node.id, node.server) for node in controller.state.nodes if not node.country_code]
    if not needs:
        return
    controller._country_resolver = CountryResolver(needs, parent=controller)
    controller._country_resolver.resolved.connect(controller._on_countries_resolved)
    controller._country_resolver.start()


def on_countries_resolved(controller: AppController, results: dict[str, str]) -> None:
    if not results:
        return
    for node in controller.state.nodes:
        if node.id in results:
            node.country_code = results[node.id]
    controller.save()
    controller.nodes_changed.emit(controller.state.nodes)


def get_node_by_id(controller: AppController, node_id: str | None) -> Node | None:
    if not node_id:
        return None
    for node in controller.state.nodes:
        if node.id == node_id:
            return node
    return None


def prepare_node_for_runtime(controller: AppController, node: Node | None) -> str | None:
    if node is None:
        return None
    if repair_node_outbound_from_link(node):
        controller.schedule_save()
    return validate_node_outbound(node)


def get_fastest_alive_node(controller: AppController) -> Node | None:
    alive_nodes = [node for node in controller.state.nodes if node.is_alive is True]
    if not alive_nodes:
        alive_nodes = [node for node in controller.state.nodes if node.ping_ms is not None]
    if not alive_nodes:
        return controller.selected_node
    with_speed = [node for node in alive_nodes if node.speed_mbps is not None and node.speed_mbps > 0]
    if with_speed:
        return max(with_speed, key=lambda node: node.speed_mbps)
    return min(alive_nodes, key=lambda node: node.ping_ms if node.ping_ms is not None else float("inf"))
