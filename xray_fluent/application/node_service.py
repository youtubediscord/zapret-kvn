from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import QTimer

from ..country_flags import detect_country
from ..link_parser import parse_links_text, validate_node_outbound

if TYPE_CHECKING:
    from ..app_controller import AppController


def import_nodes_from_text(controller: AppController, text: str) -> tuple[int, list[str]]:
    nodes, errors = parse_links_text(text)
    if not nodes:
        return 0, errors

    existing_links = {node.link for node in controller.state.nodes}
    max_order = max((node.sort_order for node in controller.state.nodes), default=0)
    first_new_id: str | None = None
    added = 0
    for node in nodes:
        problem = validate_node_outbound(node)
        if problem:
            errors.append(problem)
            continue
        if node.link in existing_links:
            continue
        if not node.country_code:
            node.country_code = detect_country(node.name, node.server)
        max_order += 1
        node.sort_order = max_order
        controller.state.nodes.append(node)
        existing_links.add(node.link)
        if first_new_id is None:
            first_new_id = node.id
        added += 1

    if first_new_id:
        controller.state.selected_node_id = first_new_id
    elif not controller.state.selected_node_id and controller.state.nodes:
        controller.state.selected_node_id = controller.state.nodes[0].id

    controller.nodes_changed.emit(controller.state.nodes)
    controller.selection_changed.emit(controller.selected_node)
    controller.save()
    QTimer.singleShot(500, controller._start_country_ip_resolution)

    if added:
        controller._desired_connected = True
        controller._request_transition("new node imported")

    return added, errors


def remove_nodes(controller: AppController, node_ids: set[str]) -> None:
    if not node_ids:
        return
    removed_selected = controller.state.selected_node_id in node_ids
    should_reconcile = removed_selected and (controller.connected or controller._desired_connected)
    controller.state.nodes = [node for node in controller.state.nodes if node.id not in node_ids]
    if removed_selected:
        controller.state.selected_node_id = controller.state.nodes[0].id if controller.state.nodes else None
        controller._reset_auto_switch_state(reset_cooldown=True, reset_cycle=True)
    controller.nodes_changed.emit(controller.state.nodes)
    controller.selection_changed.emit(controller.selected_node)
    controller.save()
    if not should_reconcile:
        return
    if controller.state.selected_node_id is None:
        if controller._can_connect_without_selected_node():
            controller._request_transition("active node removed")
            return
        controller._desired_connected = False
        controller._request_transition("active node removed")
        return
    controller._desired_connected = True
    controller._request_transition("active node removed")


def update_node(controller: AppController, node_id: str, updates: dict) -> bool:
    node = controller._get_node_by_id(node_id)
    if not node:
        return False
    if "name" in updates:
        node.name = updates["name"]
    if "group" in updates:
        node.group = updates["group"]
    if "tags" in updates:
        node.tags = list(updates["tags"])
    controller.nodes_changed.emit(controller.state.nodes)
    controller.save()
    return True


def bulk_update_nodes(controller: AppController, node_ids: set[str], operations: dict) -> int:
    group = operations.get("group", "")
    add_tags = operations.get("add_tags", [])
    remove_tags = set(operations.get("remove_tags", []))
    updated = 0
    for node in controller.state.nodes:
        if node.id not in node_ids:
            continue
        if group:
            node.group = group
        if add_tags:
            existing = set(node.tags)
            for tag in add_tags:
                if tag not in existing:
                    node.tags.append(tag)
        if remove_tags:
            node.tags = [tag for tag in node.tags if tag not in remove_tags]
        updated += 1
    if updated:
        controller.nodes_changed.emit(controller.state.nodes)
        controller.save()
    return updated


def get_all_groups(controller: AppController) -> list[str]:
    return sorted({node.group for node in controller.state.nodes if node.group})


def get_all_tags(controller: AppController) -> list[str]:
    tags: set[str] = set()
    for node in controller.state.nodes:
        tags.update(node.tags)
    return sorted(tags)


def reorder_nodes(controller: AppController, node_id: str, direction: str) -> None:
    ordered = sorted(controller.state.nodes, key=lambda node: node.sort_order)
    idx = next((i for i, node in enumerate(ordered) if node.id == node_id), None)
    if idx is None:
        return
    if direction == "up" and idx > 0:
        ordered[idx], ordered[idx - 1] = ordered[idx - 1], ordered[idx]
    elif direction == "down" and idx < len(ordered) - 1:
        ordered[idx], ordered[idx + 1] = ordered[idx + 1], ordered[idx]
    elif direction == "top" and idx > 0:
        node = ordered.pop(idx)
        ordered.insert(0, node)
    elif direction == "bottom" and idx < len(ordered) - 1:
        node = ordered.pop(idx)
        ordered.append(node)
    else:
        return
    for index, node in enumerate(ordered):
        node.sort_order = index + 1
    controller.nodes_changed.emit(controller.state.nodes)
    controller.save()


def set_selected_node(controller: AppController, node_id: str) -> None:
    if controller.state.selected_node_id == node_id:
        return
    controller.state.selected_node_id = node_id
    controller._reset_auto_switch_state(reset_cooldown=True, reset_cycle=True)
    controller.selection_changed.emit(controller.selected_node)
    controller.schedule_save()
    if controller.connected or controller._desired_connected:
        controller._desired_connected = True
        controller._request_transition("node switched")
