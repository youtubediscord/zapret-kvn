"""Node/domain/country facade."""

from .auto_switch_service import check_auto_switch, get_next_node_for_auto_switch
from .node_runtime_service import (
    detect_countries_sync,
    get_fastest_alive_node,
    get_node_by_id,
    on_countries_resolved,
    prepare_node_for_runtime,
    start_country_ip_resolution,
)
from .node_service import (
    bulk_update_nodes,
    get_all_groups,
    get_all_tags,
    import_nodes_from_text,
    remove_nodes,
    reorder_nodes,
    set_selected_node,
    update_node,
)
