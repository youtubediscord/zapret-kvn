"""Config/profile/runtime-config facade."""

from .config_documents import SingboxDocumentCache
from .config_profiles import (
    default_singbox_config_text,
    default_xray_config_text,
    format_json_error_message,
    normalize_relative_json_path,
    resolve_profile_path,
    validate_json_text,
)
from .profile_service import (
    apply_singbox_config_text,
    apply_xray_config_text,
    ensure_active_config,
    get_active_config_name,
    get_active_config_path,
    get_active_template_path,
    import_template,
    load_active_config_text,
    load_config_text,
    reset_active_config_to_template,
    save_config_text,
)
from .runtime_introspection import (
    collect_xray_inbound_ports,
    config_has_proxy_outbound,
    ensure_dict,
    ensure_list,
    extract_xray_runtime_ports,
    infer_singbox_outbound_endpoint,
    infer_singbox_ping_target,
    infer_xray_outbound_endpoint,
    infer_xray_ping_target,
    is_local_runtime_host,
    replace_or_append_tagged,
)
from .xray_runtime_service import (
    apply_xray_tun_loop_prevention,
    build_runtime_xray_config,
    ensure_xray_metrics_contract,
    ensure_xray_tun_contract,
    inspect_active_xray_config,
    xray_outbound_is_loop_protected,
)
