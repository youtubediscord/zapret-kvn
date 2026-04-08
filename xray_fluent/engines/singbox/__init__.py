"""sing-box engine helpers."""

from .config_builder import build_singbox_outbound
from .manager import SingBoxManager, get_singbox_version
from .operations import restart_runtime, start_tun
from .runtime_planner import (
    ParsedSingboxDocument,
    SingboxDocumentState,
    SingboxRuntimePlan,
    SingboxXraySidecarPlan,
    classify_node_for_singbox,
    inspect_singbox_document_text,
    parse_singbox_document,
    plan_singbox_runtime,
)

__all__ = [
    "build_singbox_outbound",
    "SingBoxManager",
    "get_singbox_version",
    "restart_runtime",
    "start_tun",
    "ParsedSingboxDocument",
    "SingboxDocumentState",
    "SingboxRuntimePlan",
    "SingboxXraySidecarPlan",
    "classify_node_for_singbox",
    "inspect_singbox_document_text",
    "parse_singbox_document",
    "plan_singbox_runtime",
]
