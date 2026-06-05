"""Internal utilities for caching, hashing, suppression logic, and logging."""

from ai_artifact_risk_validator._internal.cache import ScanCache
from ai_artifact_risk_validator._internal.hashing import compute_cache_key, compute_content_hash
from ai_artifact_risk_validator._internal.logging import (
    bind_scan_context,
    clear_scan_context,
    configure_logging,
    get_logger,
)
from ai_artifact_risk_validator._internal.suppression import (
    apply_config_suppressions,
    apply_inline_suppressions,
    clear_suppressions,
    parse_inline_suppressions,
)

__all__ = [
    "ScanCache",
    "apply_config_suppressions",
    "apply_inline_suppressions",
    "bind_scan_context",
    "clear_scan_context",
    "clear_suppressions",
    "compute_cache_key",
    "compute_content_hash",
    "configure_logging",
    "get_logger",
    "parse_inline_suppressions",
]
