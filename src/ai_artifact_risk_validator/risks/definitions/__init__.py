"""Risk definition modules for all artifact types and cross-cutting concerns.

Provides the load_all_risks() function that imports all definition modules
and collects their RISKS lists into a single flat list of RiskDefinition objects.
"""

from __future__ import annotations

import importlib
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_artifact_risk_validator.models.risk import RiskDefinition

logger = logging.getLogger(__name__)

# Module names within this package that export a RISKS list.
# Each module is expected to define: RISKS: list[RiskDefinition]
_DEFINITION_MODULES: list[str] = [
    "prompts",
    "skills",
    "agents",
    "sops",
    "steering",
    "mcp",
    "hooks",
    "instructions",
    "plugins",
    "memory",
    "rag",
    "eval_harness",
    "orchestration",
    "api_schema",
    "cross_cutting",
    "yara_risks",
    "taint_tracking",
    "dep_scan_risks",
]


def load_all_risks() -> list[RiskDefinition]:
    """Load all built-in risk definitions from definition modules.

    Imports each definition module and collects the RISKS variable from it.
    Modules that don't exist yet or lack a RISKS attribute are skipped
    gracefully with a debug-level log message.

    Returns:
        A flat list of all RiskDefinition objects from all definition modules.
    """
    from ai_artifact_risk_validator.models.risk import RiskDefinition

    all_risks: list[RiskDefinition] = []

    for module_name in _DEFINITION_MODULES:
        full_module_path = f"ai_artifact_risk_validator.risks.definitions.{module_name}"
        try:
            module = importlib.import_module(full_module_path)
        except ImportError:
            logger.debug("Risk definition module not found: %s", full_module_path)
            continue

        risks = getattr(module, "RISKS", None)
        if risks is None:
            logger.debug(
                "Module %s does not export a RISKS variable, skipping.",
                full_module_path,
            )
            continue

        if not isinstance(risks, list):
            logger.warning(
                "Module %s RISKS is not a list, skipping.",
                full_module_path,
            )
            continue

        for risk in risks:
            if isinstance(risk, RiskDefinition):
                all_risks.append(risk)
            else:
                logger.warning(
                    "Non-RiskDefinition item in %s.RISKS, skipping: %r",
                    full_module_path,
                    risk,
                )

    return all_risks
