"""Pipeline engine for file discovery, scanner execution, and finding aggregation."""

from ai_artifact_risk_validator.pipeline.aggregator import Aggregator
from ai_artifact_risk_validator.pipeline.discovery import FileDiscovery
from ai_artifact_risk_validator.pipeline.executor import PipelineExecutor
from ai_artifact_risk_validator.pipeline.gate import (
    assign_gate_action,
    compute_overall_gate,
    should_suppress,
)

__all__ = [
    "Aggregator",
    "FileDiscovery",
    "PipelineExecutor",
    "assign_gate_action",
    "compute_overall_gate",
    "should_suppress",
]
