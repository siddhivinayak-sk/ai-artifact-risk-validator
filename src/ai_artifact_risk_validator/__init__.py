"""AI Artifact Risk Validator - Validates AI artifacts for security, performance, quality, compliance, and operational risks."""

__version__ = "0.10.0"


from typing import Any


def __getattr__(name: str) -> Any:
    """Lazy import for Validator to avoid circular imports during package setup."""
    if name == "Validator":
        from ai_artifact_risk_validator.validator import Validator

        return Validator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["Validator", "__version__"]
