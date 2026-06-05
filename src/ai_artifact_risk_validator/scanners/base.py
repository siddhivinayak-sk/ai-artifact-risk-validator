"""Abstract base class for all scanner modules.

All scanner implementations must inherit from BaseScanner and implement
the abstract properties and methods defined here.
"""

from abc import ABC, abstractmethod

from ai_artifact_risk_validator.models import ArtifactType, ScanFinding, ScannerModule


class BaseScanner(ABC):
    """Abstract base class for all scanner modules.

    Scanners detect specific categories of risks in AI artifacts. Each scanner
    declares which artifact types it can analyze and which risk IDs it detects.

    Subclasses must implement:
        - name: The scanner module identifier
        - applicable_artifact_types: Which artifact types this scanner handles
        - detected_risk_ids: Which risk IDs this scanner can detect
        - scan(): The core scanning logic

    Optionally override:
        - is_available(): For scanners with optional dependencies
    """

    @property
    @abstractmethod
    def name(self) -> ScannerModule:
        """Scanner module identifier."""
        ...

    @property
    @abstractmethod
    def applicable_artifact_types(self) -> list[ArtifactType]:
        """Artifact types this scanner can analyze."""
        ...

    @property
    @abstractmethod
    def detected_risk_ids(self) -> list[str]:
        """Risk IDs this scanner is capable of detecting."""
        ...

    @abstractmethod
    def scan(
        self,
        artifact_content: str,
        artifact_type: ArtifactType,
        artifact_path: str,
    ) -> list[ScanFinding]:
        """Scan an artifact for risks.

        Args:
            artifact_content: The full text content of the artifact.
            artifact_type: Classified type of the artifact.
            artifact_path: File path of the artifact.

        Returns:
            List of ScanFinding objects (may be empty).
        """
        ...

    def is_available(self) -> bool:
        """Check if required dependencies for this scanner are installed.

        Returns True by default. Override for scanners with optional deps.
        """
        return True
