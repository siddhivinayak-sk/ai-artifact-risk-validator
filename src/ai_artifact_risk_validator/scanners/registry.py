"""Scanner registry for managing scanner module discovery, registration, and lifecycle.

The ScannerRegistry supports three discovery mechanisms:
1. Direct Python API registration via register()
2. Python entry point discovery (ai_artifact_validator.scanners group)
3. Plugin directory loading from .py files
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from ai_artifact_risk_validator._internal.logging import get_logger
from ai_artifact_risk_validator.models.enums import ArtifactType, ScannerModule
from ai_artifact_risk_validator.scanners.base import BaseScanner

if TYPE_CHECKING:
    from ai_artifact_risk_validator.models.config import ValidatorConfig

logger = get_logger(__name__)


class ScannerRegistry:
    """Manages scanner module discovery, registration, and lifecycle.

    Scanners are stored as classes and instantiated lazily on first access.
    The registry respects enabled/disabled configuration and availability checks.
    """

    def __init__(self, config: ValidatorConfig | None = None) -> None:
        """Initialize the scanner registry.

        Args:
            config: Optional validator configuration for enabled/disabled scanner filtering.
        """
        self._scanner_classes: dict[ScannerModule, type[BaseScanner]] = {}
        self._scanner_instances: dict[ScannerModule, BaseScanner] = {}
        self._config = config

    def register(self, scanner_class: type[BaseScanner]) -> None:
        """Register a scanner class for lazy instantiation.

        Args:
            scanner_class: A class that inherits from BaseScanner.

        Raises:
            TypeError: If scanner_class is not a subclass of BaseScanner.
        """
        if not (isinstance(scanner_class, type) and issubclass(scanner_class, BaseScanner)):
            raise TypeError(
                f"Expected a subclass of BaseScanner, got {scanner_class!r}"
            )

        # We need to get the name from the class. Since `name` is an abstract property,
        # we instantiate temporarily only to read the name, but to support lazy loading
        # we'll try to get it from the class if possible, otherwise instantiate.
        try:
            instance = scanner_class()
            name = instance.name
            # Store the instance so we don't need to re-create it
            self._scanner_classes[name] = scanner_class
            self._scanner_instances[name] = instance
        except Exception:
            # If instantiation fails (e.g. missing deps), we still store the class
            # but we can't get the name without instantiation for abstract properties.
            # In practice, scanners should always be instantiable at registration time
            # or provide the name some other way.
            logger.warning(
                "Failed to instantiate scanner class during registration",
                scanner_class=scanner_class.__name__,
            )

    def discover_entry_points(self) -> None:
        """Discover scanners via Python entry points.

        Looks for entry points in the 'ai_artifact_validator.scanners' group
        and registers any BaseScanner subclasses found.
        """
        try:
            if sys.version_info >= (3, 12):
                from importlib.metadata import entry_points

                eps = entry_points(group="ai_artifact_validator.scanners")
            else:
                from importlib.metadata import entry_points

                eps = entry_points(group="ai_artifact_validator.scanners")
        except Exception as exc:
            logger.warning("Failed to query entry points", error=str(exc))
            return

        for ep in eps:
            try:
                scanner_class = ep.load()
                if isinstance(scanner_class, type) and issubclass(scanner_class, BaseScanner):
                    self.register(scanner_class)
                    logger.debug("Discovered scanner via entry point", entry_point=ep.name)
                else:
                    logger.warning(
                        "Entry point did not resolve to a BaseScanner subclass",
                        entry_point=ep.name,
                    )
            except Exception as exc:
                logger.warning(
                    "Failed to load entry point",
                    entry_point=ep.name,
                    error=str(exc),
                )

    def discover_plugin_dir(self, path: Path) -> None:
        """Discover scanners from a plugin directory.

        Loads all .py files from the given directory and registers any
        BaseScanner subclasses found within them.

        Args:
            path: Directory path to scan for scanner plugin files.
        """
        if not path.is_dir():
            logger.warning("Plugin directory does not exist", plugin_dir=str(path))
            return

        for py_file in sorted(path.glob("*.py")):
            if py_file.name.startswith("_"):
                continue

            module_name = f"aav_plugin_{py_file.stem}"
            try:
                spec = importlib.util.spec_from_file_location(module_name, py_file)
                if spec is None or spec.loader is None:
                    logger.warning(
                        "Could not load spec for plugin file",
                        plugin_file=str(py_file),
                    )
                    continue

                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)  # type: ignore[union-attr]

                # Find all BaseScanner subclasses in the module
                for _name, obj in inspect.getmembers(module, inspect.isclass):
                    if (
                        issubclass(obj, BaseScanner)
                        and obj is not BaseScanner
                        and not inspect.isabstract(obj)
                    ):
                        self.register(obj)
                        logger.debug(
                            "Discovered scanner from plugin file",
                            scanner_class=_name,
                            plugin_file=str(py_file),
                        )
            except Exception as exc:
                logger.warning(
                    "Failed to load plugin file",
                    plugin_file=str(py_file),
                    error=str(exc),
                )

    def get_scanners_for_artifact(
        self, artifact_type: ArtifactType
    ) -> list[BaseScanner]:
        """Return scanner instances applicable to the given artifact type.

        Filters scanners based on:
        1. Artifact type applicability
        2. Enabled/disabled configuration
        3. Scanner availability (is_available() check)

        Args:
            artifact_type: The type of artifact to find scanners for.

        Returns:
            List of scanner instances that can scan the given artifact type.
        """
        result: list[BaseScanner] = []

        for name, scanner_class in self._scanner_classes.items():
            # Check enabled/disabled configuration
            if not self._is_scanner_enabled(name):
                continue

            # Get or create the scanner instance (lazy instantiation)
            instance = self._get_or_create_instance(name, scanner_class)
            if instance is None:
                continue

            # Check if scanner applies to this artifact type
            if artifact_type not in instance.applicable_artifact_types:
                continue

            # Check if scanner is available (dependencies installed)
            try:
                if not instance.is_available():
                    logger.debug(
                        "Scanner is not available (missing dependencies)",
                        scanner_module=name.value,
                    )
                    continue
            except Exception as exc:
                logger.warning(
                    "Scanner availability check failed",
                    scanner_module=name.value,
                    error=str(exc),
                )
                continue

            result.append(instance)

        return result

    def get_scanner_by_name(self, name: ScannerModule) -> BaseScanner | None:
        """Retrieve a specific scanner by its module name.

        Args:
            name: The ScannerModule enum value to look up.

        Returns:
            The scanner instance, or None if not registered or not available.
        """
        if name not in self._scanner_classes:
            return None

        scanner_class = self._scanner_classes[name]
        instance = self._get_or_create_instance(name, scanner_class)
        return instance

    def _is_scanner_enabled(self, name: ScannerModule) -> bool:
        """Check if a scanner is enabled based on configuration.

        Args:
            name: The scanner module name to check.

        Returns:
            True if the scanner should be used, False otherwise.
        """
        if self._config is None:
            return True

        # If in disabled list, skip it
        if name in self._config.disabled_scanners:
            return False

        # If enabled list is specified, only allow scanners in that list
        if self._config.enabled_scanners is not None:
            return name in self._config.enabled_scanners

        return True

    def _get_or_create_instance(
        self, name: ScannerModule, scanner_class: type[BaseScanner]
    ) -> BaseScanner | None:
        """Get an existing instance or create one lazily.

        Args:
            name: The scanner module name.
            scanner_class: The scanner class to instantiate.

        Returns:
            The scanner instance, or None if instantiation fails.
        """
        if name in self._scanner_instances:
            return self._scanner_instances[name]

        try:
            instance = scanner_class()
            self._scanner_instances[name] = instance
            return instance
        except Exception as exc:
            logger.warning(
                "Failed to instantiate scanner",
                scanner_module=name.value,
                error=str(exc),
            )
            return None

    @property
    def registered_scanners(self) -> list[ScannerModule]:
        """Return a list of all registered scanner module names."""
        return list(self._scanner_classes.keys())
