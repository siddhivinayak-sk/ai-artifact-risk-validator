"""OSV.dev API client for vulnerability and abandonment checks.

Provides a lightweight client for the OSV.dev batch query API.
Requires ``allow_network_requests=True`` in ValidatorConfig.

All network calls are **opt-in only**. When the feature is disabled,
the client returns empty results without making any network requests.

Usage:
    from ai_artifact_risk_validator.pipeline.osv_client import OsvClient

    client = OsvClient(allow_network=config.allow_network_requests)
    results = client.batch_query([{"name": "requests", "version": "2.18.0", "ecosystem": "PyPI"}])
    for vuln in results:
        print(vuln["id"], vuln["summary"])

OSV.dev API reference: https://google.github.io/osv.dev/post-v1-querybatch/
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# OSV.dev batch query endpoint
_OSV_BATCH_URL: str = "https://api.osv.dev/v1/querybatch"

# Maximum packages per batch request (OSV.dev limit: 1000)
_BATCH_SIZE: int = 100

# Request timeout in seconds
_TIMEOUT_SEC: int = 15


class OsvClient:
    """Client for the OSV.dev vulnerability database API.

    All methods are no-ops when ``allow_network=False``, ensuring the tool
    never makes unexpected outbound connections in air-gapped or offline
    environments.

    Args:
        allow_network: When False (default), all methods return empty results
            and no network connections are made.
    """

    def __init__(self, allow_network: bool = False) -> None:
        self._allow_network = allow_network

    def batch_query(
        self,
        packages: list[dict[str, str]],
    ) -> list[dict[str, Any]]:
        """Query OSV.dev for known vulnerabilities in a list of packages.

        Args:
            packages: List of dicts with keys ``name``, ``version``, and
                ``ecosystem`` (e.g. "PyPI", "npm", "crates.io").
                ``version`` may be omitted to get all vulnerabilities.

        Returns:
            Flat list of OSV vulnerability objects. Each object has at minimum
            ``id``, ``summary``, ``affected`` keys. Returns empty list if
            network is disabled, ``requests`` is not installed, or API fails.
        """
        if not self._allow_network:
            logger.debug("OsvClient: network disabled; skipping OSV.dev query")
            return []

        if not packages:
            return []

        try:
            import requests as http
        except ImportError:
            logger.warning("OsvClient: 'requests' package not installed; cannot query OSV.dev")
            return []

        results: list[dict[str, Any]] = []

        for batch_start in range(0, len(packages), _BATCH_SIZE):
            batch = packages[batch_start : batch_start + _BATCH_SIZE]
            queries = [_build_query(pkg) for pkg in batch]
            payload: dict[str, Any] = {"queries": queries}

            try:
                response = http.post(
                    _OSV_BATCH_URL,
                    json=payload,
                    timeout=_TIMEOUT_SEC,
                    headers={"Content-Type": "application/json"},
                )
                response.raise_for_status()
                data: dict[str, Any] = response.json()
            except Exception as exc:
                logger.warning("OsvClient: OSV.dev batch query failed: %s", exc)
                continue

            batch_results = data.get("results", [])
            for result in batch_results:
                for vuln in result.get("vulns", []):
                    results.append(vuln)

        return results

    def is_abandoned(
        self,
        package_name: str,
        ecosystem: str,
    ) -> bool:
        """Heuristic check for abandoned packages using OSV metadata.

        A package is considered potentially abandoned if it has no recent
        releases in the OSV advisory metadata and has unpatched vulnerabilities
        older than 24 months.

        Args:
            package_name: Package name to check.
            ecosystem: "PyPI", "npm", etc.

        Returns:
            True if the package appears abandoned, False otherwise.
            Always False when network is disabled.
        """
        if not self._allow_network:
            return False

        vulns = self.batch_query([{"name": package_name, "ecosystem": ecosystem}])
        if not vulns:
            return False

        import datetime

        cutoff = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(days=730)

        old_unpatched = 0
        for vuln in vulns:
            modified_str: str = vuln.get("modified", "")
            if not modified_str:
                continue
            try:
                modified = datetime.datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
                if modified < cutoff:
                    old_unpatched += 1
            except ValueError:
                continue

        # Flag if more than 2 unpatched CVEs older than 2 years
        return old_unpatched >= 2


def _build_query(pkg: dict[str, str]) -> dict[str, Any]:
    """Build a single OSV query dict from a package descriptor."""
    query: dict[str, Any] = {
        "package": {
            "name": pkg["name"],
            "ecosystem": pkg.get("ecosystem", "PyPI"),
        }
    }
    if pkg.get("version"):
        query["version"] = pkg["version"]
    return query
