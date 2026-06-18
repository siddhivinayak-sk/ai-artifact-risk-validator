"""Tests for the OSV.dev client."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ai_artifact_risk_validator.pipeline.osv_client import OsvClient, _build_query


class TestOsvClientDisabled:
    """When allow_network=False, no network calls should be made."""

    def test_batch_query_returns_empty_when_disabled(self) -> None:
        client = OsvClient(allow_network=False)
        result = client.batch_query(
            [{"name": "requests", "version": "2.18.0", "ecosystem": "PyPI"}]
        )
        assert result == []

    def test_is_abandoned_returns_false_when_disabled(self) -> None:
        client = OsvClient(allow_network=False)
        assert client.is_abandoned("requests", "PyPI") is False

    def test_batch_query_does_not_import_requests_when_disabled(self) -> None:
        """Ensure no network calls are made when disabled."""
        client = OsvClient(allow_network=False)
        with patch("builtins.__import__") as mock_import:
            client.batch_query([{"name": "requests", "ecosystem": "PyPI"}])
            # Should not have tried to import requests for network calls
            called_modules = [call[0][0] for call in mock_import.call_args_list]
            assert "requests" not in called_modules


class TestOsvClientEnabled:
    """Tests for enabled client (with mocked network)."""

    @pytest.fixture
    def client(self) -> OsvClient:
        return OsvClient(allow_network=True)

    def test_batch_query_returns_empty_on_missing_requests(
        self, client: OsvClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When requests package not installed, should return empty list."""
        import sys

        monkeypatch.setitem(sys.modules, "requests", None)  # type: ignore[arg-type]
        result = client.batch_query([{"name": "pyyaml", "ecosystem": "PyPI"}])
        assert result == []

    def test_batch_query_with_mocked_http(self, client: OsvClient) -> None:
        """Verify the batch query correctly parses OSV.dev response."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "results": [{"vulns": [{"id": "GHSA-xxx-yyy", "summary": "Test vuln"}]}]
        }
        mock_response.raise_for_status = MagicMock()

        mock_requests = MagicMock()
        mock_requests.post.return_value = mock_response

        with patch.dict("sys.modules", {"requests": mock_requests}):
            result = client.batch_query([{"name": "pyyaml", "version": "5.3", "ecosystem": "PyPI"}])

        assert len(result) == 1
        assert result[0]["id"] == "GHSA-xxx-yyy"

    def test_batch_query_handles_api_error_gracefully(self, client: OsvClient) -> None:
        """API errors should be caught and return empty list."""
        mock_requests = MagicMock()
        mock_requests.post.side_effect = Exception("Connection refused")

        with patch.dict("sys.modules", {"requests": mock_requests}):
            result = client.batch_query([{"name": "pyyaml", "ecosystem": "PyPI"}])

        assert result == []

    def test_batch_query_empty_packages(self, client: OsvClient) -> None:
        result = client.batch_query([])
        assert result == []


class TestBuildQuery:
    def test_builds_query_with_version(self) -> None:
        q = _build_query({"name": "requests", "version": "2.18.0", "ecosystem": "PyPI"})
        assert q["package"]["name"] == "requests"
        assert q["version"] == "2.18.0"
        assert q["package"]["ecosystem"] == "PyPI"

    def test_builds_query_without_version(self) -> None:
        q = _build_query({"name": "pyyaml", "ecosystem": "PyPI"})
        assert q["package"]["name"] == "pyyaml"
        assert "version" not in q

    def test_default_ecosystem_is_pypi(self) -> None:
        q = _build_query({"name": "requests"})
        assert q["package"]["ecosystem"] == "PyPI"
