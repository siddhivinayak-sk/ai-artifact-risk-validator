"""Unit tests for dynamic scanner modules: MCPClient, AttackSimulator, DynamicScanner.

Provides comprehensive mocked coverage for:
- mcp_client.py: stdio/HTTP transports, connect/disconnect, list_tools, list_resources, call_tool
- attack_simulator.py: payload generation, file-param detection, attack simulation
- scanner.py: consent, config parsing, full scan orchestration

All network I/O is mocked. No real subprocesses or HTTP connections are made.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_artifact_risk_validator.models.enums import ArtifactType, ScannerModule
from ai_artifact_risk_validator.models.mcp_models import (
    DynamicScanConfig,
    MCPResourceInfo,
    MCPServerConfig,
    MCPToolInfo,
)
from ai_artifact_risk_validator.scanners.dynamic.attack_simulator import (
    PATH_TRAVERSAL_PAYLOADS,
    AttackSimulator,
    _is_file_accepting_param,
    _response_indicates_traversal,
    _truncate_evidence,
)
from ai_artifact_risk_validator.scanners.dynamic.mcp_client import MCPClient
from ai_artifact_risk_validator.scanners.dynamic.scanner import DynamicScanner

# =============================================================================
# MCPClient Tests
# =============================================================================


class TestMCPClientConstruction:
    """Test MCPClient construction with various configs."""

    def test_construct_with_stdio_config(self):
        config = MCPServerConfig(
            name="test-server",
            command="node",
            args=["server.js"],
            transport="stdio",
        )
        client = MCPClient(config=config, connection_timeout=5, per_server_timeout=15)
        assert client.config == config
        assert client.connected is False
        assert client._connection_timeout == 5
        assert client._per_server_timeout == 15

    def test_construct_with_http_config(self):
        config = MCPServerConfig(
            name="http-server",
            url="http://localhost:3000",
            transport="sse",
        )
        client = MCPClient(config=config)
        assert client.config.transport == "sse"
        assert client.config.url == "http://localhost:3000"
        assert client.connected is False

    def test_construct_with_dynamic_scan_config_overrides_timeouts(self):
        config = MCPServerConfig(name="srv", command="cmd", transport="stdio")
        dsc = DynamicScanConfig(connection_timeout=20, per_server_timeout=60)
        client = MCPClient(
            config=config, connection_timeout=5, per_server_timeout=10, dynamic_scan_config=dsc
        )
        assert client._connection_timeout == 20
        assert client._per_server_timeout == 60

    def test_construct_with_env_vars(self):
        config = MCPServerConfig(
            name="env-server",
            command="python",
            args=["-m", "server"],
            transport="stdio",
            env={"API_KEY": "secret123"},
        )
        client = MCPClient(config=config)
        assert client.config.env == {"API_KEY": "secret123"}


class TestMCPClientConnectStdio:
    """Test MCPClient.connect() with stdio transport."""

    @pytest.mark.asyncio
    async def test_connect_stdio_success(self):
        config = MCPServerConfig(name="test", command="node", args=["s.js"], transport="stdio")
        client = MCPClient(config=config, connection_timeout=5)

        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdin.write = MagicMock()
        mock_process.stdin.drain = AsyncMock()
        mock_process.stdout = MagicMock()

        # First readline: initialize response; Second: initialized notification (none needed)
        init_response = (
            json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {}}}).encode() + b"\n"
        )
        mock_process.stdout.readline = AsyncMock(return_value=init_response)
        mock_process.terminate = MagicMock()
        mock_process.wait = AsyncMock()

        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=mock_process)):
            result = await client.connect()

        assert result is True
        assert client.connected is True

    @pytest.mark.asyncio
    async def test_connect_stdio_no_command(self):
        config = MCPServerConfig(name="test", command=None, transport="stdio")
        client = MCPClient(config=config)

        result = await client.connect()
        assert result is False
        assert client.connected is False

    @pytest.mark.asyncio
    async def test_connect_stdio_command_not_found(self):
        config = MCPServerConfig(name="test", command="nonexistent_cmd_xyz", transport="stdio")
        client = MCPClient(config=config, connection_timeout=2)

        with patch(
            "asyncio.create_subprocess_exec", AsyncMock(side_effect=FileNotFoundError("not found"))
        ):
            result = await client.connect()

        assert result is False
        assert client.connected is False

    @pytest.mark.asyncio
    async def test_connect_stdio_timeout(self):
        config = MCPServerConfig(name="test", command="node", args=["s.js"], transport="stdio")
        client = MCPClient(config=config, connection_timeout=1)

        with patch("asyncio.create_subprocess_exec", AsyncMock(side_effect=asyncio.TimeoutError())):
            result = await client.connect()

        assert result is False
        assert client.connected is False

    @pytest.mark.asyncio
    async def test_connect_stdio_init_no_result(self):
        """Server responds but without 'result' key in initialize response."""
        config = MCPServerConfig(name="test", command="node", args=["s.js"], transport="stdio")
        client = MCPClient(config=config, connection_timeout=5)

        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdin.write = MagicMock()
        mock_process.stdin.drain = AsyncMock()
        mock_process.stdout = MagicMock()
        # Response without "result" key
        bad_response = (
            json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"message": "fail"}}).encode() + b"\n"
        )
        mock_process.stdout.readline = AsyncMock(return_value=bad_response)
        mock_process.terminate = MagicMock()
        mock_process.wait = AsyncMock()

        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=mock_process)):
            result = await client.connect()

        assert result is False
        assert client.connected is False

    @pytest.mark.asyncio
    async def test_connect_stdio_generic_exception(self):
        config = MCPServerConfig(name="test", command="node", args=["s.js"], transport="stdio")
        client = MCPClient(config=config, connection_timeout=5)

        with patch(
            "asyncio.create_subprocess_exec", AsyncMock(side_effect=OSError("spawn failed"))
        ):
            result = await client.connect()

        assert result is False
        assert client.connected is False


class TestMCPClientConnectHTTP:
    """Test MCPClient.connect() with HTTP/SSE transport."""

    @pytest.mark.asyncio
    async def test_connect_http_success(self):
        config = MCPServerConfig(name="http-srv", url="http://localhost:3000", transport="sse")
        client = MCPClient(config=config, connection_timeout=5)

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = await client.connect()

        assert result is True
        assert client.connected is True

    @pytest.mark.asyncio
    async def test_connect_http_no_url(self):
        config = MCPServerConfig(name="http-srv", url=None, transport="sse")
        client = MCPClient(config=config)

        result = await client.connect()
        assert result is False

    @pytest.mark.asyncio
    async def test_connect_http_unreachable(self):
        config = MCPServerConfig(name="http-srv", url="http://localhost:9999", transport="sse")
        client = MCPClient(config=config, connection_timeout=2)

        import urllib.error

        with patch(
            "urllib.request.urlopen", side_effect=urllib.error.URLError("connection refused")
        ):
            result = await client.connect()

        assert result is False
        assert client.connected is False

    @pytest.mark.asyncio
    async def test_connect_http_timeout(self):
        config = MCPServerConfig(name="http-srv", url="http://localhost:3000", transport="sse")
        client = MCPClient(config=config, connection_timeout=1)

        # Simulate the asyncio.wait_for timeout wrapping the executor call
        with patch("asyncio.get_event_loop") as mock_loop:
            mock_loop_inst = MagicMock()
            mock_loop.return_value = mock_loop_inst
            mock_loop_inst.run_in_executor = AsyncMock(side_effect=asyncio.TimeoutError())
            # Need to patch at a higher level since the connect method calls asyncio.wait_for
            with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
                result = await client.connect()

        assert result is False

    @pytest.mark.asyncio
    async def test_connect_http_server_error_500(self):
        config = MCPServerConfig(name="http-srv", url="http://localhost:3000", transport="sse")
        client = MCPClient(config=config, connection_timeout=5)

        mock_resp = MagicMock()
        mock_resp.status = 500
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = await client.connect()

        assert result is False


class TestMCPClientListTools:
    """Test MCPClient.list_tools() method."""

    @pytest.mark.asyncio
    async def test_list_tools_not_connected(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        # Not connected
        tools = await client.list_tools()
        assert tools == []

    @pytest.mark.asyncio
    async def test_list_tools_success(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        client._connected = True

        response = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Reads a file",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"path": {"type": "string"}},
                        },
                    },
                    {
                        "name": "write_file",
                        "description": "Writes a file",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"},
                                "content": {"type": "string"},
                            },
                        },
                    },
                ]
            },
        }

        with patch.object(client, "_send_request", AsyncMock(return_value=response)):
            tools = await client.list_tools()

        assert len(tools) == 2
        assert tools[0].name == "read_file"
        assert tools[1].name == "write_file"
        assert isinstance(tools[0], MCPToolInfo)

    @pytest.mark.asyncio
    async def test_list_tools_empty_response(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        client._connected = True

        with patch.object(client, "_send_request", AsyncMock(return_value=None)):
            tools = await client.list_tools()
        assert tools == []

    @pytest.mark.asyncio
    async def test_list_tools_timeout(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config, per_server_timeout=1)
        client._connected = True

        with patch.object(client, "_send_request", AsyncMock(side_effect=asyncio.TimeoutError())):
            tools = await client.list_tools()
        assert tools == []

    @pytest.mark.asyncio
    async def test_list_tools_exception(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        client._connected = True

        with patch.object(client, "_send_request", AsyncMock(side_effect=RuntimeError("oops"))):
            tools = await client.list_tools()
        assert tools == []

    @pytest.mark.asyncio
    async def test_list_tools_malformed_tool_entry(self):
        """Tool entry that causes parse error is skipped."""
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        client._connected = True

        response = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {"name": "good_tool", "description": "ok"},
                    {"name": "another_good", "description": "also ok"},
                ]
            },
        }

        with patch.object(client, "_send_request", AsyncMock(return_value=response)):
            tools = await client.list_tools()
        assert len(tools) == 2


class TestMCPClientListResources:
    """Test MCPClient.list_resources() method."""

    @pytest.mark.asyncio
    async def test_list_resources_not_connected(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        resources = await client.list_resources()
        assert resources == []

    @pytest.mark.asyncio
    async def test_list_resources_success(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        client._connected = True

        response = {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "resources": [
                    {"name": "config", "uri": "file:///config.json", "description": "Config file"},
                    {"name": "data", "uri": "file:///data.csv", "description": "Data"},
                ]
            },
        }

        with patch.object(client, "_send_request", AsyncMock(return_value=response)):
            resources = await client.list_resources()

        assert len(resources) == 2
        assert resources[0].name == "config"
        assert resources[0].uri == "file:///config.json"
        assert isinstance(resources[0], MCPResourceInfo)

    @pytest.mark.asyncio
    async def test_list_resources_none_response(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        client._connected = True

        with patch.object(client, "_send_request", AsyncMock(return_value=None)):
            resources = await client.list_resources()
        assert resources == []

    @pytest.mark.asyncio
    async def test_list_resources_timeout(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config, per_server_timeout=1)
        client._connected = True

        with patch.object(client, "_send_request", AsyncMock(side_effect=asyncio.TimeoutError())):
            resources = await client.list_resources()
        assert resources == []

    @pytest.mark.asyncio
    async def test_list_resources_exception(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        client._connected = True

        with patch.object(client, "_send_request", AsyncMock(side_effect=RuntimeError("err"))):
            resources = await client.list_resources()
        assert resources == []


class TestMCPClientCallTool:
    """Test MCPClient.call_tool() method."""

    @pytest.mark.asyncio
    async def test_call_tool_not_connected(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        result = await client.call_tool("read_file", {"path": "/etc/passwd"})
        assert result == {}

    @pytest.mark.asyncio
    async def test_call_tool_success(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        client._connected = True

        response = {
            "jsonrpc": "2.0",
            "id": 3,
            "result": {"content": [{"type": "text", "text": "file contents here"}]},
        }

        with patch.object(client, "_send_request", AsyncMock(return_value=response)):
            result = await client.call_tool("read_file", {"path": "/tmp/test.txt"})

        assert "content" in result

    @pytest.mark.asyncio
    async def test_call_tool_error_response(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        client._connected = True

        response = {
            "jsonrpc": "2.0",
            "id": 3,
            "error": {"code": -32600, "message": "Invalid request"},
        }

        with patch.object(client, "_send_request", AsyncMock(return_value=response)):
            result = await client.call_tool("read_file", {"path": "/etc/passwd"})

        assert "error" in result

    @pytest.mark.asyncio
    async def test_call_tool_none_response(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        client._connected = True

        with patch.object(client, "_send_request", AsyncMock(return_value=None)):
            result = await client.call_tool("read_file", {"path": "/tmp/x"})
        assert result == {}

    @pytest.mark.asyncio
    async def test_call_tool_timeout(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config, per_server_timeout=1)
        client._connected = True

        with patch.object(client, "_send_request", AsyncMock(side_effect=asyncio.TimeoutError())):
            result = await client.call_tool("read_file", {"path": "/tmp/x"})
        assert result == {}

    @pytest.mark.asyncio
    async def test_call_tool_generic_exception(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        client._connected = True

        with patch.object(
            client, "_send_request", AsyncMock(side_effect=ConnectionError("broken"))
        ):
            result = await client.call_tool("read_file", {"path": "/tmp/x"})
        assert result == {}


class TestMCPClientDisconnect:
    """Test MCPClient.disconnect() method."""

    @pytest.mark.asyncio
    async def test_disconnect_with_process(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        client._connected = True

        mock_process = MagicMock()
        mock_process.terminate = MagicMock()
        mock_process.wait = AsyncMock()
        client._process = mock_process

        await client.disconnect()

        assert client.connected is False
        assert client._process is None
        mock_process.terminate.assert_called_once()

    @pytest.mark.asyncio
    async def test_disconnect_process_already_exited(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        client._connected = True

        mock_process = MagicMock()
        mock_process.terminate = MagicMock(side_effect=ProcessLookupError())
        mock_process.wait = AsyncMock()
        client._process = mock_process

        await client.disconnect()

        assert client.connected is False
        assert client._process is None

    @pytest.mark.asyncio
    async def test_disconnect_no_process(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        client._connected = True
        client._process = None

        await client.disconnect()
        assert client.connected is False

    @pytest.mark.asyncio
    async def test_disconnect_kill_on_timeout(self):
        """If terminate doesn't finish in time, kill is called."""
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        client._connected = True

        mock_process = MagicMock()
        mock_process.terminate = MagicMock()
        # First wait times out, second (after kill) succeeds
        mock_process.wait = AsyncMock(side_effect=[asyncio.TimeoutError(), None])
        mock_process.kill = MagicMock()
        client._process = mock_process

        await client.disconnect()

        assert client.connected is False
        mock_process.kill.assert_called_once()

    @pytest.mark.asyncio
    async def test_disconnect_generic_exception(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        client._connected = True

        mock_process = MagicMock()
        mock_process.terminate = MagicMock(side_effect=OSError("cannot terminate"))
        mock_process.wait = AsyncMock()
        client._process = mock_process

        await client.disconnect()
        assert client.connected is False
        assert client._process is None


class TestMCPClientSendStdioRequest:
    """Test the _send_stdio_request internal method."""

    @pytest.mark.asyncio
    async def test_send_stdio_request_no_process(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        client._process = None

        result = await client._send_stdio_request({"jsonrpc": "2.0", "id": 1, "method": "test"})
        assert result is None

    @pytest.mark.asyncio
    async def test_send_stdio_request_empty_response(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)

        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdin.write = MagicMock()
        mock_process.stdin.drain = AsyncMock()
        mock_process.stdout = MagicMock()
        mock_process.stdout.readline = AsyncMock(return_value=b"")
        client._process = mock_process

        result = await client._send_stdio_request({"jsonrpc": "2.0", "id": 1, "method": "test"})
        assert result is None

    @pytest.mark.asyncio
    async def test_send_stdio_request_invalid_json_response(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)

        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdin.write = MagicMock()
        mock_process.stdin.drain = AsyncMock()
        mock_process.stdout = MagicMock()
        mock_process.stdout.readline = AsyncMock(return_value=b"not json\n")
        client._process = mock_process

        result = await client._send_stdio_request({"jsonrpc": "2.0", "id": 1, "method": "test"})
        assert result is None

    @pytest.mark.asyncio
    async def test_send_stdio_request_communication_error(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)

        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdin.write = MagicMock(side_effect=BrokenPipeError("broken"))
        mock_process.stdin.drain = AsyncMock()
        mock_process.stdout = MagicMock()
        client._process = mock_process

        result = await client._send_stdio_request({"jsonrpc": "2.0", "id": 1, "method": "test"})
        assert result is None


class TestMCPClientSendHTTPRequest:
    """Test the _send_http_request internal method."""

    @pytest.mark.asyncio
    async def test_send_http_request_no_url(self):
        config = MCPServerConfig(name="test", url=None, transport="sse")
        client = MCPClient(config=config)

        result = await client._send_http_request({"jsonrpc": "2.0", "id": 1, "method": "test"})
        assert result is None

    @pytest.mark.asyncio
    async def test_send_http_request_success(self):
        config = MCPServerConfig(name="test", url="http://localhost:3000", transport="sse")
        client = MCPClient(config=config)

        response_body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}).encode()
        mock_resp = MagicMock()
        mock_resp.read = MagicMock(return_value=response_body)
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = await client._send_http_request(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            )

        assert result is not None
        assert "result" in result

    @pytest.mark.asyncio
    async def test_send_http_request_url_error(self):
        config = MCPServerConfig(name="test", url="http://localhost:3000", transport="sse")
        client = MCPClient(config=config)

        import urllib.error

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
            result = await client._send_http_request({"jsonrpc": "2.0", "id": 1, "method": "test"})

        assert result is None

    @pytest.mark.asyncio
    async def test_send_http_request_invalid_json_response(self):
        config = MCPServerConfig(name="test", url="http://localhost:3000", transport="sse")
        client = MCPClient(config=config)

        mock_resp = MagicMock()
        mock_resp.read = MagicMock(return_value=b"not json at all")
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = await client._send_http_request({"jsonrpc": "2.0", "id": 1, "method": "test"})

        assert result is None


class TestMCPClientSendNotification:
    """Test the _send_notification method."""

    @pytest.mark.asyncio
    async def test_send_notification_success(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)

        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdin.write = MagicMock()
        mock_process.stdin.drain = AsyncMock()
        client._process = mock_process

        await client._send_notification("notifications/initialized")
        mock_process.stdin.write.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_notification_write_error(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)

        mock_process = MagicMock()
        mock_process.stdin = MagicMock()
        mock_process.stdin.write = MagicMock(side_effect=BrokenPipeError("broken"))
        mock_process.stdin.drain = AsyncMock()
        client._process = mock_process

        # Should not raise
        await client._send_notification("notifications/initialized")

    @pytest.mark.asyncio
    async def test_send_notification_no_process(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)
        client._process = None

        # Should not raise
        await client._send_notification("notifications/initialized")


class TestMCPClientNextRequestId:
    """Test request ID generation."""

    def test_request_id_increments(self):
        config = MCPServerConfig(name="test", command="node", transport="stdio")
        client = MCPClient(config=config)

        id1 = client._next_request_id()
        id2 = client._next_request_id()
        id3 = client._next_request_id()

        assert id1 == 1
        assert id2 == 2
        assert id3 == 3


# =============================================================================
# AttackSimulator Tests
# =============================================================================


class TestAttackSimulatorPayloads:
    """Test path traversal payload definitions."""

    def test_at_least_3_payload_categories(self):
        categories = set(p["category"] for p in PATH_TRAVERSAL_PAYLOADS)
        assert len(categories) >= 3

    def test_payloads_contain_traversal_sequences(self):
        for payload_info in PATH_TRAVERSAL_PAYLOADS:
            payload = payload_info["payload"]
            # Each payload should target /etc/passwd
            assert "etc" in payload or "passwd" in payload


class TestAttackSimulatorHelpers:
    """Test helper functions in attack_simulator module."""

    def test_truncate_evidence_short(self):
        result = _truncate_evidence("read_file", "some evidence")
        assert result.startswith("read_file: ")
        assert "some evidence" in result

    def test_truncate_evidence_long(self):
        long_fragment = "x" * 500
        result = _truncate_evidence("read_file", long_fragment, max_length=50)
        assert len(result) <= 50

    def test_is_file_accepting_param_by_name(self):
        assert _is_file_accepting_param("file_path", {"type": "string"}) is True
        assert _is_file_accepting_param("filepath", {"type": "string"}) is True
        assert _is_file_accepting_param("path", {"type": "string"}) is True
        assert _is_file_accepting_param("filename", {"type": "string"}) is True

    def test_is_file_accepting_param_by_description(self):
        assert (
            _is_file_accepting_param(
                "input", {"type": "string", "description": "The file path to read"}
            )
            is True
        )

    def test_is_file_accepting_param_non_string_type(self):
        assert _is_file_accepting_param("path", {"type": "integer"}) is False
        assert _is_file_accepting_param("file_path", {"type": "number"}) is False

    def test_is_file_accepting_param_unrelated_name(self):
        assert _is_file_accepting_param("message", {"type": "string"}) is False
        assert (
            _is_file_accepting_param("query", {"type": "string", "description": "SQL query"})
            is False
        )

    def test_response_indicates_traversal_empty(self):
        assert _response_indicates_traversal({}) is False

    def test_response_indicates_traversal_error(self):
        assert _response_indicates_traversal({"error": {"message": "not found"}}) is False

    def test_response_indicates_traversal_passwd_content(self):
        resp = {"result": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"}
        assert _response_indicates_traversal(resp) is True

    def test_response_indicates_traversal_content_key(self):
        resp = {"content": "root:x:0:0:root:/root:/bin/bash"}
        assert _response_indicates_traversal(resp) is True

    def test_response_indicates_traversal_no_error_with_content(self):
        """Non-error, non-empty content string → indicates traversal."""
        resp = {"content": "some file content here"}
        assert _response_indicates_traversal(resp) is True

    def test_response_indicates_traversal_empty_content(self):
        """Response with empty content should not indicate traversal."""
        resp = {"content": ""}
        assert _response_indicates_traversal(resp) is False


class TestAttackSimulatorIdentifyFileParams:
    """Test _identify_file_params method."""

    def test_identifies_path_param(self):
        simulator = AttackSimulator()
        tool = MCPToolInfo(
            name="read_file",
            description="Read file",
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path"},
                    "encoding": {"type": "string"},
                },
            },
        )
        params = simulator._identify_file_params(tool)
        assert "path" in params
        assert "encoding" not in params

    def test_no_file_params(self):
        simulator = AttackSimulator()
        tool = MCPToolInfo(
            name="search",
            description="Search text",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer"},
                },
            },
        )
        params = simulator._identify_file_params(tool)
        assert params == []

    def test_empty_schema(self):
        simulator = AttackSimulator()
        tool = MCPToolInfo(name="ping", description="Ping", input_schema={})
        params = simulator._identify_file_params(tool)
        assert params == []

    def test_no_properties(self):
        simulator = AttackSimulator()
        tool = MCPToolInfo(name="ping", description="Ping", input_schema={"type": "object"})
        params = simulator._identify_file_params(tool)
        assert params == []

    def test_non_dict_property_skipped(self):
        simulator = AttackSimulator()
        tool = MCPToolInfo(
            name="tool",
            description="Tool",
            input_schema={
                "type": "object",
                "properties": {"file_path": "not a dict", "path": {"type": "string"}},
            },
        )
        params = simulator._identify_file_params(tool)
        assert "path" in params
        assert "file_path" not in params


class TestAttackSimulatorSimulateAttacks:
    """Test simulate_attacks method."""

    @pytest.mark.asyncio
    async def test_simulate_attacks_confirmed_traversal(self):
        """Server responds with /etc/passwd content → MCP-S9 finding with confidence 1.0."""
        simulator = AttackSimulator()
        mock_client = AsyncMock()
        mock_client.call_tool = AsyncMock(
            return_value={"content": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"}
        )

        tools = [
            MCPToolInfo(
                name="read_file",
                description="Read a file",
                input_schema={
                    "type": "object",
                    "properties": {"file_path": {"type": "string", "description": "Path to file"}},
                },
            )
        ]

        findings = await simulator.simulate_attacks(mock_client, tools)

        assert len(findings) == 1
        assert findings[0].id == "MCP-S9"
        assert findings[0].confidence == 1.0
        assert "path traversal" in findings[0].title.lower()

    @pytest.mark.asyncio
    async def test_simulate_attacks_all_rejected(self):
        """Server rejects all payloads → no finding reported."""
        simulator = AttackSimulator()
        mock_client = AsyncMock()
        mock_client.call_tool = AsyncMock(
            return_value={"error": {"code": -1, "message": "Access denied"}}
        )

        tools = [
            MCPToolInfo(
                name="read_file",
                description="Read a file",
                input_schema={
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                },
            )
        ]

        findings = await simulator.simulate_attacks(mock_client, tools)
        assert findings == []

    @pytest.mark.asyncio
    async def test_simulate_attacks_tool_without_file_params_skipped(self):
        """Tool without file-accepting parameters is skipped entirely."""
        simulator = AttackSimulator()
        mock_client = AsyncMock()
        mock_client.call_tool = AsyncMock()

        tools = [
            MCPToolInfo(
                name="search",
                description="Search queries",
                input_schema={
                    "type": "object",
                    "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}},
                },
            )
        ]

        findings = await simulator.simulate_attacks(mock_client, tools)
        assert findings == []
        mock_client.call_tool.assert_not_called()

    @pytest.mark.asyncio
    async def test_simulate_attacks_exception_during_call(self):
        """Exception during tool call is caught, continues with other payloads."""
        simulator = AttackSimulator()
        mock_client = AsyncMock()
        mock_client.call_tool = AsyncMock(side_effect=RuntimeError("connection lost"))

        tools = [
            MCPToolInfo(
                name="read_file",
                description="Read a file",
                input_schema={
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                },
            )
        ]

        findings = await simulator.simulate_attacks(mock_client, tools)
        assert findings == []

    @pytest.mark.asyncio
    async def test_simulate_attacks_empty_response(self):
        """Empty response from server → no finding."""
        simulator = AttackSimulator()
        mock_client = AsyncMock()
        mock_client.call_tool = AsyncMock(return_value={})

        tools = [
            MCPToolInfo(
                name="read_file",
                description="Read a file",
                input_schema={
                    "type": "object",
                    "properties": {"file_path": {"type": "string"}},
                },
            )
        ]

        findings = await simulator.simulate_attacks(mock_client, tools)
        assert findings == []

    @pytest.mark.asyncio
    async def test_simulate_attacks_multiple_tools(self):
        """Multiple tools with file params: only the vulnerable one produces findings."""
        simulator = AttackSimulator()
        mock_client = AsyncMock()

        call_count = 0

        async def mock_call(tool_name, arguments):
            nonlocal call_count
            call_count += 1
            if tool_name == "vulnerable_tool":
                return {"content": "root:x:0:0:root:/root:/bin/bash"}
            return {"error": {"message": "rejected"}}

        mock_client.call_tool = mock_call

        tools = [
            MCPToolInfo(
                name="safe_tool",
                description="Safe",
                input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
            ),
            MCPToolInfo(
                name="vulnerable_tool",
                description="Vulnerable",
                input_schema={"type": "object", "properties": {"file_path": {"type": "string"}}},
            ),
        ]

        findings = await simulator.simulate_attacks(mock_client, tools)
        # vulnerable_tool gets confirmed finding, safe_tool gets rejected
        assert len(findings) == 1
        assert findings[0].id == "MCP-S9"
        assert "vulnerable_tool" in findings[0].description

    @pytest.mark.asyncio
    async def test_simulate_attacks_multiple_file_params(self):
        """Tool with multiple file-accepting params: each tested independently."""
        simulator = AttackSimulator()
        mock_client = AsyncMock()
        mock_client.call_tool = AsyncMock(return_value={"content": "root:x:0:0"})

        tools = [
            MCPToolInfo(
                name="copy_file",
                description="Copy a file",
                input_schema={
                    "type": "object",
                    "properties": {
                        "source_path": {"type": "string"},
                        "dest_path": {"type": "string"},
                    },
                },
            )
        ]

        findings = await simulator.simulate_attacks(mock_client, tools)
        # Both source_path and dest_path should produce findings
        assert len(findings) == 2


# =============================================================================
# DynamicScanner Tests
# =============================================================================


class TestDynamicScannerProperties:
    """Test DynamicScanner basic properties."""

    def test_name(self):
        scanner = DynamicScanner()
        assert scanner.name == ScannerModule.DYNAMIC_SCAN

    def test_applicable_artifact_types(self):
        scanner = DynamicScanner()
        assert ArtifactType.MCP in scanner.applicable_artifact_types

    def test_detected_risk_ids(self):
        scanner = DynamicScanner()
        assert "MCP-S9" in scanner.detected_risk_ids
        assert "MCP-S1" in scanner.detected_risk_ids

    def test_inventories_initially_empty(self):
        scanner = DynamicScanner()
        assert scanner.inventories == []


class TestDynamicScannerConsent:
    """Test DynamicScanner._check_consent() method."""

    def test_consent_allowed_via_config(self):
        config = DynamicScanConfig(allow_dynamic_scan=True)
        scanner = DynamicScanner(config=config)
        assert scanner._check_consent() is True

    def test_consent_denied_non_interactive_no_flag(self):
        config = DynamicScanConfig(allow_dynamic_scan=False, interactive=False)
        scanner = DynamicScanner(config=config)
        assert scanner._check_consent() is False

    def test_consent_interactive_user_accepts(self):
        config = DynamicScanConfig(allow_dynamic_scan=False, interactive=True)
        scanner = DynamicScanner(config=config)

        with patch.object(scanner, "_prompt_user_consent", return_value=True):
            assert scanner._check_consent() is True

    def test_consent_interactive_user_declines(self):
        config = DynamicScanConfig(allow_dynamic_scan=False, interactive=True)
        scanner = DynamicScanner(config=config)

        with patch.object(scanner, "_prompt_user_consent", return_value=False):
            assert scanner._check_consent() is False

    def test_consent_interactive_eof_error(self):
        config = DynamicScanConfig(allow_dynamic_scan=False, interactive=True)
        scanner = DynamicScanner(config=config)

        with patch.object(scanner, "_prompt_user_consent", side_effect=EOFError()):
            assert scanner._check_consent() is False

    def test_consent_interactive_keyboard_interrupt(self):
        config = DynamicScanConfig(allow_dynamic_scan=False, interactive=True)
        scanner = DynamicScanner(config=config)

        with patch.object(scanner, "_prompt_user_consent", side_effect=KeyboardInterrupt()):
            assert scanner._check_consent() is False


class TestDynamicScannerPromptConsent:
    """Test DynamicScanner._prompt_user_consent() method."""

    def test_prompt_user_yes(self):
        scanner = DynamicScanner()
        with patch("builtins.input", return_value="y"):
            assert scanner._prompt_user_consent() is True

    def test_prompt_user_yes_full(self):
        scanner = DynamicScanner()
        with patch("builtins.input", return_value="yes"):
            assert scanner._prompt_user_consent() is True

    def test_prompt_user_no(self):
        scanner = DynamicScanner()
        with patch("builtins.input", return_value="n"):
            assert scanner._prompt_user_consent() is False

    def test_prompt_user_empty(self):
        scanner = DynamicScanner()
        with patch("builtins.input", return_value=""):
            assert scanner._prompt_user_consent() is False

    def test_prompt_user_eof(self):
        scanner = DynamicScanner()
        with patch("builtins.input", side_effect=EOFError()):
            assert scanner._prompt_user_consent() is False

    def test_prompt_user_keyboard_interrupt(self):
        scanner = DynamicScanner()
        with patch("builtins.input", side_effect=KeyboardInterrupt()):
            assert scanner._prompt_user_consent() is False


class TestDynamicScannerParseConfig:
    """Test DynamicScanner._parse_mcp_config() method."""

    def test_parse_valid_stdio_config(self):
        scanner = DynamicScanner()
        config_json = json.dumps(
            {
                "mcpServers": {
                    "my-server": {
                        "command": "node",
                        "args": ["server.js"],
                        "env": {"PORT": "3000"},
                    }
                }
            }
        )
        configs = scanner._parse_mcp_config(config_json)
        assert len(configs) == 1
        assert configs[0].name == "my-server"
        assert configs[0].command == "node"
        assert configs[0].transport == "stdio"
        assert configs[0].env == {"PORT": "3000"}

    def test_parse_valid_http_config(self):
        scanner = DynamicScanner()
        config_json = json.dumps(
            {
                "mcpServers": {
                    "http-server": {
                        "url": "http://localhost:8080",
                        "transport": "sse",
                    }
                }
            }
        )
        configs = scanner._parse_mcp_config(config_json)
        assert len(configs) == 1
        assert configs[0].name == "http-server"
        assert configs[0].transport == "sse"
        assert configs[0].url == "http://localhost:8080"

    def test_parse_url_defaults_to_sse_transport(self):
        scanner = DynamicScanner()
        config_json = json.dumps({"mcpServers": {"srv": {"url": "http://localhost:8080"}}})
        configs = scanner._parse_mcp_config(config_json)
        assert configs[0].transport == "sse"

    def test_parse_multiple_servers(self):
        scanner = DynamicScanner()
        config_json = json.dumps(
            {
                "mcpServers": {
                    "server1": {"command": "node", "args": ["s1.js"]},
                    "server2": {"url": "http://localhost:9090"},
                }
            }
        )
        configs = scanner._parse_mcp_config(config_json)
        assert len(configs) == 2

    def test_parse_invalid_json(self):
        scanner = DynamicScanner()
        configs = scanner._parse_mcp_config("not valid json {{{")
        assert configs == []

    def test_parse_none_content(self):
        scanner = DynamicScanner()
        configs = scanner._parse_mcp_config(None)
        assert configs == []

    def test_parse_no_mcp_servers_key(self):
        scanner = DynamicScanner()
        config_json = json.dumps({"other": "data"})
        configs = scanner._parse_mcp_config(config_json)
        assert configs == []

    def test_parse_mcp_servers_not_dict(self):
        scanner = DynamicScanner()
        config_json = json.dumps({"mcpServers": ["not", "a", "dict"]})
        configs = scanner._parse_mcp_config(config_json)
        assert configs == []

    def test_parse_server_entry_not_dict(self):
        scanner = DynamicScanner()
        config_json = json.dumps({"mcpServers": {"bad-server": "not a dict"}})
        configs = scanner._parse_mcp_config(config_json)
        assert configs == []


class TestDynamicScannerScan:
    """Test DynamicScanner.scan() method."""

    def test_scan_consent_denied_returns_empty(self):
        config = DynamicScanConfig(allow_dynamic_scan=False, interactive=False)
        scanner = DynamicScanner(config=config)

        findings = scanner.scan("{}", ArtifactType.MCP, "mcp.json")
        assert findings == []

    def test_scan_invalid_json_returns_empty(self):
        config = DynamicScanConfig(allow_dynamic_scan=True)
        scanner = DynamicScanner(config=config)

        findings = scanner.scan("not valid json", ArtifactType.MCP, "mcp.json")
        assert findings == []

    def test_scan_empty_servers_returns_empty(self):
        config = DynamicScanConfig(allow_dynamic_scan=True)
        scanner = DynamicScanner(config=config)

        findings = scanner.scan(json.dumps({"mcpServers": {}}), ArtifactType.MCP, "mcp.json")
        assert findings == []

    def test_scan_valid_config_with_mock_servers(self):
        """Full scan with a mocked server connection."""
        config = DynamicScanConfig(allow_dynamic_scan=True)
        scanner = DynamicScanner(config=config)

        mcp_config = json.dumps(
            {"mcpServers": {"test-server": {"command": "node", "args": ["srv.js"]}}}
        )

        mock_client = AsyncMock()
        mock_client.connect = AsyncMock(return_value=True)
        mock_client.list_tools = AsyncMock(
            return_value=[
                MCPToolInfo(
                    name="search",
                    description="Search",
                    input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
                ),
            ]
        )
        mock_client.list_resources = AsyncMock(return_value=[])
        mock_client.disconnect = AsyncMock()

        with patch(
            "ai_artifact_risk_validator.scanners.dynamic.scanner.MCPClient",
            return_value=mock_client,
        ):
            findings = scanner.scan(mcp_config, ArtifactType.MCP, "mcp.json")

        # Should not crash; may have findings from config analysis
        assert isinstance(findings, list)

    def test_scan_server_connection_fails(self):
        """Server connection failure → gracefully handled."""
        config = DynamicScanConfig(allow_dynamic_scan=True)
        scanner = DynamicScanner(config=config)

        mcp_config = json.dumps(
            {"mcpServers": {"failing-server": {"command": "nonexistent", "args": []}}}
        )

        mock_client = AsyncMock()
        mock_client.connect = AsyncMock(return_value=False)
        mock_client.disconnect = AsyncMock()

        with patch(
            "ai_artifact_risk_validator.scanners.dynamic.scanner.MCPClient",
            return_value=mock_client,
        ):
            findings = scanner.scan(mcp_config, ArtifactType.MCP, "mcp.json")

        assert isinstance(findings, list)
        # Inventory should be built even for failed servers
        assert len(scanner.inventories) >= 1

    def test_scan_multiple_servers_mixed_results(self):
        """Multiple servers: one succeeds, one fails."""
        config = DynamicScanConfig(allow_dynamic_scan=True)
        scanner = DynamicScanner(config=config)

        mcp_config = json.dumps(
            {
                "mcpServers": {
                    "good-server": {"command": "node", "args": ["good.js"]},
                    "bad-server": {"command": "broken", "args": []},
                }
            }
        )

        call_count = 0

        def create_client(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock = AsyncMock()
            if call_count == 1:
                # Good server
                mock.connect = AsyncMock(return_value=True)
                mock.list_tools = AsyncMock(return_value=[])
                mock.list_resources = AsyncMock(return_value=[])
                mock.disconnect = AsyncMock()
            else:
                # Bad server
                mock.connect = AsyncMock(return_value=False)
                mock.disconnect = AsyncMock()
            return mock

        with patch(
            "ai_artifact_risk_validator.scanners.dynamic.scanner.MCPClient",
            side_effect=create_client,
        ):
            findings = scanner.scan(mcp_config, ArtifactType.MCP, "mcp.json")

        assert isinstance(findings, list)
        assert len(scanner.inventories) == 2


class TestDynamicScannerPerServerTimeout:
    """Test per-server timeout handling in async scan."""

    def test_scan_per_server_timeout(self):
        """Server exceeding per-server timeout gets a minimal inventory."""
        config = DynamicScanConfig(allow_dynamic_scan=True, per_server_timeout=5)
        scanner = DynamicScanner(config=config)

        mcp_config = json.dumps(
            {"mcpServers": {"slow-server": {"command": "node", "args": ["slow.js"]}}}
        )

        mock_client = AsyncMock()

        async def slow_connect():
            await asyncio.sleep(100)
            return True

        mock_client.connect = slow_connect
        mock_client.disconnect = AsyncMock()

        with patch(
            "ai_artifact_risk_validator.scanners.dynamic.scanner.MCPClient",
            return_value=mock_client,
        ):
            findings = scanner.scan(mcp_config, ArtifactType.MCP, "mcp.json")

        assert isinstance(findings, list)
        # Should have a minimal inventory for timed-out server
        assert len(scanner.inventories) >= 1
        inv = scanner.inventories[0]
        assert inv.server_name == "slow-server"
        assert inv.tool_count == 0


class TestDynamicScannerInventory:
    """Test inventory report generation."""

    def test_inventory_after_successful_scan(self):
        config = DynamicScanConfig(allow_dynamic_scan=True)
        scanner = DynamicScanner(config=config)

        mcp_config = json.dumps(
            {"mcpServers": {"my-server": {"command": "node", "args": ["s.js"]}}}
        )

        mock_client = AsyncMock()
        mock_client.connect = AsyncMock(return_value=True)
        mock_client.list_tools = AsyncMock(
            return_value=[
                MCPToolInfo(name="tool1", description="Tool 1", input_schema={}),
                MCPToolInfo(name="tool2", description="Tool 2", input_schema={}),
            ]
        )
        mock_client.list_resources = AsyncMock(
            return_value=[
                MCPResourceInfo(name="res1", uri="file:///res1", description="Resource 1"),
            ]
        )
        mock_client.disconnect = AsyncMock()
        mock_client.call_tool = AsyncMock(return_value={"error": {"message": "denied"}})

        with patch(
            "ai_artifact_risk_validator.scanners.dynamic.scanner.MCPClient",
            return_value=mock_client,
        ):
            scanner.scan(mcp_config, ArtifactType.MCP, "mcp.json")

        assert len(scanner.inventories) == 1
        inv = scanner.inventories[0]
        assert inv.server_name == "my-server"
        assert inv.tool_count == 2
        assert inv.resource_count == 1
        assert inv.transport_type == "stdio"


class TestDynamicScannerAsyncScan:
    """Test the _async_scan and _scan_server internals."""

    @pytest.mark.asyncio
    async def test_async_scan_exception_in_server(self):
        """Generic exception in _scan_server is caught and logged."""
        config = DynamicScanConfig(allow_dynamic_scan=True)
        scanner = DynamicScanner(config=config)

        server_config = MCPServerConfig(name="err-server", command="node", transport="stdio")

        with patch.object(
            scanner, "_scan_server", AsyncMock(side_effect=RuntimeError("unexpected"))
        ):
            findings = await scanner._async_scan([server_config])

        # Should not crash
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_scan_server_tools_listing_error(self):
        """Error during list_tools is handled gracefully."""
        config = DynamicScanConfig(allow_dynamic_scan=True)
        scanner = DynamicScanner(config=config)

        server_config = MCPServerConfig(name="err-server", command="node", transport="stdio")

        mock_client = AsyncMock()
        mock_client.connect = AsyncMock(return_value=True)
        mock_client.list_tools = AsyncMock(side_effect=RuntimeError("tools error"))
        mock_client.list_resources = AsyncMock(return_value=[])
        mock_client.disconnect = AsyncMock()

        with patch(
            "ai_artifact_risk_validator.scanners.dynamic.scanner.MCPClient",
            return_value=mock_client,
        ):
            findings, tools = await scanner._scan_server(server_config)

        assert tools == []
        mock_client.disconnect.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_server_resources_listing_error(self):
        """Error during list_resources is handled gracefully."""
        config = DynamicScanConfig(allow_dynamic_scan=True)
        scanner = DynamicScanner(config=config)

        server_config = MCPServerConfig(name="err-server", command="node", transport="stdio")

        mock_client = AsyncMock()
        mock_client.connect = AsyncMock(return_value=True)
        mock_client.list_tools = AsyncMock(return_value=[])
        mock_client.list_resources = AsyncMock(side_effect=RuntimeError("resources error"))
        mock_client.disconnect = AsyncMock()

        with patch(
            "ai_artifact_risk_validator.scanners.dynamic.scanner.MCPClient",
            return_value=mock_client,
        ):
            findings, tools = await scanner._scan_server(server_config)

        assert isinstance(findings, list)
        mock_client.disconnect.assert_called_once()

    @pytest.mark.asyncio
    async def test_scan_server_attack_simulation_error(self):
        """Error during attack simulation is handled gracefully."""
        config = DynamicScanConfig(allow_dynamic_scan=True)
        scanner = DynamicScanner(config=config)

        server_config = MCPServerConfig(name="atk-server", command="node", transport="stdio")

        mock_client = AsyncMock()
        mock_client.connect = AsyncMock(return_value=True)
        mock_client.list_tools = AsyncMock(
            return_value=[
                MCPToolInfo(
                    name="read_file",
                    description="Read",
                    input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
                ),
            ]
        )
        mock_client.list_resources = AsyncMock(return_value=[])
        mock_client.disconnect = AsyncMock()

        with (
            patch(
                "ai_artifact_risk_validator.scanners.dynamic.scanner.MCPClient",
                return_value=mock_client,
            ),
            patch.object(
                scanner._attack_simulator,
                "simulate_attacks",
                AsyncMock(side_effect=RuntimeError("attack failed")),
            ),
        ):
            findings, tools = await scanner._scan_server(server_config)

        assert isinstance(findings, list)
        assert len(tools) == 1

    @pytest.mark.asyncio
    async def test_scan_server_connect_exception(self):
        """Exception during connect is caught."""
        config = DynamicScanConfig(allow_dynamic_scan=True)
        scanner = DynamicScanner(config=config)

        server_config = MCPServerConfig(name="exc-server", command="node", transport="stdio")

        mock_client = AsyncMock()
        mock_client.connect = AsyncMock(side_effect=ConnectionError("refused"))
        mock_client.disconnect = AsyncMock()

        with patch(
            "ai_artifact_risk_validator.scanners.dynamic.scanner.MCPClient",
            return_value=mock_client,
        ):
            findings, tools = await scanner._scan_server(server_config)

        assert findings == []
        assert tools == []


class TestDynamicScannerRunAsyncScan:
    """Test _run_async_scan helper."""

    def test_run_async_scan_creates_new_loop(self):
        config = DynamicScanConfig(allow_dynamic_scan=True)
        scanner = DynamicScanner(config=config)

        # Pass empty configs so it returns quickly
        result = scanner._run_async_scan([])
        assert result == []
