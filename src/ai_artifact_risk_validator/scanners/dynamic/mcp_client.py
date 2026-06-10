"""MCP client for connecting to live MCP servers and discovering tools/resources.

Supports stdio transport (subprocess with JSON-RPC 2.0 over stdin/stdout) and
HTTP/SSE transport (HTTP requests to server URL). Implements tools/list and
resources/list invocations with configurable connection and per-server timeouts.
"""

import asyncio
import json
import logging
from typing import Any

from ai_artifact_risk_validator.models.mcp_models import (
    DynamicScanConfig,
    MCPResourceInfo,
    MCPServerConfig,
    MCPToolInfo,
)

logger = logging.getLogger(__name__)


class MCPClient:
    """Client for connecting to MCP servers and discovering tools/resources.

    Supports two transport modes:
    - stdio: Spawns a subprocess and communicates via stdin/stdout using JSON-RPC 2.0
    - HTTP/SSE: Connects to a server URL using HTTP requests

    Args:
        config: MCP server configuration specifying transport, command/URL, etc.
        connection_timeout: Seconds to wait for initial connection (default 10).
        per_server_timeout: Overall timeout for operations on a server (default 30).
    """

    def __init__(
        self,
        config: MCPServerConfig,
        connection_timeout: int = 10,
        per_server_timeout: int = 30,
        dynamic_scan_config: DynamicScanConfig | None = None,
    ) -> None:
        """Initialize with server config and timeouts.

        If dynamic_scan_config is provided, its connection_timeout and
        per_server_timeout values take precedence over the individual
        timeout parameters.
        """
        self._config = config
        if dynamic_scan_config is not None:
            self._connection_timeout = dynamic_scan_config.connection_timeout
            self._per_server_timeout = dynamic_scan_config.per_server_timeout
        else:
            self._connection_timeout = connection_timeout
            self._per_server_timeout = per_server_timeout
        self._connected = False
        self._process: asyncio.subprocess.Process | None = None
        self._request_id = 0
        self._reader_lock = asyncio.Lock()
        self._session_id: str | None = None
        self._server_capabilities: dict[str, Any] = {}
        self._server_info: dict[str, Any] = {}

    @property
    def config(self) -> MCPServerConfig:
        """Return the server configuration."""
        return self._config

    @property
    def connected(self) -> bool:
        """Return whether the client is currently connected."""
        return self._connected

    @property
    def server_capabilities(self) -> dict[str, Any]:
        """Return the server's declared capabilities from initialization."""
        return self._server_capabilities

    @property
    def server_info(self) -> dict[str, Any]:
        """Return the server's info (name, version) from initialization."""
        return self._server_info

    async def connect(self) -> bool:
        """Establish connection to MCP server.

        For stdio transport, spawns the configured command as a subprocess.
        For HTTP/SSE transport, verifies the server URL is reachable.

        Returns:
            True if connection was established successfully, False otherwise.

        Raises no exceptions - connection failures are logged and return False.
        """
        try:
            if self._config.transport == "stdio":
                return await self._connect_stdio()
            else:
                return await self._connect_http()
        except Exception as exc:
            logger.warning(
                "Failed to connect to MCP server '%s': %s",
                self._config.name,
                exc,
            )
            self._connected = False
            return False

    async def list_tools(self) -> list[MCPToolInfo]:
        """Invoke tools/list and return discovered tools.

        Sends a JSON-RPC 2.0 request with method "tools/list" and parses
        the response into MCPToolInfo objects.

        Returns:
            List of MCPToolInfo objects. Empty list if not connected or on error.
        """
        if not self._connected:
            logger.warning(
                "Cannot list tools: not connected to server '%s'",
                self._config.name,
            )
            return []

        try:
            response = await asyncio.wait_for(
                self._send_request("tools/list"),
                timeout=self._per_server_timeout,
            )
            if response is None:
                return []

            tools_data = response.get("result", {}).get("tools", [])
            tools: list[MCPToolInfo] = []
            for tool in tools_data:
                try:
                    tools.append(
                        MCPToolInfo(
                            name=tool.get("name", ""),
                            description=tool.get("description", ""),
                            input_schema=tool.get("inputSchema", {}),
                        )
                    )
                except Exception as exc:
                    logger.warning(
                        "Failed to parse tool info from server '%s': %s",
                        self._config.name,
                        exc,
                    )
            return tools
        except asyncio.TimeoutError:
            logger.warning(
                "Timeout listing tools from server '%s' (timeout=%ds)",
                self._config.name,
                self._per_server_timeout,
            )
            return []
        except Exception as exc:
            logger.warning(
                "Error listing tools from server '%s': %s",
                self._config.name,
                exc,
            )
            return []

    async def list_resources(self) -> list[MCPResourceInfo]:
        """Invoke resources/list and return discovered resources.

        Sends a JSON-RPC 2.0 request with method "resources/list" and parses
        the response into MCPResourceInfo objects.

        Returns:
            List of MCPResourceInfo objects. Empty list if not connected or on error.
        """
        if not self._connected:
            logger.warning(
                "Cannot list resources: not connected to server '%s'",
                self._config.name,
            )
            return []

        try:
            response = await asyncio.wait_for(
                self._send_request("resources/list"),
                timeout=self._per_server_timeout,
            )
            if response is None:
                return []

            resources_data = response.get("result", {}).get("resources", [])
            resources: list[MCPResourceInfo] = []
            for resource in resources_data:
                try:
                    resources.append(
                        MCPResourceInfo(
                            name=resource.get("name", ""),
                            uri=resource.get("uri", ""),
                            description=resource.get("description", ""),
                        )
                    )
                except Exception as exc:
                    logger.warning(
                        "Failed to parse resource info from server '%s': %s",
                        self._config.name,
                        exc,
                    )
            return resources
        except asyncio.TimeoutError:
            logger.warning(
                "Timeout listing resources from server '%s' (timeout=%ds)",
                self._config.name,
                self._per_server_timeout,
            )
            return []
        except Exception as exc:
            logger.warning(
                "Error listing resources from server '%s': %s",
                self._config.name,
                exc,
            )
            return []

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call a tool with given arguments. Used by AttackSimulator.

        Sends a JSON-RPC 2.0 request with method "tools/call" and the specified
        tool name and arguments.

        Args:
            tool_name: Name of the tool to invoke.
            arguments: Dictionary of arguments to pass to the tool.

        Returns:
            Response dictionary from the server. Empty dict on error.
        """
        if not self._connected:
            logger.warning(
                "Cannot call tool '%s': not connected to server '%s'",
                tool_name,
                self._config.name,
            )
            return {}

        try:
            response = await asyncio.wait_for(
                self._send_request(
                    "tools/call",
                    params={"name": tool_name, "arguments": arguments},
                ),
                timeout=self._per_server_timeout,
            )
            if response is None:
                return {}

            # Check for JSON-RPC error
            if "error" in response:
                logger.warning(
                    "Tool call '%s' on server '%s' returned error: %s",
                    tool_name,
                    self._config.name,
                    response["error"],
                )
                return {"error": response["error"]}

            result: dict[str, Any] = response.get("result", {})
            return result
        except asyncio.TimeoutError:
            logger.warning(
                "Timeout calling tool '%s' on server '%s' (timeout=%ds)",
                tool_name,
                self._config.name,
                self._per_server_timeout,
            )
            return {}
        except Exception as exc:
            logger.warning(
                "Error calling tool '%s' on server '%s': %s",
                tool_name,
                self._config.name,
                exc,
            )
            return {}

    async def disconnect(self) -> None:
        """Clean up connection.

        For stdio transport, terminates the subprocess.
        For HTTP/SSE transport, sends HTTP DELETE to terminate the session (per MCP spec).
        """
        # HTTP session cleanup: send DELETE with session ID per MCP spec
        if self._config.transport != "stdio" and self._session_id and self._config.url:
            try:
                import urllib.error
                import urllib.request

                req = urllib.request.Request(  # noqa: S310
                    self._config.url,
                    method="DELETE",
                )
                req.add_header("Mcp-Session-Id", self._session_id)
                try:
                    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
                        _ = resp.read()
                except urllib.error.HTTPError:
                    pass  # 405 Method Not Allowed is acceptable per spec
                except Exception:
                    pass
            except Exception:
                pass  # Best-effort session cleanup
            self._session_id = None

        if self._process is not None:
            try:
                self._process.terminate()
                # Give the process a moment to terminate gracefully
                try:
                    await asyncio.wait_for(self._process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    self._process.kill()
                    await self._process.wait()
            except ProcessLookupError:
                pass  # Process already exited
            except Exception as exc:
                logger.warning(
                    "Error terminating process for server '%s': %s",
                    self._config.name,
                    exc,
                )
            finally:
                self._process = None

        self._connected = False

    # -------------------------------------------------------------------------
    # Private transport methods
    # -------------------------------------------------------------------------

    async def _connect_stdio(self) -> bool:
        """Establish stdio connection by spawning subprocess."""
        if not self._config.command:
            logger.warning(
                "No command configured for stdio server '%s'",
                self._config.name,
            )
            return False

        try:
            env = self._config.env if self._config.env else None
            cmd = [self._config.command] + self._config.args

            self._process = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                ),
                timeout=self._connection_timeout,
            )

            # Send initialize request to verify the server is responding
            init_response = await asyncio.wait_for(
                self._send_request(
                    "initialize",
                    params={
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {
                            "name": "ai-artifact-risk-validator",
                            "version": "0.6.0",
                        },
                    },
                ),
                timeout=self._connection_timeout,
            )

            if init_response is not None and "result" in init_response:
                self._connected = True
                result = init_response["result"]
                self._server_capabilities = result.get("capabilities", {})
                self._server_info = result.get("serverInfo", {})
                # Send initialized notification
                await self._send_notification("notifications/initialized")
                logger.info(
                    "Connected to MCP server '%s' via stdio",
                    self._config.name,
                )
                return True
            else:
                logger.warning(
                    "MCP server '%s' did not respond to initialize",
                    self._config.name,
                )
                await self.disconnect()
                return False

        except asyncio.TimeoutError:
            logger.warning(
                "Connection timeout for stdio server '%s' (timeout=%ds)",
                self._config.name,
                self._connection_timeout,
            )
            await self.disconnect()
            return False
        except FileNotFoundError:
            logger.warning(
                "Command not found for server '%s': %s",
                self._config.name,
                self._config.command,
            )
            return False
        except Exception as exc:
            logger.warning(
                "Failed to spawn process for server '%s': %s",
                self._config.name,
                exc,
            )
            await self.disconnect()
            return False

    async def _connect_http(self) -> bool:
        """Establish HTTP/SSE connection by verifying server URL."""
        if not self._config.url:
            logger.warning(
                "No URL configured for HTTP/SSE server '%s'",
                self._config.name,
            )
            return False

        try:
            # For HTTP/SSE transport, we attempt a basic HTTP connection check
            # using asyncio-compatible approach without requiring aiohttp
            import urllib.error
            import urllib.request

            # Use a simple POST request to verify reachability
            # MCP Streamable HTTP uses POST for JSON-RPC requests
            loop = asyncio.get_event_loop()

            def _check_url() -> bool:
                req = urllib.request.Request(  # noqa: S310
                    self._config.url,  # type: ignore[arg-type]
                    method="POST",
                    data=b"{}",
                )
                req.add_header("Content-Type", "application/json")
                req.add_header("Accept", "application/json, text/event-stream")
                try:
                    with urllib.request.urlopen(req, timeout=self._connection_timeout) as resp:  # noqa: S310
                        return bool(resp.status < 500)
                except urllib.error.HTTPError as e:
                    # 4xx errors (400, 405, 406, etc.) mean server is reachable
                    # but the request wasn't valid — that's fine for a check
                    return bool(e.code < 500)
                except urllib.error.URLError:
                    return False
                except Exception:
                    return False

            reachable = await asyncio.wait_for(
                loop.run_in_executor(None, _check_url),
                timeout=self._connection_timeout,
            )

            if reachable:
                self._connected = True
                # Send MCP initialize handshake and capture session ID
                init_result = await self._send_http_initialize()
                if init_result:
                    # Send initialized notification
                    await self._send_notification("notifications/initialized")
                    logger.info(
                        "Connected to MCP server '%s' via HTTP/SSE at %s",
                        self._config.name,
                        self._config.url,
                    )
                    return True
                else:
                    # Server is reachable but didn't respond to initialize
                    # Still proceed — some servers may not require initialization
                    logger.info(
                        "Connected to MCP server '%s' via HTTP/SSE at %s (no init handshake)",
                        self._config.name,
                        self._config.url,
                    )
                    return True
            else:
                logger.warning(
                    "HTTP/SSE server '%s' at %s is not reachable",
                    self._config.name,
                    self._config.url,
                )
                return False

        except asyncio.TimeoutError:
            logger.warning(
                "Connection timeout for HTTP/SSE server '%s' (timeout=%ds)",
                self._config.name,
                self._connection_timeout,
            )
            return False
        except Exception as exc:
            logger.warning(
                "Failed to connect to HTTP/SSE server '%s': %s",
                self._config.name,
                exc,
            )
            return False

    async def _send_http_initialize(self) -> bool:
        """Send MCP initialize request via HTTP and capture session ID.

        Returns:
            True if initialization succeeded (server returned a result).
        """
        import urllib.error
        import urllib.request

        request_id = self._next_request_id()
        request = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": request_id,
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {
                    "name": "ai-artifact-risk-validator",
                    "version": "0.6.0",
                },
            },
        }

        loop = asyncio.get_event_loop()

        def _do_init() -> bool:
            data = json.dumps(request).encode("utf-8")
            req = urllib.request.Request(  # noqa: S310
                self._config.url,  # type: ignore[arg-type]
                data=data,
                method="POST",
            )
            req.add_header("Content-Type", "application/json")
            req.add_header("Accept", "application/json, text/event-stream")
            try:
                with urllib.request.urlopen(req, timeout=self._connection_timeout) as resp:  # noqa: S310
                    # Capture session ID from response headers
                    session_id = resp.headers.get("mcp-session-id")
                    if session_id:
                        self._session_id = session_id

                    content_type = resp.headers.get("Content-Type", "")
                    body = resp.read().decode("utf-8")

                    # Parse response (may be SSE or plain JSON)
                    if "text/event-stream" in content_type:
                        parsed = self._parse_sse_response(body)
                    else:
                        parsed = json.loads(body)

                    if parsed is not None and "result" in parsed:
                        result = parsed["result"]
                        self._server_capabilities = result.get("capabilities", {})
                        self._server_info = result.get("serverInfo", {})
                        return True
                    return False
            except Exception as exc:
                logger.debug(
                    "HTTP initialize failed for server '%s': %s",
                    self._config.name,
                    exc,
                )
                return False

        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, _do_init),
                timeout=self._connection_timeout,
            )
        except asyncio.TimeoutError:
            return False

    def _next_request_id(self) -> int:
        """Generate the next JSON-RPC request ID."""
        self._request_id += 1
        return self._request_id

    async def _send_request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Send a JSON-RPC 2.0 request and return the response.

        For stdio transport, writes to subprocess stdin and reads from stdout.
        For HTTP transport, sends HTTP POST request.

        Args:
            method: The JSON-RPC method name.
            params: Optional parameters for the request.

        Returns:
            Parsed JSON response dictionary, or None on error.
        """
        request_id = self._next_request_id()
        request: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
            "id": request_id,
        }
        if params is not None:
            request["params"] = params

        if self._config.transport == "stdio":
            return await self._send_stdio_request(request)
        else:
            return await self._send_http_request(request)

    async def _send_notification(self, method: str, params: dict[str, Any] | None = None) -> None:
        """Send a JSON-RPC 2.0 notification (no response expected).

        Args:
            method: The JSON-RPC method name.
            params: Optional parameters for the notification.
        """
        notification: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params is not None:
            notification["params"] = params

        if self._config.transport == "stdio" and self._process and self._process.stdin:
            try:
                message = json.dumps(notification) + "\n"
                self._process.stdin.write(message.encode("utf-8"))
                await self._process.stdin.drain()
            except Exception as exc:
                logger.warning(
                    "Failed to send notification '%s' to server '%s': %s",
                    method,
                    self._config.name,
                    exc,
                )
        elif self._config.transport != "stdio" and self._config.url:
            # HTTP transport: POST the notification, expect 202 Accepted
            try:
                import urllib.error
                import urllib.request

                loop = asyncio.get_event_loop()

                def _send_http_notification() -> None:
                    data = json.dumps(notification).encode("utf-8")
                    req = urllib.request.Request(  # noqa: S310
                        self._config.url,  # type: ignore[arg-type]
                        data=data,
                        method="POST",
                    )
                    req.add_header("Content-Type", "application/json")
                    req.add_header("Accept", "application/json, text/event-stream")
                    if self._session_id:
                        req.add_header("Mcp-Session-Id", self._session_id)
                    try:
                        with urllib.request.urlopen(req, timeout=self._per_server_timeout) as resp:  # noqa: S310
                            _ = resp.read()  # drain response body
                    except urllib.error.HTTPError:
                        pass  # 202 Accepted or other status is fine for notifications
                    except Exception:
                        pass

                await loop.run_in_executor(None, _send_http_notification)
            except Exception as exc:
                logger.warning(
                    "Failed to send notification '%s' to HTTP server '%s': %s",
                    method,
                    self._config.name,
                    exc,
                )

    async def _send_stdio_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Send request via stdio transport and read response."""
        if not self._process or not self._process.stdin or not self._process.stdout:
            logger.warning(
                "Process not available for server '%s'",
                self._config.name,
            )
            return None

        async with self._reader_lock:
            try:
                # Write request as JSON line
                message = json.dumps(request) + "\n"
                self._process.stdin.write(message.encode("utf-8"))
                await self._process.stdin.drain()

                # Read response line
                response_line = await self._process.stdout.readline()
                if not response_line:
                    logger.warning(
                        "Empty response from server '%s'",
                        self._config.name,
                    )
                    return None

                response: dict[str, Any] = json.loads(response_line.decode("utf-8").strip())
                return response
            except json.JSONDecodeError as exc:
                logger.warning(
                    "Invalid JSON response from server '%s': %s",
                    self._config.name,
                    exc,
                )
                return None
            except Exception as exc:
                logger.warning(
                    "Error communicating with server '%s': %s",
                    self._config.name,
                    exc,
                )
                return None

    async def _send_http_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Send request via HTTP transport.

        Handles both plain JSON responses and SSE (text/event-stream) responses.
        For SSE, extracts the JSON-RPC response from the first 'message' event data line.
        """
        if not self._config.url:
            return None

        try:
            import urllib.error
            import urllib.request

            loop = asyncio.get_event_loop()

            def _do_post() -> dict[str, Any] | None:
                data = json.dumps(request).encode("utf-8")
                req = urllib.request.Request(  # noqa: S310
                    self._config.url,  # type: ignore[arg-type]
                    data=data,
                    method="POST",
                )
                req.add_header("Content-Type", "application/json")
                req.add_header("Accept", "application/json, text/event-stream")
                if self._session_id:
                    req.add_header("Mcp-Session-Id", self._session_id)
                try:
                    with urllib.request.urlopen(req, timeout=self._per_server_timeout) as resp:  # noqa: S310
                        content_type = resp.headers.get("Content-Type", "")
                        body = resp.read().decode("utf-8")

                        # Handle SSE response format
                        if "text/event-stream" in content_type:
                            return self._parse_sse_response(body)

                        # Plain JSON response
                        parsed: dict[str, Any] = json.loads(body)
                        return parsed
                except urllib.error.URLError as exc:
                    logger.warning(
                        "HTTP request failed for server '%s': %s",
                        self._config.name,
                        exc,
                    )
                    return None
                except json.JSONDecodeError as exc:
                    logger.warning(
                        "Invalid JSON response from HTTP server '%s': %s",
                        self._config.name,
                        exc,
                    )
                    return None

            return await loop.run_in_executor(None, _do_post)
        except Exception as exc:
            logger.warning(
                "Error sending HTTP request to server '%s': %s",
                self._config.name,
                exc,
            )
            return None

    @staticmethod
    def _parse_sse_response(body: str) -> dict[str, Any] | None:
        """Parse an SSE response body to extract the JSON-RPC message.

        SSE format:
            event: message
            data: {"jsonrpc":"2.0","id":1,"result":{...}}

        Args:
            body: Raw SSE response body.

        Returns:
            Parsed JSON-RPC response dict, or None if parsing fails.
        """
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith("data:"):
                data_content = stripped[5:].strip()
                if data_content:
                    try:
                        parsed: dict[str, Any] = json.loads(data_content)
                        # Return the first valid JSON-RPC response
                        if "jsonrpc" in parsed:
                            return parsed
                    except json.JSONDecodeError:
                        continue
        return None
