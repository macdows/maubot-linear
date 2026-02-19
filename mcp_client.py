from __future__ import annotations

import hashlib
import logging
import time

import aiohttp

log = logging.getLogger("maubot.linear.mcp")

MCP_URL = "https://mcp.linear.app/mcp"


class TokenInvalidError(Exception):
    pass


class MCPError(Exception):
    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


class MCPClient:
    def __init__(self) -> None:
        self._sessions: dict[str, str] = {}  # token_hash -> session_id
        self._request_id = 0
        self._tools_cache: list[dict] | None = None
        self._tools_cache_time: float = 0
        self._tools_cache_ttl = 3600  # 1 hour

    def _token_hash(self, token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()[:16]

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    async def _request(
        self,
        session: aiohttp.ClientSession,
        token: str,
        method: str,
        params: dict | None = None,
    ) -> tuple[dict, dict]:
        """Send a JSON-RPC request and return (result, response_headers)."""
        th = self._token_hash(token)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        session_id = self._sessions.get(th)
        if session_id:
            headers["Mcp-Session-Id"] = session_id

        body = {
            "jsonrpc": "2.0",
            "method": method,
            "id": self._next_id(),
        }
        if params is not None:
            body["params"] = params

        async with session.post(MCP_URL, json=body, headers=headers) as resp:
            if resp.status == 401:
                self._sessions.pop(th, None)
                raise TokenInvalidError("Linear token is invalid or expired")
            if resp.status >= 400:
                text = await resp.text()
                raise MCPError(f"MCP server returned {resp.status}: {text}", resp.status)

            resp_headers = dict(resp.headers)
            data = await resp.json()

            # Capture session ID from response
            new_session_id = resp.headers.get("Mcp-Session-Id")
            if new_session_id:
                self._sessions[th] = new_session_id

            if "error" in data:
                err = data["error"]
                raise MCPError(err.get("message", str(err)), err.get("code"))

            return data.get("result", {}), resp_headers

    async def initialize(self, session: aiohttp.ClientSession, token: str) -> dict:
        """Initialize an MCP session. Must be called before other methods."""
        th = self._token_hash(token)
        self._sessions.pop(th, None)  # Clear any stale session

        result, _ = await self._request(session, token, "initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "maubot-linear", "version": "0.1.0"},
        })
        log.debug("MCP session initialized for token %s", th)
        return result

    async def _ensure_session(self, session: aiohttp.ClientSession, token: str) -> None:
        """Ensure we have an active MCP session for this token."""
        th = self._token_hash(token)
        if th not in self._sessions:
            await self.initialize(session, token)

    async def list_tools(self, session: aiohttp.ClientSession, token: str) -> list[dict]:
        """Fetch available tools from Linear MCP. Cached for 1 hour."""
        now = time.monotonic()
        if self._tools_cache and (now - self._tools_cache_time) < self._tools_cache_ttl:
            return self._tools_cache

        await self._ensure_session(session, token)
        try:
            result, _ = await self._request(session, token, "tools/list")
        except TokenInvalidError:
            raise
        except Exception:
            self._tools_cache = None
            raise

        tools = result.get("tools", [])
        self._tools_cache = tools
        self._tools_cache_time = now
        log.info("Cached %d MCP tools from Linear", len(tools))
        return tools

    async def call_tool(
        self,
        session: aiohttp.ClientSession,
        token: str,
        tool_name: str,
        arguments: dict,
    ) -> dict:
        """Call a tool on the Linear MCP server."""
        await self._ensure_session(session, token)
        try:
            result, _ = await self._request(session, token, "tools/call", {
                "name": tool_name,
                "arguments": arguments,
            })
        except TokenInvalidError:
            raise
        except MCPError:
            raise
        except Exception:
            # Session might be stale — re-initialize and retry once
            log.warning("MCP call_tool failed, retrying with fresh session")
            await self.initialize(session, token)
            result, _ = await self._request(session, token, "tools/call", {
                "name": tool_name,
                "arguments": arguments,
            })

        return result
