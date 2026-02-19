from __future__ import annotations

import json
import logging

import aiohttp

from .mcp_client import MCPClient, TokenInvalidError

log = logging.getLogger("maubot.linear.claude")

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"
API_TIMEOUT = aiohttp.ClientTimeout(total=60)

SYSTEM_PROMPT = """\
You are a Linear assistant in a Matrix chat room. Execute the user's request using \
the provided Linear tools.

Current user's Linear identity: {linear_user_name}
{context}

Rules:
- Only reference issue identifiers and URLs that are returned by tool calls. \
Do NOT guess or fabricate issue IDs.
- Respond with a brief confirmation including the issue identifier and URL when relevant.
- Be concise — one or two sentences."""


def mcp_tools_to_claude(mcp_tools: list[dict]) -> list[dict]:
    """Convert MCP tool schemas to Claude's tool format."""
    claude_tools = []
    for tool in mcp_tools:
        claude_tools.append({
            "name": tool["name"],
            "description": tool.get("description", ""),
            "input_schema": tool.get("inputSchema", {"type": "object", "properties": {}}),
        })
    return claude_tools


def _extract_text(content_blocks: list[dict]) -> str:
    """Extract text from Claude response content blocks."""
    parts = []
    for block in content_blocks:
        if block.get("type") == "text":
            parts.append(block["text"])
    return "\n".join(parts)


def _extract_tool_uses(content_blocks: list[dict]) -> list[dict]:
    """Extract tool_use blocks from Claude response."""
    return [b for b in content_blocks if b.get("type") == "tool_use"]


class ClaudeClient:
    def __init__(self, api_key: str, model: str, max_rounds: int) -> None:
        self.api_key = api_key
        self.model = model
        self.max_rounds = max_rounds

    async def run(
        self,
        http: aiohttp.ClientSession,
        mcp: MCPClient,
        linear_token: str,
        instruction: str,
        linear_user_name: str | None = None,
        issue_context: str | None = None,
    ) -> dict:
        """Run the Claude tool-use loop.

        Returns {"text": str, "tool_calls": list[dict], "usage": dict}
        """
        mcp_tools = await mcp.list_tools(http, linear_token)
        claude_tools = mcp_tools_to_claude(mcp_tools)

        context = ""
        if issue_context:
            context = f"Context: {issue_context}"

        system = SYSTEM_PROMPT.format(
            linear_user_name=linear_user_name or "Unknown",
            context=context,
        )

        messages = [{"role": "user", "content": instruction}]
        all_tool_calls = []
        total_usage = {"input_tokens": 0, "output_tokens": 0}

        for round_num in range(self.max_rounds):
            resp_data = await self._call_api(http, system, messages, claude_tools)

            # Track usage
            usage = resp_data.get("usage", {})
            total_usage["input_tokens"] += usage.get("input_tokens", 0)
            total_usage["output_tokens"] += usage.get("output_tokens", 0)

            content = resp_data.get("content", [])
            stop_reason = resp_data.get("stop_reason")

            if stop_reason != "tool_use":
                # Final response
                return {
                    "text": _extract_text(content),
                    "tool_calls": all_tool_calls,
                    "usage": total_usage,
                }

            # Process tool calls
            tool_uses = _extract_tool_uses(content)
            tool_results = []

            for tu in tool_uses:
                tool_name = tu["name"]
                tool_input = tu["input"]
                tool_id = tu["id"]
                all_tool_calls.append({"name": tool_name, "input": tool_input})

                log.info("Tool call [round %d]: %s(%s)", round_num + 1, tool_name, json.dumps(tool_input)[:200])

                try:
                    result = await mcp.call_tool(http, linear_token, tool_name, tool_input)
                    # MCP result has "content" which is a list of content blocks
                    result_content = result.get("content", [])
                    result_text = "\n".join(
                        c.get("text", json.dumps(c)) for c in result_content
                    ) if result_content else json.dumps(result)

                    is_error = result.get("isError", False)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "content": result_text,
                        **({"is_error": True} if is_error else {}),
                    })
                except TokenInvalidError:
                    raise
                except Exception as e:
                    log.exception("Tool call %s failed", tool_name)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "content": f"Error calling {tool_name}: {e}",
                        "is_error": True,
                    })

            # Append assistant message + tool results for next round
            messages.append({"role": "assistant", "content": content})
            messages.append({"role": "user", "content": tool_results})

        # Exhausted rounds — ask Claude for a final summary without tools
        messages.append({
            "role": "user",
            "content": "You've used the maximum number of tool calls. Please summarize what you accomplished.",
        })
        resp_data = await self._call_api(http, system, messages, tools=[])
        usage = resp_data.get("usage", {})
        total_usage["input_tokens"] += usage.get("input_tokens", 0)
        total_usage["output_tokens"] += usage.get("output_tokens", 0)

        return {
            "text": _extract_text(resp_data.get("content", [])),
            "tool_calls": all_tool_calls,
            "usage": total_usage,
        }

    async def _call_api(
        self,
        http: aiohttp.ClientSession,
        system: str,
        messages: list[dict],
        tools: list[dict],
    ) -> dict:
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": API_VERSION,
            "content-type": "application/json",
        }
        body = {
            "model": self.model,
            "max_tokens": 4096,
            "system": system,
            "messages": messages,
        }
        if tools:
            body["tools"] = tools

        async with http.post(API_URL, json=body, headers=headers, timeout=API_TIMEOUT) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise Exception(f"Claude API returned {resp.status}: {text[:500]}")
            return await resp.json()
