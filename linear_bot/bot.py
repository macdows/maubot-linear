from __future__ import annotations

import asyncio
import html
import json
import logging
import re
import secrets
import time
from typing import Type
from urllib.parse import urlencode

import aiohttp
from aiohttp.web import Request, Response

from maubot import Plugin, MessageEvent
from maubot.handlers import command, event, web
from mautrix.types import EventType, RoomID
from mautrix.util.config import BaseProxyConfig, ConfigUpdateHelper

from .store import upgrade_table, UserTokenStore, TicketLinkStore
from .mcp_client import MCPClient, TokenInvalidError, MCPError
from .claude_client import ClaudeClient

log = logging.getLogger("maubot.linear")

LINEAR_URL_RE = re.compile(r"https://linear\.app/[^\s)]+/issue/([A-Z]+-\d+)")


class Config(BaseProxyConfig):
    def do_update(self, helper: ConfigUpdateHelper) -> None:
        helper.copy("anthropic_api_key")
        helper.copy("claude_model")
        helper.copy("allowed_users")
        helper.copy("max_tool_rounds")
        helper.copy("linear_client_id")
        helper.copy("linear_client_secret")
        helper.copy("linear_redirect_uri")
        helper.copy("token_encryption_key")


class LinearBot(Plugin):
    user_tokens: UserTokenStore
    ticket_links: TicketLinkStore
    mcp: MCPClient
    http: aiohttp.ClientSession
    _in_flight: dict[str, bool]
    _oauth_states: dict[str, tuple[str, float]]
    _dm_cache: dict[RoomID, bool]

    async def start(self) -> None:
        self.config.load_and_update()
        self.user_tokens = UserTokenStore(
            self.database,
            encryption_key=self.config.get("token_encryption_key", None),
        )
        self.ticket_links = TicketLinkStore(self.database)
        self.mcp = MCPClient()
        self.http = aiohttp.ClientSession()
        self._in_flight = {}
        self._oauth_states = {}
        self._dm_cache = {}

        if self.config["linear_client_id"]:
            log.info(
                "OAuth configured — ensure maubot is accessible at %s",
                self.config["linear_redirect_uri"],
            )
        else:
            log.info("OAuth not configured — users can link via !linear token in DMs")

    async def stop(self) -> None:
        await self.http.close()

    @classmethod
    def get_config_class(cls) -> Type[BaseProxyConfig]:
        return Config

    @classmethod
    def get_db_upgrade_table(cls):
        return upgrade_table

    # --- Permission checks ---

    def _is_allowed(self, sender: str) -> bool:
        allowed = self.config["allowed_users"] or []
        return not allowed or sender in allowed

    async def _is_dm(self, room_id: RoomID) -> bool:
        cached = self._dm_cache.get(room_id)
        if cached is not None:
            return cached
        members = await self.client.get_joined_members(room_id)
        is_dm = len(members) <= 2
        self._dm_cache[room_id] = is_dm
        return is_dm

    # --- Commands ---

    @command.new("linear", help="Linear integration commands")
    async def linear_cmd(self, evt: MessageEvent) -> None:
        pass

    @linear_cmd.subcommand("link", help="Link your Linear account")
    async def link(self, evt: MessageEvent) -> None:
        if self.config["linear_client_id"]:
            state = secrets.token_urlsafe(32)
            self._oauth_states[state] = (evt.sender, time.monotonic())
            # Clean expired states
            now = time.monotonic()
            self._oauth_states = {
                k: v for k, v in self._oauth_states.items() if now - v[1] < 600
            }
            params = urlencode({
                "client_id": self.config["linear_client_id"],
                "redirect_uri": self.config["linear_redirect_uri"],
                "scope": "read,write",
                "state": state,
                "response_type": "code",
                "prompt": "consent",
            })
            url = f"https://linear.app/oauth/authorize?{params}"
            await evt.reply(f"[Click here to link your Linear account]({url})")
        else:
            await evt.reply(
                "Send me your Linear API key in a DM:\n\n"
                "`!linear token <your-api-key>`\n\n"
                "You can create one at https://linear.app/settings/api"
            )

    @linear_cmd.subcommand("unlink", help="Unlink your Linear account")
    async def unlink(self, evt: MessageEvent) -> None:
        deleted = await self.user_tokens.delete_token(evt.sender)
        if deleted:
            await evt.reply("Linear account unlinked.")
        else:
            await evt.reply("No linked account found.")

    @linear_cmd.subcommand("token", help="Set your Linear API key (DM only)")
    @command.argument("key", pass_raw=True)
    async def set_token(self, evt: MessageEvent, key: str) -> None:
        key = key.strip()
        if not key:
            await evt.reply("Usage: `!linear token <your-api-key>`")
            return

        is_dm = await self._is_dm(evt.room_id)
        if not is_dm:
            await evt.reply(
                "Please send your token in a **direct message** for security."
            )
            try:
                await self.client.redact(
                    evt.room_id, evt.event_id, "Token sent in public room"
                )
            except Exception:
                log.warning("Failed to redact token message in %s", evt.room_id)
            return

        # Verify token by initializing an MCP session
        try:
            await self.mcp.initialize(self.http, key)
        except TokenInvalidError:
            await evt.reply(
                "That token appears to be invalid. Please check and try again."
            )
            return
        except Exception:
            log.exception("Failed to verify Linear token")
            await evt.reply(
                "Couldn't verify the token right now. Please try again later."
            )
            return

        # Fetch Linear user identity
        viewer = await self._fetch_viewer(key)
        await self.user_tokens.save_token(
            evt.sender, key,
            linear_user_id=viewer.get("id"),
            linear_user_name=viewer.get("name"),
        )
        name = viewer.get("name") or "your account"
        await evt.reply(f"Linear account linked successfully as **{name}**!")

    @linear_cmd.subcommand("status", help="Check your Linear account status")
    async def status(self, evt: MessageEvent) -> None:
        info = await self.user_tokens.get_user_info(evt.sender)
        if info:
            name = info.get("user_name") or "Unknown"
            await evt.reply(f"Linked to Linear as **{name}**.")
        else:
            await evt.reply(
                "No linked Linear account. Use `!linear link` to get started."
            )

    # --- OAuth callback ---

    @web.get("/linear/callback")
    async def oauth_callback(self, req: Request) -> Response:
        if not self.config["linear_client_id"]:
            return Response(text="OAuth not configured", status=404)

        error = req.query.get("error")
        if error:
            return Response(
                text=f"<h1>Authorization failed</h1><p>{html.escape(error)}</p>",
                content_type="text/html",
            )

        state = req.query.get("state")
        code = req.query.get("code")
        if not state or not code:
            return Response(text="Missing state or code", status=400)

        pending = self._oauth_states.pop(state, None)
        if not pending:
            return Response(
                text=(
                    "<h1>Link expired</h1>"
                    "<p>Please try again with <code>!linear link</code>.</p>"
                ),
                content_type="text/html",
            )

        matrix_user_id, created_at = pending
        if time.monotonic() - created_at > 600:
            return Response(
                text="<h1>Link expired</h1><p>Please try again.</p>",
                content_type="text/html",
            )

        # Exchange code for access token
        try:
            async with self.http.post(
                "https://api.linear.app/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": self.config["linear_client_id"],
                    "client_secret": self.config["linear_client_secret"],
                    "redirect_uri": self.config["linear_redirect_uri"],
                },
            ) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    log.error("OAuth token exchange failed: %s", text)
                    return Response(
                        text="<h1>Failed to exchange token</h1>",
                        content_type="text/html",
                    )
                data = await resp.json()
        except Exception:
            log.exception("OAuth token exchange error")
            return Response(
                text="<h1>Something went wrong</h1>", content_type="text/html"
            )

        access_token = data.get("access_token")
        if not access_token:
            return Response(
                text="<h1>No access token received</h1>", content_type="text/html"
            )

        # Verify token works
        try:
            await self.mcp.initialize(self.http, access_token)
        except Exception:
            log.exception("Failed to verify OAuth token via MCP")
            return Response(
                text="<h1>Token verification failed</h1>", content_type="text/html"
            )

        # Fetch Linear user identity
        viewer = await self._fetch_viewer(access_token)
        await self.user_tokens.save_token(
            matrix_user_id, access_token,
            linear_user_id=viewer.get("id"),
            linear_user_name=viewer.get("name"),
        )

        return Response(
            text=(
                "<h1>Account linked!</h1>"
                "<p>You can now mention the bot in Matrix rooms "
                "to interact with Linear.</p>"
            ),
            content_type="text/html",
        )

    # --- Mention handler ---

    @event.on(EventType.ROOM_MESSAGE)
    async def handle_message(self, evt: MessageEvent) -> None:
        # Skip own messages
        if evt.sender == self.client.mxid:
            return

        # Skip commands (handled by command decorators)
        body = evt.content.body or ""
        if body == "!linear" or body.startswith("!linear "):
            return

        # Skip edits
        if evt.content.get_edit():
            return

        # Check for mention
        if not self._is_mentioned(evt):
            return

        # Don't handle mentions in DMs
        if await self._is_dm(evt.room_id):
            return

        await self._handle_mention(evt)

    async def _handle_mention(self, evt: MessageEvent) -> None:
        if not self._is_allowed(evt.sender):
            return

        # Rate limit: one in-flight request per user
        if self._in_flight.get(evt.sender):
            await evt.reply("Still working on your previous request.")
            return

        # Look up user token
        info = await self.user_tokens.get_user_info(evt.sender)
        if not info:
            await evt.reply(
                "You haven't linked your Linear account yet.\n\n"
                "Use `!linear link` to get started."
            )
            return

        # Extract instruction
        body = evt.content.body or ""
        instruction = self._strip_mention(body)
        if not instruction.strip():
            await evt.reply("What would you like me to do in Linear?")
            return

        # Resolve reply context (ticket from replied-to message)
        issue_context = await self._resolve_reply_context(evt)

        # Note file attachments
        mxc_url = getattr(evt.content, "url", None)
        if mxc_url:
            filename = body if body else "attachment"
            instruction += f"\n\n[Attached file: {filename} ({mxc_url})]"

        # Check API key
        api_key = self.config["anthropic_api_key"]
        if not api_key:
            await evt.reply("The bot's Anthropic API key is not configured.")
            return

        # Run Claude + MCP loop
        self._in_flight[evt.sender] = True
        try:
            claude = ClaudeClient(
                api_key=api_key,
                model=self.config["claude_model"],
                max_rounds=self.config["max_tool_rounds"],
            )

            result = await asyncio.wait_for(
                claude.run(
                    http=self.http,
                    mcp=self.mcp,
                    linear_token=info["token"],
                    instruction=instruction,
                    linear_user_name=info.get("user_name"),
                    issue_context=issue_context,
                ),
                timeout=120,
            )

            log.info(
                "Claude usage for %s: input=%d output=%d",
                evt.sender,
                result["usage"]["input_tokens"],
                result["usage"]["output_tokens"],
            )

            response_text = result["text"] or "Done (no response from Claude)."
            reply_event_id = await evt.reply(response_text)

            # Store ticket link if a ticket was created
            await self._store_ticket_links(result, reply_event_id, evt.room_id)

        except TimeoutError:
            log.warning("Claude loop timed out for %s", evt.sender)
            await evt.reply("Sorry, the request took too long. Please try again.")
        except TokenInvalidError:
            await evt.reply(
                "Your Linear token appears invalid. "
                "Re-link with `!linear token <key>` or `!linear link`."
            )
        except MCPError:
            log.exception("MCP error for %s", evt.sender)
            await evt.reply("Sorry, couldn't reach Linear. Please try again.")
        except Exception:
            log.exception("Error processing request for %s", evt.sender)
            await evt.reply("Sorry, something went wrong processing your request.")
        finally:
            self._in_flight.pop(evt.sender, None)

    # --- Helpers ---

    async def _fetch_viewer(self, token: str) -> dict:
        """Fetch the authenticated Linear user's identity. Returns {} on failure."""
        try:
            return await self.mcp.get_viewer(self.http, token)
        except Exception:
            log.warning("Could not fetch Linear viewer info, continuing without it")
            return {}

    def _is_mentioned(self, evt: MessageEvent) -> bool:
        """Check if the bot is mentioned in the message."""
        mxid = self.client.mxid

        # Check m.mentions (MSC3952 / Matrix 1.7+)
        mentions = evt.content.get("m.mentions")
        if isinstance(mentions, dict):
            user_ids = mentions.get("user_ids")
            if isinstance(user_ids, list) and mxid in user_ids:
                return True

        # Fallback: check for mention pill in formatted body
        formatted = getattr(evt.content, "formatted_body", None) or ""
        if f'href="https://matrix.to/#/{mxid}"' in formatted:
            return True

        # Fallback: plain-text mention
        body = evt.content.body or ""
        if mxid in body:
            return True

        return False

    def _strip_mention(self, body: str) -> str:
        """Remove the bot mention from the message body."""
        mxid = self.client.mxid
        text = body.replace(mxid, "").strip()
        # Strip leading colon/comma left after mention removal
        text = re.sub(r"^[,:]\s*", "", text)
        return text

    async def _resolve_reply_context(self, evt: MessageEvent) -> str | None:
        """If the message is a reply, try to resolve the related Linear issue."""
        reply_to = evt.content.get_reply_to()
        if not reply_to:
            return None

        # 1. Check ticket_links DB
        link = await self.ticket_links.get_link(reply_to)
        if link:
            identifier = link["issue_identifier"] or link["issue_id"]
            return f"This is about Linear issue {identifier}."

        # 2. Fetch the replied-to event and inspect it
        try:
            replied_evt = await self.client.get_event(evt.room_id, reply_to)
        except Exception:
            log.debug("Could not fetch replied-to event %s", reply_to)
            return None

        replied_body = getattr(replied_evt.content, "body", None) or ""

        # Match Linear URLs (high confidence)
        match = LINEAR_URL_RE.search(replied_body)
        if match:
            return f"This is about Linear issue {match.group(1)}."

        # If the replied-to message is from the bot, trust its issue identifiers
        if replied_evt.sender == self.client.mxid:
            id_match = re.search(r"\b([A-Z]+-\d+)\b", replied_body)
            if id_match:
                return f"This is about Linear issue {id_match.group(1)}."

        return None

    async def _store_ticket_links(
        self, result: dict, reply_event_id, room_id: RoomID
    ) -> None:
        """Store a ticket link mapping if a ticket was created."""
        if not reply_event_id:
            return

        response_text = result.get("text", "")
        tool_calls = result.get("tool_calls", [])

        # Look for issue creation tool calls
        for tc in tool_calls:
            name = tc["name"].lower()
            if "create" not in name or "issue" not in name:
                continue
            if tc.get("is_error"):
                continue

            # Extract issue identifier from Claude's response text
            id_match = re.search(r"\b([A-Z]+-\d+)\b", response_text)
            identifier = id_match.group(1) if id_match else None

            # Extract issue ID from the tool result (MCP response)
            tool_result = tc.get("result", "")
            issue_id = None
            try:
                result_data = json.loads(tool_result)
                if isinstance(result_data, dict):
                    issue_id = result_data.get("id")
            except (json.JSONDecodeError, TypeError):
                # Result may not be JSON — try regex for UUID-like IDs
                uuid_match = re.search(
                    r'"id"\s*:\s*"([a-f0-9-]{36})"', tool_result
                )
                if uuid_match:
                    issue_id = uuid_match.group(1)

            if not issue_id:
                issue_id = identifier or "unknown"

            await self.ticket_links.save_link(
                event_id=str(reply_event_id),
                room_id=str(room_id),
                issue_id=issue_id,
                issue_identifier=identifier,
            )
            return
