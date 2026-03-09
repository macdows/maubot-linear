"""Tests for pure functions in linear_bot.bot (no maubot Plugin instantiation needed)."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from linear_bot.bot import LinearBot


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MXID = "@linearbot:example.com"


def _make_bot():
    """Create a minimal LinearBot-like object with just what the pure helpers need."""
    bot = object.__new__(LinearBot)
    bot.client = MagicMock()
    bot.client.mxid = MXID
    bot.config = MagicMock()
    bot.ticket_links = MagicMock()
    bot.ticket_links.save_link = AsyncMock()
    return bot


def _make_evt(
    body="",
    formatted_body=None,
    mentions=None,
    sender="@user:example.com",
):
    """Build a minimal fake MessageEvent."""
    content = MagicMock()
    content.body = body
    content.formatted_body = formatted_body

    def _get(key, default=None):
        if key == "m.mentions":
            return mentions
        return default

    content.get = MagicMock(side_effect=_get)

    evt = MagicMock()
    evt.content = content
    evt.sender = sender
    return evt


# ---------------------------------------------------------------------------
# _is_mentioned
# ---------------------------------------------------------------------------

class TestIsMentioned:
    def setup_method(self):
        self.bot = _make_bot()

    def test_m_mentions_user_ids(self):
        evt = _make_evt(mentions={"user_ids": [MXID, "@other:example.com"]})
        assert self.bot._is_mentioned(evt) is True

    def test_m_mentions_does_not_include_bot(self):
        evt = _make_evt(mentions={"user_ids": ["@other:example.com"]})
        # Fallback: no formatted_body, no MXID in plain body → False
        assert self.bot._is_mentioned(evt) is False

    def test_formatted_body_href(self):
        fb = f'<a href="https://matrix.to/#/{MXID}">LinearBot</a> do something'
        evt = _make_evt(formatted_body=fb)
        assert self.bot._is_mentioned(evt) is True

    def test_plain_body_contains_mxid(self):
        evt = _make_evt(body=f"{MXID}: please do thing")
        assert self.bot._is_mentioned(evt) is True

    def test_not_mentioned(self):
        evt = _make_evt(body="hello world")
        assert self.bot._is_mentioned(evt) is False

    def test_m_mentions_not_dict_falls_through(self):
        evt = _make_evt(mentions="not_a_dict", body=f"{MXID} hi")
        assert self.bot._is_mentioned(evt) is True

    def test_empty_mentions_user_ids_falls_through(self):
        evt = _make_evt(mentions={"user_ids": []}, body=f"{MXID} hi")
        assert self.bot._is_mentioned(evt) is True


# ---------------------------------------------------------------------------
# _strip_mention
# ---------------------------------------------------------------------------

class TestStripMention:
    def setup_method(self):
        self.bot = _make_bot()

    def test_strip_from_formatted_body(self):
        fb = f'<a href="https://matrix.to/#/{MXID}">LinearBot</a> create a bug'
        evt = _make_evt(body=f"{MXID} create a bug", formatted_body=fb)
        assert self.bot._strip_mention(evt) == "create a bug"

    def test_strip_from_formatted_body_with_comma(self):
        fb = f'<a href="https://matrix.to/#/{MXID}">LinearBot</a>, create a bug'
        evt = _make_evt(formatted_body=fb)
        assert self.bot._strip_mention(evt) == "create a bug"

    def test_strip_from_formatted_body_with_colon(self):
        fb = f'<a href="https://matrix.to/#/{MXID}">LinearBot</a>: create a bug'
        evt = _make_evt(formatted_body=fb)
        assert self.bot._strip_mention(evt) == "create a bug"

    def test_fallback_to_plain_body(self):
        """No formatted_body with MXID — falls back to stripping from plain text."""
        evt = _make_evt(body=f"{MXID} do the thing", formatted_body=None)
        assert self.bot._strip_mention(evt) == "do the thing"

    def test_fallback_plain_body_colon(self):
        evt = _make_evt(body=f"{MXID}: do the thing", formatted_body=None)
        assert self.bot._strip_mention(evt) == "do the thing"

    def test_formatted_body_without_mxid_falls_back(self):
        fb = "<b>some bold text</b>"
        evt = _make_evt(body=f"{MXID} do thing", formatted_body=fb)
        # formatted_body exists but doesn't have MXID → falls back to plain body
        result = self.bot._strip_mention(evt)
        assert "do thing" in result

    def test_html_entities_unescaped(self):
        fb = f'<a href="https://matrix.to/#/{MXID}">Bot</a> create issue &amp; assign'
        evt = _make_evt(formatted_body=fb)
        assert self.bot._strip_mention(evt) == "create issue & assign"


# ---------------------------------------------------------------------------
# _is_allowed
# ---------------------------------------------------------------------------

class TestIsAllowed:
    def setup_method(self):
        self.bot = _make_bot()

    def test_empty_list_allows_all(self):
        self.bot.config.__getitem__ = MagicMock(return_value=[])
        assert self.bot._is_allowed("@anyone:example.com") is True

    def test_non_empty_list_allows_listed(self):
        self.bot.config.__getitem__ = MagicMock(return_value=["@alice:example.com"])
        assert self.bot._is_allowed("@alice:example.com") is True

    def test_non_empty_list_blocks_unlisted(self):
        self.bot.config.__getitem__ = MagicMock(return_value=["@alice:example.com"])
        assert self.bot._is_allowed("@bob:example.com") is False

    def test_none_config_allows_all(self):
        self.bot.config.__getitem__ = MagicMock(return_value=None)
        assert self.bot._is_allowed("@anyone:example.com") is True


# ---------------------------------------------------------------------------
# _store_ticket_links
# ---------------------------------------------------------------------------

async def test_store_ticket_links_json_id():
    bot = _make_bot()
    result = {
        "text": "Created PROJ-1.",
        "tool_calls": [
            {
                "name": "create_issue",
                "input": {"title": "Bug"},
                "result": '{"id": "aaaabbbb-1234-5678-abcd-eeeeffffaaaa", "identifier": "PROJ-1"}',
                "is_error": False,
            }
        ],
    }
    await bot._store_ticket_links(result, "$reply_evt", "!room:example.com")

    bot.ticket_links.save_link.assert_awaited_once()
    call_kwargs = bot.ticket_links.save_link.call_args[1]
    assert call_kwargs["issue_id"] == "aaaabbbb-1234-5678-abcd-eeeeffffaaaa"
    assert call_kwargs["issue_identifier"] == "PROJ-1"


async def test_store_ticket_links_uuid_regex_fallback():
    """When the tool result is not JSON, extract UUID via regex."""
    bot = _make_bot()
    result = {
        "text": "Done.",
        "tool_calls": [
            {
                "name": "create_issue",
                "input": {},
                "result": 'result: "id": "abcd1234-0000-1111-2222-333344445555"',
                "is_error": False,
            }
        ],
    }
    await bot._store_ticket_links(result, "$reply_evt", "!room:example.com")
    bot.ticket_links.save_link.assert_awaited_once()
    call_kwargs = bot.ticket_links.save_link.call_args[1]
    assert call_kwargs["issue_id"] == "abcd1234-0000-1111-2222-333344445555"


async def test_store_ticket_links_skips_error_calls():
    bot = _make_bot()
    result = {
        "text": "Error!",
        "tool_calls": [
            {
                "name": "create_issue",
                "input": {},
                "result": "error text",
                "is_error": True,
            }
        ],
    }
    await bot._store_ticket_links(result, "$reply_evt", "!room:example.com")
    bot.ticket_links.save_link.assert_not_awaited()


async def test_store_ticket_links_skips_non_matching_name():
    bot = _make_bot()
    result = {
        "text": "Done.",
        "tool_calls": [
            {
                "name": "list_issues",  # no "create" in name
                "input": {},
                "result": '{"id": "some-id"}',
                "is_error": False,
            }
        ],
    }
    await bot._store_ticket_links(result, "$reply_evt", "!room:example.com")
    bot.ticket_links.save_link.assert_not_awaited()


async def test_store_ticket_links_no_reply_event_id():
    bot = _make_bot()
    result = {
        "text": "Done.",
        "tool_calls": [
            {"name": "create_issue", "input": {}, "result": '{"id": "x"}', "is_error": False}
        ],
    }
    await bot._store_ticket_links(result, None, "!room:example.com")
    bot.ticket_links.save_link.assert_not_awaited()


# ---------------------------------------------------------------------------
# _fetch_thread_context
# ---------------------------------------------------------------------------

def _make_parent_evt(body: str, sender: str, reply_to=None):
    """Build a minimal fake parent event."""
    content = MagicMock()
    content.body = body
    content.get_reply_to = MagicMock(return_value=reply_to)
    evt = MagicMock()
    evt.content = content
    evt.sender = sender
    return evt


class TestFetchThreadContext:
    def setup_method(self):
        self.bot = _make_bot()
        self.bot.client.get_event = AsyncMock()

    async def test_no_reply_returns_empty(self):
        evt = MagicMock()
        evt.content = MagicMock()
        evt.content.get_reply_to = MagicMock(return_value=None)
        evt.room_id = "!room:example.com"
        result = await self.bot._fetch_thread_context(evt)
        assert result == []

    async def test_single_parent(self):
        parent = _make_parent_evt("Hello from user", "@user:example.com")
        evt = MagicMock()
        evt.content = MagicMock()
        evt.content.get_reply_to = MagicMock(return_value="$parent_evt")
        evt.room_id = "!room:example.com"
        self.bot.client.get_event = AsyncMock(return_value=parent)

        result = await self.bot._fetch_thread_context(evt)
        assert len(result) == 1
        assert result[0]["sender"] == "@user:example.com"
        assert result[0]["body"] == "Hello from user"
        assert result[0]["is_bot"] is False

    async def test_bot_message_marked_is_bot(self):
        parent = _make_parent_evt("I created ENG-1 for you.", MXID)
        evt = MagicMock()
        evt.content = MagicMock()
        evt.content.get_reply_to = MagicMock(return_value="$bot_msg")
        evt.room_id = "!room:example.com"
        self.bot.client.get_event = AsyncMock(return_value=parent)

        result = await self.bot._fetch_thread_context(evt)
        assert result[0]["is_bot"] is True

    async def test_chain_returned_oldest_first(self):
        # Chain: evt → C → B → A  (A is oldest)
        evt_a = _make_parent_evt("Message A", "@alice:example.com", reply_to=None)
        evt_b = _make_parent_evt("Message B", "@bob:example.com", reply_to="$a")
        evt_c = _make_parent_evt("Message C", "@carol:example.com", reply_to="$b")

        async def get_event(room_id, event_id):
            return {"$c": evt_c, "$b": evt_b, "$a": evt_a}[event_id]

        self.bot.client.get_event = AsyncMock(side_effect=get_event)

        evt = MagicMock()
        evt.content = MagicMock()
        evt.content.get_reply_to = MagicMock(return_value="$c")
        evt.room_id = "!room:example.com"

        result = await self.bot._fetch_thread_context(evt)
        assert [m["body"] for m in result] == ["Message A", "Message B", "Message C"]

    async def test_reply_fallback_lines_stripped(self):
        body_with_quotes = "> quoted line\n> another quote\nActual reply"
        parent = _make_parent_evt(body_with_quotes, "@user:example.com")
        evt = MagicMock()
        evt.content = MagicMock()
        evt.content.get_reply_to = MagicMock(return_value="$parent")
        evt.room_id = "!room:example.com"
        self.bot.client.get_event = AsyncMock(return_value=parent)

        result = await self.bot._fetch_thread_context(evt)
        assert result[0]["body"] == "Actual reply"

    async def test_empty_body_after_stripping_excluded(self):
        body_only_quotes = "> quoted line\n> another quote\n"
        parent = _make_parent_evt(body_only_quotes, "@user:example.com")
        evt = MagicMock()
        evt.content = MagicMock()
        evt.content.get_reply_to = MagicMock(return_value="$parent")
        evt.room_id = "!room:example.com"
        self.bot.client.get_event = AsyncMock(return_value=parent)

        result = await self.bot._fetch_thread_context(evt)
        assert result == []

    async def test_get_event_exception_breaks_chain(self):
        self.bot.client.get_event = AsyncMock(side_effect=Exception("network error"))
        evt = MagicMock()
        evt.content = MagicMock()
        evt.content.get_reply_to = MagicMock(return_value="$parent")
        evt.room_id = "!room:example.com"

        result = await self.bot._fetch_thread_context(evt)
        assert result == []
