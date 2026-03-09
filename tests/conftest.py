"""Stub out maubot/mautrix at the sys.modules level before any test module is imported.

This lets us import and test linear_bot.{store,claude_client,mcp_client,bot} without
a running maubot instance or the maubot/mautrix packages installed.
"""
from __future__ import annotations

import sys
from unittest.mock import MagicMock


# Real dummy base classes for types used in `class Foo(Base):` definitions.
# Using a plain MagicMock() instance would break Python's metaclass resolution.
class _FakePlugin:
    pass


class _FakeBaseProxyConfig:
    pass


# --- maubot ---
_maubot = MagicMock()
_maubot.Plugin = _FakePlugin
_maubot.MessageEvent = MagicMock()

_maubot_handlers = MagicMock()

# --- mautrix ---
_mautrix = MagicMock()
_mautrix_util = MagicMock()
_mautrix_util_async_db = MagicMock()
_mautrix_util_config = MagicMock()
_mautrix_util_config.BaseProxyConfig = _FakeBaseProxyConfig
_mautrix_util_config.ConfigUpdateHelper = MagicMock()
_mautrix_types = MagicMock()

for _mod, _obj in [
    ("maubot", _maubot),
    ("maubot.handlers", _maubot_handlers),
    ("mautrix", _mautrix),
    ("mautrix.util", _mautrix_util),
    ("mautrix.util.async_db", _mautrix_util_async_db),
    ("mautrix.util.config", _mautrix_util_config),
    ("mautrix.types", _mautrix_types),
]:
    sys.modules.setdefault(_mod, _obj)
