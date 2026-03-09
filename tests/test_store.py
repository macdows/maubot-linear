"""Tests for linear_bot.store: crypto primitives and DB-backed stores."""
from __future__ import annotations

import base64
import os

import pytest
from unittest.mock import AsyncMock, MagicMock

from linear_bot.store import (
    _ENC_PREFIX_V1,
    _ENC_PREFIX_V2,
    _derive_keys,
    _decrypt_value,
    _encrypt_value,
    _keystream,
    TicketLinkStore,
    TokenDecryptionError,
    UserTokenStore,
)


# ---------------------------------------------------------------------------
# _derive_keys
# ---------------------------------------------------------------------------

class TestDeriveKeys:
    def test_deterministic(self):
        k1a, k2a = _derive_keys("secret")
        k1b, k2b = _derive_keys("secret")
        assert k1a == k1b
        assert k2a == k2b

    def test_different_secrets_give_different_keys(self):
        k1, _ = _derive_keys("secret_a")
        k2, _ = _derive_keys("secret_b")
        assert k1 != k2

    def test_output_length(self):
        enc_key, mac_key = _derive_keys("test")
        assert len(enc_key) == 32
        assert len(mac_key) == 32

    def test_enc_and_mac_keys_differ(self):
        enc_key, mac_key = _derive_keys("same_secret")
        assert enc_key != mac_key


# ---------------------------------------------------------------------------
# _keystream
# ---------------------------------------------------------------------------

class TestKeystream:
    def test_exact_length(self):
        enc_key, _ = _derive_keys("secret")
        nonce = os.urandom(16)
        assert len(_keystream(enc_key, nonce, 100)) == 100

    def test_zero_length(self):
        enc_key, _ = _derive_keys("secret")
        assert _keystream(enc_key, b"\x00" * 16, 0) == b""

    def test_nonce_changes_output(self):
        enc_key, _ = _derive_keys("secret")
        s1 = _keystream(enc_key, b"\x00" * 16, 32)
        s2 = _keystream(enc_key, b"\x01" * 16, 32)
        assert s1 != s2

    def test_deterministic(self):
        enc_key, _ = _derive_keys("secret")
        nonce = b"\xab" * 16
        assert _keystream(enc_key, nonce, 64) == _keystream(enc_key, nonce, 64)


# ---------------------------------------------------------------------------
# _encrypt_value / _decrypt_value
# ---------------------------------------------------------------------------

class TestEncryptDecrypt:
    def setup_method(self):
        self.enc_key, self.mac_key = _derive_keys("test_secret")

    def test_roundtrip_ascii(self):
        ct = _encrypt_value("hello world", self.enc_key, self.mac_key)
        assert _decrypt_value(ct, self.enc_key, self.mac_key) == "hello world"

    def test_roundtrip_unicode(self):
        pt = "héllo wörld 🎉"
        ct = _encrypt_value(pt, self.enc_key, self.mac_key)
        assert _decrypt_value(ct, self.enc_key, self.mac_key) == pt

    def test_roundtrip_empty(self):
        ct = _encrypt_value("", self.enc_key, self.mac_key)
        assert _decrypt_value(ct, self.enc_key, self.mac_key) == ""

    def test_roundtrip_long(self):
        pt = "x" * 10_000
        ct = _encrypt_value(pt, self.enc_key, self.mac_key)
        assert _decrypt_value(ct, self.enc_key, self.mac_key) == pt

    def test_prefix(self):
        ct = _encrypt_value("test", self.enc_key, self.mac_key)
        assert ct.startswith(_ENC_PREFIX_V2)

    def test_randomized_nonce(self):
        ct1 = _encrypt_value("hello", self.enc_key, self.mac_key)
        ct2 = _encrypt_value("hello", self.enc_key, self.mac_key)
        assert ct1 != ct2

    def test_wrong_key_returns_none(self):
        ct = _encrypt_value("secret", self.enc_key, self.mac_key)
        wrong_enc, wrong_mac = _derive_keys("different_secret")
        assert _decrypt_value(ct, wrong_enc, wrong_mac) is None

    def test_tampered_mac_returns_none(self):
        ct = _encrypt_value("secret", self.enc_key, self.mac_key)
        raw = base64.urlsafe_b64decode(ct[len(_ENC_PREFIX_V2):])
        # Flip a byte in the MAC (last 32 bytes)
        tampered = raw[:-4] + bytes([raw[-4] ^ 0xFF]) + raw[-3:]
        tampered_ct = _ENC_PREFIX_V2 + base64.urlsafe_b64encode(tampered).decode()
        assert _decrypt_value(tampered_ct, self.enc_key, self.mac_key) is None

    def test_too_short_returns_none(self):
        short = _ENC_PREFIX_V2 + base64.urlsafe_b64encode(b"\x00" * 10).decode()
        assert _decrypt_value(short, self.enc_key, self.mac_key) is None


# ---------------------------------------------------------------------------
# UserTokenStore._decrypt (pure path, no DB)
# ---------------------------------------------------------------------------

class TestUserTokenStoreDecrypt:
    def _store(self, key=None):
        return UserTokenStore(db=MagicMock(), encryption_key=key)

    def test_enc2_correct_key(self):
        store = self._store("my_secret")
        ct = _encrypt_value("my_token", *_derive_keys("my_secret"))
        assert store._decrypt(ct) == "my_token"

    def test_enc2_wrong_key_raises(self):
        store = self._store("my_secret")
        ct = _encrypt_value("my_token", *_derive_keys("different_secret"))
        with pytest.raises(TokenDecryptionError):
            store._decrypt(ct)

    def test_enc1_prefix_passthrough(self):
        """Legacy enc: tokens are returned as-is (cannot be decrypted)."""
        store = self._store("any_key")
        legacy = _ENC_PREFIX_V1 + "some_base64_data"
        assert store._decrypt(legacy) == legacy

    def test_plaintext_passthrough_with_key(self):
        """Token stored before encryption was enabled — returned as-is."""
        store = self._store("any_key")
        assert store._decrypt("plain_token") == "plain_token"

    def test_no_key_always_passthrough(self):
        store = self._store(None)
        assert store._decrypt("anything") == "anything"
        assert store._decrypt(_ENC_PREFIX_V2 + "data") == _ENC_PREFIX_V2 + "data"


# ---------------------------------------------------------------------------
# UserTokenStore async methods (mock DB)
# ---------------------------------------------------------------------------

def _mock_db():
    db = MagicMock()
    db.execute = AsyncMock()
    db.fetchval = AsyncMock()
    db.fetchrow = AsyncMock()
    return db


async def test_save_token_encrypts():
    db = _mock_db()
    store = UserTokenStore(db, encryption_key="enc_key")
    await store.save_token("@user:example.com", "lin_token")

    stored = db.execute.call_args[0][2]  # 3rd positional arg is the token value
    assert stored.startswith(_ENC_PREFIX_V2)


async def test_save_and_get_token_roundtrip():
    db = _mock_db()
    store = UserTokenStore(db, encryption_key="enc_key")
    await store.save_token("@user:example.com", "lin_token")

    stored = db.execute.call_args[0][2]
    db.fetchval.return_value = stored
    assert await store.get_token("@user:example.com") == "lin_token"


async def test_get_token_missing():
    db = _mock_db()
    db.fetchval.return_value = None
    store = UserTokenStore(db)
    assert await store.get_token("@nobody:example.com") is None


async def test_delete_token_exists():
    db = _mock_db()
    db.fetchrow.return_value = {"matrix_user_id": "@user:example.com"}
    store = UserTokenStore(db)
    assert await store.delete_token("@user:example.com") is True


async def test_delete_token_not_found():
    db = _mock_db()
    db.fetchrow.return_value = None
    store = UserTokenStore(db)
    assert await store.delete_token("@nobody:example.com") is False


async def test_get_user_info_decrypts():
    db = _mock_db()
    store = UserTokenStore(db, encryption_key="key")
    enc_token = _encrypt_value("lin_tok", *_derive_keys("key"))
    db.fetchrow.return_value = {
        "linear_access_token": enc_token,
        "linear_user_id": "uid-123",
        "linear_user_name": "Alice",
    }
    info = await store.get_user_info("@alice:example.com")
    assert info == {"token": "lin_tok", "user_id": "uid-123", "user_name": "Alice"}


async def test_get_user_info_missing():
    db = _mock_db()
    db.fetchrow.return_value = None
    store = UserTokenStore(db)
    assert await store.get_user_info("@nobody:example.com") is None


# ---------------------------------------------------------------------------
# TicketLinkStore (mock DB)
# ---------------------------------------------------------------------------

async def test_ticket_link_save_and_get():
    db = _mock_db()
    store = TicketLinkStore(db)
    await store.save_link("$evt1", "!room:example.com", "uuid-123", "PROJ-1")

    args = db.execute.call_args[0]
    assert "$evt1" in args
    assert "uuid-123" in args

    db.fetchrow.return_value = {"issue_id": "uuid-123", "issue_identifier": "PROJ-1"}
    link = await store.get_link("$evt1")
    assert link == {"issue_id": "uuid-123", "issue_identifier": "PROJ-1"}


async def test_ticket_link_get_unknown():
    db = _mock_db()
    db.fetchrow.return_value = None
    store = TicketLinkStore(db)
    assert await store.get_link("$unknown") is None
