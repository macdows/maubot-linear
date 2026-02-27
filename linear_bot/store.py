from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os

from mautrix.util.async_db import UpgradeTable, Connection

log = logging.getLogger("maubot.linear.store")

upgrade_table = UpgradeTable()

# Prefix to distinguish encrypted values from plaintext
_ENC_PREFIX = "enc:"


def _derive_keys(secret: str) -> tuple[bytes, bytes]:
    """Derive an encryption key and HMAC key from a secret string."""
    master = hashlib.sha256(secret.encode()).digest()
    enc_key = hashlib.sha256(b"enc:" + master).digest()
    mac_key = hashlib.sha256(b"mac:" + master).digest()
    return enc_key, mac_key


def _xor_bytes(data: bytes, key_stream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, key_stream))


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Generate a keystream using HMAC-SHA256 in counter mode."""
    stream = b""
    counter = 0
    while len(stream) < length:
        block = hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        stream += block
        counter += 1
    return stream[:length]


def _encrypt_value(plaintext: str, enc_key: bytes, mac_key: bytes) -> str:
    """Encrypt a string. Returns base64-encoded nonce + ciphertext + mac."""
    data = plaintext.encode()
    nonce = os.urandom(16)
    stream = _keystream(enc_key, nonce, len(data))
    ciphertext = _xor_bytes(data, stream)
    mac = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    return _ENC_PREFIX + base64.urlsafe_b64encode(nonce + ciphertext + mac).decode()


def _decrypt_value(stored: str, enc_key: bytes, mac_key: bytes) -> str | None:
    """Decrypt a value. Returns None if MAC verification fails."""
    raw = base64.urlsafe_b64decode(stored[len(_ENC_PREFIX):])
    if len(raw) < 16 + 32:  # nonce + mac minimum
        return None
    nonce = raw[:16]
    ciphertext = raw[16:-32]
    stored_mac = raw[-32:]
    expected_mac = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(stored_mac, expected_mac):
        return None
    stream = _keystream(enc_key, nonce, len(ciphertext))
    return _xor_bytes(ciphertext, stream).decode()


@upgrade_table.register(description="Initial revision: user tokens and ticket links")
async def upgrade_v1(conn: Connection) -> None:
    await conn.execute(
        """CREATE TABLE user_tokens (
            matrix_user_id    TEXT PRIMARY KEY,
            linear_access_token TEXT NOT NULL,
            linear_user_id     TEXT,
            linear_user_name   TEXT,
            created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"""
    )
    await conn.execute(
        """CREATE TABLE ticket_links (
            event_id   TEXT PRIMARY KEY,
            room_id    TEXT NOT NULL,
            issue_id   TEXT NOT NULL,
            issue_identifier TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"""
    )


class UserTokenStore:
    def __init__(self, db, encryption_key: str | None = None) -> None:
        self.db = db
        self._enc_key: bytes | None = None
        self._mac_key: bytes | None = None
        if encryption_key:
            self._enc_key, self._mac_key = _derive_keys(encryption_key)

    def _encrypt(self, plaintext: str) -> str:
        if self._enc_key:
            return _encrypt_value(plaintext, self._enc_key, self._mac_key)
        return plaintext

    def _decrypt(self, stored: str) -> str:
        if not self._enc_key:
            return stored
        if not stored.startswith(_ENC_PREFIX):
            # Token was stored before encryption was enabled — return as-is
            log.debug("Token not encrypted, returning plaintext (migration needed)")
            return stored
        result = _decrypt_value(stored, self._enc_key, self._mac_key)
        if result is None:
            log.warning("Token decryption failed (wrong key?), returning raw value")
            return stored
        return result

    async def get_token(self, matrix_user_id: str) -> str | None:
        stored = await self.db.fetchval(
            "SELECT linear_access_token FROM user_tokens WHERE matrix_user_id=$1",
            matrix_user_id,
        )
        if stored:
            return self._decrypt(stored)
        return None

    async def get_user_info(self, matrix_user_id: str) -> dict | None:
        row = await self.db.fetchrow(
            "SELECT linear_access_token, linear_user_id, linear_user_name "
            "FROM user_tokens WHERE matrix_user_id=$1",
            matrix_user_id,
        )
        if row:
            return {
                "token": self._decrypt(row["linear_access_token"]),
                "user_id": row["linear_user_id"],
                "user_name": row["linear_user_name"],
            }
        return None

    async def save_token(
        self,
        matrix_user_id: str,
        token: str,
        linear_user_id: str | None = None,
        linear_user_name: str | None = None,
    ) -> None:
        encrypted = self._encrypt(token)
        await self.db.execute(
            "INSERT INTO user_tokens (matrix_user_id, linear_access_token, linear_user_id, linear_user_name) "
            "VALUES ($1, $2, $3, $4) "
            "ON CONFLICT (matrix_user_id) DO UPDATE SET "
            "linear_access_token=excluded.linear_access_token, "
            "linear_user_id=excluded.linear_user_id, "
            "linear_user_name=excluded.linear_user_name",
            matrix_user_id,
            encrypted,
            linear_user_id,
            linear_user_name,
        )

    async def delete_token(self, matrix_user_id: str) -> bool:
        row = await self.db.fetchrow(
            "DELETE FROM user_tokens WHERE matrix_user_id=$1 RETURNING matrix_user_id",
            matrix_user_id,
        )
        return row is not None


class TicketLinkStore:
    def __init__(self, db) -> None:
        self.db = db

    async def save_link(
        self,
        event_id: str,
        room_id: str,
        issue_id: str,
        issue_identifier: str | None = None,
    ) -> None:
        await self.db.execute(
            "INSERT INTO ticket_links (event_id, room_id, issue_id, issue_identifier) "
            "VALUES ($1, $2, $3, $4) "
            "ON CONFLICT (event_id) DO UPDATE SET "
            "issue_id=excluded.issue_id, issue_identifier=excluded.issue_identifier",
            event_id,
            room_id,
            issue_id,
            issue_identifier,
        )

    async def get_link(self, event_id: str) -> dict | None:
        row = await self.db.fetchrow(
            "SELECT issue_id, issue_identifier FROM ticket_links WHERE event_id=$1",
            event_id,
        )
        if row:
            return {"issue_id": row["issue_id"], "issue_identifier": row["issue_identifier"]}
        return None
