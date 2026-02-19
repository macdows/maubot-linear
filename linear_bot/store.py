from __future__ import annotations

from mautrix.util.async_db import UpgradeTable, Connection

upgrade_table = UpgradeTable()


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
    def __init__(self, db) -> None:
        self.db = db

    async def get_token(self, matrix_user_id: str) -> str | None:
        return await self.db.fetchval(
            "SELECT linear_access_token FROM user_tokens WHERE matrix_user_id=$1",
            matrix_user_id,
        )

    async def get_user_info(self, matrix_user_id: str) -> dict | None:
        row = await self.db.fetchrow(
            "SELECT linear_access_token, linear_user_id, linear_user_name "
            "FROM user_tokens WHERE matrix_user_id=$1",
            matrix_user_id,
        )
        if row:
            return {
                "token": row["linear_access_token"],
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
        await self.db.execute(
            "INSERT INTO user_tokens (matrix_user_id, linear_access_token, linear_user_id, linear_user_name) "
            "VALUES ($1, $2, $3, $4) "
            "ON CONFLICT (matrix_user_id) DO UPDATE SET "
            "linear_access_token=excluded.linear_access_token, "
            "linear_user_id=excluded.linear_user_id, "
            "linear_user_name=excluded.linear_user_name",
            matrix_user_id,
            token,
            linear_user_id,
            linear_user_name,
        )

    async def delete_token(self, matrix_user_id: str) -> bool:
        result = await self.db.execute(
            "DELETE FROM user_tokens WHERE matrix_user_id=$1", matrix_user_id
        )
        return result == "DELETE 1"


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
