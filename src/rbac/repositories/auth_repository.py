from datetime import datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from rbac.types import LogoutAllResultType, LogoutResultType, RefreshResultType, UserIdentityType


class AuthRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_user_identity(self, token_hash: str) -> UserIdentityType | None:
        sql_query = text("""WITH token_info AS (
    SELECT
        u.id AS user_id,
        u.username,
        CASE
            WHEN t.token_type != 'ACCESS' THEN 'WRONG_TYPE'
            WHEN s.forced_status IS NOT NULL THEN 'SESSION_REVOKED'
            WHEN t.forced_status IS NOT NULL THEN 'TOKEN_REVOKED'
            WHEN t.expires_at <= NOW() THEN 'EXPIRED'
            ELSE 'VALID'
        END AS status
    FROM tokens t
    JOIN sessions s ON t.session_id = s.id
    JOIN users u ON s.user_id = u.id
    WHERE t.token_hash = :token_hash
),
perms AS (
    SELECT p.id, p.codename, up.effect, Null AS role_name
    FROM token_info ti
    JOIN user_permissions up ON ti.user_id = up.user_id
    JOIN permissions p ON up.permission_id = p.id
    WHERE ti.status = 'VALID'

    UNION ALL

    SELECT
        p.id, p.codename,
        CASE
            WHEN ur.effect = 'DENY' OR rp.effect = 'DENY' THEN 'DENY'
            ELSE 'ALLOW'
        END AS effect,
        CASE WHEN ur.effect = 'ALLOW' THEN r.name END AS role_name
    FROM token_info ti
    JOIN user_roles ur ON ti.user_id = ur.user_id
    JOIN roles r ON ur.role_id = r.id
    JOIN role_permissions rp ON r.id = rp.role_id
    JOIN permissions p ON rp.permission_id = p.id
    WHERE ti.status = 'VALID'
),
final_permissions AS (
    SELECT codename, MAX(effect) AS effect
    FROM perms
    GROUP BY codename
),
final_roles AS (
    SELECT role_name
    FROM perms
    WHERE role_name IS NOT NULL
    GROUP BY role_name
)
SELECT
    ti.status,
    ti.user_id,
    ti.username,
    COALESCE(
        (SELECT json_agg(p.codename) FROM final_permissions p WHERE p.effect = 'ALLOW'),
        '[]'::json
    ) AS permissions,
    COALESCE(
        (SELECT json_agg(r.role_name) FROM final_roles r),
        '[]'::json
    ) AS roles
FROM token_info ti""")

        result = await self.session.execute(
            sql_query,
            {"token_hash": token_hash},
        )
        row = result.mappings().one_or_none()
        if row is None:
            return None
        return UserIdentityType(
            status=row["status"],
            user_id=row["user_id"],
            username=row["username"],
            roles=row["roles"],
            permissions=row["permissions"],
        )

    async def logout(self, token_hash: str) -> LogoutResultType | None:
        sql_query = text("""
WITH token_info AS (
    SELECT
        s.id AS session_id,
        CASE
            WHEN t.token_type != 'ACCESS'     THEN 'WRONG_TYPE'
            WHEN s.forced_status IS NOT NULL  THEN 'SESSION_REVOKED'
            WHEN t.forced_status IS NOT NULL  THEN 'TOKEN_REVOKED'
            WHEN t.expires_at <= NOW()        THEN 'EXPIRED'
            ELSE 'VALID'
        END AS status
    FROM tokens t
    JOIN sessions s ON t.session_id = s.id
    WHERE t.token_hash = :token_hash
    FOR UPDATE
),
session_update AS (
    UPDATE sessions
    SET forced_status = 'LOGGED_OUT'
    WHERE id IN (SELECT session_id FROM token_info WHERE status = 'VALID')
),
token_update AS (
    UPDATE tokens
    SET forced_status = 'REVOKED_BY_OWNER'
    WHERE session_id IN (SELECT session_id FROM token_info WHERE status = 'VALID')
)
SELECT
    ti.status,
    ti.session_id
FROM token_info ti
""")

        result = await self.session.execute(
            sql_query,
            {"token_hash": token_hash},
        )
        row = result.mappings().one_or_none()

        if row is None:
            return None

        return LogoutResultType(
            session_id=row["session_id"],
            status=row["status"],
        )

    async def logout_all(self, token_hash: str, *, exclude_current: bool) -> LogoutAllResultType | None:
        sql_query = text("""
WITH current_info AS (
    SELECT
        s.user_id,
        s.id AS current_session_id,
        CASE
            WHEN t.token_type != 'ACCESS'     THEN 'WRONG_TYPE'
            WHEN s.forced_status IS NOT NULL  THEN 'SESSION_REVOKED'
            WHEN t.forced_status IS NOT NULL  THEN 'TOKEN_REVOKED'
            WHEN t.expires_at <= NOW()        THEN 'EXPIRED'
            ELSE 'VALID'
        END AS status
    FROM tokens t
    JOIN sessions s ON t.session_id = s.id
    WHERE t.token_hash = :token_hash
    FOR UPDATE
),
sessions_to_revoke AS (
    UPDATE sessions
    SET forced_status = 'LOGGED_OUT'
    WHERE user_id = (SELECT user_id FROM current_info)
      AND forced_status IS NULL
      AND (id != (SELECT current_session_id FROM current_info) OR NOT :exclude_current)
    RETURNING id
),
_unused_tokens_update AS (
    UPDATE tokens
    SET forced_status = 'REVOKED_BY_OWNER'
    WHERE forced_status IS NULL
      AND session_id IN (SELECT id FROM sessions_to_revoke)
)
SELECT
    ci.status,
    ci.user_id,
    ci.current_session_id
FROM current_info ci
""")

        result = await self.session.execute(
            sql_query,
            {
                "token_hash": token_hash,
                "exclude_current": exclude_current,
            },
        )
        row = result.mappings().one_or_none()

        if row is None:
            return None

        return LogoutAllResultType(
            status=row["status"],
            user_id=row["user_id"],
            current_session_id=row["current_session_id"],
        )

    async def refresh_session(  # noqa: PLR0913
            self,
            access_hash: str,
            refresh_hash: str,
            new_access_hash: str,
            new_refresh_hash: str,
            access_expires_at: datetime,
            refresh_expires_at: datetime,
            ip_address: str,
            user_agent: str,
    ) -> RefreshResultType:
        sql_query = text("""
WITH
access_lookup AS (
    SELECT
        t.id,
        s.id AS session_id,
        s.user_id,
        s.forced_status AS s_status,
        t.forced_status AS t_status,
        t.token_type
    FROM tokens t
    JOIN sessions s ON t.session_id = s.id
    WHERE t.token_hash = :access_hash
    FOR UPDATE OF s, t
),
refresh_lookup AS (
    SELECT
        id,
        session_id,
        forced_status,
        expires_at,
        token_type
    FROM tokens
    WHERE token_hash = :refresh_hash
    FOR UPDATE OF tokens
),
validation AS (
    SELECT
        CASE
            WHEN al.id IS NULL THEN 'ACCESS_NOT_FOUND'
            WHEN rl.id IS NULL THEN 'REFRESH_NOT_FOUND'
            WHEN al.token_type != 'ACCESS' THEN 'ACCESS_WRONG_TYPE'
            WHEN rl.token_type != 'REFRESH' THEN 'REFRESH_WRONG_TYPE'
            WHEN al.session_id != rl.session_id THEN 'SESSION_MISMATCH'
            WHEN al.s_status IS NOT NULL THEN 'SESSION_REVOKED'
            WHEN al.t_status IS NOT NULL THEN 'ACCESS_REVOKED'
            WHEN rl.forced_status IS NOT NULL THEN 'REFRESH_REVOKED'
            WHEN rl.expires_at <= NOW() THEN 'REFRESH_EXPIRED'
            ELSE 'VALID'
        END AS status,
        al.user_id,
        al.session_id
    FROM (SELECT 1) AS anchor
    LEFT JOIN access_lookup al ON TRUE
    LEFT JOIN refresh_lookup rl ON TRUE
),
do_revoke AS (
    UPDATE tokens
    SET forced_status = 'REVOKED_DUE_TO_REFRESH'
    WHERE session_id = (SELECT session_id FROM validation WHERE status = 'VALID')
      AND forced_status IS NULL
    RETURNING session_id
),
do_update_session AS (
    UPDATE sessions
    SET
        ip_address = :ip_address,
        user_agent = :user_agent,
        updated_at = NOW()
    WHERE id = (SELECT session_id FROM validation WHERE status = 'VALID')
),
do_insert AS (
    INSERT INTO tokens (session_id, token_hash, token_type, expires_at)
    SELECT v.session_id, t.token_hash, t.token_type, t.expires_at
    FROM validation v
    JOIN (SELECT DISTINCT session_id FROM do_revoke) dr ON v.session_id = dr.session_id
    CROSS JOIN (
        SELECT
            :new_access_hash AS token_hash,
            'ACCESS' AS token_type,
            (:access_expires_at)::timestamptz AS expires_at
        UNION ALL
        SELECT
            :new_refresh_hash AS token_hash,
            'REFRESH' AS token_type,
            (:refresh_expires_at)::timestamptz AS expires_at
    ) t
    WHERE v.status = 'VALID'
)
SELECT
    status,
    user_id,
    session_id
FROM validation
""")
        result = await self.session.execute(
            sql_query,
            {
                "access_hash": access_hash,
                "refresh_hash": refresh_hash,
                "new_access_hash": new_access_hash,
                "new_refresh_hash": new_refresh_hash,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "access_expires_at": access_expires_at,
                "refresh_expires_at": refresh_expires_at,
            },
        )
        row = result.mappings().one()

        return RefreshResultType(
            status=row["status"],
            user_id=row["user_id"],
            session_id=row["session_id"],
        )
