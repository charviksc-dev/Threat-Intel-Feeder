import logging
from datetime import timedelta
from typing import Optional

import httpx
from asyncpg import Pool
from fastapi.concurrency import run_in_threadpool

from ..utils.security import create_access_token, get_password_hash, verify_password
from ..config import settings
from ..schemas import Token, User, UserInDB

logger = logging.getLogger(__name__)

ALLOWED_ROLES = {"admin", "analyst", "viewer", "soc_manager", "observer"}


def _normalize_role(role: str | None) -> str:
    if role in ALLOWED_ROLES:
        return role
    logger.warning("Unknown role '%s'; defaulting to analyst", role)
    return "analyst"


async def get_user(pool: Pool, email: str) -> Optional[UserInDB]:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, email, full_name, hashed_password, role, is_active, provider, provider_id, avatar_url FROM users WHERE email = $1",
            email,
        )
        if not row:
            return None
        return UserInDB(
            id=row["id"],
            email=row["email"],
            full_name=row["full_name"],
            hashed_password=row["hashed_password"],
            role=_normalize_role(row["role"]),
            is_active=row["is_active"],
            provider=row["provider"] or "local",
            provider_id=row["provider_id"],
            avatar_url=row["avatar_url"],
        )


async def get_user_by_provider(
    pool: Pool, provider: str, provider_id: str
) -> Optional[UserInDB]:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, email, full_name, hashed_password, role, is_active, provider, provider_id, avatar_url FROM users WHERE provider = $1 AND provider_id = $2",
            provider,
            provider_id,
        )
        if not row:
            return None
        return UserInDB(
            id=row["id"],
            email=row["email"],
            full_name=row["full_name"],
            hashed_password=row["hashed_password"],
            role=_normalize_role(row["role"]),
            is_active=row["is_active"],
            provider=row["provider"] or "local",
            provider_id=row["provider_id"],
            avatar_url=row["avatar_url"],
        )


async def authenticate_user(
    pool: Pool, email: str, password: str
) -> Optional[UserInDB]:
    user = await get_user(pool, email)
    if not user:
        return None
    if not user.hashed_password:
        return None
    password_matches = await run_in_threadpool(
        verify_password, password, user.hashed_password
    )
    if not password_matches:
        return None
    return user


def build_access_token(user: UserInDB) -> Token:
    timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    normalized_role = _normalize_role(str(user.role))
    token = create_access_token({"sub": user.email, "role": normalized_role})
    return Token(
        access_token=token,
        token_type="bearer",
        user=User(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            role=normalized_role,
            is_active=user.is_active,
            provider=user.provider,
            avatar_url=user.avatar_url,
        ),
    )


async def create_user(
    pool: Pool,
    email: str,
    full_name: str,
    password: str | None = None,
    role: str = "analyst",
    provider: str = "local",
    provider_id: str | None = None,
    avatar_url: str | None = None,
) -> User:
    hashed_password = get_password_hash(password) if password else None
    normalized_role = _normalize_role(role)
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """INSERT INTO users (email, full_name, hashed_password, role, provider, provider_id, avatar_url)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               RETURNING id, email, full_name, role, is_active, provider, avatar_url""",
            email,
            full_name,
            hashed_password,
            normalized_role,
            provider,
            provider_id,
            avatar_url,
        )
    return User(**row)


async def update_last_login(pool: Pool, email: str) -> None:
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE users SET last_login = NOW() WHERE email = $1",
            email,
        )


async def check_email_exists(pool: Pool, email: str) -> bool:
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT id FROM users WHERE email = $1", email)
        return row is not None


# ── OAuth Provider Functions ────────────────────────────────────────


async def exchange_google_code(code: str) -> dict | None:
    """Exchange Google OAuth code for user info."""
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            # Exchange code for tokens
            token_res = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "redirect_uri": settings.GOOGLE_REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            )
            if token_res.status_code != 200:
                logger.warning("Google token exchange failed: %s", token_res.text)
                return None

            tokens = token_res.json()
            access_token = tokens.get("access_token")

            # Get user info
            user_res = await client.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if user_res.status_code != 200:
                return None

            user_info = user_res.json()
            return {
                "provider_id": user_info.get("id"),
                "email": user_info.get("email"),
                "full_name": user_info.get("name", ""),
                "avatar_url": user_info.get("picture"),
            }
    except Exception as e:
        logger.warning("Google OAuth error: %s", e)
        return None


async def exchange_github_code(code: str) -> dict | None:
    """Exchange GitHub OAuth code for user info."""
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            # Exchange code for access token
            token_res = await client.post(
                "https://github.com/login/oauth/access_token",
                json={
                    "client_id": settings.GITHUB_CLIENT_ID,
                    "client_secret": settings.GITHUB_CLIENT_SECRET,
                    "code": code,
                },
                headers={"Accept": "application/json"},
            )
            if token_res.status_code != 200:
                logger.warning("GitHub token exchange failed: %s", token_res.text)
                return None

            tokens = token_res.json()
            access_token = tokens.get("access_token")

            # Get user info
            user_res = await client.get(
                "https://api.github.com/user",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
            if user_res.status_code != 200:
                return None

            user_info = user_res.json()

            # GitHub may not expose email in profile, fetch emails
            email = user_info.get("email")
            if not email:
                emails_res = await client.get(
                    "https://api.github.com/user/emails",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/json",
                    },
                )
                if emails_res.status_code == 200:
                    emails = emails_res.json()
                    primary = next((e for e in emails if e.get("primary")), None)
                    email = (
                        primary.get("email")
                        if primary
                        else (emails[0].get("email") if emails else "")
                    )

            return {
                "provider_id": str(user_info.get("id")),
                "email": email,
                "full_name": user_info.get("name") or user_info.get("login", ""),
                "avatar_url": user_info.get("avatar_url"),
            }
    except Exception as e:
        logger.warning("GitHub OAuth error: %s", e)
        return None


async def exchange_microsoft_code(code: str) -> dict | None:
    """Exchange Microsoft OAuth code for user info."""
    try:
        tenant = settings.MICROSOFT_TENANT_ID
        async with httpx.AsyncClient(timeout=30) as client:
            # Exchange code for tokens
            token_res = await client.post(
                f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
                data={
                    "code": code,
                    "client_id": settings.MICROSOFT_CLIENT_ID,
                    "client_secret": settings.MICROSOFT_CLIENT_SECRET,
                    "redirect_uri": settings.MICROSOFT_REDIRECT_URI,
                    "grant_type": "authorization_code",
                    "scope": "openid profile email User.Read",
                },
            )
            if token_res.status_code != 200:
                logger.warning("Microsoft token exchange failed: %s", token_res.text)
                return None

            tokens = token_res.json()
            access_token = tokens.get("access_token")

            # Get user info
            user_res = await client.get(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if user_res.status_code != 200:
                return None

            user_info = user_res.json()
            return {
                "provider_id": user_info.get("id"),
                "email": user_info.get("mail") or user_info.get("userPrincipalName"),
                "full_name": user_info.get("displayName", ""),
                "avatar_url": None,
            }
    except Exception as e:
        logger.warning("Microsoft OAuth error: %s", e)
        return None


OAUTH_EXCHANGERS = {
    "google": exchange_google_code,
    "github": exchange_github_code,
    "microsoft": exchange_microsoft_code,
}
