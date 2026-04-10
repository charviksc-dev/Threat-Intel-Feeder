import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError

from ..dependencies import get_postgres_pool
from ..schemas import (
    Token,
    User,
    UserInDB,
    SignupRequest,
    OAuthCallback,
)
from ..services.auth import (
    authenticate_user,
    build_access_token,
    get_user,
    create_user,
    check_email_exists,
    get_user_by_provider,
    OAUTH_EXCHANGERS,
    update_last_login,
)
from ..utils.security import decode_access_token
from ..config import settings

router = APIRouter(prefix="/api/v1", tags=["auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")
PRIVILEGED_SIGNUP_ROLES = {"admin", "soc_manager"}
SELF_SERVICE_SIGNUP_ROLES = {"analyst", "viewer", "observer"}
VALID_ROLES = {"admin", "analyst", "viewer", "soc_manager", "observer"}
logger = logging.getLogger(__name__)


async def _update_last_login_safely(pool, email: str) -> None:
    try:
        await update_last_login(pool, email)
    except Exception:
        logger.exception("Failed to update last_login for %s", email)


async def get_current_token_payload(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
        email: str | None = payload.get("sub")
        if not email:
            raise credentials_exception
        return payload
    except JWTError:
        raise credentials_exception


def _normalize_role(role: str | None) -> str:
    normalized = str(role or "").strip().lower()
    if normalized in VALID_ROLES:
        return normalized
    return "analyst"


async def get_current_user_role(
    payload: dict = Depends(get_current_token_payload),
) -> str:
    return _normalize_role(payload.get("role"))


def require_roles(*allowed_roles: str):
    allowed = {_normalize_role(role) for role in allowed_roles}

    async def _check_role(role: str = Depends(get_current_user_role)) -> str:
        if role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions for this operation",
            )
        return role

    return _check_role


async def get_current_user(
    token: str = Depends(oauth2_scheme), pool=Depends(get_postgres_pool)
) -> UserInDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = await get_current_token_payload(token)
    email: str = payload["sub"]

    if pool is None:
        raise HTTPException(status_code=500, detail="Database pool is unavailable")

    user = await get_user(pool, email)
    if user is None:
        raise credentials_exception
    return user


# ── Email/Password Login ────────────────────────────────────────────


@router.post("/auth/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    pool=Depends(get_postgres_pool),
) -> Token:
    import time

    start = time.perf_counter()
    user = await authenticate_user(pool, form_data.username, form_data.password)
    duration = time.perf_counter() - start
    logger.info("Login authentication took %.4fs for %s", duration, form_data.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    asyncio.create_task(_update_last_login_safely(pool, user.email))
    return build_access_token(user)


# ── Signup ──────────────────────────────────────────────────────────


async def _admin_exists(pool) -> bool:
    async with pool.acquire() as conn:
        existing = await conn.fetchval(
            "SELECT 1 FROM users WHERE role = 'admin' AND is_active = true LIMIT 1"
        )
    return bool(existing)


@router.get("/auth/signup-options")
async def signup_options(pool=Depends(get_postgres_pool)) -> dict:
    """Public signup role options with bootstrap guidance."""
    admin_exists = await _admin_exists(pool)
    allowed_roles = (
        sorted(SELF_SERVICE_SIGNUP_ROLES)
        if admin_exists
        else sorted(SELF_SERVICE_SIGNUP_ROLES | PRIVILEGED_SIGNUP_ROLES)
    )
    return {
        "admin_exists": admin_exists,
        "allowed_roles": allowed_roles,
        "privileged_roles": sorted(PRIVILEGED_SIGNUP_ROLES),
        "default_role": "analyst",
    }


@router.post("/auth/signup", response_model=Token, status_code=status.HTTP_201_CREATED)
async def signup(body: SignupRequest, pool=Depends(get_postgres_pool)) -> Token:
    """Register a new user with email and password."""
    if await check_email_exists(pool, body.email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    requested_role = body.role.value
    admin_exists = await _admin_exists(pool)

    # Backward-compatible bootstrap:
    # Older frontend builds do not send "role". In that case, if no admin exists,
    # automatically promote the very first signup to admin so RBAC can be initialized.
    role_explicitly_provided = "role" in getattr(body, "model_fields_set", set())
    if not admin_exists and not role_explicitly_provided:
        requested_role = "admin"

    if admin_exists and requested_role in PRIVILEGED_SIGNUP_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Privileged role signup is disabled. Ask an admin to create this account.",
        )

    user = await create_user(
        pool=pool,
        email=body.email,
        full_name=body.full_name,
        password=body.password,
        role=requested_role,
        provider="local",
    )
    return build_access_token(user)


# ── OAuth Callbacks ─────────────────────────────────────────────────


@router.post("/auth/oauth/{provider}", response_model=Token)
async def oauth_callback(
    provider: str,
    body: OAuthCallback,
    pool=Depends(get_postgres_pool),
) -> Token:
    """Handle OAuth callback from Google, GitHub, or Microsoft.

    The frontend sends the authorization code after the OAuth redirect.
    This endpoint exchanges the code for user info and creates/returns a user.
    """
    if provider not in OAUTH_EXCHANGERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported OAuth provider: {provider}",
        )

    # Check if provider is configured
    provider_configured = {
        "google": bool(settings.GOOGLE_CLIENT_ID),
        "github": bool(settings.GITHUB_CLIENT_ID),
        "microsoft": bool(settings.MICROSOFT_CLIENT_ID),
    }

    if not provider_configured.get(provider):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"{provider.title()} OAuth is not configured on this server",
        )

    # Exchange code for user info
    exchanger = OAUTH_EXCHANGERS[provider]
    user_info = await exchanger(body.code)

    if not user_info or not user_info.get("email"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Failed to authenticate with {provider.title()}",
        )

    email = user_info["email"]
    provider_id = user_info.get("provider_id")

    # Check if user exists by provider
    user = (
        await get_user_by_provider(pool, provider, provider_id) if provider_id else None
    )

    # Check if user exists by email (local account linking)
    if not user:
        user = await get_user(pool, email)

    if user:
        # User exists - update provider info if needed
        if not user.provider_id and provider_id:
            async with pool.acquire() as conn:
                await conn.execute(
                    "UPDATE users SET provider = $1, provider_id = $2, avatar_url = COALESCE($3, avatar_url) WHERE email = $4",
                    provider,
                    provider_id,
                    user_info.get("avatar_url"),
                    email,
                )
        # Update last login
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE users SET last_login = NOW() WHERE email = $1", email
            )
    else:
        # Create new user from OAuth
        user = await create_user(
            pool=pool,
            email=email,
            full_name=user_info.get("full_name", email.split("@")[0]),
            role="analyst",
            provider=provider,
            provider_id=provider_id,
            avatar_url=user_info.get("avatar_url"),
        )

    return build_access_token(user)


# ── OAuth Config (public) ──────────────────────────────────────────


@router.get("/auth/providers")
async def get_oauth_providers() -> dict:
    """Return which OAuth providers are configured (no secrets exposed)."""
    return {
        "providers": {
            "google": {
                "enabled": bool(settings.GOOGLE_CLIENT_ID),
                "client_id": settings.GOOGLE_CLIENT_ID or None,
            },
            "github": {
                "enabled": bool(settings.GITHUB_CLIENT_ID),
                "client_id": settings.GITHUB_CLIENT_ID or None,
            },
            "microsoft": {
                "enabled": bool(settings.MICROSOFT_CLIENT_ID),
                "client_id": settings.MICROSOFT_CLIENT_ID or None,
            },
        }
    }


# ── Current User ────────────────────────────────────────────────────


@router.get("/auth/me", response_model=User)
async def read_current_user(current_user: UserInDB = Depends(get_current_user)) -> User:
    return User(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name or current_user.email.split("@")[0],
        role=current_user.role,
        is_active=current_user.is_active,
        provider=current_user.provider,
        avatar_url=current_user.avatar_url,
    )
