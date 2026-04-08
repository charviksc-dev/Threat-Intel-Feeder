
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError

from ..dependencies import get_postgres_pool
from ..schemas import (
    Token,
    TokenData,
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
)
from ..utils.security import decode_access_token
from ..config import settings

router = APIRouter(prefix="/api/v1", tags=["auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


async def get_current_user(
    token: str = Depends(oauth2_scheme), pool=Depends(get_postgres_pool)
) -> UserInDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(sub=email, role=payload.get("role"))
    except JWTError:
        raise credentials_exception

    if pool is None:
        raise HTTPException(status_code=500, detail="Database pool is unavailable")

    user = await get_user(pool, token_data.sub)
    if user is None:
        raise credentials_exception
    return user


# ── Email/Password Login ────────────────────────────────────────────


@router.post("/auth/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    pool=Depends(get_postgres_pool),
) -> Token:
    user = await authenticate_user(pool, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return build_access_token(user)


# ── Signup ──────────────────────────────────────────────────────────


@router.post("/auth/signup", response_model=Token, status_code=status.HTTP_201_CREATED)
async def signup(body: SignupRequest, pool=Depends(get_postgres_pool)) -> Token:
    """Register a new user with email and password."""
    if await check_email_exists(pool, body.email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    user = await create_user(
        pool=pool,
        email=body.email,
        full_name=body.full_name,
        password=body.password,
        role="analyst",
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
        full_name=current_user.full_name,
        role=current_user.role,
        is_active=current_user.is_active,
        provider=current_user.provider,
        avatar_url=current_user.avatar_url,
    )
