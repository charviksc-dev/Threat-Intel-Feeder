from datetime import datetime
from enum import Enum

from pydantic import BaseModel, EmailStr, Field


class UserRole(str, Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"
    soc_manager = "soc_manager"
    observer = "observer"


class AuthProvider(str, Enum):
    local = "local"
    google = "google"
    github = "github"
    microsoft = "microsoft"


class UserBase(BaseModel):
    email: EmailStr
    full_name: str | None = None
    role: UserRole = UserRole.analyst


class UserInDB(UserBase):
    id: int
    hashed_password: str | None = None
    is_active: bool = True
    provider: AuthProvider = AuthProvider.local
    provider_id: str | None = None
    avatar_url: str | None = None


class User(UserBase):
    id: int
    is_active: bool = True
    provider: AuthProvider = AuthProvider.local
    avatar_url: str | None = None


class Token(BaseModel):
    access_token: str
    token_type: str
    user: User | None = None


class TokenData(BaseModel):
    sub: str | None = None
    role: str | None = None


class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str = Field(..., min_length=1)
    role: UserRole = UserRole.analyst


class OAuthCallback(BaseModel):
    code: str
    state: str | None = None
    provider: AuthProvider


class IOCType(str, Enum):
    ipv4 = "ipv4"
    ipv6 = "ipv6"
    domain = "domain"
    hostname = "hostname"
    url = "url"
    hash = "hash"
    cve = "cve"
    email = "email"


class IOCBase(BaseModel):
    indicator: str
    type: IOCType
    source: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    confidence_score: float | None = None
    tags: list[str] = Field(default_factory=list)
    threat_types: list[str] = Field(default_factory=list)
    metadata: dict | None = None
    geo: dict | None = None
    relationships: list[dict] = Field(default_factory=list)


class IndicatorResponse(IOCBase):
    id: str


class IndicatorSearchRequest(BaseModel):
    query: str | None = None
    indicator_type: IOCType | None = None
    source: str | None = None
    min_score: float | None = None
    max_score: float | None = None
    page: int = 1
    page_size: int = 50


class FeedStatus(str, Enum):
    active = "active"
    standby = "standby"
    stale = "stale"
    error = "error"
    unknown = "unknown"


class FeedHealthResponse(BaseModel):
    id: int
    feed_name: str
    feed_label: str
    status: FeedStatus
    last_ingested_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error_at: datetime | None = None
    last_error_message: str | None = None
    ioc_count: int = 0
    ingestion_rate: int = 0
    consecutive_failures: int = 0
    sla_threshold_minutes: int = 60
    is_enabled: bool = True
    updated_at: datetime | None = None


class FeedHealthUpdate(BaseModel):
    feed_name: str
    ioc_count: int | None = None
    success: bool = True
    error_message: str | None = None
