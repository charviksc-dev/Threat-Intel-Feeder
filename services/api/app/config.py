from pydantic import Field, AnyHttpUrl
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "Neev Threat Intelligence API"
    APP_ENV: str = "production"
    SECRET_KEY: str = Field(..., env="SECRET_KEY")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    ALLOWED_ORIGINS: str = (
        "http://localhost:4173,http://127.0.0.1:4173,http://10.81.20.144:4173"
    )
    JWT_ISSUER: str = "neev-tip"

    POSTGRES_DSN: str = Field(..., env="POSTGRES_DSN")
    ELASTICSEARCH_HOST: AnyHttpUrl = Field(..., env="ELASTICSEARCH_HOST")
    ELASTICSEARCH_INDEX: str = Field("neeve-indicators", env="ELASTICSEARCH_INDEX")

    REDIS_URL: str = Field(..., env="REDIS_URL")
    ACCESS_TOKEN_EXPIRE_SECONDS: int = 3600

    # OAuth providers
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://localhost:4173/auth/callback/google"

    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    GITHUB_REDIRECT_URI: str = "http://localhost:4173/auth/callback/github"

    MICROSOFT_CLIENT_ID: str = ""
    MICROSOFT_CLIENT_SECRET: str = ""
    MICROSOFT_REDIRECT_URI: str = "http://localhost:4173/auth/callback/microsoft"
    MICROSOFT_TENANT_ID: str = "common"

    # Frontend URL for OAuth redirects
    FRONTEND_URL: str = "http://localhost:4173"

    # Threat feed credentials
    VIRUSTOTAL_API_KEY: str = ""
    CACHE_TTL_SECONDS: int = 3600
    OTX_API_KEY: str = ""
    ABUSECH_FEED_URL: str = ""
    MISP_API_URL: str = ""
    MISP_API_KEY: str = ""

    # SIEM tool integrations
    THEHIVE_URL: str = ""
    THEHIVE_API_KEY: str = ""
    CORTEX_URL: str = ""
    CORTEX_API_KEY: str = ""

    # Neo4j
    NEO4J_URI: str = ""
    NEO4J_USER: str = ""
    NEO4J_PASSWORD: str = ""

    # Notifications
    SLACK_WEBHOOK_URL: str = ""
    ALERT_WEBHOOK_URL: str = ""

    # Webhook authentication for SIEM integrations
    WEBHOOK_AUTH_TOKEN: str = ""

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 60

    # Real-time
    REDIS_STREAM_ENABLED: bool = True

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
