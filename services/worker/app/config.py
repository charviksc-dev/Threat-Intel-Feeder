from pydantic import AnyHttpUrl, Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    POSTGRES_DSN: str = Field(..., env="POSTGRES_DSN")
    ELASTICSEARCH_HOST: AnyHttpUrl = Field(..., env="ELASTICSEARCH_HOST")
    ELASTICSEARCH_INDEX: str = Field("neeve-indicators", env="ELASTICSEARCH_INDEX")
    REDIS_URL: str = Field(..., env="REDIS_URL")
    CELERY_BROKER_URL: str = Field(..., env="CELERY_BROKER_URL")
    CELERY_RESULT_BACKEND: str = Field(..., env="CELERY_RESULT_BACKEND")

    # --- Threat feed credentials ---
    # OTX (AlienVault)
    OTX_API_KEY: str = ""

    # Abuse.ch (legacy CSV feed)
    ABUSECH_FEED_URL: str = ""

    # MISP
    MISP_API_URL: str = ""
    MISP_API_KEY: str = ""

    # VirusTotal
    VIRUSTOTAL_API_KEY: str = ""
    MAX_VT_REQUESTS_PER_MINUTE: int = 4

    # URLhaus (abuse.ch) - no API key required
    URLHAUS_ENABLED: bool = Field(True, env="URLHAUS_ENABLED")

    # ThreatFox (abuse.ch) - no API key required
    THREATFOX_ENABLED: bool = Field(True, env="THREATFOX_ENABLED")

    # Feodo Tracker (abuse.ch) - no API key required
    FEODO_TRACKER_ENABLED: bool = Field(True, env="FEODO_TRACKER_ENABLED")

    # Emerging Threats - no API key required
    EMERGING_THREATS_ENABLED: bool = Field(True, env="EMERGING_THREATS_ENABLED")

    # OpenPhish - no API key required
    OPENPHISH_ENABLED: bool = Field(True, env="OPENPHISH_ENABLED")

    # PhishTank - no API key required
    PHISHTANK_ENABLED: bool = Field(True, env="PHISHTANK_ENABLED")

    # Spamhaus - no API key required
    SPAMHAUS_ENABLED: bool = Field(True, env="SPAMHAUS_ENABLED")

    # GreyNoise
    GREYNOISE_API_KEY: str = ""

    # Have I Been Pwned
    HIBP_API_KEY: str = ""
    HIBP_MONITORED_EMAILS: list[str] = []

    # Hybrid Analysis
    HYBRID_ANALYSIS_API_KEY: str = ""

    # ipinfo.io (for passive DNS enrichment)
    IPINFO_API_KEY: str = ""

    # AI
    AI_SUMMARIZE_ENABLED: bool = True

    # Cache
    CACHE_TTL_SECONDS: int = 3600

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
