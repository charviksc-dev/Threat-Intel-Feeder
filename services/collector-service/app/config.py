from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    MONGODB_URI: str = "mongodb://mongo:27017"
    MONGODB_DB: str = "threatintel"
    OPENCTI_API_URL: str = ""
    OPENCTI_API_TOKEN: str = ""
    MISP_API_URL: str = ""
    MISP_API_KEY: str = ""
    FEED_SYNC_INTERVAL: int = 300

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
