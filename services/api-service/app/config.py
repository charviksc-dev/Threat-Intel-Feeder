from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    MONGODB_URI: str = "mongodb://mongo:27017"
    MONGODB_DB: str = "threatintel"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
