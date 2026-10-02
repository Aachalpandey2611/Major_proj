from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    DATABASE_URL: str
    REDIS_URL: str
    OPENAI_API_KEY: str
    SECRET_KEY: str
    TOKEN_ENCRYPTION_KEY: str
    ENVIRONMENT: str = "development"
    WATCHER_INTERVAL_SECONDS: int = 300
    MAX_LLM_CALLS_PER_SCAN: int = 50

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
