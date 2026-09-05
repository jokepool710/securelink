from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    max_upload_bytes: int = Field(default=5 * 1024 * 1024)
    request_timeout_seconds: float = 5.0
    max_redirects: int = 5
    enable_external_intel: bool = False
    virus_total_api_key: str | None = None
    google_safe_browsing_api_key: str | None = None
    allowed_origins: str = "http://localhost:5173"
    environment: str = "development"

settings = Settings()
