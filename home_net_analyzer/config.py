"""Configuration management using Pydantic Settings."""

from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "home-net-analyzer"
    debug: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # Capture settings
    capture_interface: str = "eth0"
    capture_promiscuous: bool = True
    capture_buffer_size: int = 65536
    capture_timeout: float = 1.0  # seconds per sniff iteration

    # Storage settings
    database_path: str = "data/packets.db"
    database_type: Literal["sqlite", "duckdb"] = "sqlite"
    max_packets_in_memory: int = 10000

    # BPF filter (optional pre-filter at kernel level)
    bpf_filter: str = ""

    # Packet parsing
    parse_raw_payload: bool = False  # Store raw bytes if True
    max_payload_bytes: int = 512

    def get_database_path(self) -> Path:
        """Return database path as Path object, creating parent dirs if needed."""
        p = Path(self.database_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def validate_interface(self) -> bool:
        """Basic check that interface name is non-empty."""
        return bool(self.capture_interface and self.capture_interface.strip())


# Singleton-like accessor (can be overridden in tests)
_settings: Settings | None = None


def get_settings() -> Settings:
    """Get the current settings instance (creates default if not set)."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def set_settings(settings: Settings) -> None:
    """Override settings (useful for testing)."""
    global _settings
    _settings = settings
