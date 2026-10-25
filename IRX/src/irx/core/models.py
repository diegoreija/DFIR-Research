"""Validated configuration and JSON-ready domain models."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IRXConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data_dir: Path = Field(default_factory=lambda: Path.home() / ".local" / "share" / "irx")
    analyst: Optional[str] = None
    organization: Optional[str] = None
    timezone: str = "UTC"

    @field_validator("data_dir", mode="before")
    @classmethod
    def expand_data_dir(cls, value: Any) -> Path:
        return Path(value).expanduser()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def json_safe(value: Any) -> Any:
    """Convert SQLite row-like values into JSON-compatible primitives."""
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    return value
