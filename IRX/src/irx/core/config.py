"""Config file discovery and validation."""

import json
from pathlib import Path
from typing import Optional

from pydantic import ValidationError

from irx.core.exceptions import ConfigurationError
from irx.core.models import IRXConfig


def load_config(path: Optional[Path] = None) -> IRXConfig:
    config_path = path or Path.home() / ".config" / "irx" / "config.json"
    if not config_path.exists():
        return IRXConfig()
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
        return IRXConfig.model_validate(raw)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise ConfigurationError(
            "Invalid configuration at {}: {}".format(config_path, exc)
        ) from exc


def initialize_data_dir(config: IRXConfig) -> None:
    try:
        config.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        (config.data_dir / "cases").mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        raise ConfigurationError(
            "Cannot initialize data directory {}: {}".format(config.data_dir, exc)
        ) from exc
