import os
from getpass import getpass
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .exceptions import ConfigurationError


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server: str
    base_dn: str
    username: str
    port: int = 389
    use_ssl: bool = False
    validate_tls: bool = True
    connect_timeout: int = Field(default=5, ge=1, le=120)
    receive_timeout: int = Field(default=15, ge=1, le=300)
    page_size: int = Field(default=500, ge=1, le=5000)

    @field_validator("server", "base_dn", "username")
    @classmethod
    def non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be empty")
        return value

    @field_validator("port")
    @classmethod
    def valid_port(cls, value: int) -> int:
        if not 1 <= value <= 65535:
            raise ValueError("port must be between 1 and 65535")
        return value


def load_settings(config_path: str | None, overrides: dict) -> Settings:
    data: dict = {}
    if config_path:
        path = Path(config_path).expanduser()
        if not path.is_file():
            raise ConfigurationError(f"Configuration file not found: {path}")
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigurationError(f"Could not read configuration: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ConfigurationError("Configuration YAML must contain a mapping.")
        if any("password" in str(key).lower() for key in loaded):
            raise ConfigurationError("Passwords are not allowed in configuration files.")
        data.update(loaded)

    data.update({key: value for key, value in overrides.items() if value is not None})
    try:
        return Settings.model_validate(data)
    except ValidationError as exc:
        messages = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
        raise ConfigurationError(messages) from exc


def obtain_password() -> str:
    password = os.environ.get("DELEGATIONFLOW_PASSWORD")
    if password:
        return password
    return getpass("LDAP password: ")
