"""Constants for the Apex Fusion (Local) integration.

This module centralizes configuration keys, defaults, and platform registration.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Final

from homeassistant.const import Platform

DOMAIN: Final = "apex_fusion"

# Use a stable logger name so users can configure logging via
# `logger: default: ... logs: { custom_components.apex_fusion: debug }`.
LOGGER_NAME: Final = f"custom_components.{DOMAIN}"

CONF_HOST: Final = "host"
CONF_USERNAME: Final = "username"
CONF_PASSWORD: Final = "password"
CONF_STATUS_PATH: Final = "status_path"

DEFAULT_USERNAME: Final = "admin"
DEFAULT_PASSWORD: Final = ""
DEFAULT_STATUS_PATH: Final = "/cgi-bin/status.xml"

DEFAULT_SCAN_INTERVAL: Final = timedelta(seconds=30)
DEFAULT_TIMEOUT_SECONDS: Final[int] = 10

PLATFORMS: Final[list[Platform]] = [
    Platform.SENSOR,
    Platform.SELECT,
    Platform.BINARY_SENSOR,
]
