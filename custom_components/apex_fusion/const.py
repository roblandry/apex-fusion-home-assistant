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
CONF_NO_LOGIN: Final = "no_login"
CONF_STATUS_PATH: Final = "status_path"

# Transport used to talk to the controller, detected once by the config flow and
# stored on the entry. The coordinator only ever polls this transport; an outage
# makes entities unavailable, it never switches transport.
#
# - "rest":   the newer /rest/* API (Apex Jr / full Apex on current firmware).
# - "legacy": /cgi-bin/status.json and /cgi-bin/status.xml (older controllers).
CONF_TRANSPORT: Final = "transport"
TRANSPORT_REST: Final = "rest"
TRANSPORT_LEGACY: Final = "legacy"

# Legacy controllers expose status.json and status.xml. status.xml keys probes by
# name (no ``did``), so the working format is pinned too: flipping between the two
# would create a second set of entities.
CONF_LEGACY_FORMAT: Final = "legacy_format"
LEGACY_FORMAT_CGI_JSON: Final = "cgi_json"
LEGACY_FORMAT_XML: Final = "xml"

# Optional reconfigure-flow checkbox: probe the controller again and replace the
# stored transport.
CONF_REDETECT_TRANSPORT: Final = "redetect_transport"

# Written by releases that picked the transport on every poll. Only read to
# infer the transport of entries created by those releases.
CONF_LAST_SOURCE: Final = "last_source"

DEFAULT_USERNAME: Final = "admin"
DEFAULT_PASSWORD: Final = ""
DEFAULT_STATUS_PATH: Final = "/cgi-bin/status.xml"

DEFAULT_SCAN_INTERVAL: Final = timedelta(seconds=30)
DEFAULT_TIMEOUT_SECONDS: Final[int] = 10

PLATFORMS: Final[list[Platform]] = [
    Platform.SENSOR,
    Platform.SELECT,
    Platform.SWITCH,
    Platform.BINARY_SENSOR,
    Platform.BUTTON,
    Platform.NUMBER,
    Platform.UPDATE,
]

# Friendly module names for Aquabus hardware types.
#
# These are used for Home Assistant device naming (not for identifiers), so the
# UI shows descriptive names instead of short hwtype tokens.
MODULE_HWTYPE_FRIENDLY_NAMES: Final[dict[str, str]] = {
    "FMM": "Fluid Monitoring Module",
    "PM2": "Salinity Probe Module",
    "PM1": "pH/ORP Probe Module",
    "MXM": "Mobius Wireless Control Module",
    "VDM": "LED & Pump Control Module",
    "PM3": "Dissolved Oxygen Module",
    "AFS": "Automatic Feeding System",
    "LSM": "Lunar Simulator Module",
    # Common/related modules (not explicitly requested, but keeps naming tidy).
    "TRI": "Trident",
    "TNP": "Trident NP",
}

# Icons

# Network / diagnostics
ICON_IP_NETWORK: Final[str] = "mdi:ip-network"
ICON_ROUTER_NETWORK: Final[str] = "mdi:router-network"
ICON_IP_NETWORK_OUTLINE: Final[str] = "mdi:ip-network-outline"
ICON_WIFI_SETTINGS: Final[str] = "mdi:wifi-settings"
ICON_WIFI_STRENGTH_4: Final[str] = "mdi:wifi-strength-4"
ICON_SIGNAL: Final[str] = "mdi:signal"
ICON_ALERT_CIRCLE_OUTLINE: Final[str] = "mdi:alert-circle-outline"
ICON_LAN_CONNECT: Final[str] = "mdi:lan-connect"
ICON_WIFI: Final[str] = "mdi:wifi"
ICON_BUG_OUTLINE: Final[str] = "mdi:bug-outline"

# Trident
ICON_FLASK_OUTLINE: Final[str] = "mdi:flask-outline"
ICON_BEAKER_OUTLINE: Final[str] = "mdi:beaker-outline"
ICON_TRASH_CAN_OUTLINE: Final[str] = "mdi:trash-can-outline"
ICON_CUP_OFF: Final[str] = "mdi:cup-off"
ICON_FLASK_EMPTY: Final[str] = "mdi:flask-empty"
ICON_FLASK_EMPTY_PLUS_OUTLINE: Final[str] = "mdi:flask-empty-plus-outline"
ICON_CUP_OUTLINE: Final[str] = "mdi:cup-outline"
ICON_CUP_WATER: Final[str] = "mdi:cup-water"
ICON_TEST_TUBE: Final[str] = "mdi:test-tube"

# Probes
ICON_THERMOMETER: Final[str] = "mdi:thermometer"
ICON_PH: Final[str] = "mdi:ph"
ICON_SHAKER_OUTLINE: Final[str] = "mdi:shaker-outline"
ICON_FLASH: Final[str] = "mdi:flash"
ICON_CURRENT_AC: Final[str] = "mdi:current-ac"
ICON_FLASK: Final[str] = "mdi:flask"
ICON_GAUGE: Final[str] = "mdi:gauge"

# Outlets / controls
ICON_PUMP: Final[str] = "mdi:pump"
ICON_LIGHTBULB: Final[str] = "mdi:lightbulb"
ICON_RADIATOR: Final[str] = "mdi:radiator"
ICON_POWER_SOCKET_US: Final[str] = "mdi:power-socket-us"
ICON_ALARM: Final[str] = "mdi:alarm"
ICON_TOGGLE_SWITCH_OUTLINE: Final[str] = "mdi:toggle-switch-outline"
ICON_BRIGHTNESS_PERCENT: Final[str] = "mdi:brightness-percent"
ICON_REFRESH: Final[str] = "mdi:refresh"
ICON_SHAKER: Final[str] = "mdi:shaker"
