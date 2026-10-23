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

# Stable controller identity: the controller serial, persisted on first setup. It
# is the device identifier and the prefix of every unique_id, so it must never
# depend on the transport or on the host/IP. A controller that reports no serial
# falls back to the entry's original unique_id (kept for the entry's lifetime).
CONF_SERIAL: Final = "serial"

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

# Firmware install window.
#
# The controller reboots while it installs a new AOS, and its own web UI tracks
# the install with fixed timers only (it reads no progress from the controller).
# The coordinator mirrors that: elapsed time since the install request returned
# drives the reported phase and percentage, and a changed software version is the
# only evidence of success.
INSTALL_PHASE_RESTARTING: Final = "restarting"
INSTALL_PHASE_RECONNECTING: Final = "reconnecting"
INSTALL_PHASE_WEB_PAGES: Final = "web_pages"

INSTALL_RESULT_SUCCESS: Final = "success"
INSTALL_RESULT_TIMEOUT: Final = "timeout"
INSTALL_RESULT_REJECTED: Final = "rejected"

# restarting: 0 -> 40 % over 120 s.
INSTALL_RESTART_SECONDS: Final = 120.0
INSTALL_RESTART_PERCENT: Final = 40
# reconnecting: holds at 40 %, creeping to at most 49 % over the next 60 s.
INSTALL_RECONNECT_CREEP_SECONDS: Final = 60.0
INSTALL_RECONNECT_CREEP_PERCENT: Final = 9
# web_pages: 50 -> 99 % over 120 s; 100 % is never reported.
INSTALL_WEB_PAGES_SECONDS: Final = 120.0
INSTALL_WEB_PAGES_START_PERCENT: Final = 50
INSTALL_WEB_PAGES_SPAN_PERCENT: Final = 49
# The controller UI declares failure at this point; we only log a warning.
INSTALL_UI_FAIL_WARNING_SECONDS: Final = 184.0
# Hard cap: after this the window is closed and a Repairs issue is raised.
INSTALL_WINDOW_MAX_SECONDS: Final = 20 * 60.0
INSTALL_PROGRESS_TICK: Final = timedelta(seconds=5)
# Longest REST backoff honoured while the controller is expected to be rebooting.
INSTALL_REST_BACKOFF_CAP_SECONDS: Final = 30.0

# Key names (case-insensitive substring, at any depth) that are never sent back
# to the controller with the install request. The controller treats omitted
# fields as unchanged, so dropping them is safe; echoing a secret is not.
INSTALL_NCONF_REDACT_PATTERN: Final = r"pass|pwd|secret|token|key|auth|credential|ssid"

# Persisted in-flight marker (one per config entry).
INSTALL_STORE_VERSION: Final = 1

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
