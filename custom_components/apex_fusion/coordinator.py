"""Coordinator for fetching/parsing Apex controller state.

Strategy:
- Each config entry is pinned to one transport (REST or legacy), chosen once.
- Only that transport is polled; failures make entities unavailable.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from http import HTTPStatus
from typing import Any, cast

import aiohttp
import async_timeout
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.event import async_call_later, async_track_time_interval
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import slugify
from yarl import URL

from .const import (
    CONF_HOST,
    CONF_LAST_SOURCE,
    CONF_LEGACY_FORMAT,
    CONF_NO_LOGIN,
    CONF_PASSWORD,
    CONF_SERIAL,
    CONF_TRANSPORT,
    CONF_USERNAME,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_STATUS_PATH,
    DEFAULT_TIMEOUT_SECONDS,
    DOMAIN,
    INSTALL_NCONF_STRIPPED_KEYS,
    INSTALL_PHASE_RECONNECTING,
    INSTALL_PHASE_RESTARTING,
    INSTALL_PHASE_WEB_PAGES,
    INSTALL_PROGRESS_TICK,
    INSTALL_RECONNECT_CREEP_PERCENT,
    INSTALL_RECONNECT_CREEP_SECONDS,
    INSTALL_REST_BACKOFF_CAP_SECONDS,
    INSTALL_RESTART_PERCENT,
    INSTALL_RESTART_SECONDS,
    INSTALL_RESULT_REJECTED,
    INSTALL_RESULT_SUCCESS,
    INSTALL_RESULT_TIMEOUT,
    INSTALL_UI_FAIL_WARNING_SECONDS,
    INSTALL_WEB_PAGES_SECONDS,
    INSTALL_WEB_PAGES_SPAN_PERCENT,
    INSTALL_WEB_PAGES_START_PERCENT,
    INSTALL_WINDOW_MAX_SECONDS,
    LEGACY_FORMAT_CGI_JSON,
    LEGACY_FORMAT_XML,
    LOGGER_NAME,
    MODULE_HWTYPE_FRIENDLY_NAMES,
    TRANSPORT_LEGACY,
    TRANSPORT_REST,
)

_LOGGER = logging.getLogger(LOGGER_NAME)


def _safe_str(err: BaseException) -> str:
    """Describe an exception without letting a broken ``__str__`` escape."""
    try:
        return str(err)
    except Exception:  # noqa: BLE001
        return err.__class__.__name__


def transport_from_entry_data(data: Mapping[str, Any]) -> str | None:
    """Return the transport stored on a config entry, if it can be determined.

    Args:
        data: Config entry data.

    Returns:
        ``"rest"`` or ``"legacy"``; ``None`` when nothing usable is stored. Entries
        written by releases that chose a source per poll carry ``last_source``,
        which is mapped here.
    """
    stored = str(data.get(CONF_TRANSPORT) or "").strip().lower()
    if stored in (TRANSPORT_REST, TRANSPORT_LEGACY):
        return stored
    last = str(data.get(CONF_LAST_SOURCE) or "").strip().lower()
    if last == TRANSPORT_REST:
        return TRANSPORT_REST
    if last in (LEGACY_FORMAT_CGI_JSON, LEGACY_FORMAT_XML):
        return TRANSPORT_LEGACY
    return None


def legacy_format_from_entry_data(data: Mapping[str, Any]) -> str | None:
    """Return the legacy status format stored on a config entry, if known.

    Args:
        data: Config entry data.

    Returns:
        ``"cgi_json"`` or ``"xml"``; ``None`` when not yet known (the first
        refresh then tries status.json before status.xml and records the result).
    """
    stored = str(data.get(CONF_LEGACY_FORMAT) or "").strip().lower()
    if stored in (LEGACY_FORMAT_CGI_JSON, LEGACY_FORMAT_XML):
        return stored
    last = str(data.get(CONF_LAST_SOURCE) or "").strip().lower()
    if last in (LEGACY_FORMAT_CGI_JSON, LEGACY_FORMAT_XML):
        return last
    return None


_INPUT_DID_MODULE_ABADDR = re.compile(r"^(?P<abaddr>\d+)_")


def _to_int(value: Any) -> int | None:
    """Best-effort conversion to int.

    Accepts real ints (excluding bool), integer-valued floats, and digit-only
    strings.
    """

    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        t = value.strip()
        if t.isdigit():
            return int(t)
    return None


def _status_key(s: str) -> str:
    t = s.strip().lower()
    t = re.sub(r"\s+", " ", t)
    t = re.sub(r"[^a-z0-9]+", "_", t)
    return t.strip("_")


def _normalize_trident_status(
    raw_status: str | None,
) -> tuple[str | None, bool | None, str | None]:
    """Normalize Trident-family status strings for human display.

    Controllers sometimes emit lowercase or inconsistent casing (e.g. "prime 1",
    "testing no3"). We normalize for stable display, and also provide a stable
    lowercase status key suitable for future translation mapping.
    """

    if raw_status is None:
        return None, None, None

    raw = str(raw_status).strip()
    if not raw:
        return None, None, None

    lower = re.sub(r"\s+", " ", raw).strip().lower()

    # Abbreviations like OK should remain uppercase.
    if lower in {"ok"}:
        return "OK", False, "ok"

    if lower in {"idle"}:
        return "Idle", False, "idle"

    def _fix_analytes(text: str) -> str:
        # Common analytes/abbreviations.
        out = text
        out = re.sub(r"\bno3\b", "NO3", out, flags=re.IGNORECASE)
        out = re.sub(r"\bpo4\b", "PO4", out, flags=re.IGNORECASE)
        out = re.sub(r"\bca\s*/\s*mg\b", "Ca/Mg", out, flags=re.IGNORECASE)
        # Keep single-element analytes in Apex UI style.
        out = re.sub(r"\balk\b", "Alk", out, flags=re.IGNORECASE)
        out = re.sub(r"\bca\b", "Ca", out, flags=re.IGNORECASE)
        out = re.sub(r"\bmg\b", "Mg", out, flags=re.IGNORECASE)
        return out

    status_key = _status_key(lower)

    # Testing statuses.
    if lower.startswith("testing"):
        rest = lower[len("testing") :].strip()
        if rest:
            display = f"Testing {_fix_analytes(rest)}"
        else:
            display = "Testing"
        return display, True, status_key

    # Prime statuses.
    if lower.startswith("prime"):
        rest = lower[len("prime") :].strip()
        display = "Prime" if not rest else f"Prime {rest}"
        display = _fix_analytes(display[:1].upper() + display[1:])
        return display, False, status_key

    # Generic fallback: sentence-case + analyte fixes.
    display = raw
    if display[:1].islower():
        display = display[:1].upper() + display[1:]
    display = _fix_analytes(display)
    return display, ("testing" in lower), status_key


def _trident_error_message(error_code: int | None) -> str | None:
    """Decode Trident-family error codes.

    The REST payload exposes an integer `errorCode` in `modules[].extra`.
    Neptune appears to use bit flags; we only map the ones we've observed.
    Unknown codes are still surfaced as a generic message.
    """

    if error_code is None:
        return None
    if isinstance(error_code, bool):
        return None
    if error_code <= 0:
        return None

    # Observed on Trident (TRI):
    # - 1024 shows as "Test B Failed" in Apex Fusion.
    # These appear to be bit flags (may be combined).
    bit_messages: list[str] = []
    known_bits = 0
    for bit, msg in (
        (512, "Test A Failed"),
        (1024, "Test B Failed"),
        (2048, "Test C Failed"),
    ):
        if error_code & bit:
            bit_messages.append(msg)
            known_bits |= bit

    unknown_bits = error_code & ~known_bits
    if not bit_messages and unknown_bits == error_code:
        return f"Error code {error_code}"
    if unknown_bits:
        bit_messages.append(f"Error bits {unknown_bits}")

    return ", ".join(bit_messages) or f"Error code {error_code}"


def clean_hostname_display(hostname: str | None) -> str | None:
    """Return a display-friendly hostname/tank name.

    Controllers commonly report hostnames with underscores. HA UIs read better
    with spaces, so normalize for display only.

    Args:
        hostname: Raw hostname or tank name.

    Returns:
        Normalized display name, or None if empty.
    """

    t = (hostname or "").strip()
    if not t:
        return None
    t = t.replace("_", " ")
    t = " ".join(t.split())
    return t or None


def _tank_slug_from_meta(
    meta: dict[str, Any],
    *,
    tank_slug: str | None = None,
    tank_name: str | None = None,
) -> str:
    """Return the tank slug used for entity ids/device names."""

    if tank_slug is not None and str(tank_slug).strip():
        out = slugify(str(tank_slug).strip())
        return out or "tank"

    raw_name = str(tank_name or meta.get("hostname") or "").strip()
    disp = clean_hostname_display(raw_name) or raw_name
    out = slugify(disp or "tank")
    return out or "tank"


def module_abaddr_from_input_did(did: str) -> int | None:
    """Extract module Aquabus address from an input DID like `5_I1` or `4_0`.

    Many Apex REST payloads encode the module address into the DID for module-
    backed inputs (digital inputs, PM2 conductivity, Trident values, etc.).

    This function is intentionally conservative and returns None when the DID
    is not in the expected format.

    Args:
        did: Input DID value.

    Returns:
        Aquabus address when present, otherwise None.
    """

    t = (did or "").strip()
    if not t:
        return None
    m = _INPUT_DID_MODULE_ABADDR.match(t)
    if not m:
        return None
    try:
        return int(m.group("abaddr"))
    except ValueError:
        return None


# Conservative safety margins for Trident derived warnings.
#
# Waste: a full sample run can add ~12 mL; warning should trigger before the
# container is completely full.
TRIDENT_WASTE_FULL_MARGIN_ML = 20.0

# TODO: Determine sane value based on real-world usage.
# Issue URL: https://github.com/roblandry/apex-fusion-home-assistant/issues/20
# Reagents: warn conservatively when near-empty.
TRIDENT_REAGENT_EMPTY_THRESHOLD_ML = 20.0


_TRANSIENT_HTTP_STATUSES: set[int] = {
    HTTPStatus.REQUEST_TIMEOUT,
    HTTPStatus.TOO_MANY_REQUESTS,
    HTTPStatus.INTERNAL_SERVER_ERROR,
    HTTPStatus.BAD_GATEWAY,
    HTTPStatus.SERVICE_UNAVAILABLE,
    HTTPStatus.GATEWAY_TIMEOUT,
}


def _is_transient_http_status(status: int) -> bool:
    return status in _TRANSIENT_HTTP_STATUSES


def _session_has_connect_sid(session: aiohttp.ClientSession, base_url: str) -> bool:
    try:
        cookies = session.cookie_jar.filter_cookies(URL(base_url))
        return "connect.sid" in cookies
    except Exception:
        return False


def _set_connect_sid_cookie(
    session: aiohttp.ClientSession, *, base_url: str, sid: str
) -> None:
    if not sid:
        return
    session.cookie_jar.update_cookies({"connect.sid": sid}, response_url=URL(base_url))


def build_device_info(
    *,
    host: str,
    meta: dict[str, Any],
    device_identifier: str,
    tank_slug: str | None = None,
) -> DeviceInfo:
    """Build DeviceInfo for this controller.

    Args:
        host: Controller host/IP.
        meta: Coordinator meta dict.
        device_identifier: Stable identifier for the HA device registry.

    Returns:
        DeviceInfo instance.
    """
    serial = str(meta.get("serial") or "").strip() or None
    model = str(meta.get("type") or meta.get("hardware") or "Apex").strip() or "Apex"
    hostname = str(meta.get("hostname") or "").strip() or None
    tank_slug_effective = (
        _tank_slug_from_meta(meta, tank_slug=tank_slug).replace("_", " ").title()
    )
    name = f"{tank_slug_effective} - APEX"

    identifiers = {(DOMAIN, device_identifier)}
    return DeviceInfo(
        identifiers=identifiers,
        name=name,
        manufacturer="Neptune Systems",
        model=model,
        serial_number=serial,
        hw_version=(str(meta.get("hardware") or "").strip() or None),
        sw_version=(str(meta.get("software") or "").strip() or None),
        configuration_url=f"http://{host}",
        suggested_area=clean_hostname_display(hostname),
    )


def build_trident_device_info(
    *,
    host: str,
    meta: dict[str, Any],
    controller_device_identifier: str,
    trident_abaddr: int,
    tank_slug: str | None = None,
    trident_hwtype: str | None = None,
    trident_hwrev: str | None = None,
    trident_swrev: str | None = None,
    trident_serial: str | None = None,
) -> DeviceInfo:
    """Build DeviceInfo for a Trident module.

    The Trident is a distinct physical module; grouping its entities under a
    separate device keeps the controller device page manageable.

    Args:
        host: Controller host/IP.
        meta: Coordinator meta dict.
        controller_device_identifier: Stable identifier for the controller device.
        trident_abaddr: Aquabus address of the Trident.
        trident_hwtype: Optional module hwtype token.
        trident_hwrev: Optional module hardware revision.
        trident_swrev: Optional module software revision.
        trident_serial: Optional module serial.

    Returns:
        DeviceInfo instance for the Trident module.
    """

    # Keep the helper for call-site readability, but align identifiers and
    # naming with generic Aquabus module devices.

    hwtype = str(trident_hwtype).strip().upper() if trident_hwtype else "TRI"
    return build_module_device_info(
        host=host,
        controller_device_identifier=controller_device_identifier,
        module_hwtype=hwtype,
        module_abaddr=trident_abaddr,
        tank_slug=tank_slug,
        module_name=None,
        module_hwrev=(str(trident_hwrev).strip() or None if trident_hwrev else None),
        module_swrev=(str(trident_swrev).strip() or None if trident_swrev else None),
        module_serial=(str(trident_serial).strip() or None if trident_serial else None),
        tank_name=(str(meta.get("hostname") or "").strip() or None),
    )


def build_aquabus_child_device_info_from_data(
    *,
    host: str,
    controller_meta: dict[str, Any],
    controller_device_identifier: str,
    data: dict[str, Any],
    module_abaddr: int,
    tank_slug: str | None = None,
    module_hwtype_hint: str | None = None,
    module_name_hint: str | None = None,
) -> DeviceInfo | None:
    """Build DeviceInfo for an Aquabus module at an address.

    Returns a Trident DeviceInfo for Trident-family modules, otherwise returns a
    generic module DeviceInfo.

    This uses only controller-provided metadata (config/status payloads).

    Args:
        host: Controller host/IP.
        controller_meta: Meta dict for the controller.
        controller_device_identifier: Stable identifier for the controller device.
        data: Coordinator data dict.
        module_abaddr: Aquabus address of the child module.
        module_hwtype_hint: Optional hwtype hint.
        module_name_hint: Optional friendly name hint.

    Returns:
        DeviceInfo instance when the module can be identified, otherwise None.
    """

    meta = module_meta_from_data(data, module_abaddr=module_abaddr)
    hwtype = str(meta.get("hwtype") or "").strip().upper()
    if not hwtype and module_hwtype_hint:
        hwtype = str(module_hwtype_hint).strip().upper()
    if not hwtype:
        return None

    if hwtype in {"TRI", "TNP"}:
        return build_trident_device_info(
            host=host,
            meta=controller_meta,
            controller_device_identifier=controller_device_identifier,
            trident_abaddr=module_abaddr,
            tank_slug=tank_slug,
            trident_hwtype=hwtype,
            trident_hwrev=meta.get("hwrev"),
            trident_swrev=meta.get("swrev"),
            trident_serial=meta.get("serial"),
        )

    module_name = meta.get("name") or (
        str(module_name_hint).strip() if module_name_hint else None
    )

    return build_module_device_info(
        host=host,
        controller_device_identifier=controller_device_identifier,
        module_hwtype=hwtype,
        module_abaddr=module_abaddr,
        tank_slug=tank_slug,
        module_name=module_name,
        module_hwrev=meta.get("hwrev"),
        module_swrev=meta.get("swrev"),
        module_serial=meta.get("serial"),
        tank_name=(str(controller_meta.get("hostname") or "").strip() or None),
    )


def build_module_device_info(
    *,
    host: str,
    controller_device_identifier: str,
    module_hwtype: str,
    module_abaddr: int,
    module_name: str | None = None,
    module_hwrev: str | None = None,
    module_swrev: str | None = None,
    module_serial: str | None = None,
    tank_name: str | None = None,
    tank_slug: str | None = None,
) -> DeviceInfo:
    """Build DeviceInfo for a generic Aquabus module.

    This is used to group module-backed entities under their own device pages
    (FMM/PM2/MXM/EB* etc.) while keeping the Apex controller device manageable.

    Notes:
    - No model/identifier fallbacks: callers should only pass real values.
    - The module device is parented under the Apex controller device.

    Args:
        host: Controller host/IP.
        controller_device_identifier: Stable identifier for the controller device.
        module_hwtype: Module hwtype token.
        module_abaddr: Aquabus address.
        module_name: Optional module name.
        module_hwrev: Optional hardware revision.
        module_swrev: Optional software revision.
        module_serial: Optional serial.
        tank_name: Optional tank/hostname for suggested area.

    Returns:
        DeviceInfo instance for the module.
    """

    hwtype = str(module_hwtype or "").strip().upper()
    identifiers = {
        (DOMAIN, f"{controller_device_identifier}_module_{hwtype}_{module_abaddr}")
    }

    tank_slug_effective = (
        _tank_slug_from_meta(
            {},
            tank_slug=tank_slug,
            tank_name=tank_name,
        )
        .replace("_", " ")
        .title()
    )

    module_token = MODULE_HWTYPE_FRIENDLY_NAMES.get(hwtype) or hwtype.upper()
    name = f"{tank_slug_effective} - {module_token} ({module_abaddr})"

    return DeviceInfo(
        identifiers=identifiers,
        name=name,
        manufacturer="Neptune Systems",
        model=hwtype or None,
        hw_version=(str(module_hwrev).strip() or None if module_hwrev else None),
        sw_version=(str(module_swrev).strip() or None if module_swrev else None),
        serial_number=(str(module_serial).strip() or None if module_serial else None),
        configuration_url=f"http://{host}",
        via_device=(DOMAIN, controller_device_identifier),
    )


def _modules_from_raw_status(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract module dicts from a raw REST payload.

    Args:
        raw: Raw REST payload mapping.

    Returns:
        List of module mappings.
    """

    modules_any: Any = raw.get("modules")
    if isinstance(modules_any, list):
        return [m for m in cast(list[Any], modules_any) if isinstance(m, dict)]

    for container_key in ("data", "status", "istat", "systat", "result"):
        container_any: Any = raw.get(container_key)
        if not isinstance(container_any, dict):
            continue
        nested_any: Any = cast(dict[str, Any], container_any).get("modules")
        if isinstance(nested_any, list):
            return [m for m in cast(list[Any], nested_any) if isinstance(m, dict)]

    return []


def module_meta_from_data(
    data: dict[str, Any], *, module_abaddr: int
) -> dict[str, str | None]:
    """Return module metadata for a specific Aquabus address.

    Args:
        data: Coordinator data.
        module_abaddr: Aquabus address.

    Returns:
        Dict containing keys: `hwtype`, `name`, `hwrev`, `swrev`, `serial`.
    """

    out: dict[str, str | None] = {
        "hwtype": None,
        "name": None,
        "hwrev": None,
        "swrev": None,
        "serial": None,
    }

    # Config-derived metadata (stable names and hwtype mapping).
    config_any: Any = data.get("config")
    if isinstance(config_any, dict):
        mconf_any: Any = cast(dict[str, Any], config_any).get("mconf")
        if isinstance(mconf_any, list):
            for item_any in cast(list[Any], mconf_any):
                if not isinstance(item_any, dict):
                    continue
                item = cast(dict[str, Any], item_any)
                if item.get("abaddr") != module_abaddr:
                    continue
                hwtype = (
                    str(item.get("hwtype") or item.get("hwType") or "").strip().upper()
                )
                if hwtype:
                    out["hwtype"] = out["hwtype"] or hwtype
                name_any: Any = item.get("name")
                if isinstance(name_any, str) and name_any.strip():
                    out["name"] = out["name"] or name_any.strip()
                break

    # Status-derived metadata (versions/serial when the controller provides them).
    raw_any: Any = data.get("raw")
    raw = cast(dict[str, Any], raw_any) if isinstance(raw_any, dict) else {}
    for module in _modules_from_raw_status(raw):
        if module.get("abaddr") != module_abaddr:
            continue

        hwtype_any: Any = (
            module.get("hwtype") or module.get("hwType") or module.get("type")
        )
        if isinstance(hwtype_any, str) and hwtype_any.strip():
            out["hwtype"] = out["hwtype"] or hwtype_any.strip().upper()

        hwrev_any: Any = (
            module.get("hwrev")
            or module.get("hwRev")
            or module.get("hw_version")
            or module.get("hwVersion")
            or module.get("rev")
        )
        if isinstance(hwrev_any, (str, int, float)):
            t = str(hwrev_any).strip()
            out["hwrev"] = out["hwrev"] or (t or None)

        swrev_any: Any = (
            module.get("software")
            or module.get("swrev")
            or module.get("swRev")
            or module.get("sw_version")
            or module.get("swVersion")
        )
        if isinstance(swrev_any, (str, int, float)):
            t = str(swrev_any).strip()
            out["swrev"] = out["swrev"] or (t or None)

        serial_any: Any = (
            module.get("serial")
            or module.get("serialNo")
            or module.get("serialNO")
            or module.get("serial_number")
        )
        if isinstance(serial_any, (str, int, float)):
            t = str(serial_any).strip()
            out["serial"] = out["serial"] or (t or None)

        break

    return out


def build_module_device_info_from_data(
    *,
    host: str,
    controller_device_identifier: str,
    data: dict[str, Any],
    module_abaddr: int,
    tank_slug: str | None = None,
) -> DeviceInfo | None:
    """Build module DeviceInfo from coordinator data.

    Args:
        host: Controller host/IP.
        controller_device_identifier: Device identifier used for the parent device.
        data: Coordinator data.
        module_abaddr: Aquabus address.

    Returns:
        DeviceInfo when the module can be identified; otherwise `None`.
    """

    meta = module_meta_from_data(data, module_abaddr=module_abaddr)
    hwtype = str(meta.get("hwtype") or "").strip().upper()
    if not hwtype:
        return None
    # Trident-family modules use a dedicated device builder.
    if hwtype in {"TRI", "TNP"}:
        return None

    return build_module_device_info(
        host=host,
        controller_device_identifier=controller_device_identifier,
        module_hwtype=hwtype,
        module_abaddr=module_abaddr,
        tank_slug=tank_slug,
        module_name=meta.get("name"),
        module_hwrev=meta.get("hwrev"),
        module_swrev=meta.get("swrev"),
        module_serial=meta.get("serial"),
        tank_name=(
            str(
                cast(dict[str, Any], data.get("meta", {})).get("hostname") or ""
            ).strip()
            if isinstance(data.get("meta"), dict)
            else None
        )
        or None,
    )


def normalize_module_hwtype_from_outlet_type(outlet_type: str | None) -> str | None:
    """Normalize an outlet type string into a module hwtype token.

    Outlet types are controller-reported strings like:
    - "EB832"
    - "MXMPump|AI|Nero5" (device-specific, but the hosting module is "MXM")

    This function is intentionally conservative and returns None when empty.

    Args:
        outlet_type: Raw outlet type token.

    Returns:
        Normalized module hwtype token, or `None` when unknown.
    """

    t = (outlet_type or "").strip()
    if not t:
        return None

    # Many device-backed outlets encode extra detail after '|'.
    token = t.split("|", 1)[0].strip()
    if not token:
        return None

    up = token.upper()
    # The MXM module hosts multiple device types (pumps/lights) under MXM* tokens.
    if up.startswith("MXM"):
        return "MXM"

    return up


def unambiguous_module_abaddr_from_config(
    data: dict[str, Any], *, module_hwtype: str
) -> int | None:
    """Return module abaddr when config.mconf has exactly one matching hwtype.

    This is used for safely parenting entities under a module device without
    guessing when multiple modules of the same hwtype exist.

    Args:
        data: Coordinator data dict.
        module_hwtype: Module hwtype token to match.

    Returns:
        Aquabus address when exactly one matching module is present, otherwise None.
    """

    hw = str(module_hwtype or "").strip().upper()
    if not hw:
        return None

    config_any: Any = data.get("config")
    if not isinstance(config_any, dict):
        return None
    mconf_any: Any = cast(dict[str, Any], config_any).get("mconf")
    if not isinstance(mconf_any, list):
        return None

    matches: set[int] = set()
    for item_any in cast(list[Any], mconf_any):
        if not isinstance(item_any, dict):
            continue
        item = cast(dict[str, Any], item_any)
        item_hw = str(item.get("hwtype") or item.get("hwType") or "").strip().upper()
        if item_hw != hw:
            continue
        abaddr_any: Any = item.get("abaddr")
        if isinstance(abaddr_any, int):
            matches.add(abaddr_any)

    if len(matches) != 1:
        return None
    return next(iter(matches))


class _RestNotSupported(Exception):
    """Internal signal used to switch to the XML status endpoint."""


class _RestAuthRejected(Exception):
    """Internal signal that REST login/auth was rejected; try the XML endpoint."""


class _RestRateLimited(Exception):
    """Internal signal that REST is rate limited; temporarily disable REST."""

    def __init__(self, *, retry_after_seconds: float | None = None) -> None:
        super().__init__("REST rate limited")
        self.retry_after_seconds = retry_after_seconds


def install_progress(
    *, elapsed: float, reconnected_for: float | None
) -> tuple[str, int]:
    """Return the install phase and percentage for a firmware install window.

    The controller's web UI shows no server-side progress; it is driven by
    fixed timers. This mirrors it so the reported value is a pure function of
    elapsed time and cannot move backwards.

    Args:
        elapsed: Seconds since the install request returned.
        reconnected_for: Seconds since the first good poll after the restart
            period, or ``None`` if the controller has not come back yet.

    Returns:
        ``(phase, percentage)``; the percentage never reaches 100 here, since
        100 is reserved for a verified version change.
    """
    if reconnected_for is not None:
        fraction = min(1.0, max(0.0, reconnected_for) / INSTALL_WEB_PAGES_SECONDS)
        return (
            INSTALL_PHASE_WEB_PAGES,
            INSTALL_WEB_PAGES_START_PERCENT
            + int(INSTALL_WEB_PAGES_SPAN_PERCENT * fraction),
        )
    if elapsed < INSTALL_RESTART_SECONDS:
        return (
            INSTALL_PHASE_RESTARTING,
            int(INSTALL_RESTART_PERCENT * max(0.0, elapsed) / INSTALL_RESTART_SECONDS),
        )
    creep = min(
        1.0, (elapsed - INSTALL_RESTART_SECONDS) / INSTALL_RECONNECT_CREEP_SECONDS
    )
    return (
        INSTALL_PHASE_RECONNECTING,
        INSTALL_RESTART_PERCENT + int(INSTALL_RECONNECT_CREEP_PERCENT * creep),
    )


_MXM_STATUS_LINE = re.compile(
    r"^\s*(?P<name>[^\(]+)\([^\)]*\)\s*-\s*Rev\s+(?P<rev>[^\s]+)\s+Ser\s+#:\s+(?P<serial>[^\s]+)\s+-\s*(?P<status>.+?)\s*$"
)


def _parse_mxm_devices_from_mconf(
    mconf_obj: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Extract MXM device metadata from `mconf` (from `/rest/config`).

    The MXM module includes a multiline `extra.status` string listing attached
    devices with revision and serial numbers.

    Args:
        mconf_obj: Parsed JSON from `/rest/config` (expects an `mconf` list).

    Returns:
        Mapping of device name -> metadata dict.
    """
    out: dict[str, dict[str, Any]] = {}

    mconf_any: Any = mconf_obj.get("mconf")
    if not isinstance(mconf_any, list):
        return out

    for module_any in cast(list[Any], mconf_any):
        if not isinstance(module_any, dict):
            continue
        module = cast(dict[str, Any], module_any)
        if str(module.get("hwtype") or "").strip().upper() != "MXM":
            continue
        extra_any: Any = module.get("extra")
        if not isinstance(extra_any, dict):
            continue
        extra = cast(dict[str, Any], extra_any)
        status_text_any: Any = extra.get("status")
        if not isinstance(status_text_any, str) or not status_text_any.strip():
            continue
        for line in status_text_any.splitlines():
            match = _MXM_STATUS_LINE.match(line)
            if not match:
                continue
            name = match.group("name").strip()
            if not name:
                continue

            status_raw = match.group("status").strip()
            status_clean = status_raw
            device_index: int | None = None
            suffix_match = re.match(
                r"^(?P<status>.*?)(?:\s*-\s*(?P<index>\d+))?$", status_raw
            )
            if suffix_match is not None:
                base = (suffix_match.group("status") or "").strip()
                idx = (suffix_match.group("index") or "").strip()
                if base:
                    status_clean = base
                if idx.isdigit():
                    device_index = int(idx)

            out[name] = {
                "rev": match.group("rev").strip(),
                "serial": match.group("serial").strip(),
                "status": status_clean,
                "device_index": device_index,
            }

    return out


def _sanitize_mconf_for_storage(mconf_obj: dict[str, Any]) -> list[dict[str, Any]]:
    """Sanitize `mconf` (from `/rest/config`) for storage.

    The raw payload can include a lot of device metadata. For coordinator state,
    only retain fields needed by this integration (module update flags, a small
    subset of `extra`, and identity fields).

    Args:
        mconf_obj: REST config payload object.

    Returns:
        Sanitized list of module config dicts.
    """

    mconf_any: Any = mconf_obj.get("mconf")
    if not isinstance(mconf_any, list):
        return []

    out: list[dict[str, Any]] = []
    for module_any in cast(list[Any], mconf_any):
        if not isinstance(module_any, dict):
            continue
        module = cast(dict[str, Any], module_any)

        hwtype = str(module.get("hwtype") or module.get("hwType") or "").strip().upper()
        if not hwtype:
            continue

        item: dict[str, Any] = {"hwtype": hwtype}

        abaddr_any: Any = module.get("abaddr")
        if isinstance(abaddr_any, int):
            item["abaddr"] = abaddr_any

        name_any: Any = module.get("name")
        if isinstance(name_any, str) and name_any.strip():
            item["name"] = name_any.strip()

        update_any: Any = module.get("update")
        if isinstance(update_any, bool):
            item["update"] = update_any

        update_stat_any: Any = module.get("updateStat")
        if isinstance(update_stat_any, int):
            item["updateStat"] = update_stat_any

        extra_any: Any = module.get("extra")
        if isinstance(extra_any, dict):
            extra = cast(dict[str, Any], extra_any)
            extra_out: dict[str, Any] = {}

            # Trident waste container size (mL)
            waste_any: Any = extra.get("wasteSize")
            if isinstance(waste_any, (int, float)):
                extra_out["wasteSize"] = float(waste_any)

            # MXM uses a multiline status string listing attached devices.
            status_any: Any = extra.get("status")
            if hwtype == "MXM" and isinstance(status_any, str) and status_any.strip():
                extra_out["status"] = status_any

            if extra_out:
                item["extra"] = extra_out

        out.append(item)

    return out


def _sanitize_nconf_for_storage(nconf_obj: dict[str, Any]) -> dict[str, Any]:
    """Sanitize `nconf` (from `/rest/config`) for storage.

    This payload commonly includes credentials. Keep only update-related fields.

    Args:
        nconf_obj: REST config payload object.

    Returns:
        Sanitized dict containing update-related controller fields.
    """

    nconf_any: Any = nconf_obj.get("nconf")
    if not isinstance(nconf_any, dict):
        return {}

    nconf = cast(dict[str, Any], nconf_any)
    out: dict[str, Any] = {}

    latest_any: Any = nconf.get("latestFirmware")
    if isinstance(latest_any, str) and latest_any.strip():
        out["latestFirmware"] = latest_any.strip()

    flag_any: Any = nconf.get("updateFirmware")
    if isinstance(flag_any, bool):
        out["updateFirmware"] = flag_any

    return out


def _to_number(s: str | None) -> float | None:
    """Convert a string to a float if possible.

    Args:
        s: Input string.

    Returns:
        Parsed float, or None if not parseable.
    """
    if s is None:
        return None
    t = s.strip()
    if not t:
        return None
    try:
        return float(t)
    except ValueError:
        return None


def build_status_url(host: str, status_path: str) -> str:
    """Build a full URL to the XML status endpoint.

    Args:
        host: Hostname or URL.
        status_path: Path to status endpoint.

    Returns:
        Fully-qualified URL.
    """
    host = (host or "").strip()
    if host.startswith("http://") or host.startswith("https://"):
        base = host.rstrip("/")
    else:
        base = f"http://{host}".rstrip("/")

    path = (status_path or DEFAULT_STATUS_PATH).strip()
    if not path.startswith("/"):
        path = "/" + path

    return base + path


def build_base_url(host: str) -> str:
    """Build the base URL for the controller.

    Args:
        host: Hostname or URL.

    Returns:
        Base URL without trailing slash.
    """
    host = (host or "").strip()
    if host.startswith("http://") or host.startswith("https://"):
        return host.rstrip("/")
    return f"http://{host}".rstrip("/")


def parse_status_xml(xml_text: str) -> dict[str, Any]:
    """Parse `status.xml` into a normalized dict.

    Args:
        xml_text: Raw XML text.

    Returns:
        Normalized dict containing at least: meta, probes, outlets.
    """
    root = ET.fromstring(xml_text)

    meta: dict[str, Any] = {
        "software": (root.attrib.get("software") or "").strip() or None,
        "hardware": (root.attrib.get("hardware") or "").strip() or None,
        "hostname": (root.findtext("./hostname") or "").strip() or None,
        "serial": (root.findtext("./serial") or "").strip() or None,
        "timezone": (root.findtext("./timezone") or "").strip() or None,
        "date": (root.findtext("./date") or "").strip() or None,
    }

    probes: dict[str, dict[str, Any]] = {}
    for p in root.findall("./probes/probe"):
        name = (p.findtext("name") or "").strip()
        if not name:
            continue
        value_raw = p.findtext("value")
        probes[name] = {
            "name": name,
            "type": (p.findtext("type") or "").strip() or None,
            "value_raw": (value_raw.strip() if value_raw else None),
            "value": _to_number(value_raw),
        }

    outlets: list[dict[str, Any]] = []
    for o in root.findall("./outlets/outlet"):
        name = (o.findtext("name") or "").strip()
        if not name:
            continue
        outlets.append(
            {
                "name": name,
                "output_id": (o.findtext("outputID") or "").strip() or None,
                "state": (o.findtext("state") or "").strip() or None,
                "device_id": (o.findtext("deviceID") or "").strip() or None,
            }
        )

    return {
        "meta": meta,
        "probes": probes,
        "outlets": outlets,
        "alerts": {"last_statement": None, "last_message": None},
        "trident": {"status": None, "is_testing": None},
    }


def parse_status_rest(status_obj: dict[str, Any]) -> dict[str, Any]:
    """Parse REST status JSON into a normalized dict.

    This integration uses `/rest/status` (and tolerates variants that nest the
    same data under keys like `status`, `data`, etc.).

    Args:
        status_obj: Parsed JSON dict from `/rest/status`.

    Returns:
        Normalized dict containing at least: meta, probes, outlets, network, raw.
    """

    def _find_field(root: dict[str, Any], key: str) -> Any:
        direct = root.get(key)
        if direct is not None:
            return direct

        # Payloads may be nested under common container keys.
        for container_key in (
            "data",
            "status",
            "istat",
            "systat",
            "result",
        ):
            container_any: Any = root.get(container_key)
            if isinstance(container_any, dict):
                container = cast(dict[str, Any], container_any)
                nested = container.get(key)
                if nested is not None:
                    return nested
        return None

    nstat_any: Any = _find_field(status_obj, "nstat")
    nstat: dict[str, Any] = (
        cast(dict[str, Any], nstat_any) if isinstance(nstat_any, dict) else {}
    )

    system_any: Any = _find_field(status_obj, "system")
    system: dict[str, Any] = (
        cast(dict[str, Any], system_any) if isinstance(system_any, dict) else {}
    )

    meta: dict[str, Any] = {
        "software": (str(system.get("software") or "").strip() or None),
        "hardware": (str(system.get("hardware") or "").strip() or None),
        "hostname": (
            str(system.get("hostname") or nstat.get("hostname") or "").strip() or None
        ),
        "serial": (str(system.get("serial") or "").strip() or None),
        "timezone": (str(system.get("timezone") or "").strip() or None),
        "date": system.get("date"),
        "type": (str(system.get("type") or "").strip() or None),
        "firmware_latest": (str(nstat.get("latestFirmware") or "").strip() or None),
        "source": "rest",
    }

    network: dict[str, Any] = {
        "ipaddr": (str(nstat.get("ipaddr") or "").strip() or None),
        "gateway": (str(nstat.get("gateway") or "").strip() or None),
        "netmask": (str(nstat.get("netmask") or "").strip() or None),
        "dhcp": nstat.get("dhcp"),
        "wifi_enable": nstat.get("wifiEnable"),
        "ssid": nstat.get("ssid"),
        "strength": nstat.get("strength"),
        "quality": nstat.get("quality"),
    }

    def _coerce_id(item: dict[str, Any], *keys: str) -> str:
        for k in keys:
            v: Any = item.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        # Sometimes IDs are ints.
        for k in keys:
            v = item.get(k)
            if isinstance(v, int):
                return str(v)
        return ""

    probes: dict[str, dict[str, Any]] = {}
    inputs_any: Any = _find_field(status_obj, "inputs")
    if not isinstance(inputs_any, list):
        inputs_any = _find_field(status_obj, "probes")
    if isinstance(inputs_any, list):
        for item_any in cast(list[Any], inputs_any):
            if not isinstance(item_any, dict):
                continue
            item = cast(dict[str, Any], item_any)
            did = _coerce_id(item, "did", "device_id", "deviceID", "id")
            if not did:
                # Fall back to name as a stable key.
                did = _coerce_id(item, "name")
            if not did:
                continue

            # Module identity fields for inputs may be present.
            module_abaddr: int | None = None
            module_abaddr_any: Any = (
                item.get("module_abaddr") or item.get("abaddr") or item.get("abAddr")
            )
            if module_abaddr_any is None and isinstance(item.get("module"), dict):
                module = cast(dict[str, Any], item.get("module"))
                module_abaddr_any = module.get("abaddr") or module.get("abAddr")
            if isinstance(module_abaddr_any, int):
                module_abaddr = module_abaddr_any

            if module_abaddr is None:
                module_abaddr = module_abaddr_from_input_did(did)

            module_hwtype: str | None = None
            module_hwtype_any: Any = (
                item.get("module_hwtype") or item.get("hwtype") or item.get("hwType")
            )
            if module_hwtype_any is None and isinstance(item.get("module"), dict):
                module = cast(dict[str, Any], item.get("module"))
                module_hwtype_any = module.get("hwtype") or module.get("hwType")
            if isinstance(module_hwtype_any, str) and module_hwtype_any.strip():
                module_hwtype = module_hwtype_any.strip().upper()

            value: Any = item.get("value")
            probes[did] = {
                "name": (str(item.get("name") or did)).strip(),
                "type": (str(item.get("type") or "")).strip() or None,
                "value_raw": value,
                "value": value,
                "module_abaddr": module_abaddr,
                "module_hwtype": module_hwtype,
            }

    outlets: list[dict[str, Any]] = []
    outputs_any: Any = _find_field(status_obj, "outputs")
    if not isinstance(outputs_any, list):
        outputs_any = _find_field(status_obj, "outlets")
    if isinstance(outputs_any, list):
        for item_any in cast(list[Any], outputs_any):
            if not isinstance(item_any, dict):
                continue
            item = cast(dict[str, Any], item_any)
            did = _coerce_id(item, "did", "device_id", "deviceID", "id")
            if not did:
                did = _coerce_id(item, "name")
            if not did:
                continue
            status_any: Any = item.get("status")
            state: str | None = None
            if isinstance(status_any, list) and status_any:
                first: Any = cast(list[Any], status_any)[0]
                state = str(first) if first is not None else None

            output_type_any: Any = item.get("type")
            output_type = output_type_any if isinstance(output_type_any, str) else None

            gid_any: Any = item.get("gid")
            gid = gid_any if isinstance(gid_any, str) else None

            # Module identity fields for outputs may be present.
            out_module_abaddr: int | None = None
            out_abaddr_any: Any = (
                item.get("module_abaddr")
                or item.get("abaddr")
                or item.get("abAddr")
                or item.get("moduleAbAddr")
            )
            if out_abaddr_any is None and isinstance(item.get("module"), dict):
                module = cast(dict[str, Any], item.get("module"))
                out_abaddr_any = module.get("abaddr") or module.get("abAddr")
            if isinstance(out_abaddr_any, int):
                out_module_abaddr = out_abaddr_any

            if out_module_abaddr is None:
                out_module_abaddr = module_abaddr_from_input_did(did)

            out_module_hwtype: str | None = None
            out_hwtype_any: Any = (
                item.get("module_hwtype")
                or item.get("hwtype")
                or item.get("hwType")
                or item.get("moduleHwType")
            )
            if out_hwtype_any is None and isinstance(item.get("module"), dict):
                module = cast(dict[str, Any], item.get("module"))
                out_hwtype_any = module.get("hwtype") or module.get("hwType")
            if isinstance(out_hwtype_any, str) and out_hwtype_any.strip():
                out_module_hwtype = out_hwtype_any.strip().upper()

            intensity_any: Any = item.get("intensity")
            intensity: int | None = None
            if isinstance(intensity_any, int) and not isinstance(intensity_any, bool):
                intensity = intensity_any
            elif isinstance(intensity_any, float) and intensity_any.is_integer():
                intensity = int(intensity_any)
            elif isinstance(intensity_any, str) and intensity_any.strip().isdigit():
                intensity = int(intensity_any.strip())

            module_abaddr = out_module_abaddr

            outlets.append(
                {
                    "name": (str(item.get("name") or did)).strip(),
                    "output_id": (
                        str(item.get("ID") or item.get("output_id") or "").strip()
                        or None
                    ),
                    "state": (state or "").strip() or None,
                    "device_id": did,
                    "type": (output_type or "").strip() or None,
                    "gid": (gid or "").strip() or None,
                    "status": status_any if isinstance(status_any, list) else None,
                    "intensity": intensity,
                    "module_abaddr": module_abaddr,
                    "module_hwtype": out_module_hwtype,
                }
            )

            # DOS / DOS Quiet Drive (DQD) dosing pump outputs.
            # Some controllers encode capacity/remaining in status[3]/status[4].
            output_type_key = (output_type or "").strip().lower()
            if output_type_key in {"dos", "dqd"} and isinstance(status_any, list):
                status_list = cast(list[Any], status_any)
                capacity_ml = _to_int(status_list[3]) if len(status_list) > 3 else None
                remaining_ml = _to_int(status_list[4]) if len(status_list) > 4 else None
                if capacity_ml is not None or remaining_ml is not None:
                    outlets[-1]["doser_capacity_ml"] = capacity_ml
                    outlets[-1]["doser_remaining_ml"] = remaining_ml

    def _parse_tridents_from_modules() -> list[dict[str, Any]]:
        def _coerce_percent(value: Any) -> int | None:
            if value is None:
                return None
            if isinstance(value, bool):
                return None
            if isinstance(value, (int, float)):
                n = int(value)
                return n if 0 <= n <= 100 else None
            t = str(value).strip()
            if not t:
                return None
            if t.endswith("%"):
                t = t[:-1].strip()
            if not t.isdigit():
                return None
            n = int(t)
            return n if 0 <= n <= 100 else None

        def _flatten(d: dict[str, Any], *, prefix: str = "") -> list[tuple[str, Any]]:
            out: list[tuple[str, Any]] = []
            for k, v in d.items():
                key = f"{prefix}{k}" if not prefix else f"{prefix}_{k}"
                if isinstance(v, dict):
                    out.extend(_flatten(cast(dict[str, Any], v), prefix=key))
                else:
                    out.append((key, v))
            return out

        def _extract_consumables(extra: dict[str, Any]) -> dict[str, Any]:
            reagent_a: int | None = None
            reagent_b: int | None = None
            reagent_c: int | None = None
            waste_level: int | None = None

            # Reagents may be exposed as a single list/tuple.
            reagents_any: Any = extra.get("reagents")
            if isinstance(reagents_any, (list, tuple)):
                reagents_list: list[Any]
                if isinstance(reagents_any, list):
                    reagents_list = cast(list[Any], reagents_any)
                else:
                    reagents_list = list(cast(tuple[Any, ...], reagents_any))

                if len(reagents_list) >= 3:
                    reagent_a = _coerce_percent(reagents_list[0])
                    reagent_b = _coerce_percent(reagents_list[1])
                    reagent_c = _coerce_percent(reagents_list[2])

            for key, value in _flatten(extra):
                k = str(key).strip().lower().replace(" ", "_")
                p = _coerce_percent(value)
                if p is None:
                    continue

                if "reagent" in k:
                    if reagent_a is None and (
                        "reagenta" in k
                        or "reagent_a" in k
                        or "reagent1" in k
                        or "reagent_1" in k
                        or "reagent-1" in k
                    ):
                        reagent_a = p
                        continue
                    if reagent_b is None and (
                        "reagentb" in k
                        or "reagent_b" in k
                        or "reagent2" in k
                        or "reagent_2" in k
                        or "reagent-2" in k
                    ):
                        reagent_b = p
                        continue
                    if reagent_c is None and (
                        "reagentc" in k
                        or "reagent_c" in k
                        or "reagent3" in k
                        or "reagent_3" in k
                        or "reagent-3" in k
                    ):
                        reagent_c = p
                        continue

                if (
                    waste_level is None
                    and "waste" in k
                    and any(token in k for token in ("level", "pct", "percent"))
                ):
                    waste_level = p

            return {
                "reagent_a_remaining": reagent_a,
                "reagent_b_remaining": reagent_b,
                "reagent_c_remaining": reagent_c,
                "waste_container_level": waste_level,
            }

        modules_any: Any = _find_field(status_obj, "modules")
        if not isinstance(modules_any, list):
            return []

        tridents: list[dict[str, Any]] = []
        for module_any in cast(list[Any], modules_any):
            if not isinstance(module_any, dict):
                continue
            module = cast(dict[str, Any], module_any)
            hwtype = (
                str(
                    module.get("hwtype")
                    or module.get("hwType")
                    or module.get("type")
                    or ""
                )
                .strip()
                .upper()
            )

            # Only treat explicitly-known hardware types as Trident-family.
            # Avoid heuristic detection to prevent false positives across modules.
            if hwtype not in {"TRI", "TNP"}:
                continue

            # Some controller variants omit `extra` or populate it lazily.
            # Keep the module as a Trident-family device even if `extra` is
            # missing so entities are not suppressed.
            extra_any: Any = module.get("extra")
            extra = (
                cast(dict[str, Any], extra_any) if isinstance(extra_any, dict) else {}
            )

            trident_hwtype = hwtype or None

            trident_hwrev: str | None = None
            hwrev_any: Any = (
                module.get("hwrev")
                or module.get("hwRev")
                or module.get("hw_version")
                or module.get("hwVersion")
                or module.get("rev")
            )
            if isinstance(hwrev_any, (str, int, float)):
                t = str(hwrev_any).strip()
                trident_hwrev = t or None

            trident_swrev: str | None = None
            swrev_any: Any = (
                module.get("software")
                or module.get("swrev")
                or module.get("swRev")
                or module.get("sw_version")
                or module.get("swVersion")
            )
            if isinstance(swrev_any, (str, int, float)):
                t = str(swrev_any).strip()
                trident_swrev = t or None

            trident_serial: str | None = None
            serial_any: Any = (
                module.get("serial")
                or module.get("serialNo")
                or module.get("serialNO")
                or module.get("serial_number")
            )
            if isinstance(serial_any, (str, int, float)):
                t = str(serial_any).strip()
                trident_serial = t or None

            abaddr: int | None = None
            abaddr_any: Any = module.get("abaddr")
            if isinstance(abaddr_any, int):
                abaddr = abaddr_any

            present_any: Any = module.get("present")
            present = bool(present_any) if isinstance(present_any, bool) else True

            # Trident container levels are provided as a list of numbers.
            levels_ml: list[float] | None = None
            levels_any: Any = extra.get("levels")
            if isinstance(levels_any, list):
                parsed_levels: list[float] = []
                for item_any in cast(list[Any], levels_any):
                    if item_any is None or isinstance(item_any, bool):
                        continue
                    if isinstance(item_any, (int, float)):
                        parsed_levels.append(float(item_any))
                        continue
                    if isinstance(item_any, str):
                        n = _to_number(item_any)
                        if n is not None:
                            parsed_levels.append(n)
                levels_ml = parsed_levels or None

            consumables = _extract_consumables(extra)

            error_code: int | None = None
            error_message: str | None = None
            error_code_any: Any = extra.get("errorCode")
            if isinstance(error_code_any, int) and not isinstance(error_code_any, bool):
                error_code = error_code_any if error_code_any > 0 else None
                error_message = _trident_error_message(error_code_any)

            status: str | None = None
            is_testing: bool | None = None
            status_any: Any = extra.get("status")
            if isinstance(status_any, str):
                status, is_testing, status_key = _normalize_trident_status(status_any)
            else:
                status_key = None

            tridents.append(
                {
                    "present": present,
                    "status": status,
                    "status_key": status_key,
                    "is_testing": is_testing,
                    "error_code": error_code,
                    "error_message": error_message,
                    "abaddr": abaddr,
                    "hwtype": trident_hwtype,
                    "hwrev": trident_hwrev,
                    "swrev": trident_swrev,
                    "serial": trident_serial,
                    "levels_ml": levels_ml,
                    **consumables,
                }
            )

        return tridents

    def _parse_last_alert_statement() -> dict[str, Any]:
        # The REST payload may use different container keys for alerts.
        # Try common container names and extract a human-facing statement.
        for key in ("notifications", "alerts", "alarms", "warnings", "messages"):
            items_any: Any = _find_field(status_obj, key)
            if not isinstance(items_any, list) or not items_any:
                continue
            last_any: Any = cast(list[Any], items_any)[-1]
            if isinstance(last_any, dict):
                last = cast(dict[str, Any], last_any)
                statement_any: Any = (
                    last.get("statement")
                    or last.get("Statement")
                    or last.get("detail")
                    or last.get("details")
                )
                if isinstance(statement_any, str) and statement_any.strip():
                    return {
                        "last_statement": statement_any.strip(),
                        "last_message": None,
                    }

                message_any: Any = (
                    last.get("message")
                    or last.get("msg")
                    or last.get("text")
                    or last.get("title")
                )
                if isinstance(message_any, str) and message_any.strip():
                    msg = message_any.strip()
                    m = re.search(r"(?:^|\b)Statement:\s*(?P<s>.+)$", msg)
                    if m:
                        stmt = m.group("s").strip()
                        return {"last_statement": stmt or None, "last_message": msg}
                    return {"last_statement": None, "last_message": msg}

            if isinstance(last_any, str) and last_any.strip():
                msg = last_any.strip()
                m = re.search(r"(?:^|\b)Statement:\s*(?P<s>.+)$", msg)
                if m:
                    stmt = m.group("s").strip()
                    return {"last_statement": stmt or None, "last_message": msg}
                return {"last_statement": None, "last_message": msg}

        return {"last_statement": None, "last_message": None}

    def _parse_feed() -> dict[str, Any] | None:
        """Extract feed-mode status from common REST payload variants.

        Returns:
            Feed-mode dict when present, otherwise None.
        """

        def _to_int(v: Any) -> int | None:
            if isinstance(v, int):
                return v
            if isinstance(v, float) and v.is_integer():
                return int(v)
            if isinstance(v, str):
                t = v.strip()
                if t.isdigit():
                    return int(t)
            return None

        feed_any: Any = _find_field(status_obj, "feed")
        if feed_any is None:
            feed_any = _find_field(status_obj, "feeds")

        if isinstance(feed_any, (int, float, str)):
            feed_id = _to_int(feed_any)
            if feed_id is None:
                return None
            return {"name": feed_id, "active": bool(feed_id), "active_raw": None}

        if isinstance(feed_any, dict):
            feed = cast(dict[str, Any], feed_any)
            feed_id = _to_int(feed.get("name") or feed.get("id") or feed.get("sel"))

            active_raw: Any = feed.get("active")
            active: bool | None = None
            if isinstance(active_raw, bool):
                active = active_raw
            else:
                active_int = _to_int(active_raw)
                if active_int is not None:
                    active = active_int == 1

            if active is None and feed_id is not None:
                active = feed_id in (1, 2, 3, 4)

            return {"name": feed_id, "active": active, "active_raw": active_raw}

        if isinstance(feed_any, list):
            active_id: int | None = None
            active_raw: Any = None
            for item_any in cast(list[Any], feed_any):
                if not isinstance(item_any, dict):
                    continue
                item = cast(dict[str, Any], item_any)
                item_id = _to_int(item.get("name") or item.get("id"))
                item_active_raw: Any = item.get("active") or item.get("running")
                item_active: bool | None = None
                if isinstance(item_active_raw, bool):
                    item_active = item_active_raw
                else:
                    item_active_int = _to_int(item_active_raw)
                    if item_active_int is not None:
                        item_active = item_active_int == 1

                if item_active:
                    active_id = item_id
                    active_raw = item_active_raw
                    break

            return {
                "name": active_id or 0,
                "active": bool(active_id),
                "active_raw": active_raw,
            }

        return None

    data: dict[str, Any] = {
        "meta": meta,
        "network": network,
        "probes": probes,
        "outlets": outlets,
        "feed": _parse_feed(),
        "alerts": _parse_last_alert_statement(),
        "tridents": _parse_tridents_from_modules(),
        "trident": None,
        "raw": status_obj,
    }

    # Backward compatibility: preserve `data["trident"]` as the primary Trident.
    data["trident"] = _primary_trident_from_data(data)
    return data


def _primary_trident_from_data(data: dict[str, Any]) -> dict[str, Any]:
    tridents_any: Any = data.get("tridents")
    if isinstance(tridents_any, list) and tridents_any:
        tridents: list[dict[str, Any]] = [
            cast(dict[str, Any], t)
            for t in cast(list[Any], tridents_any)
            if isinstance(t, dict)
        ]
        if tridents:
            # Prefer a present module when multiple Trident-family devices exist.
            for t in tridents:
                if t.get("present") is True:
                    return t
            return tridents[0]
    return {
        "present": False,
        "status": None,
        "is_testing": None,
        "abaddr": None,
        "hwtype": None,
        "hwrev": None,
        "swrev": None,
        "serial": None,
        "levels_ml": None,
        "reagent_a_remaining": None,
        "reagent_b_remaining": None,
        "reagent_c_remaining": None,
        "waste_container_level": None,
    }


def parse_status_cgi_json(status_obj: dict[str, Any]) -> dict[str, Any]:
    """Parse `/cgi-bin/status.json` into a normalized dict.

    Args:
        status_obj: Parsed JSON dict from `/cgi-bin/status.json`.

    Returns:
        Normalized dict containing at least: meta, probes, outlets, raw.
    """
    istat_any: Any = status_obj.get("istat")
    istat: dict[str, Any] = {}
    if isinstance(istat_any, dict):
        istat = cast(dict[str, Any], istat_any)

    def _find_serial() -> str | None:
        for candidate in (
            istat.get("serial"),
            istat.get("serialNo"),
            istat.get("serialNO"),
            istat.get("serial_number"),
            status_obj.get("serial"),
            status_obj.get("serialNo"),
        ):
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
            if isinstance(candidate, int):
                return str(candidate)

        system_any: Any = status_obj.get("system")
        if isinstance(system_any, dict):
            system = cast(dict[str, Any], system_any)
            candidate = system.get("serial")
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
            if isinstance(candidate, int):
                return str(candidate)

        return None

    meta: dict[str, Any] = {
        "software": None,
        "hardware": (str(istat.get("hardware") or "").strip() or None),
        "hostname": (str(istat.get("hostname") or "").strip() or None),
        "serial": _find_serial(),
        "timezone": None,
        "date": istat.get("date"),
        "type": None,
        "source": "cgi_json",
    }

    probes: dict[str, dict[str, Any]] = {}
    inputs_any: Any = istat.get("inputs")
    if isinstance(inputs_any, list):
        for item_any in cast(list[Any], inputs_any):
            if not isinstance(item_any, dict):
                continue
            item = cast(dict[str, Any], item_any)
            did_any: Any = item.get("did")
            did = did_any if isinstance(did_any, str) else None
            if not did:
                continue

            module_abaddr: int | None = None
            module_abaddr_any: Any = (
                item.get("module_abaddr") or item.get("abaddr") or item.get("abAddr")
            )
            if isinstance(module_abaddr_any, int):
                module_abaddr = module_abaddr_any

            if module_abaddr is None:
                module_abaddr = module_abaddr_from_input_did(did)

            module_hwtype: str | None = None
            module_hwtype_any: Any = (
                item.get("module_hwtype") or item.get("hwtype") or item.get("hwType")
            )
            if isinstance(module_hwtype_any, str) and module_hwtype_any.strip():
                module_hwtype = module_hwtype_any.strip().upper()

            value: Any = item.get("value")
            probes[did] = {
                "name": (str(item.get("name") or did)).strip(),
                "type": (str(item.get("type") or "")).strip() or None,
                "value_raw": value,
                "value": value,
                "module_abaddr": module_abaddr,
                "module_hwtype": module_hwtype,
            }

    outlets: list[dict[str, Any]] = []
    outputs_any: Any = istat.get("outputs")
    if isinstance(outputs_any, list):
        for item_any in cast(list[Any], outputs_any):
            if not isinstance(item_any, dict):
                continue
            item = cast(dict[str, Any], item_any)
            did_any: Any = item.get("did")
            did = did_any if isinstance(did_any, str) else None
            if not did:
                continue
            status_any: Any = item.get("status")
            state: str | None = None
            if isinstance(status_any, list) and status_any:
                first: Any = cast(list[Any], status_any)[0]
                state = str(first) if first is not None else None

            output_type_any: Any = item.get("type")
            output_type = output_type_any if isinstance(output_type_any, str) else None

            gid_any: Any = item.get("gid")
            gid = gid_any if isinstance(gid_any, str) else None

            module_abaddr: int | None = None
            module_abaddr_any: Any = (
                item.get("module_abaddr") or item.get("abaddr") or item.get("abAddr")
            )
            if isinstance(module_abaddr_any, int):
                module_abaddr = module_abaddr_any
            if module_abaddr is None:
                module_abaddr = module_abaddr_from_input_did(did)

            module_hwtype: str | None = None
            module_hwtype_any: Any = (
                item.get("module_hwtype") or item.get("hwtype") or item.get("hwType")
            )
            if isinstance(module_hwtype_any, str) and module_hwtype_any.strip():
                module_hwtype = module_hwtype_any.strip().upper()

            outlets.append(
                {
                    "name": (str(item.get("name") or did)).strip(),
                    "output_id": str(item.get("ID") or "").strip() or None,
                    "state": (state or "").strip() or None,
                    "device_id": did,
                    "type": (output_type or "").strip() or None,
                    "gid": (gid or "").strip() or None,
                    "status": status_any if isinstance(status_any, list) else None,
                    "module_abaddr": module_abaddr,
                    "module_hwtype": module_hwtype,
                }
            )

            # DOS / DOS Quiet Drive (DQD) dosing pump outputs.
            output_type_key = (output_type or "").strip().lower()
            if output_type_key in {"dos", "dqd"} and isinstance(status_any, list):
                status_list = cast(list[Any], status_any)
                capacity_ml = _to_int(status_list[3]) if len(status_list) > 3 else None
                remaining_ml = _to_int(status_list[4]) if len(status_list) > 4 else None
                if capacity_ml is not None or remaining_ml is not None:
                    outlets[-1]["doser_capacity_ml"] = capacity_ml
                    outlets[-1]["doser_remaining_ml"] = remaining_ml

    def _parse_feed() -> dict[str, Any] | None:
        def _to_int(v: Any) -> int | None:
            if isinstance(v, int):
                return v
            if isinstance(v, float) and v.is_integer():
                return int(v)
            if isinstance(v, str):
                t = v.strip()
                if t.isdigit():
                    return int(t)
            return None

        feed_any: Any = istat.get("feed")
        if feed_any is None:
            feed_any = status_obj.get("feed")

        if isinstance(feed_any, (int, float, str)):
            feed_id = _to_int(feed_any)
            if feed_id is None:
                return None
            return {"name": feed_id, "active": bool(feed_id), "active_raw": None}

        if isinstance(feed_any, dict):
            feed = cast(dict[str, Any], feed_any)
            feed_id = _to_int(feed.get("name") or feed.get("id") or feed.get("sel"))

            active_raw: Any = feed.get("active")
            active: bool | None = None
            if isinstance(active_raw, bool):
                active = active_raw
            else:
                active_int = _to_int(active_raw)
                if active_int is not None:
                    active = active_int == 1

            if active is None and feed_id is not None:
                active = feed_id in (1, 2, 3, 4)

            return {"name": feed_id, "active": active, "active_raw": active_raw}

        return None

    return {
        "meta": meta,
        "probes": probes,
        "outlets": outlets,
        "feed": _parse_feed(),
        "alerts": {"last_statement": None, "last_message": None},
        "trident": {"status": None, "is_testing": None},
        "raw": status_obj,
    }


class ApexNeptuneDataUpdateCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Fetches and parses status.xml into a shared data dict."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        entry: ConfigEntry,
        rest_sid_seed: str | None = None,
    ) -> None:
        """Initialize the coordinator.

        Args:
            hass: Home Assistant instance.
            entry: Config entry containing connection details.
            rest_sid_seed: Optional connect.sid value to reuse for the first refresh.
        """
        self.hass = hass
        self.entry = entry
        self._rest_sid: str | None = (
            rest_sid_seed if isinstance(rest_sid_seed, str) and rest_sid_seed else None
        )
        self._rest_disabled_until: float = 0.0
        self._rest_status_path: str | None = None
        self._cached_serial: str | None = None

        # REST config is large and changes infrequently.
        #
        # We prefer a single /rest/config fetch (sanitized) on a slower cadence than
        # /rest/status. When the user changes a config value via HA, we force a
        # refresh immediately after the PUT (no optimistic "fake" state).
        self._rest_config_last_fetch: float = 0.0
        self._rest_config_refresh_seconds: float = 5 * 60
        self._cached_mconf: list[dict[str, Any]] | None = None
        self._cached_nconf: dict[str, Any] | None = None
        self._cached_mxm_devices: dict[str, dict[str, str]] | None = None

        # Firmware install window (see async_begin_install_window).
        self._install_active: bool = False
        self._install_started: float | None = None
        self._install_reconnected_at: float | None = None
        self._install_from_version: str | None = None
        self._install_expected_version: str | None = None
        self._install_unsubs: list[CALLBACK_TYPE] = []

        super().__init__(
            hass,
            _LOGGER,
            name=f"Apex Fusion ({entry.data.get(CONF_HOST, '')})",
            update_interval=DEFAULT_SCAN_INTERVAL,
        )

    @property
    def device_identifier(self) -> str:
        """Return the stable, transport-independent identifier for this controller.

        This is the serial persisted on the config entry. Until it has been
        persisted (first setup) the serial seen in the data is used, and for a
        controller that never reports one, the entry's original unique_id.

        Returns:
            Identifier for use in the HA device registry.
        """
        stored = str(self.entry.data.get(CONF_SERIAL) or "").strip()
        if stored:
            return stored
        if self._cached_serial:
            return self._cached_serial
        return str(self.entry.unique_id or self.entry.entry_id)

    def _apply_serial_cache(self, data: dict[str, Any]) -> dict[str, Any]:
        meta_any: Any = data.get("meta")
        meta: dict[str, Any]
        if isinstance(meta_any, dict):
            meta = cast(dict[str, Any], meta_any)
        else:
            meta = {}
            data["meta"] = meta

        serial = str(meta.get("serial") or "").strip() or None
        if serial:
            self._cached_serial = serial
        elif self._cached_serial:
            meta["serial"] = self._cached_serial

        return data

    def _merge_cached_rest_config(self, data: dict[str, Any]) -> None:
        """Merge cached sanitized REST config into the new coordinator data.

        Args:
            data: Coordinator data dict being assembled for this poll.

        Returns:
            None.
        """
        if self._cached_mconf is not None or self._cached_nconf is not None:
            config_any: Any = data.get("config")
            if not isinstance(config_any, dict):
                config_any = {}
                data["config"] = config_any
            config = cast(dict[str, Any], config_any)
            if self._cached_mconf is not None and "mconf" not in config:
                config["mconf"] = self._cached_mconf
            if self._cached_nconf is not None and "nconf" not in config:
                config["nconf"] = self._cached_nconf

        if self._cached_mxm_devices and "mxm_devices" not in data:
            data["mxm_devices"] = self._cached_mxm_devices

        # If Trident waste size was learned from config previously, carry it forward.
        waste_by_abaddr: dict[int, float] = {}
        waste_default: float | None = None
        if self._cached_mconf:
            for m in self._cached_mconf:
                if str(m.get("hwtype") or "").strip().upper() not in {"TRI", "TNP"}:
                    continue
                extra_any: Any = m.get("extra")
                if not isinstance(extra_any, dict):
                    continue
                waste_any: Any = cast(dict[str, Any], extra_any).get("wasteSize")
                if not isinstance(waste_any, (int, float)):
                    continue
                waste_value = float(waste_any)
                abaddr_any: Any = m.get("abaddr")
                if isinstance(abaddr_any, int):
                    waste_by_abaddr[abaddr_any] = waste_value
                if waste_default is None:
                    waste_default = waste_value

        def _apply_waste_size(trident: dict[str, Any]) -> None:
            if trident.get("waste_size_ml") is not None:
                return
            abaddr_any: Any = trident.get("abaddr")
            if isinstance(abaddr_any, int) and abaddr_any in waste_by_abaddr:
                trident["waste_size_ml"] = waste_by_abaddr[abaddr_any]
                return
            if waste_default is not None:
                trident["waste_size_ml"] = waste_default

        tridents_any: Any = data.get("tridents")
        if isinstance(tridents_any, list):
            for t_any in cast(list[Any], tridents_any):
                if isinstance(t_any, dict):
                    _apply_waste_size(cast(dict[str, Any], t_any))

        trident_any: Any = data.get("trident")
        if isinstance(trident_any, dict):
            _apply_waste_size(cast(dict[str, Any], trident_any))

    async def _async_try_refresh_rest_config(
        self,
        *,
        data: dict[str, Any],
        session: aiohttp.ClientSession,
        base_url: str,
        sid: str | None,
        timeout_seconds: int,
        host: str,
        force: bool = False,
    ) -> None:
        """Optionally refresh cached config subsets.

        This is best-effort and should never fail the main status poll.

        Args:
            data: Coordinator data dict being assembled for this poll.
            session: aiohttp client session.
            base_url: Controller base URL.
            sid: Optional connect.sid value.
            timeout_seconds: Request timeout in seconds.
            host: Controller host/IP.
            force: Whether to force a refresh regardless of cache age.

        Returns:
            None.
        """

        def _cookie_headers(sid_value: str | None) -> dict[str, str]:
            headers = {
                "Accept": "*/*",
                "Content-Type": "application/json",
            }
            if sid_value:
                headers["Cookie"] = f"connect.sid={sid_value}"
            return headers

        now = time.monotonic()

        # If we already have cached values, merge them into this poll's output
        # regardless of whether we refresh.
        self._merge_cached_rest_config(data)

        should_refresh = force or (
            self._cached_mconf is None
            or (now - self._rest_config_last_fetch) >= self._rest_config_refresh_seconds
        )
        if not should_refresh:
            return

        def _apply_sanitized_config(
            *,
            config_obj: dict[str, Any],
            sanitized_mconf: list[dict[str, Any]] | None,
            sanitized_nconf: dict[str, Any] | None,
        ) -> None:
            if sanitized_mconf is not None:
                self._cached_mconf = sanitized_mconf
                data.setdefault("config", {})["mconf"] = sanitized_mconf

                waste_by_abaddr: dict[int, float] = {}
                waste_default: float | None = None
                for m in sanitized_mconf:
                    if str(m.get("hwtype") or "").strip().upper() not in {"TRI", "TNP"}:
                        continue
                    extra_any: Any = m.get("extra")
                    if not isinstance(extra_any, dict):
                        continue
                    waste_any: Any = cast(dict[str, Any], extra_any).get("wasteSize")
                    if not isinstance(waste_any, (int, float)):
                        continue
                    waste_value = float(waste_any)
                    abaddr_any: Any = m.get("abaddr")
                    if isinstance(abaddr_any, int):
                        waste_by_abaddr[abaddr_any] = waste_value
                    if waste_default is None:
                        waste_default = waste_value

                def _apply_waste_size(trident: dict[str, Any]) -> None:
                    abaddr_any: Any = trident.get("abaddr")
                    if isinstance(abaddr_any, int) and abaddr_any in waste_by_abaddr:
                        trident["waste_size_ml"] = waste_by_abaddr[abaddr_any]
                        return
                    if waste_default is not None:
                        trident["waste_size_ml"] = waste_default

                tridents_any: Any = data.get("tridents")
                if isinstance(tridents_any, list):
                    for t_any in cast(list[Any], tridents_any):
                        if isinstance(t_any, dict):
                            _apply_waste_size(cast(dict[str, Any], t_any))

                trident_any: Any = data.get("trident")
                if isinstance(trident_any, dict):
                    _apply_waste_size(cast(dict[str, Any], trident_any))

                mxm_devices = _parse_mxm_devices_from_mconf(config_obj)
                if mxm_devices:
                    self._cached_mxm_devices = mxm_devices
                    data["mxm_devices"] = mxm_devices

            if sanitized_nconf:
                self._cached_nconf = sanitized_nconf
                data.setdefault("config", {})["nconf"] = sanitized_nconf

        # Prefer a single /rest/config GET (contains mconf+nconf among others).
        try:
            config_url = f"{base_url}/rest/config"
            _LOGGER.debug("Trying REST config update: %s", config_url)
            async with async_timeout.timeout(timeout_seconds):
                async with session.get(
                    config_url, headers=_cookie_headers(sid)
                ) as resp:
                    if resp.status == 404:
                        raise FileNotFoundError
                    if resp.status in (401, 403):
                        raise PermissionError
                    resp.raise_for_status()
                    config_text = await resp.text()

            config_any: Any = json.loads(config_text) if config_text else {}
            if isinstance(config_any, dict):
                config_obj = cast(dict[str, Any], config_any)
                sanitized_mconf = _sanitize_mconf_for_storage(config_obj)
                sanitized_nconf = _sanitize_nconf_for_storage(config_obj)
                _apply_sanitized_config(
                    config_obj=config_obj,
                    sanitized_mconf=sanitized_mconf,
                    sanitized_nconf=sanitized_nconf,
                )
                self._rest_config_last_fetch = now
                return
        except (PermissionError, FileNotFoundError):
            # Permission/404: either forbidden or not present.
            pass
        except (asyncio.TimeoutError, aiohttp.ClientError, json.JSONDecodeError) as err:
            _LOGGER.debug("REST config fetch failed: %s", err)
        except Exception as err:
            _LOGGER.debug("Unexpected REST config error: %s", err)

    def _finalize_trident(self, data: dict[str, Any]) -> None:
        """Compute derived Trident fields from raw status + config.

        Args:
            data: Coordinator data dict.

        Returns:
            None.
        """

        def _finalize_one(trident: dict[str, Any]) -> None:
            levels_any: Any = trident.get("levels_ml")
            waste_used_ml: float | None = None
            reagent_a_ml: float | None = None
            reagent_b_ml: float | None = None
            reagent_c_ml: float | None = None
            if isinstance(levels_any, list) and levels_any:
                levels = cast(list[Any], levels_any)
                first = levels[0]
                if isinstance(first, (int, float)) and not isinstance(first, bool):
                    waste_used_ml = float(first)

                # Trident `levels` is most commonly a 5-element list:
                # - index 0: waste used (counts up)
                # - index 1: auxiliary/unknown
                # - index 2: reagent C remaining
                # - index 3: reagent B remaining
                # - index 4: reagent A remaining
                # Controllers may omit the aux value; handle 4-element lists as
                # [waste, reagent C, reagent B, reagent A].
                idx_a: int | None = None
                idx_b: int | None = None
                idx_c: int | None = None
                if len(levels) >= 5:
                    idx_c, idx_b, idx_a = 2, 3, 4
                elif len(levels) == 4:
                    idx_c, idx_b, idx_a = 1, 2, 3

                def _read_ml(idx: int | None) -> float | None:
                    if idx is None:
                        return None
                    v = levels[idx]
                    if isinstance(v, (int, float)) and not isinstance(v, bool):
                        return float(v)
                    return None

                reagent_a_ml = _read_ml(idx_a)
                reagent_b_ml = _read_ml(idx_b)
                reagent_c_ml = _read_ml(idx_c)

            trident["waste_used_ml"] = waste_used_ml

            # Reagent bottles are typically ~250 mL when brand new. The controller
            # reports remaining volume in mL, which we expose directly and use for
            # conservative near-empty warnings.
            trident["reagent_a_remaining_ml"] = reagent_a_ml
            trident["reagent_b_remaining_ml"] = reagent_b_ml
            trident["reagent_c_remaining_ml"] = reagent_c_ml

            trident["reagent_a_empty"] = (
                (reagent_a_ml <= TRIDENT_REAGENT_EMPTY_THRESHOLD_ML)
                if reagent_a_ml is not None
                else None
            )
            trident["reagent_b_empty"] = (
                (reagent_b_ml <= TRIDENT_REAGENT_EMPTY_THRESHOLD_ML)
                if reagent_b_ml is not None
                else None
            )
            trident["reagent_c_empty"] = (
                (reagent_c_ml <= TRIDENT_REAGENT_EMPTY_THRESHOLD_ML)
                if reagent_c_ml is not None
                else None
            )

            waste_size_any: Any = trident.get("waste_size_ml")
            waste_size_ml: float | None = None
            if isinstance(waste_size_any, (int, float)) and not isinstance(
                waste_size_any, bool
            ):
                if float(waste_size_any) > 0:
                    waste_size_ml = float(waste_size_any)
            trident["waste_size_ml"] = waste_size_ml

            if waste_used_ml is None or waste_size_ml is None:
                trident["waste_percent"] = None
                trident["waste_full"] = None
                trident["waste_remaining_ml"] = None
                return

            remaining = max(0.0, waste_size_ml - waste_used_ml)
            percent = (waste_used_ml / waste_size_ml) * 100.0
            trident["waste_percent"] = percent
            trident["waste_remaining_ml"] = remaining
            trident["waste_full"] = remaining <= TRIDENT_WASTE_FULL_MARGIN_ML

        tridents_any: Any = data.get("tridents")
        if isinstance(tridents_any, list):
            for t_any in cast(list[Any], tridents_any):
                if isinstance(t_any, dict):
                    _finalize_one(cast(dict[str, Any], t_any))

        trident_any: Any = data.get("trident")
        if isinstance(trident_any, dict):
            _finalize_one(cast(dict[str, Any], trident_any))

    def _disable_rest(self, *, seconds: float, reason: str) -> None:
        if self._install_active:
            # A reboot is expected; do not extend the outage with a long backoff.
            seconds = min(seconds, INSTALL_REST_BACKOFF_CAP_SECONDS)
        until = time.monotonic() + max(0.0, seconds)
        if until > self._rest_disabled_until:
            self._rest_disabled_until = until
        _LOGGER.debug(
            "REST temporarily disabled host=%s seconds=%s reason=%s",
            str(self.entry.data.get(CONF_HOST, "")),
            int(max(0.0, seconds)),
            reason,
        )

    def _parse_retry_after_seconds(self, headers: Any) -> float | None:
        try:
            value = headers.get("Retry-After")
            if value is None:
                return None
            t = str(value).strip()
            if not t:
                return None
            # Retry-After can be seconds or an HTTP date; handle seconds.
            return float(int(t))
        except Exception:
            return None

    async def _async_rest_login(self, *, session: aiohttp.ClientSession) -> str:
        """Ensure a REST session cookie exists and return connect.sid.

        Args:
            session: aiohttp client session.

        Returns:
            The connect.sid session value.

        Raises:
            FileNotFoundError: If REST is not supported.
            HomeAssistantError: If login fails.
        """
        host = str(self.entry.data.get(CONF_HOST, ""))
        username = str(self.entry.data.get(CONF_USERNAME, "") or "admin")
        password = str(self.entry.data.get(CONF_PASSWORD, "") or "")
        if not password:
            raise HomeAssistantError("Password is required for REST control")

        base_url = build_base_url(host)

        # Prefer cached SID.
        if self._rest_sid:
            return self._rest_sid

        # Prefer cookie jar.
        sid_morsel = session.cookie_jar.filter_cookies(URL(base_url)).get("connect.sid")
        if sid_morsel is not None and sid_morsel.value:
            self._rest_sid = sid_morsel.value
            return sid_morsel.value

        login_url = f"{base_url}/rest/login"
        timeout_seconds = DEFAULT_TIMEOUT_SECONDS

        login_candidates: list[str] = []
        if username:
            login_candidates.append(username)
        if "admin" not in login_candidates:
            login_candidates.append("admin")

        last_status: int | None = None
        last_error: Exception | None = None
        for login_user in login_candidates:
            max_login_attempts = 1 if self._install_active else 4
            for login_attempt in range(1, max_login_attempts + 1):
                try:
                    async with async_timeout.timeout(timeout_seconds):
                        async with session.post(
                            login_url,
                            json={
                                "login": login_user,
                                "password": password,
                                "remember_me": False,
                            },
                            headers={
                                "Accept": "*/*",
                                "Content-Type": "application/json",
                                "User-Agent": "HomeAssistant-ApexFusion",
                            },
                        ) as resp:
                            last_status = resp.status
                            _LOGGER.debug(
                                "REST login (control) host=%s user=%s HTTP %s attempt=%s/%s",
                                host,
                                login_user,
                                resp.status,
                                login_attempt,
                                max_login_attempts,
                            )
                            if resp.status == 404:
                                raise FileNotFoundError
                            if resp.status in (401, 403):
                                if login_attempt < max_login_attempts:
                                    await asyncio.sleep(0.25 * login_attempt)
                                    continue
                                break
                            if resp.status == 429:
                                retry_after = self._parse_retry_after_seconds(
                                    resp.headers
                                )
                                backoff = (
                                    float(retry_after)
                                    if retry_after is not None
                                    else 300.0
                                )
                                self._disable_rest(
                                    seconds=backoff, reason="rate_limited_control"
                                )
                                raise HomeAssistantError(
                                    f"Controller rate limited REST login; retry after ~{int(backoff)}s"
                                )

                            resp.raise_for_status()
                            body = await resp.text()

                    # Prefer Set-Cookie.
                    morsel = resp.cookies.get("connect.sid")
                    if morsel is not None and morsel.value:
                        self._rest_sid = morsel.value
                        _set_connect_sid_cookie(
                            session, base_url=base_url, sid=morsel.value
                        )
                        return morsel.value

                    # Fallback: JSON body.
                    login_any: Any = json.loads(body) if body else {}
                    if isinstance(login_any, dict):
                        sid_any: Any = cast(dict[str, Any], login_any).get(
                            "connect.sid"
                        )
                        if isinstance(sid_any, str) and sid_any:
                            self._rest_sid = sid_any
                            _set_connect_sid_cookie(
                                session, base_url=base_url, sid=sid_any
                            )
                            return sid_any

                except FileNotFoundError:
                    raise
                except (
                    asyncio.TimeoutError,
                    aiohttp.ClientError,
                    json.JSONDecodeError,
                ) as err:
                    last_error = err
                    if login_attempt < max_login_attempts:
                        await asyncio.sleep(0.25 * login_attempt)
                    continue

        self._rest_sid = None
        if last_error is not None:
            raise HomeAssistantError(
                f"Error logging into Apex REST API: {last_error}"
            ) from last_error
        raise HomeAssistantError(
            f"REST login rejected (HTTP {last_status})"
            if last_status
            else "REST login rejected"
        )

    async def async_rest_put_json(self, *, path: str, payload: dict[str, Any]) -> None:
        """Send a REST control PUT with coordinator-managed auth and rate limiting.

        Args:
            path: URL path starting with `/rest/...`.
            payload: JSON payload.

        Raises:
            FileNotFoundError: If the endpoint does not exist (REST unsupported/variant).
            HomeAssistantError: On auth, rate limit, or network failures, or
                while a firmware install is in progress.
        """
        if self._install_active:
            raise HomeAssistantError(
                "A firmware install is in progress; controller writes are blocked "
                "until it finishes"
            )

        now = time.monotonic()
        if now < self._rest_disabled_until:
            raise HomeAssistantError(
                f"REST temporarily disabled (retry in ~{int(self._rest_disabled_until - now)}s)"
            )

        host = str(self.entry.data.get(CONF_HOST, ""))
        password = str(self.entry.data.get(CONF_PASSWORD, "") or "")
        if not password:
            raise HomeAssistantError("Password is required for REST control")

        base_url = build_base_url(host)
        if not path.startswith("/"):
            path = "/" + path
        url = f"{base_url}{path}"

        session = async_get_clientsession(self.hass)
        timeout_seconds = DEFAULT_TIMEOUT_SECONDS

        async def _do_put(*, sid: str | None) -> None:
            headers: dict[str, str] = {"Accept": "*/*"}
            if sid:
                headers["Cookie"] = f"connect.sid={sid}"
            async with async_timeout.timeout(timeout_seconds):
                async with session.put(url, json=payload, headers=headers) as resp:
                    if resp.status == 404:
                        raise FileNotFoundError
                    if resp.status == 429:
                        retry_after = self._parse_retry_after_seconds(resp.headers)
                        backoff = (
                            float(retry_after) if retry_after is not None else 300.0
                        )
                        self._disable_rest(
                            seconds=backoff, reason="rate_limited_control"
                        )
                        raise HomeAssistantError(
                            f"Controller rate limited REST control; retry after ~{int(backoff)}s"
                        )
                    if resp.status in (401, 403):
                        raise PermissionError
                    if _is_transient_http_status(resp.status):
                        raise HomeAssistantError(
                            f"Transient REST control HTTP error (status={resp.status})"
                        )
                    resp.raise_for_status()
                    await resp.text()

        try:
            sid = await self._async_rest_login(session=session)
            await _do_put(sid=sid)
            return
        except PermissionError:
            # Session may have expired; clear and try once more.
            self._rest_sid = None
            sid2 = await self._async_rest_login(session=session)
            await _do_put(sid=sid2)
            return
        except FileNotFoundError:
            raise
        except HomeAssistantError:
            raise
        except (asyncio.TimeoutError, aiohttp.ClientError) as err:
            raise HomeAssistantError(f"Error sending REST control: {err}") from err

    async def async_rest_get_json(self, *, path: str) -> dict[str, Any]:
        """Send a REST GET with coordinator-managed auth and rate limiting.

        Args:
            path: REST path beginning with or without a leading slash.

        Returns:
            Parsed JSON object.

        Raises:
            FileNotFoundError: If the REST path does not exist.
            HomeAssistantError: If REST is disabled or the request fails.
        """
        now = time.monotonic()
        if now < self._rest_disabled_until:
            raise HomeAssistantError(
                f"REST temporarily disabled (retry in ~{int(self._rest_disabled_until - now)}s)"
            )

        host = str(self.entry.data.get(CONF_HOST, ""))
        password = str(self.entry.data.get(CONF_PASSWORD, "") or "")
        if not password:
            raise HomeAssistantError("Password is required for REST")

        base_url = build_base_url(host)
        if not path.startswith("/"):
            path = "/" + path
        url = f"{base_url}{path}"

        session = async_get_clientsession(self.hass)
        timeout_seconds = DEFAULT_TIMEOUT_SECONDS

        async def _do_get(*, sid: str | None) -> dict[str, Any]:
            headers: dict[str, str] = {"Accept": "*/*"}
            if sid:
                headers["Cookie"] = f"connect.sid={sid}"
            async with async_timeout.timeout(timeout_seconds):
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 404:
                        raise FileNotFoundError
                    if resp.status == 429:
                        retry_after = self._parse_retry_after_seconds(resp.headers)
                        backoff = (
                            float(retry_after) if retry_after is not None else 300.0
                        )
                        self._disable_rest(seconds=backoff, reason="rate_limited_get")
                        raise HomeAssistantError(
                            f"Controller rate limited REST GET; retry after ~{int(backoff)}s"
                        )
                    if resp.status in (401, 403):
                        raise PermissionError
                    if _is_transient_http_status(resp.status):
                        raise HomeAssistantError(
                            f"Transient REST GET HTTP error (status={resp.status})"
                        )
                    resp.raise_for_status()
                    body = await resp.text()

            any_obj: Any = json.loads(body) if body else {}
            if not isinstance(any_obj, dict):
                raise HomeAssistantError("REST response was not a JSON object")
            return cast(dict[str, Any], any_obj)

        try:
            sid = await self._async_rest_login(session=session)
            return await _do_get(sid=sid)
        except PermissionError:
            self._rest_sid = None
            sid2 = await self._async_rest_login(session=session)
            return await _do_get(sid=sid2)
        except FileNotFoundError:
            raise
        except HomeAssistantError:
            raise
        except (asyncio.TimeoutError, aiohttp.ClientError, json.JSONDecodeError) as err:
            raise HomeAssistantError(f"Error fetching REST data: {err}") from err

    async def async_refresh_config_now(self) -> None:
        """Force a sanitized /rest/config refresh and update coordinator data.

        This is used by manual refresh buttons and after config-affecting PUTs.
        """
        config_obj = await self.async_rest_get_json(path="/rest/config")

        sanitized_mconf = _sanitize_mconf_for_storage(config_obj)
        sanitized_nconf = _sanitize_nconf_for_storage(config_obj)
        mxm_devices = _parse_mxm_devices_from_mconf(config_obj)

        self._cached_mconf = sanitized_mconf
        self._cached_nconf = sanitized_nconf or self._cached_nconf
        if mxm_devices:
            self._cached_mxm_devices = mxm_devices

        self._rest_config_last_fetch = time.monotonic()

        # Update current data in-place so entities reflect the fresh config
        # without waiting for the next poll.
        data = self.data
        data.setdefault("config", {})["mconf"] = sanitized_mconf
        if sanitized_nconf:
            data["config"]["nconf"] = sanitized_nconf
        if mxm_devices:
            data["mxm_devices"] = mxm_devices

        # Ensure Trident derived fields are recomputed with new wasteSize.
        waste_by_abaddr: dict[int, float] = {}
        waste_default: float | None = None
        for m in sanitized_mconf:
            if str(m.get("hwtype") or "").strip().upper() not in {"TRI", "TNP"}:
                continue
            abaddr_any: Any = m.get("abaddr")
            if not isinstance(abaddr_any, int):
                continue
            extra_any: Any = m.get("extra")
            if not isinstance(extra_any, dict):
                continue
            waste_any: Any = cast(dict[str, Any], extra_any).get("wasteSize")
            if isinstance(waste_any, (int, float)):
                waste_value = float(waste_any)
                waste_by_abaddr[abaddr_any] = waste_value
                if waste_default is None:
                    waste_default = waste_value

        def _apply_waste_size(trident: dict[str, Any]) -> None:
            abaddr_any: Any = trident.get("abaddr")
            if isinstance(abaddr_any, int) and abaddr_any in waste_by_abaddr:
                trident["waste_size_ml"] = waste_by_abaddr[abaddr_any]
                return
            if waste_default is not None:
                trident["waste_size_ml"] = waste_default

        tridents_any: Any = data.get("tridents")
        if isinstance(tridents_any, list):
            for t_any in cast(list[Any], tridents_any):
                if not isinstance(t_any, dict):
                    continue
                _apply_waste_size(cast(dict[str, Any], t_any))

        trident_any: Any = data.get("trident")
        if isinstance(trident_any, dict):
            _apply_waste_size(cast(dict[str, Any], trident_any))

        self._finalize_trident(data)
        self.async_set_updated_data(data)

    def _get_trident_abaddr(self, *, trident_abaddr: int | None = None) -> int:
        if isinstance(trident_abaddr, int):
            return trident_abaddr
        data = self.data or {}
        trident_any: Any = data.get("trident")
        if not isinstance(trident_any, dict):
            raise HomeAssistantError("Trident module not detected")
        trident = cast(dict[str, Any], trident_any)
        abaddr_any: Any = trident.get("abaddr")
        if not isinstance(abaddr_any, int):
            raise HomeAssistantError("Trident module address unavailable")
        return abaddr_any

    async def _async_trident_put_mconf_extra(
        self, *, extra: dict[str, Any], trident_abaddr: int | None = None
    ) -> None:
        """Send a REST update for Trident module config/commands.

        We try the per-module endpoint first, then fall back to the bulk endpoint.
        """
        abaddr = self._get_trident_abaddr(trident_abaddr=trident_abaddr)

        try:
            await self.async_rest_put_json(
                path=f"/rest/config/mconf/{abaddr}",
                payload={"abaddr": abaddr, "extra": extra},
            )
        except FileNotFoundError:
            await self.async_rest_put_json(
                path="/rest/config/mconf",
                payload={"mconf": [{"abaddr": abaddr, "extra": extra}]},
            )

        await self.async_request_refresh()

    async def async_trident_set_waste_size_ml(
        self, *, size_ml: float, trident_abaddr: int | None = None
    ) -> None:
        if size_ml <= 0:
            raise HomeAssistantError("Waste container size must be > 0")

        await self._async_trident_put_mconf_extra(
            extra={"wasteSize": float(size_ml)}, trident_abaddr=trident_abaddr
        )
        # Pull fresh config so HA reflects the real controller state.
        await self.async_refresh_config_now()

    async def async_trident_reset_waste(
        self, *, trident_abaddr: int | None = None
    ) -> None:
        # Trident exposes `reset` as a 5-element list aligned with `levels`.
        # Best-known mapping for levels index 0 is waste used.
        await self._async_trident_put_mconf_extra(
            extra={"reset": [True, False, False, False, False]},
            trident_abaddr=trident_abaddr,
        )

    async def async_trident_reset_reagent(
        self, *, reagent_index: int, trident_abaddr: int | None = None
    ) -> None:
        if reagent_index not in (0, 1, 2):
            raise HomeAssistantError("Invalid reagent index")
        payload = [False, False, False]
        payload[reagent_index] = True
        await self._async_trident_put_mconf_extra(
            extra={"newReagent": payload}, trident_abaddr=trident_abaddr
        )

    async def async_trident_prime_channel(
        self, *, channel_index: int, trident_abaddr: int | None = None
    ) -> None:
        if channel_index not in (0, 1, 2, 3):
            raise HomeAssistantError("Invalid prime channel")
        payload = [False, False, False, False]
        payload[channel_index] = True
        await self._async_trident_put_mconf_extra(
            extra={"prime": payload}, trident_abaddr=trident_abaddr
        )

    @property
    def legacy_format(self) -> str | None:
        """Return the legacy format this entry is pinned to, if known."""
        return legacy_format_from_entry_data(self.entry.data)

    @property
    def transport(self) -> str | None:
        """Return the transport this entry is pinned to (``rest``/``legacy``)."""
        return transport_from_entry_data(self.entry.data)

    # ------------------------------------------------------------------
    # Firmware install window
    # ------------------------------------------------------------------

    @property
    def install_in_progress(self) -> bool:
        """Return whether a firmware install window is open."""
        return self._install_active

    @property
    def install_phase(self) -> str | None:
        """Return ``restarting``, ``reconnecting``, ``web_pages`` or ``None``."""
        progress = self._install_progress()
        return progress[0] if progress is not None else None

    @property
    def install_percentage(self) -> int | None:
        """Return the time-based install percentage (0-99) or ``None``."""
        progress = self._install_progress()
        return progress[1] if progress is not None else None

    def _install_progress(self) -> tuple[str, int] | None:
        if not self._install_active or self._install_started is None:
            return None
        now = time.monotonic()
        reconnected_for = (
            now - self._install_reconnected_at
            if self._install_reconnected_at is not None
            else None
        )
        return install_progress(
            elapsed=now - self._install_started, reconnected_for=reconnected_for
        )

    async def async_begin_install_window(
        self, *, expected_version: str | None = None
    ) -> None:
        """Open the firmware install window.

        While it is open, a controller that refuses sessions or lacks endpoints
        (it is rebooting) makes polls fail with ``UpdateFailed`` instead of
        starting reauth, retries and REST backoff are capped, and every other
        REST write is blocked.

        Args:
            expected_version: Version the install is expected to produce, used
                only to flag a surprising result in the log.

        Raises:
            HomeAssistantError: If a window is already open or the installed
                version is unknown (success could not be detected).
        """
        if self._install_active:
            raise HomeAssistantError("A firmware install is already in progress")
        meta_any: Any = (self.data or {}).get("meta")
        software: Any = (
            cast(dict[str, Any], meta_any).get("software")
            if isinstance(meta_any, dict)
            else None
        )
        from_version = str(software or "").strip()
        if not from_version:
            raise HomeAssistantError(
                "The installed firmware version is unknown; cannot track an install"
            )

        self._install_active = True
        self._install_from_version = from_version
        self._install_expected_version = expected_version
        self._install_reconnected_at = None
        # A pre-reboot session will not survive the restart.
        self._rest_sid = None
        ir.async_delete_issue(self.hass, DOMAIN, self._install_issue_id)
        self._start_install_clock()
        self.async_update_listeners()

    @property
    def _install_issue_id(self) -> str:
        return f"firmware_install_unconfirmed_{self.entry.entry_id}"

    def _start_install_clock(self) -> None:
        """(Re)start the install clock and its timers from now."""
        self._cancel_install_timers()
        self._install_started = time.monotonic()
        self._install_unsubs = [
            async_track_time_interval(
                self.hass, self._async_install_tick, INSTALL_PROGRESS_TICK
            ),
            async_call_later(
                self.hass,
                INSTALL_UI_FAIL_WARNING_SECONDS,
                self._async_install_ui_fail_point,
            ),
            async_call_later(
                self.hass, INSTALL_WINDOW_MAX_SECONDS, self._async_install_hard_cap
            ),
        ]

    def _cancel_install_timers(self) -> None:
        unsubs, self._install_unsubs = self._install_unsubs, []
        for unsub in unsubs:
            unsub()

    @callback
    def _async_install_tick(self, _now: Any) -> None:
        """Push the time-based progress to listeners."""
        self.async_update_listeners()

    @callback
    def _async_install_ui_fail_point(self, _now: Any) -> None:
        """Log where the controller UI would give up; trigger nothing."""
        if self._install_active and self._install_reconnected_at is None:
            _LOGGER.warning(
                "Controller has not come back %ds after the firmware install "
                "request; the controller's own UI would declare failure here. "
                "Still waiting (hard cap %d min); nothing is retried",
                int(INSTALL_UI_FAIL_WARNING_SECONDS),
                int(INSTALL_WINDOW_MAX_SECONDS // 60),
            )

    async def _async_install_hard_cap(self, _now: Any) -> None:
        if self._install_active:
            await self.async_end_install_window(INSTALL_RESULT_TIMEOUT)

    def _observe_install_poll(self, data: dict[str, Any]) -> None:
        """Track a good poll while the window is open (reconnect, completion)."""
        now = time.monotonic()
        started = self._install_started
        if (
            self._install_reconnected_at is None
            and started is not None
            and now - started >= INSTALL_RESTART_SECONDS
        ):
            self._install_reconnected_at = now
            # Do not carry a pre-reboot session into the new firmware.
            self._rest_sid = None

        meta_any: Any = data.get("meta")
        software: Any = (
            cast(dict[str, Any], meta_any).get("software")
            if isinstance(meta_any, dict)
            else None
        )
        version = str(software or "").strip()
        if version and version != self._install_from_version:
            expected = self._install_expected_version
            if expected and version != expected:
                _LOGGER.warning(
                    "Controller reports firmware %s after the install, not the "
                    "expected %s",
                    version,
                    expected,
                )
            self._close_install_window(INSTALL_RESULT_SUCCESS)
            self.entry.async_create_background_task(
                self.hass,
                self._async_refresh_config_after_install(),
                f"{DOMAIN}_post_install_config_refresh",
            )

    async def _async_refresh_config_after_install(self) -> None:
        try:
            await self.async_refresh_config_now()
        except (HomeAssistantError, FileNotFoundError) as err:
            _LOGGER.warning(
                "Could not refresh controller config after the install: %s",
                _safe_str(err),
            )

    def _close_install_window(self, result: str) -> None:
        """Close the window and clear its state (never retries anything)."""
        self._cancel_install_timers()
        self._install_active = False
        self._install_started = None
        self._install_reconnected_at = None
        self._install_from_version = None
        self._install_expected_version = None
        if result == INSTALL_RESULT_TIMEOUT:
            _LOGGER.error(
                "Controller did not report a new firmware version within %d "
                "minutes; the install is not retried",
                int(INSTALL_WINDOW_MAX_SECONDS // 60),
            )
            ir.async_create_issue(
                self.hass,
                DOMAIN,
                self._install_issue_id,
                is_fixable=False,
                severity=ir.IssueSeverity.ERROR,
                translation_key="firmware_install_unconfirmed",
                translation_placeholders={"name": self.entry.title},
            )
        elif result == INSTALL_RESULT_SUCCESS:
            ir.async_delete_issue(self.hass, DOMAIN, self._install_issue_id)
        self.async_update_listeners()

    async def async_end_install_window(self, result: str) -> None:
        """Close the install window.

        Args:
            result: ``success`` (refreshes the controller config), ``timeout``
                (raises a Repairs issue) or ``rejected``.
        """
        if not self._install_active:
            return
        self._close_install_window(result)
        if result == INSTALL_RESULT_SUCCESS:
            await self._async_refresh_config_after_install()

    async def async_shutdown(self) -> None:
        """Cancel the install timers, then shut the coordinator down."""
        self._cancel_install_timers()
        self._install_active = False
        await super().async_shutdown()

    async def async_request_firmware_install(self) -> str:
        """Ask the controller to install its latest firmware, exactly once.

        Sends one ``PUT /rest/config/nconf`` with ``updateFirmware: true`` and
        never resends it, whatever happens: an ambiguous outcome (timeout,
        reset, 5xx) may mean the controller already started, and the window,
        not a retry, decides what happened. The body is the controller's own
        nconf object (read fresh) minus the credential fields and ``ssid``;
        the controller treats omitted fields as unchanged. The nconf object is
        held in a local only and is never logged or stored.

        Returns:
            ``"accepted"`` for a 2xx answer, ``"possibly_started"`` when the
            outcome is ambiguous. In both cases the install window is open.

        Raises:
            HomeAssistantError: If the preconditions are not met or the
                controller definitely rejected the request (window closed).
        """
        if self.transport != TRANSPORT_REST:
            raise HomeAssistantError("Firmware install requires the REST transport")
        if self.entry.data.get(CONF_NO_LOGIN) or not str(
            self.entry.data.get(CONF_PASSWORD, "") or ""
        ):
            raise HomeAssistantError("Firmware install requires a configured password")
        if self._install_active:
            raise HomeAssistantError("A firmware install is already in progress")

        try:
            nconf_obj = await self.async_rest_get_json(path="/rest/config/nconf")
        except FileNotFoundError as err:
            raise HomeAssistantError(
                "Controller does not expose its network config; cannot install"
            ) from err
        inner: Any = nconf_obj.get("nconf")
        nconf: dict[str, Any] = cast(
            dict[str, Any], inner if isinstance(inner, dict) else nconf_obj
        )
        body: dict[str, Any] = {
            key: value
            for key, value in nconf.items()
            if key not in INSTALL_NCONF_STRIPPED_KEYS
        }
        body["updateFirmware"] = True
        del nconf, nconf_obj, inner

        sid = self._rest_sid
        latest = self._cached_latest_firmware()
        # Open the window before sending: from here on other writes are blocked
        # and an ambiguous send is handled by version detection.
        await self.async_begin_install_window(expected_version=latest)

        session = async_get_clientsession(self.hass)
        url = f"{build_base_url(str(self.entry.data.get(CONF_HOST, '')))}/rest/config/nconf"
        headers: dict[str, str] = {"Accept": "*/*", "accept-version": "1"}
        if sid:
            headers["Cookie"] = f"connect.sid={sid}"

        outcome = "accepted"
        try:
            async with async_timeout.timeout(DEFAULT_TIMEOUT_SECONDS):
                async with session.put(url, json=body, headers=headers) as resp:
                    status = resp.status
        except (asyncio.TimeoutError, aiohttp.ClientError) as err:
            _LOGGER.warning(
                "Firmware install request outcome unknown (%s); waiting for the "
                "controller to report a new version, not resending",
                err.__class__.__name__,
            )
            outcome = "possibly_started"
        else:
            if 200 <= status < 300:
                pass
            elif status >= 500 or status < 200 or 300 <= status < 400:
                _LOGGER.warning(
                    "Firmware install request answered HTTP %s; waiting for the "
                    "controller to report a new version, not resending",
                    status,
                )
                outcome = "possibly_started"
            else:
                self._close_install_window(INSTALL_RESULT_REJECTED)
                if status in (401, 403):
                    self._rest_sid = None
                    raise HomeAssistantError(
                        f"Controller rejected the firmware install session (HTTP {status})"
                    )
                if status in (404, 405):
                    raise HomeAssistantError(
                        f"Controller does not support the firmware install request (HTTP {status})"
                    )
                raise HomeAssistantError(
                    f"Controller rejected the firmware install request (HTTP {status})"
                )

        # The restart period is measured from when the request returned.
        self._start_install_clock()
        return outcome

    def _cached_latest_firmware(self) -> str | None:
        nconf = self._cached_nconf
        latest: Any = nconf.get("latestFirmware") if nconf else None
        text = str(latest or "").strip()
        return text or None

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch and parse controller status from the pinned transport.

        The transport is chosen once (config flow) and stored on the config
        entry. An outage never switches transport: it fails the update so the
        entities become unavailable.

        Returns:
            Coordinator data dict.

        Raises:
            ConfigEntryAuthFailed: If the controller rejects the credentials.
            UpdateFailed: If the pinned transport cannot be read.
        """
        transport = self.transport
        if transport == TRANSPORT_REST:
            return await self._async_update_rest()
        if transport == TRANSPORT_LEGACY:
            return await self._async_update_legacy()
        raise UpdateFailed("No transport is stored for this entry; reconfigure it")

    def _update_params(self) -> tuple[str, str, str, str]:
        """Return (host, username, password, base_url) for this entry."""
        host = str(self.entry.data[CONF_HOST])
        username = str(self.entry.data.get(CONF_USERNAME, ""))
        password = str(self.entry.data.get(CONF_PASSWORD, ""))
        if bool(self.entry.data.get(CONF_NO_LOGIN, False)):
            # Explicit read-only / unauthenticated mode.
            username = ""
            password = ""
        return host, username, password, build_base_url(host)

    async def _async_update_rest(self) -> dict[str, Any]:
        """Poll the REST API only; every failure is surfaced, never bypassed."""
        try:
            data = await self._async_update_rest_inner()
            if self._install_active:
                self._observe_install_poll(data)
            return data
        except _RestRateLimited as err:
            raise UpdateFailed("Controller rate limited the REST API") from err
        except (_RestAuthRejected, _RestNotSupported) as err:
            if self._install_active:
                # The controller is rebooting: it may refuse sessions or lack
                # its web endpoints for a while. Never open reauth for that.
                raise UpdateFailed("Controller is installing firmware") from err
            if isinstance(err, _RestAuthRejected):
                raise ConfigEntryAuthFailed(
                    "Invalid auth for Apex REST endpoints"
                ) from err
            raise UpdateFailed(
                "Controller REST endpoints not found; re-detect the transport "
                "from the reconfigure flow"
            ) from err
        except (ConfigEntryAuthFailed, UpdateFailed) as err:
            if self._install_active and isinstance(err, ConfigEntryAuthFailed):
                raise UpdateFailed("Controller is installing firmware") from err
            raise
        except (
            asyncio.TimeoutError,
            aiohttp.ClientError,
            json.JSONDecodeError,
        ) as err:
            raise UpdateFailed(f"REST update failed: {_safe_str(err)}") from err
        except Exception as err:
            raise UpdateFailed(f"Unexpected REST error: {err}") from err

    async def _async_update_rest_inner(self) -> dict[str, Any]:
        host, username, password, base_url = self._update_params()
        session = async_get_clientsession(self.hass)
        timeout_seconds = DEFAULT_TIMEOUT_SECONDS

        _LOGGER.debug(
            "REST update start host=%s user=%s has_password=%s",
            host,
            (username or "admin"),
            bool(password),
        )

        if not password:
            # Read-only mode: the status endpoint is read without a login.
            rest_status_url = f"{base_url}/rest/status"

            async def _fetch_no_login_rest_status(sid: str | None) -> dict[str, Any]:
                headers = {"Accept": "*/*"}
                if sid:
                    headers["Cookie"] = f"connect.sid={sid}"
                async with async_timeout.timeout(timeout_seconds):
                    async with session.get(rest_status_url, headers=headers) as resp:
                        if resp.status in (401, 403):
                            raise _RestAuthRejected
                        if resp.status == 404:
                            raise _RestNotSupported
                        if resp.status == 429:
                            raise _RestRateLimited(
                                retry_after_seconds=self._parse_retry_after_seconds(
                                    resp.headers
                                )
                            )
                        resp.raise_for_status()
                        body = await resp.text()

                parsed_any: Any = json.loads(body) if body else {}
                if not isinstance(parsed_any, dict):
                    raise UpdateFailed("REST status payload was not a JSON object")
                return cast(dict[str, Any], parsed_any)

            try:
                status_obj = await _fetch_no_login_rest_status(self._rest_sid)
            except _RestAuthRejected:
                if not self._rest_sid:
                    raise
                # Cached SID may be stale; clear and retry without cookie.
                self._rest_sid = None
                status_obj = await _fetch_no_login_rest_status(None)

            data = parse_status_rest(status_obj)
            self._finalize_trident(data)
            return self._apply_serial_cache(data)

        now = time.monotonic()
        if now < self._rest_disabled_until:
            raise UpdateFailed(
                "REST temporarily paused after the controller rate limited it "
                f"(retry in ~{int(self._rest_disabled_until - now)}s)"
            )

        login_url = f"{base_url}/rest/login"
        accept_headers = {
            "Accept": "*/*",
            "Content-Type": "application/json",
            "User-Agent": "HomeAssistant-ApexFusion",
        }

        def _candidate_status_urls() -> list[str]:
            if self._rest_status_path:
                return [f"{base_url}{self._rest_status_path}"]
            return [
                f"{base_url}/rest/status",
            ]

        def _cookie_headers(sid: str | None) -> dict[str, str]:
            headers = dict(accept_headers)
            if sid:
                headers["Cookie"] = f"connect.sid={sid}"
            return headers

        class _RestStatusUnauthorized(Exception):
            """REST status endpoint rejected the session."""

        def _parse_retry_after(headers: Any) -> float | None:
            try:
                value = headers.get("Retry-After")
                if value is None:
                    return None
                t = str(value).strip()
                if not t:
                    return None
                # Retry-After can be seconds or an HTTP date; handle seconds.
                return float(int(t))
            except Exception:
                return None

        async def _fetch_rest_status(
            sid: str | None, *, status_url: str
        ) -> dict[str, Any] | None:
            """Fetch a REST status payload.

            Args:
                sid: Optional connect.sid session value.
                status_url: Full URL for the status endpoint.

            Returns:
                Parsed JSON dict when available, otherwise None.
            """
            async with async_timeout.timeout(timeout_seconds):
                async with session.get(
                    status_url, headers=_cookie_headers(sid)
                ) as resp:
                    _LOGGER.debug(
                        "REST status host=%s url=%s HTTP %s content_type=%s has_connect_sid=%s",
                        host,
                        URL(status_url).path,
                        resp.status,
                        resp.headers.get("Content-Type"),
                        bool(sid) or _session_has_connect_sid(session, base_url),
                    )

                    if resp.status == 404:
                        raise FileNotFoundError
                    if resp.status in (401, 403):
                        raise _RestStatusUnauthorized
                    if resp.status == 429:
                        raise _RestRateLimited(
                            retry_after_seconds=_parse_retry_after(resp.headers)
                        )
                    if _is_transient_http_status(resp.status):
                        raise aiohttp.ClientResponseError(
                            request_info=resp.request_info,
                            history=resp.history,
                            status=resp.status,
                            message="Transient REST status HTTP error",
                            headers=resp.headers,
                        )

                    resp.raise_for_status()
                    status_text = await resp.text()

            status_any: Any = json.loads(status_text) if status_text else {}
            return (
                cast(dict[str, Any], status_any)
                if isinstance(status_any, dict)
                else None
            )

        async def _login_rest(*, login_user: str) -> str | None:
            """Perform REST login.

            Args:
                login_user: Username to attempt.

            Returns:
                The connect.sid value if found, otherwise None.
            """
            login_cookie_sid = ""
            async with async_timeout.timeout(timeout_seconds):
                async with session.post(
                    login_url,
                    json={
                        "login": login_user,
                        "password": password,
                        "remember_me": False,
                    },
                    headers=accept_headers,
                ) as resp:
                    _LOGGER.debug(
                        "REST login host=%s user=%s HTTP %s content_type=%s",
                        host,
                        login_user,
                        resp.status,
                        resp.headers.get("Content-Type"),
                    )

                    if resp.status == 404:
                        raise _RestNotSupported
                    if resp.status in (401, 403):
                        raise _RestAuthRejected
                    if resp.status == 429:
                        raise _RestRateLimited(
                            retry_after_seconds=_parse_retry_after(resp.headers)
                        )
                    if _is_transient_http_status(resp.status):
                        raise aiohttp.ClientResponseError(
                            request_info=resp.request_info,
                            history=resp.history,
                            status=resp.status,
                            message="Transient REST login HTTP error",
                            headers=resp.headers,
                        )

                    resp.raise_for_status()
                    login_body = await resp.text()

                    morsel = resp.cookies.get("connect.sid")
                    if morsel is not None and morsel.value:
                        login_cookie_sid = morsel.value

            # Prefer Set-Cookie if present.
            if login_cookie_sid:
                _set_connect_sid_cookie(
                    session, base_url=base_url, sid=login_cookie_sid
                )
                return login_cookie_sid

            # Try cookie jar.
            sid_morsel = session.cookie_jar.filter_cookies(URL(base_url)).get(
                "connect.sid"
            )
            if sid_morsel is not None and sid_morsel.value:
                return sid_morsel.value

            # Try connect.sid in JSON body.
            if login_body:
                try:
                    login_any: Any = json.loads(login_body)
                    if isinstance(login_any, dict):
                        sid_any: Any = cast(dict[str, Any], login_any).get(
                            "connect.sid"
                        )
                        if isinstance(sid_any, str) and sid_any:
                            _set_connect_sid_cookie(
                                session, base_url=base_url, sid=sid_any
                            )
                            return sid_any
                except json.JSONDecodeError:
                    pass

            return None

        async def _login_rest_with_retries(*, login_user: str) -> str | None:
            """Perform REST login with a small retry budget.

            Some controllers appear to intermittently reject the first
            login attempt even when credentials are correct.

            Args:
                login_user: Username to attempt.

            Returns:
                The connect.sid value if found, otherwise None.
            """

            max_login_attempts = 1 if self._install_active else 4

            for login_attempt in range(1, max_login_attempts + 1):
                try:
                    if login_attempt > 1:
                        _LOGGER.debug(
                            "REST login retry %s/%s host=%s user=%s",
                            login_attempt,
                            max_login_attempts,
                            host,
                            login_user,
                        )
                        # Clear cookies between attempts to avoid stale/invalid
                        # session state causing an immediate 401 loop.
                        try:
                            cookies = session.cookie_jar.filter_cookies(URL(base_url))
                            if cookies.get("connect.sid") is not None:
                                session.cookie_jar.clear()
                        except Exception:
                            pass

                    return await _login_rest(login_user=login_user)
                except _RestAuthRejected:
                    # Ensure we don't keep a cached SID around after an auth failure.
                    self._rest_sid = None
                    if login_attempt < max_login_attempts:
                        await asyncio.sleep(0.25 * login_attempt)
                        continue
                    raise

        # First try using cached SID (avoids re-login flakiness).
        if self._rest_sid:
            try:
                status_obj: dict[str, Any] | None = None
                for candidate in _candidate_status_urls():
                    try:
                        status_obj = await _fetch_rest_status(
                            self._rest_sid, status_url=candidate
                        )
                        if status_obj is not None:
                            self._rest_status_path = URL(candidate).path
                            break
                    except FileNotFoundError:
                        continue

                if status_obj is not None:
                    data = parse_status_rest(status_obj)
                    _LOGGER.debug(
                        "REST parsed host=%s probes=%s outlets=%s has_network=%s",
                        host,
                        len(cast(dict[str, Any], data.get("probes") or {})),
                        len(cast(list[Any], data.get("outlets") or [])),
                        bool(data.get("network")),
                    )
                    await self._async_try_refresh_rest_config(
                        data=data,
                        session=session,
                        base_url=base_url,
                        sid=self._rest_sid,
                        timeout_seconds=timeout_seconds,
                        host=host,
                    )
                    self._finalize_trident(data)
                    return self._apply_serial_cache(data)

                raise _RestNotSupported
            except _RestStatusUnauthorized:
                # Session expired/invalid; try to re-login.
                self._rest_sid = None

        # Some controllers allow reading status without a login cookie.
        # Probe once before attempting /rest/login to reduce session churn
        # and improve startup behavior when login is temporarily flaky.
        #
        # IMPORTANT: if credentials are configured, do not treat this
        # as success (it can mask bad credentials); proceed to login.
        try:
            status_obj: dict[str, Any] | None = None
            for candidate in _candidate_status_urls():
                try:
                    status_obj = await _fetch_rest_status(None, status_url=candidate)
                    if status_obj is not None:
                        self._rest_status_path = URL(candidate).path
                        break
                except FileNotFoundError:
                    continue
        except _RestStatusUnauthorized:
            # Expected on controllers that require auth.
            pass

        max_attempts = 1 if self._install_active else 3
        saw_auth_rejection = False
        for attempt in range(1, max_attempts + 1):
            _LOGGER.debug(
                "REST update attempt %s/%s host=%s user=%s",
                attempt,
                max_attempts,
                host,
                (username or "admin"),
            )

            try:
                # Respect the configured username. If one is provided, do not
                # automatically fall back to "admin" on the first 401; some
                # controllers are flaky and require a second login attempt.
                login_candidates: list[str] = [username] if username else ["admin"]

                sid_value: str | None = None
                for login_user in login_candidates:
                    try:
                        sid_value = await _login_rest_with_retries(
                            login_user=login_user
                        )
                        break
                    except _RestAuthRejected:
                        saw_auth_rejection = True
                        _LOGGER.debug(
                            "REST login rejected for host=%s user=%s; trying next candidate",
                            host,
                            login_user,
                        )
                        continue

                if sid_value is None:
                    raise _RestAuthRejected

                self._rest_sid = sid_value

                _LOGGER.debug(
                    "REST login session for host=%s established=%s (will_send_cookie_header=%s)",
                    host,
                    bool(sid_value) or _session_has_connect_sid(session, base_url),
                    bool(sid_value),
                )

                status_obj: dict[str, Any] | None = None
                for candidate in _candidate_status_urls():
                    try:
                        status_obj = await _fetch_rest_status(
                            sid_value, status_url=candidate
                        )
                        if status_obj is not None:
                            self._rest_status_path = URL(candidate).path
                            break
                    except FileNotFoundError:
                        continue
                    except _RestStatusUnauthorized:
                        # If REST status rejects a fresh session, treat REST as unusable
                        # for this poll and fall back to alternate endpoints.
                        self._rest_sid = None
                        raise _RestAuthRejected

                if status_obj is not None:
                    data = parse_status_rest(status_obj)

                    _LOGGER.debug(
                        "REST parsed host=%s probes=%s outlets=%s has_network=%s",
                        host,
                        len(cast(dict[str, Any], data.get("probes") or {})),
                        len(cast(list[Any], data.get("outlets") or [])),
                        bool(data.get("network")),
                    )

                    await self._async_try_refresh_rest_config(
                        data=data,
                        session=session,
                        base_url=base_url,
                        sid=self._rest_sid,
                        timeout_seconds=timeout_seconds,
                        host=host,
                    )

                    self._finalize_trident(data)

                    return self._apply_serial_cache(data)

                raise UpdateFailed("REST status payload was not a JSON object")

            except _RestNotSupported:
                raise
            except _RestAuthRejected:
                # REST rejected (credentials/user not accepted). Some controllers can
                # intermittently reject the first login attempt; allow the retry loop
                # to run before treating auth as fatal.
                saw_auth_rejection = True
                self._rest_sid = None
                if attempt < max_attempts:
                    continue
                raise
            except _RestRateLimited as err:
                self._rest_sid = None
                retry_after = err.retry_after_seconds
                # Be conservative; if no header is provided, back off for 5 minutes.
                self._disable_rest(
                    seconds=float(retry_after) if retry_after is not None else 300.0,
                    reason="rate_limited",
                )
                raise
            except aiohttp.ClientResponseError as err:
                if err.status and _is_transient_http_status(err.status):
                    try:
                        err_text = str(err)
                    except Exception:  # noqa: BLE001
                        err_text = err.__class__.__name__
                    _LOGGER.debug(
                        "Transient REST HTTP error (status=%s): %s",
                        err.status,
                        err_text,
                    )
                else:
                    raise
            except (
                asyncio.TimeoutError,
                aiohttp.ClientError,
            ) as err:
                _LOGGER.debug("Transient REST error: %s", err)

            if attempt < max_attempts:
                await asyncio.sleep(0.5 * attempt)

        if saw_auth_rejection:
            raise _RestAuthRejected

        raise UpdateFailed("REST update failed after retries")

    async def _async_update_legacy(self) -> dict[str, Any]:
        """Poll the legacy endpoints (status.json, then status.xml)."""
        host, username, password, base_url = self._update_params()
        url = build_status_url(host, DEFAULT_STATUS_PATH)
        session = async_get_clientsession(self.hass)
        timeout_seconds = DEFAULT_TIMEOUT_SECONDS

        auth: aiohttp.BasicAuth | None = None
        if password:
            auth = aiohttp.BasicAuth(username or "admin", password)

        fmt = self.legacy_format

        # Try CGI JSON first (richer metadata than status.xml), unless this entry
        # is pinned to status.xml.
        if fmt != LEGACY_FORMAT_XML:
            json_url = f"{base_url}/cgi-bin/status.json"
            try:
                _LOGGER.debug("Trying CGI JSON update: %s", json_url)
                async with async_timeout.timeout(timeout_seconds):
                    async with session.get(json_url, auth=auth) as resp:
                        if resp.status in (401, 403):
                            raise ConfigEntryAuthFailed(
                                "Invalid auth for Apex status.json"
                            )
                        if resp.status == 404:
                            raise FileNotFoundError
                        resp.raise_for_status()
                        body = await resp.text()

                parsed_any: Any = json.loads(body) if body else {}
                if isinstance(parsed_any, dict):
                    data = parse_status_cgi_json(cast(dict[str, Any], parsed_any))
                    meta = data.get("meta")
                    if isinstance(meta, dict):
                        cast(dict[str, Any], meta).setdefault("source", "cgi_json")
                    self._finalize_trident(data)
                    return self._apply_serial_cache(data)

            except FileNotFoundError:
                _LOGGER.debug("CGI status.json not found; trying status.xml")
            except ConfigEntryAuthFailed:
                _LOGGER.warning(
                    "CGI JSON authentication failed for host=%s user=%s",
                    host,
                    (username or "admin"),
                )
                raise
            except (
                asyncio.TimeoutError,
                aiohttp.ClientError,
                json.JSONDecodeError,
            ) as err:
                _LOGGER.debug("CGI JSON update failed; trying status.xml: %s", err)
            except Exception as err:
                _LOGGER.debug("Unexpected CGI JSON error; trying status.xml: %s", err)

            if fmt == LEGACY_FORMAT_CGI_JSON:
                # Pinned to status.json: do not switch to status.xml (it keys
                # probes by name, which would create a second set of entities).
                raise UpdateFailed("Apex status.json is unavailable")

        try:
            _LOGGER.debug("Trying XML update: %s", url)
            async with async_timeout.timeout(timeout_seconds):
                async with session.get(url, auth=auth) as resp:
                    if resp.status in (401, 403):
                        raise ConfigEntryAuthFailed("Invalid auth for Apex status.xml")
                    resp.raise_for_status()
                    body = await resp.text()

            data = parse_status_xml(body)
            meta = data.get("meta")
            if isinstance(meta, dict):
                cast(dict[str, Any], meta).setdefault("source", "xml")
            self._finalize_trident(data)
            return self._apply_serial_cache(data)

        except ConfigEntryAuthFailed:
            _LOGGER.warning(
                "XML authentication failed for host=%s user=%s",
                host,
                (username or "admin"),
            )
            raise
        except (asyncio.TimeoutError, aiohttp.ClientError, ET.ParseError) as err:
            raise UpdateFailed(
                f"Error fetching/parsing Apex status.xml: {err}"
            ) from err
        except Exception as err:
            raise UpdateFailed(f"Unexpected error updating Apex data: {err}") from err


__all__ = [
    "ApexNeptuneDataUpdateCoordinator",
    "build_base_url",
    "build_status_url",
    "parse_status_rest",
    "parse_status_cgi_json",
    "parse_status_xml",
]
