"""Coordinator for fetching/parsing Apex controller state.

Strategy:
- Prefer the newer REST API if present and credentials work.
- Fall back to legacy `status.xml` if REST is unavailable.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import xml.etree.ElementTree as ET
from http import HTTPStatus
from typing import Any, cast

import aiohttp
import async_timeout
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from yarl import URL

from .const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_STATUS_PATH,
    DEFAULT_TIMEOUT_SECONDS,
    LOGGER_NAME,
)

_LOGGER = logging.getLogger(LOGGER_NAME)


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


class _RestNotSupported(Exception):
    """Internal signal used to fall back to legacy XML."""


class _RestAuthRejected(Exception):
    """Internal signal that REST login/auth was rejected; try legacy XML."""


class _RestRateLimited(Exception):
    """Internal signal that REST is rate limited; temporarily disable REST."""

    def __init__(self, *, retry_after_seconds: float | None = None) -> None:
        super().__init__("REST rate limited")
        self.retry_after_seconds = retry_after_seconds


_MXM_STATUS_LINE = re.compile(
    r"^\s*(?P<name>[^\(]+)\([^\)]*\)\s*-\s*Rev\s+(?P<rev>[^\s]+)\s+Ser\s+#:\s+(?P<serial>[^\s]+)\s+-\s*(?P<status>.+?)\s*$"
)


def _parse_mxm_devices_from_mconf(
    mconf_obj: dict[str, Any],
) -> dict[str, dict[str, str]]:
    """Extract MXM device metadata from `/rest/config/mconf`.

    The MXM module includes a multiline `extra.status` string listing attached
    devices with revision and serial numbers.

    Args:
        mconf_obj: Parsed JSON from `/rest/config/mconf`.

    Returns:
        Mapping of device name -> metadata dict.
    """
    out: dict[str, dict[str, str]] = {}

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
            out[name] = {
                "rev": match.group("rev").strip(),
                "serial": match.group("serial").strip(),
                "status": match.group("status").strip(),
            }

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
    """Build a full URL to the legacy status endpoint.

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
    """Parse legacy `status.xml` into a normalized dict.

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

        # Some firmwares nest payloads.
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
            value: Any = item.get("value")
            probes[did] = {
                "name": (str(item.get("name") or did)).strip(),
                "type": (str(item.get("type") or "")).strip() or None,
                "value_raw": value,
                "value": value,
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
                }
            )

    def _parse_trident_from_modules() -> dict[str, Any]:
        modules_any: Any = _find_field(status_obj, "modules")
        if not isinstance(modules_any, list):
            return {"status": None, "is_testing": None}

        best_status: str | None = None
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
            if hwtype != "TRI":
                continue
            extra_any: Any = module.get("extra")
            if not isinstance(extra_any, dict):
                continue
            extra = cast(dict[str, Any], extra_any)
            status_any: Any = extra.get("status")
            if not isinstance(status_any, str):
                continue
            status = status_any.strip()
            if not status:
                continue

            # Some firmwares return simple statuses like "idle"/"ok".
            # Normalize those to sentence-case while preserving mixed-content
            # statuses like "testing Ca/Mg".
            if status.isalpha():
                if status.isupper() and len(status) <= 3:
                    # Preserve common abbreviations like "OK".
                    status = status
                else:
                    status = status[:1].upper() + status[1:].lower()

            best_status = status
            break

        if best_status is None:
            return {"status": None, "is_testing": None}

        lower = best_status.lower()
        is_testing = "testing" in lower
        return {"status": best_status, "is_testing": is_testing}

    def _parse_last_alert_statement() -> dict[str, Any]:
        # The Apex REST payload format for alerts/notifications varies by firmware.
        # We try common container names and extract a human-facing statement.
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

    return {
        "meta": meta,
        "network": network,
        "probes": probes,
        "outlets": outlets,
        "alerts": _parse_last_alert_statement(),
        "trident": _parse_trident_from_modules(),
        "raw": status_obj,
    }


def parse_status_cgi_json(status_obj: dict[str, Any]) -> dict[str, Any]:
    """Parse legacy `/cgi-bin/status.json` into a normalized dict.

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
            value: Any = item.get("value")
            probes[did] = {
                "name": (str(item.get("name") or did)).strip(),
                "type": (str(item.get("type") or "")).strip() or None,
                "value_raw": value,
                "value": value,
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

            outlets.append(
                {
                    "name": (str(item.get("name") or did)).strip(),
                    "output_id": str(item.get("ID") or "").strip() or None,
                    "state": (state or "").strip() or None,
                    "device_id": did,
                    "type": (output_type or "").strip() or None,
                    "gid": (gid or "").strip() or None,
                    "status": status_any if isinstance(status_any, list) else None,
                }
            )

    return {
        "meta": meta,
        "probes": probes,
        "outlets": outlets,
        "alerts": {"last_statement": None, "last_message": None},
        "trident": {"status": None, "is_testing": None},
        "raw": status_obj,
    }


class ApexNeptuneDataUpdateCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Fetches and parses status.xml into a shared data dict."""

    def __init__(self, hass: HomeAssistant, *, entry: ConfigEntry) -> None:
        """Initialize the coordinator.

        Args:
            hass: Home Assistant instance.
            entry: Config entry containing connection details.
        """
        self.hass = hass
        self.entry = entry
        self._rest_sid: str | None = None
        self._rest_disabled_until: float = 0.0
        self._rest_status_path: str | None = None
        self._cached_serial: str | None = None

        super().__init__(
            hass,
            _LOGGER,
            name=f"Apex Fusion ({entry.data.get(CONF_HOST, '')})",
            update_interval=DEFAULT_SCAN_INTERVAL,
        )

    @property
    def device_identifier(self) -> str:
        """Return a stable non-IP identifier for this controller.

        Prefer controller serial; fall back to config entry id (stable, non-IP).
        """
        if self._cached_serial:
            return self._cached_serial
        return f"entry:{self.entry.entry_id}"

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

    def _disable_rest(self, *, seconds: float, reason: str) -> None:
        until = time.monotonic() + max(0.0, seconds)
        if until > self._rest_disabled_until:
            self._rest_disabled_until = until
        _LOGGER.debug(
            "REST temporarily disabled host=%s seconds=%s reason=%s",
            str(self.entry.data.get(CONF_HOST, "")),
            int(max(0.0, seconds)),
            reason,
        )

    async def _async_update_data(self) -> dict[str, Any]:
        """Fetch and parse controller status.

        Returns:
            Coordinator data dict.

        Raises:
            UpdateFailed: If updates fail in a non-recoverable way.
        """
        host = str(self.entry.data[CONF_HOST])
        username = str(self.entry.data.get(CONF_USERNAME, ""))
        password = str(self.entry.data.get(CONF_PASSWORD, ""))
        status_path = DEFAULT_STATUS_PATH
        base_url = build_base_url(host)
        url = build_status_url(host, status_path)

        _LOGGER.debug(
            "Coordinator update start host=%s user=%s has_password=%s",
            host,
            (username or "admin"),
            bool(password),
        )

        session = async_get_clientsession(self.hass)

        auth: aiohttp.BasicAuth | None = None
        if password:
            auth = aiohttp.BasicAuth(username or "admin", password)

        timeout_seconds = DEFAULT_TIMEOUT_SECONDS

        # Prefer REST when credentials exist; fall back to XML.
        if password:
            now = time.monotonic()
            if now < self._rest_disabled_until:
                _LOGGER.debug(
                    "Skipping REST update (disabled) host=%s remaining_seconds=%s",
                    host,
                    int(self._rest_disabled_until - now),
                )
            else:
                try:
                    login_url = f"{base_url}/rest/login"
                    accept_headers = {
                        "Accept": "*/*",
                        "Content-Type": "application/json",
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
                        """Fetch REST status payload; returns parsed dict or None."""
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
                                    bool(sid)
                                    or _session_has_connect_sid(session, base_url),
                                )

                                if resp.status == 404:
                                    raise FileNotFoundError
                                if resp.status in (401, 403):
                                    raise _RestStatusUnauthorized
                                if resp.status == 429:
                                    raise _RestRateLimited(
                                        retry_after_seconds=_parse_retry_after(
                                            resp.headers
                                        )
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
                        """Perform REST login, returning connect.sid if found."""
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
                                        retry_after_seconds=_parse_retry_after(
                                            resp.headers
                                        )
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
                        sid_morsel = session.cookie_jar.filter_cookies(
                            URL(base_url)
                        ).get("connect.sid")
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
                                return self._apply_serial_cache(data)

                            raise _RestNotSupported
                        except _RestStatusUnauthorized:
                            # Session expired/invalid; try to re-login.
                            self._rest_sid = None

                    # Some controllers allow reading status without a login cookie.
                    # Try once before attempting /rest/login to reduce session churn
                    # and improve startup behavior when login is temporarily flaky.
                    try:
                        status_obj: dict[str, Any] | None = None
                        for candidate in _candidate_status_urls():
                            try:
                                status_obj = await _fetch_rest_status(
                                    None, status_url=candidate
                                )
                                if status_obj is not None:
                                    self._rest_status_path = URL(candidate).path
                                    break
                            except FileNotFoundError:
                                continue

                        if status_obj is not None:
                            data = parse_status_rest(status_obj)
                            _LOGGER.debug(
                                "REST parsed (no-login) host=%s probes=%s outlets=%s has_network=%s",
                                host,
                                len(cast(dict[str, Any], data.get("probes") or {})),
                                len(cast(list[Any], data.get("outlets") or [])),
                                bool(data.get("network")),
                            )
                            return self._apply_serial_cache(data)
                    except _RestStatusUnauthorized:
                        # Expected on controllers that require auth.
                        pass

                    max_attempts = 3
                    for attempt in range(1, max_attempts + 1):
                        _LOGGER.debug(
                            "REST update attempt %s/%s host=%s user=%s",
                            attempt,
                            max_attempts,
                            host,
                            (username or "admin"),
                        )

                        try:
                            login_candidates: list[str] = []
                            if username:
                                login_candidates.append(username)
                            if "admin" not in login_candidates:
                                login_candidates.append("admin")

                            sid_value: str | None = None
                            for login_user in login_candidates:
                                try:
                                    sid_value = await _login_rest(login_user=login_user)
                                    break
                                except _RestAuthRejected:
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
                                bool(sid_value)
                                or _session_has_connect_sid(session, base_url),
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
                                    # for this poll and fall back to legacy.
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

                                # Optional: fetch module config for richer MXM device metadata.
                                try:
                                    mconf_url = f"{base_url}/rest/config/mconf"
                                    _LOGGER.debug(
                                        "Trying REST mconf update: %s", mconf_url
                                    )
                                    async with async_timeout.timeout(timeout_seconds):
                                        async with session.get(
                                            mconf_url,
                                            headers=_cookie_headers(self._rest_sid),
                                        ) as resp:
                                            if resp.status == 404:
                                                raise FileNotFoundError
                                            if resp.status in (401, 403):
                                                raise PermissionError
                                            resp.raise_for_status()
                                            mconf_text = await resp.text()

                                    mconf_any: Any = (
                                        json.loads(mconf_text) if mconf_text else {}
                                    )
                                    if isinstance(mconf_any, dict):
                                        mxm_devices = _parse_mxm_devices_from_mconf(
                                            cast(dict[str, Any], mconf_any)
                                        )
                                        if mxm_devices:
                                            data["mxm_devices"] = mxm_devices
                                except (FileNotFoundError, PermissionError):
                                    pass
                                except (
                                    asyncio.TimeoutError,
                                    aiohttp.ClientError,
                                    json.JSONDecodeError,
                                ) as err:
                                    _LOGGER.debug("REST mconf fetch failed: %s", err)
                                except Exception as err:
                                    _LOGGER.debug(
                                        "Unexpected REST mconf error: %s", err
                                    )

                                return self._apply_serial_cache(data)

                            raise UpdateFailed(
                                "REST status payload was not a JSON object"
                            )

                        except _RestNotSupported:
                            raise
                        except _RestAuthRejected:
                            # REST rejected (credentials/user not accepted). Fall back to legacy
                            # for this poll, but keep trying REST on the next poll.
                            self._rest_sid = None
                            raise
                        except _RestRateLimited as err:
                            self._rest_sid = None
                            retry_after = err.retry_after_seconds
                            # Be conservative; if no header is provided, back off for 5 minutes.
                            self._disable_rest(
                                seconds=float(retry_after)
                                if retry_after is not None
                                else 300.0,
                                reason="rate_limited",
                            )
                            raise
                        except aiohttp.ClientResponseError as err:
                            if err.status and _is_transient_http_status(err.status):
                                _LOGGER.debug(
                                    "Transient REST HTTP error (status=%s): %s",
                                    err.status,
                                    err,
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

                    raise UpdateFailed("REST update failed after retries")

                except _RestRateLimited:
                    _LOGGER.debug("REST rate limited; falling back to legacy")
                    pass
                except _RestAuthRejected:
                    _LOGGER.debug("REST login rejected; falling back to legacy")
                    pass
                except _RestNotSupported:
                    _LOGGER.debug("REST not supported; falling back to legacy")
                    pass
                except UpdateFailed:
                    raise
                except (
                    asyncio.TimeoutError,
                    aiohttp.ClientError,
                    json.JSONDecodeError,
                ) as err:
                    _LOGGER.debug(
                        "REST update failed; falling back to status.xml: %s", err
                    )
                except Exception as err:
                    _LOGGER.debug(
                        "Unexpected REST error; falling back to status.xml: %s", err
                    )

            # End of REST block

        # Try legacy JSON first (richer metadata than status.xml).
        if True:
            json_url = f"{base_url}/cgi-bin/status.json"
            try:
                _LOGGER.debug("Trying legacy CGI JSON update: %s", json_url)
                async with async_timeout.timeout(timeout_seconds):
                    async with session.get(json_url, auth=auth) as resp:
                        if resp.status in (401, 403):
                            raise ConfigEntryAuthFailed(
                                "Invalid auth for Apex legacy status.json"
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
                    return self._apply_serial_cache(data)

            except FileNotFoundError:
                _LOGGER.debug("Legacy CGI status.json not found; trying status.xml")
            except ConfigEntryAuthFailed:
                _LOGGER.warning(
                    "Legacy CGI JSON authentication failed for host=%s user=%s",
                    host,
                    (username or "admin"),
                )
                raise
            except (
                asyncio.TimeoutError,
                aiohttp.ClientError,
                json.JSONDecodeError,
            ) as err:
                _LOGGER.debug(
                    "Legacy CGI JSON update failed; trying status.xml: %s", err
                )
            except Exception as err:
                _LOGGER.debug("Unexpected CGI JSON error; trying status.xml: %s", err)

        try:
            _LOGGER.debug("Trying legacy XML update: %s", url)
            async with async_timeout.timeout(timeout_seconds):
                async with session.get(url, auth=auth) as resp:
                    if resp.status in (401, 403):
                        raise ConfigEntryAuthFailed(
                            "Invalid auth for Apex legacy status.xml"
                        )
                    resp.raise_for_status()
                    body = await resp.text()

            data = parse_status_xml(body)
            meta = data.get("meta")
            if isinstance(meta, dict):
                cast(dict[str, Any], meta).setdefault("source", "xml")
            return self._apply_serial_cache(data)

        except ConfigEntryAuthFailed:
            _LOGGER.warning(
                "Legacy XML authentication failed for host=%s user=%s",
                host,
                (username or "admin"),
            )
            raise
        except (asyncio.TimeoutError, aiohttp.ClientError, ET.ParseError) as err:
            raise UpdateFailed(
                f"Error fetching/parsing Apex status.xml: {err}"
            ) from err
        except UpdateFailed:
            raise
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
