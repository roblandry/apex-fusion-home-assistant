"""Select entities for Apex Fusion (Local).

This platform exposes a single 3-way SelectEntity per outlet/output:
- Off
- Auto
- On

Attributes:
- state_code: Controller-reported state string (AON/AOF/TBL/ON/OFF/...)
- mode: Controller command-mode we will send (AUTO/ON/OFF) inferred from selection
- effective_state: "On"/"Off" based on whether the outlet is energized

Control is via the local REST API:
- POST /rest/login -> connect.sid
- PUT  /rest/status/outputs/<did>
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any, Callable, cast

import aiohttp
import async_timeout
from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from yarl import URL

from .const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
    DEFAULT_TIMEOUT_SECONDS,
    DOMAIN,
    LOGGER_NAME,
)
from .coordinator import ApexNeptuneDataUpdateCoordinator, build_base_url
from .sensor import build_device_info, friendly_outlet_name

_LOGGER = logging.getLogger(LOGGER_NAME)

_OPTIONS: list[str] = ["Off", "Auto", "On"]


@dataclass(frozen=True)
class _OutletRef:
    did: str
    name: str


def _is_energized_state(raw_state: str) -> bool:
    return (raw_state or "").strip().upper() in {"AON", "ON", "TBL"}


def _is_selectable_outlet(outlet: dict[str, Any]) -> bool:
    raw_state = str(outlet.get("state") or "").strip().upper()
    return raw_state in {"AON", "AOF", "TBL", "ON", "OFF"}


def _option_from_raw_state(raw_state: str) -> str | None:
    t = (raw_state or "").strip().upper()
    if t in {"ON"}:
        return "On"
    if t in {"OFF"}:
        return "Off"
    if t in {"AON", "AOF", "TBL"}:
        return "Auto"
    return None


def _effective_state_from_raw_state(raw_state: str) -> str | None:
    t = (raw_state or "").strip().upper()
    if not t:
        return None
    return "On" if _is_energized_state(t) else "Off"


def _mode_from_option(option: str) -> str:
    t = (option or "").strip().lower()
    if t == "auto":
        return "AUTO"
    if t == "on":
        return "ON"
    if t == "off":
        return "OFF"
    raise HomeAssistantError(f"Invalid option: {option}")


def _icon_for_outlet_select(outlet_name: str, outlet_type: str | None) -> str | None:
    """Return an icon for a selectable output.

    These SelectEntities control an output mode (Off/Auto/On). Avoid outlet/power-socket
    icons so they don't get confused with EB (Energy Bar) outlet entities.
    """

    name = (outlet_name or "").strip().lower()
    t = (outlet_type or "").strip().upper()

    if any(token in name for token in ("alarm", "warn")):
        return "mdi:alarm"
    if "PUMP" in t:
        return "mdi:pump"
    if "LIGHT" in t:
        return "mdi:lightbulb"
    if "HEATER" in t:
        return "mdi:radiator"
    return "mdi:toggle-switch-outline"


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: ApexNeptuneDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]

    added_dids: set[str] = set()

    def _add_outlet_selects() -> None:
        data = coordinator.data or {}
        outlets_any = data.get("outlets", [])
        new_entities: list[SelectEntity] = []

        if isinstance(outlets_any, list):
            for outlet_any in cast(list[Any], outlets_any):
                if not isinstance(outlet_any, dict):
                    continue
                outlet = cast(dict[str, Any], outlet_any)
                did_any = outlet.get("device_id")
                did = did_any if isinstance(did_any, str) else None
                if not did or did in added_dids:
                    continue
                if not _is_selectable_outlet(outlet):
                    continue

                outlet_type_any: Any = outlet.get("type")
                outlet_type = (
                    outlet_type_any if isinstance(outlet_type_any, str) else None
                )

                outlet_name = friendly_outlet_name(
                    outlet_name=str(outlet.get("name") or did),
                    outlet_type=outlet_type,
                )

                new_entities.append(
                    ApexOutletModeSelect(
                        hass,
                        coordinator,
                        entry,
                        ref=_OutletRef(did=did, name=outlet_name),
                    )
                )
                added_dids.add(did)

        if new_entities:
            async_add_entities(new_entities)

    _add_outlet_selects()
    remove = coordinator.async_add_listener(_add_outlet_selects)
    entry.async_on_unload(remove)


class ApexOutletModeSelect(SelectEntity):
    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: ApexNeptuneDataUpdateCoordinator,
        entry: ConfigEntry,
        *,
        ref: _OutletRef,
    ) -> None:
        super().__init__()
        self.hass = hass
        self._coordinator = coordinator
        self._entry = entry
        self._ref = ref
        self._unsub: Callable[[], None] | None = None

        host = str(entry.data.get(CONF_HOST, ""))
        meta = cast(dict[str, Any], (coordinator.data or {}).get("meta", {}))
        serial = str(meta.get("serial") or host or "apex").replace(":", "_")

        self._attr_unique_id = f"{serial}_outlet_mode_{ref.did}".lower()
        self._attr_name = ref.name

        self._attr_device_info = build_device_info(
            host=host,
            meta=meta,
            device_identifier=coordinator.device_identifier,
        )

        self._attr_options = list(_OPTIONS)
        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
        self._attr_current_option = None
        outlet = self._find_outlet()
        self._attr_icon = _icon_for_outlet_select(
            ref.name, cast(str | None, outlet.get("type"))
        )
        self._refresh_from_coordinator()

    def _find_outlet(self) -> dict[str, Any]:
        data = self._coordinator.data or {}
        outlets_any = data.get("outlets", [])
        if not isinstance(outlets_any, list):
            return {}
        for outlet_any in cast(list[Any], outlets_any):
            if not isinstance(outlet_any, dict):
                continue
            outlet = cast(dict[str, Any], outlet_any)
            if str(outlet.get("device_id") or "") == self._ref.did:
                return outlet
        return {}

    def _read_raw_state(self) -> str:
        outlet = self._find_outlet()
        return str(outlet.get("state") or "").strip().upper()

    def _read_extra_attrs(self) -> dict[str, Any]:
        outlet = self._find_outlet()
        raw_state = self._read_raw_state()

        attrs: dict[str, Any] = {
            "state_code": raw_state or None,
            "mode": _mode_from_option(self._attr_current_option)
            if self._attr_current_option
            else None,
            "effective_state": _effective_state_from_raw_state(raw_state),
        }

        # Preserve debug visibility from the previous raw-state sensor.
        for key in ("output_id", "type", "gid", "status"):
            if key in outlet:
                attrs[key] = outlet.get(key)

        # Serial outputs often include a percentage in the status list, e.g.
        # ["AON", "100", "OK"]. Expose a derived attribute for UI/automation.
        status_any: Any = outlet.get("status")
        if isinstance(status_any, list):
            for item_any in cast(list[Any], status_any):
                if item_any is None:
                    continue
                text = str(item_any).strip()
                if not text:
                    continue
                if text.endswith("%"):
                    text = text[:-1].strip()
                if not text.isdigit():
                    continue
                percent = int(text)
                if 0 <= percent <= 100:
                    attrs["percent"] = percent
                    break

        name_any: Any = outlet.get("name")
        outlet_name = str(name_any).strip() if name_any is not None else ""
        mxm_any: Any = (self._coordinator.data or {}).get("mxm_devices")
        if outlet_name and isinstance(mxm_any, dict):
            mxm_devices = cast(dict[str, Any], mxm_any)
            dev_any: Any = mxm_devices.get(outlet_name)
            if isinstance(dev_any, dict):
                dev = cast(dict[str, Any], dev_any)
                attrs["mxm_rev"] = dev.get("rev")
                attrs["mxm_serial"] = dev.get("serial")
                attrs["mxm_status"] = dev.get("status")

        return attrs

    def _refresh_from_coordinator(self) -> None:
        raw_state = self._read_raw_state()
        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
        self._attr_current_option = _option_from_raw_state(raw_state)
        self._attr_extra_state_attributes = self._read_extra_attrs()
        outlet = self._find_outlet()
        self._attr_icon = _icon_for_outlet_select(
            self._ref.name, cast(str | None, outlet.get("type"))
        )

    async def async_select_option(self, option: str) -> None:
        mode = _mode_from_option(option)
        await self._async_set_mode(mode)

    async def _async_set_mode(self, mode: str) -> None:
        host = str(self._entry.data.get(CONF_HOST, ""))
        username = str(self._entry.data.get(CONF_USERNAME, "") or "admin")
        password = str(self._entry.data.get(CONF_PASSWORD, "") or "")

        if not password:
            raise HomeAssistantError("Password is required to control outlets via REST")

        base_url = build_base_url(host)
        session = async_get_clientsession(self.hass)
        timeout_seconds = DEFAULT_TIMEOUT_SECONDS

        desired = (mode or "").strip().upper()
        if desired not in {"AUTO", "ON", "OFF"}:
            raise HomeAssistantError(f"Invalid outlet mode: {mode}")

        sid: str | None = None
        sid_morsel = session.cookie_jar.filter_cookies(URL(base_url)).get("connect.sid")
        if sid_morsel is not None and sid_morsel.value:
            sid = sid_morsel.value

        def _retry_after_seconds(headers: Any) -> float | None:
            try:
                value = headers.get("Retry-After")
                if value is None:
                    return None
                t = str(value).strip()
                if not t:
                    return None
                return float(int(t))
            except Exception:
                return None

        def _note_rate_limited(*, seconds: float) -> None:
            try:
                disable = getattr(self._coordinator, "_disable_rest", None)
                if callable(disable):
                    disable(seconds=seconds, reason="rate_limited_control")
            except Exception:
                pass

        try:
            if not sid:
                login_candidates: list[str] = []
                if username:
                    login_candidates.append(username)
                if "admin" not in login_candidates:
                    login_candidates.append("admin")

                login_text = ""
                for login_user in login_candidates:
                    async with async_timeout.timeout(timeout_seconds):
                        async with session.post(
                            f"{base_url}/rest/login",
                            json={
                                "login": login_user,
                                "password": password,
                                "remember_me": False,
                            },
                            headers={
                                "Accept": "*/*",
                                "Content-Type": "application/json",
                            },
                        ) as resp:
                            _LOGGER.debug(
                                "REST login for control host=%s HTTP %s user=%s",
                                host,
                                resp.status,
                                login_user,
                            )
                            if resp.status == 404:
                                raise HomeAssistantError(
                                    "REST API not supported on this device"
                                )
                            if resp.status in (401, 403):
                                continue
                            if resp.status == 429:
                                retry_after = _retry_after_seconds(resp.headers)
                                backoff = (
                                    float(retry_after)
                                    if retry_after is not None
                                    else 300.0
                                )
                                _note_rate_limited(seconds=backoff)
                                raise HomeAssistantError(
                                    f"Controller rate limited REST login; retry after ~{int(backoff)}s"
                                )
                            resp.raise_for_status()
                            login_text = await resp.text()
                            break

                login_any: Any = json.loads(login_text) if login_text else {}
                if isinstance(login_any, dict):
                    sid_any: Any = cast(dict[str, Any], login_any).get("connect.sid")
                    if isinstance(sid_any, str) and sid_any:
                        sid = sid_any
        except (asyncio.TimeoutError, aiohttp.ClientError, json.JSONDecodeError) as err:
            raise HomeAssistantError(
                f"Error logging into Apex REST API: {err}"
            ) from err

        headers: dict[str, str] = {"Accept": "*/*"}
        if sid:
            headers["Cookie"] = f"connect.sid={sid}"

        payload = {
            "did": self._ref.did,
            "status": [desired, "", "OK", ""],
            "type": "outlet",
        }

        _LOGGER.debug(
            "Setting outlet mode host=%s did=%s mode=%s", host, self._ref.did, desired
        )

        try:
            async with async_timeout.timeout(timeout_seconds):
                async with session.put(
                    f"{base_url}/rest/status/outputs/{self._ref.did}",
                    json=payload,
                    headers=headers,
                ) as resp:
                    _LOGGER.debug("REST output PUT host=%s HTTP %s", host, resp.status)
                    if resp.status in (401, 403):
                        raise HomeAssistantError("Not authorized to control output")
                    if resp.status == 429:
                        retry_after = _retry_after_seconds(resp.headers)
                        backoff = (
                            float(retry_after) if retry_after is not None else 300.0
                        )
                        _note_rate_limited(seconds=backoff)
                        raise HomeAssistantError(
                            f"Controller rate limited REST control; retry after ~{int(backoff)}s"
                        )
                    resp.raise_for_status()
                    await resp.text()
        except (asyncio.TimeoutError, aiohttp.ClientError) as err:
            raise HomeAssistantError(f"Error setting output mode: {err}") from err

        # Ensure state updates promptly.
        await self._coordinator.async_request_refresh()

    def _handle_coordinator_update(self) -> None:
        self._refresh_from_coordinator()
        self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        self._unsub = self._coordinator.async_add_listener(
            self._handle_coordinator_update
        )
        self._handle_coordinator_update()

    async def async_will_remove_from_hass(self) -> None:
        if self._unsub is not None:
            self._unsub()
            self._unsub = None
