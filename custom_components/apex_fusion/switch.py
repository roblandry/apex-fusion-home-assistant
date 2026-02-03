"""Switch entities for Apex Fusion (Local).

This platform exposes Feed Mode switches (Feed A-D).

Control is REST-first:
- POST /rest/login -> connect.sid
- PUT  /rest/status/feed/<id>   (start feed)
- PUT  /rest/status/feed/0      (cancel feed)

With a legacy fallback:
- POST /cgi-bin/status.cgi with application/x-www-form-urlencoded
    - FeedCycle=Feed&FeedSel=<0-3|5>&noResponse=1
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, cast

import aiohttp
import async_timeout
from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
    DEFAULT_TIMEOUT_SECONDS,
    DOMAIN,
    LOGGER_NAME,
)
from .coordinator import ApexNeptuneDataUpdateCoordinator, build_base_url
from .sensor import build_device_info

_LOGGER = logging.getLogger(LOGGER_NAME)


@dataclass(frozen=True)
class _FeedRef:
    did: str
    name: str


_FEEDS: tuple[_FeedRef, ...] = (
    _FeedRef(did="1", name="Feed A"),
    _FeedRef(did="2", name="Feed B"),
    _FeedRef(did="3", name="Feed C"),
    _FeedRef(did="4", name="Feed D"),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: ApexNeptuneDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]

    entities: list[SwitchEntity] = [
        ApexFeedModeSwitch(hass, coordinator, entry, ref=ref) for ref in _FEEDS
    ]
    async_add_entities(entities)


def _to_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        t = value.strip()
        if t.isdigit():
            return int(t)
    return None


class ApexFeedModeSwitch(SwitchEntity):
    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: ApexNeptuneDataUpdateCoordinator,
        entry: ConfigEntry,
        *,
        ref: _FeedRef,
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

        self._attr_unique_id = f"{serial}_feed_{ref.did}".lower()
        self._attr_name = ref.name
        self._attr_icon = "mdi:shaker"

        self._attr_device_info = build_device_info(
            host=host,
            meta=meta,
            device_identifier=coordinator.device_identifier,
        )

        self._refresh_from_coordinator()

    def _refresh_from_coordinator(self) -> None:
        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )

        feed_any: Any = (self._coordinator.data or {}).get("feed")
        feed: dict[str, Any] = (
            cast(dict[str, Any], feed_any) if isinstance(feed_any, dict) else {}
        )

        active_id = _to_int(feed.get("name"))
        self._attr_is_on = active_id == _to_int(self._ref.did)

        attrs: dict[str, Any] = {}
        if feed:
            for k in ("name", "active", "active_raw"):
                if k in feed:
                    attrs[k] = feed.get(k)
        self._attr_extra_state_attributes = attrs

    async def async_turn_on(self, **_kwargs: Any) -> None:
        await self._async_set_feed(active=True)

    async def async_turn_off(self, **_kwargs: Any) -> None:
        await self._async_set_feed(active=False)

    async def _async_set_feed(self, *, active: bool) -> None:
        host = str(self._entry.data.get(CONF_HOST, ""))
        username = str(self._entry.data.get(CONF_USERNAME, "") or "admin")
        password = str(self._entry.data.get(CONF_PASSWORD, "") or "")

        if not password:
            raise HomeAssistantError(
                "Password is required to control feed modes via REST/legacy CGI"
            )

        base_url = build_base_url(host)
        session = async_get_clientsession(self.hass)
        timeout_seconds = DEFAULT_TIMEOUT_SECONDS

        def _rest_payload_and_path() -> tuple[str, dict[str, Any]]:
            if active:
                return (
                    f"/rest/status/feed/{self._ref.did}",
                    {
                        "active": 1,
                        "errorCode": 0,
                        "errorMessage": "",
                        "name": self._ref.did,
                    },
                )
            return (
                "/rest/status/feed/0",
                {"active": 92, "errorCode": 0, "errorMessage": "", "name": 0},
            )

        async def _legacy_post_status_cgi() -> None:
            # FeedSel mapping for legacy controllers:
            # A-D => 0-3, Cancel => 5
            feed_sel_map = {"1": "0", "2": "1", "3": "2", "4": "3"}
            feed_sel = "5"
            if active:
                feed_sel = feed_sel_map.get(self._ref.did, "5")

            data = f"FeedCycle=Feed&FeedSel={feed_sel}&noResponse=1"
            url = f"{base_url}/cgi-bin/status.cgi"
            _LOGGER.debug(
                "Legacy CGI feed control host=%s did=%s active=%s FeedSel=%s",
                host,
                self._ref.did,
                active,
                feed_sel,
            )

            async with async_timeout.timeout(timeout_seconds):
                async with session.post(
                    url,
                    data=data,
                    auth=aiohttp.BasicAuth(username, password),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                ) as resp:
                    if resp.status in (401, 403):
                        raise HomeAssistantError(
                            "Invalid auth for Apex legacy status.cgi feed control"
                        )
                    if resp.status == 404:
                        raise HomeAssistantError(
                            "Legacy feed control endpoint not found on controller"
                        )
                    resp.raise_for_status()
                    await resp.text()

        try:
            rest_path, rest_payload = _rest_payload_and_path()
            await self._coordinator.async_rest_put_json(
                path=rest_path,
                payload=rest_payload,
            )
        except FileNotFoundError:
            await _legacy_post_status_cgi()
        except HomeAssistantError as err:
            # If REST failed due to auth/rate-limit/transient issues, try legacy as a last resort.
            _LOGGER.debug("REST feed control failed; trying legacy: %s", err)
            await _legacy_post_status_cgi()

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
