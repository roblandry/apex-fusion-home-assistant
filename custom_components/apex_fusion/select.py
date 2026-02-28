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

import logging
from typing import Any, Callable, cast

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .apex_fusion import ApexDiscovery, ApexFusionContext, OutletMode, OutletRef
from .const import (
    CONF_PASSWORD,
    DOMAIN,
    ICON_ALARM,
    ICON_LIGHTBULB,
    ICON_PUMP,
    ICON_RADIATOR,
    ICON_TOGGLE_SWITCH_OUTLINE,
    LOGGER_NAME,
)
from .coordinator import (
    ApexNeptuneDataUpdateCoordinator,
    build_aquabus_child_device_info_from_data,
    build_device_info,
    module_abaddr_from_input_did,
    normalize_module_hwtype_from_outlet_type,
    unambiguous_module_abaddr_from_config,
)


def icon_for_outlet_select(outlet_name: str, outlet_type: str | None) -> str | None:
    """Choose an icon for an outlet mode SelectEntity.

    Args:
        outlet_name: Outlet name.
        outlet_type: Outlet type token.

    Returns:
        A Material Design Icon string.
    """

    name = (outlet_name or "").strip().lower()
    t = (outlet_type or "").strip().upper()

    if any(token in name for token in ("alarm", "warn")):
        return ICON_ALARM
    if "PUMP" in t:
        return ICON_PUMP
    if "LIGHT" in t:
        return ICON_LIGHTBULB
    if "HEATER" in t:
        return ICON_RADIATOR
    return ICON_TOGGLE_SWITCH_OUTLINE


_LOGGER = logging.getLogger(LOGGER_NAME)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: ApexNeptuneDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]

    added_dids: set[str] = set()

    def _add_outlet_selects() -> None:
        data = coordinator.data or {}
        refs, seen_dids = ApexDiscovery.new_outlet_select_refs(
            data,
            already_added_dids=added_dids,
        )

        new_entities: list[SelectEntity] = [
            ApexOutletModeSelect(hass, coordinator, entry, ref=ref) for ref in refs
        ]
        if new_entities:
            async_add_entities(new_entities)

        added_dids.update(seen_dids)

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
        ref: OutletRef,
    ) -> None:
        super().__init__()
        self.hass = hass
        self._coordinator = coordinator
        self._entry = entry
        self._ref = ref
        self._unsub: Callable[[], None] | None = None

        ctx = ApexFusionContext.from_entry_and_coordinator(entry, coordinator)

        self._attr_unique_id = (
            f"{ctx.serial_for_ids}_outlet_mode_{ref.dedupe_key}".lower()
        )
        self._attr_name = ref.name

        # Prefer grouping under the backing Aquabus module device when the
        # mapping is unambiguous (e.g., a single EB832 on the bus).
        outlet = self._find_outlet()
        outlet_type = cast(str | None, outlet.get("type"))
        module_hwtype_hint = (
            str(outlet.get("module_hwtype")).strip()
            if isinstance(outlet.get("module_hwtype"), str)
            else None
        )
        if not module_hwtype_hint:
            module_hwtype_hint = normalize_module_hwtype_from_outlet_type(outlet_type)

        module_abaddr_any: Any = outlet.get("module_abaddr")
        module_abaddr = (
            module_abaddr_any if isinstance(module_abaddr_any, int) else None
        )
        if module_abaddr is None:
            module_abaddr = module_abaddr_from_input_did(ref.did)

        # Last resort: config-based mapping when the controller doesn't
        # provide a per-outlet module address.
        if module_abaddr is None and module_hwtype_hint:
            module_abaddr = unambiguous_module_abaddr_from_config(
                coordinator.data or {}, module_hwtype=module_hwtype_hint
            )

        tank_slug = ctx.tank_slug_with_entry_title(entry.title)
        did_slug = str(ref.dedupe_key or "").strip().lower() or "outlet"
        if isinstance(module_abaddr, int) and module_hwtype_hint:
            self._attr_suggested_object_id = ctx.object_id(
                tank_slug,
                ctx.module_token(module_hwtype_hint),
                module_abaddr,
                did_slug,
                "mode",
            )
        else:
            self._attr_suggested_object_id = ctx.object_id(
                tank_slug, "apex", did_slug, "mode"
            )

        module_device_info = (
            build_aquabus_child_device_info_from_data(
                host=ctx.host,
                controller_meta=ctx.meta,
                controller_device_identifier=ctx.controller_device_identifier,
                data=coordinator.data or {},
                module_abaddr=module_abaddr,
                module_hwtype_hint=module_hwtype_hint,
                tank_slug=tank_slug,
            )
            if isinstance(module_abaddr, int)
            else None
        )

        self._attr_device_info = module_device_info or build_device_info(
            host=ctx.host,
            meta=ctx.meta,
            device_identifier=ctx.controller_device_identifier,
            tank_slug=tank_slug,
        )

        self._attr_options = list(OutletMode.OPTIONS)
        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
        self._attr_current_option = None
        self._attr_icon = icon_for_outlet_select(ref.name, outlet_type)
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
            "mode": OutletMode.mode_from_option(self._attr_current_option)
            if self._attr_current_option
            else None,
            "effective_state": OutletMode.effective_state_from_raw_state(raw_state),
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
        self._attr_current_option = OutletMode.option_from_raw_state(raw_state)
        self._attr_extra_state_attributes = self._read_extra_attrs()
        outlet = self._find_outlet()
        self._attr_icon = icon_for_outlet_select(
            self._ref.name, cast(str | None, outlet.get("type"))
        )

    async def async_select_option(self, option: str) -> None:
        mode = OutletMode.mode_from_option(option)
        await self._async_set_mode(mode)

    async def _async_set_mode(self, mode: str) -> None:
        password = str(self._entry.data.get(CONF_PASSWORD, "") or "")
        if not password:
            raise HomeAssistantError("Password is required to control outlets via REST")

        desired = (mode or "").strip().upper()
        if desired not in {"AUTO", "ON", "OFF"}:
            raise HomeAssistantError(f"Invalid outlet mode: {mode}")

        payload = {
            "did": self._ref.did,
            "status": [desired, "", "OK", ""],
            "type": "outlet",
        }

        try:
            await self._coordinator.async_rest_put_json(
                path=f"/rest/status/outputs/{self._ref.did}",
                payload=payload,
            )
        except FileNotFoundError as err:
            raise HomeAssistantError("REST API not supported on this device") from err

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
