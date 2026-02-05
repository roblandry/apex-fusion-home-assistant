"""Number entities for Apex Fusion (Local).

This platform currently exposes Trident waste container size.
"""

from __future__ import annotations

from typing import Any, Callable, cast

from homeassistant.components.number import NumberEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory, UnitOfVolume
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import CONF_HOST, CONF_PASSWORD, DOMAIN
from .coordinator import ApexNeptuneDataUpdateCoordinator, build_device_info


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: ApexNeptuneDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]

    # Hide controls when password is not configured.
    if not str(entry.data.get(CONF_PASSWORD, "") or ""):
        return

    added = False

    def _add_trident_numbers() -> None:
        nonlocal added
        if added:
            return

        data = coordinator.data or {}
        trident_any: Any = data.get("trident")
        if not isinstance(trident_any, dict):
            return
        trident = cast(dict[str, Any], trident_any)
        if not trident.get("present"):
            return
        if not isinstance(trident.get("abaddr"), int):
            return

        async_add_entities([ApexTridentWasteSizeNumber(coordinator, entry)])
        added = True

    _add_trident_numbers()
    remove = coordinator.async_add_listener(_add_trident_numbers)
    entry.async_on_unload(remove)


class ApexTridentWasteSizeNumber(NumberEntity):
    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_entity_category = EntityCategory.CONFIG
    _attr_icon = "mdi:cup-water"
    _attr_native_unit_of_measurement = UnitOfVolume.MILLILITERS

    # Conservative bounds; can be widened if needed.
    _attr_native_min_value = 50.0
    _attr_native_max_value = 2000.0
    _attr_native_step = 10.0

    def __init__(
        self, coordinator: ApexNeptuneDataUpdateCoordinator, entry: ConfigEntry
    ) -> None:
        super().__init__()
        self._coordinator = coordinator
        self._entry = entry
        self._unsub: Callable[[], None] | None = None

        host = str(entry.data.get(CONF_HOST, ""))
        meta_any: Any = (coordinator.data or {}).get("meta", {})
        meta = cast(dict[str, Any], meta_any) if isinstance(meta_any, dict) else {}
        serial = str(meta.get("serial") or host or "apex").replace(":", "_")

        self._attr_unique_id = f"{serial}_trident_waste_size_ml".lower()
        self._attr_name = "Trident Waste Container Size"
        self._attr_device_info = build_device_info(
            host=host,
            meta=meta,
            device_identifier=coordinator.device_identifier,
        )

        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )

        self._refresh_from_coordinator()

    def _refresh_from_coordinator(self) -> None:
        data = self._coordinator.data or {}
        trident_any: Any = data.get("trident")
        if not isinstance(trident_any, dict):
            self._attr_native_value = None
            return
        value: Any = cast(dict[str, Any], trident_any).get("waste_size_ml")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            self._attr_native_value = float(value)
        else:
            self._attr_native_value = None

    async def async_set_native_value(self, value: float) -> None:
        try:
            await self._coordinator.async_trident_set_waste_size_ml(
                size_ml=float(value)
            )
        except HomeAssistantError:
            raise
        except Exception as err:
            raise HomeAssistantError(
                f"Error setting Trident waste size: {err}"
            ) from err

    def _handle_coordinator_update(self) -> None:
        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
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
