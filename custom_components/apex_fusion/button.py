"""Buttons for Apex Fusion (Local).

This platform currently exposes Trident consumables controls.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, cast

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import CONF_HOST, CONF_PASSWORD, DOMAIN
from .coordinator import ApexNeptuneDataUpdateCoordinator, build_device_info


@dataclass(frozen=True)
class _TridentButtonRef:
    key: str
    name: str
    icon: str
    press_fn: Callable[[ApexNeptuneDataUpdateCoordinator], Any]


@dataclass(frozen=True)
class _ControllerButtonRef:
    key: str
    name: str
    icon: str
    press_fn: Callable[[ApexNeptuneDataUpdateCoordinator], Any]


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up Trident control buttons."""
    coordinator: ApexNeptuneDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]

    # Hide controls when password is not configured.
    if not str(entry.data.get(CONF_PASSWORD, "") or ""):
        return

    # Manual refresh for cached config (/rest/config). This helps when config
    # polling is slower than status polling.
    async_add_entities(
        [
            ApexControllerButton(
                coordinator,
                entry,
                ref=_ControllerButtonRef(
                    key="refresh_config_now",
                    name="Refresh Config Now",
                    icon="mdi:refresh",
                    press_fn=lambda c: c.async_refresh_config_now(),
                ),
            )
        ]
    )

    added = False

    def _add_trident_buttons() -> None:
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

        refs: list[_TridentButtonRef] = [
            _TridentButtonRef(
                key="trident_prime_reagent_a",
                name="Trident Prime Reagent A",
                icon="mdi:pump",
                press_fn=lambda c: c.async_trident_prime_channel(channel_index=0),
            ),
            _TridentButtonRef(
                key="trident_prime_reagent_b",
                name="Trident Prime Reagent B",
                icon="mdi:pump",
                press_fn=lambda c: c.async_trident_prime_channel(channel_index=1),
            ),
            _TridentButtonRef(
                key="trident_prime_reagent_c",
                name="Trident Prime Reagent C",
                icon="mdi:pump",
                press_fn=lambda c: c.async_trident_prime_channel(channel_index=2),
            ),
            _TridentButtonRef(
                key="trident_prime_sample",
                name="Trident Prime Sample",
                icon="mdi:pump",
                press_fn=lambda c: c.async_trident_prime_channel(channel_index=3),
            ),
            _TridentButtonRef(
                key="trident_reset_reagent_a",
                name="Trident Reset Reagent A",
                icon="mdi:flask-empty-plus-outline",
                press_fn=lambda c: c.async_trident_reset_reagent(reagent_index=0),
            ),
            _TridentButtonRef(
                key="trident_reset_reagent_b",
                name="Trident Reset Reagent B",
                icon="mdi:flask-empty-plus-outline",
                press_fn=lambda c: c.async_trident_reset_reagent(reagent_index=1),
            ),
            _TridentButtonRef(
                key="trident_reset_reagent_c",
                name="Trident Reset Reagent C",
                icon="mdi:flask-empty-plus-outline",
                press_fn=lambda c: c.async_trident_reset_reagent(reagent_index=2),
            ),
            _TridentButtonRef(
                key="trident_reset_waste",
                name="Trident Reset Waste",
                icon="mdi:trash-can-arrow-up",
                press_fn=lambda c: c.async_trident_reset_waste(),
            ),
        ]

        async_add_entities([ApexTridentButton(coordinator, entry, ref=r) for r in refs])
        added = True

    _add_trident_buttons()
    remove = coordinator.async_add_listener(_add_trident_buttons)
    entry.async_on_unload(remove)


class ApexTridentButton(ButtonEntity):
    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(
        self,
        coordinator: ApexNeptuneDataUpdateCoordinator,
        entry: ConfigEntry,
        *,
        ref: _TridentButtonRef,
    ) -> None:
        super().__init__()
        self._coordinator = coordinator
        self._entry = entry
        self._ref = ref
        self._unsub: Callable[[], None] | None = None

        host = str(entry.data.get(CONF_HOST, ""))
        meta_any: Any = (coordinator.data or {}).get("meta", {})
        meta = cast(dict[str, Any], meta_any) if isinstance(meta_any, dict) else {}
        serial = str(meta.get("serial") or host or "apex").replace(":", "_")

        self._attr_unique_id = f"{serial}_{ref.key}".lower()
        self._attr_name = ref.name
        self._attr_icon = ref.icon
        self._attr_device_info = build_device_info(
            host=host,
            meta=meta,
            device_identifier=coordinator.device_identifier,
        )

        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )

    async def async_press(self) -> None:
        try:
            await cast(Any, self._ref.press_fn)(self._coordinator)
        except HomeAssistantError:
            raise
        except Exception as err:
            raise HomeAssistantError(f"Error running {self._ref.name}: {err}") from err

    def _handle_coordinator_update(self) -> None:
        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
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


class ApexControllerButton(ButtonEntity):
    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(
        self,
        coordinator: ApexNeptuneDataUpdateCoordinator,
        entry: ConfigEntry,
        *,
        ref: _ControllerButtonRef,
    ) -> None:
        super().__init__()
        self._coordinator = coordinator
        self._entry = entry
        self._ref = ref
        self._unsub: Callable[[], None] | None = None

        host = str(entry.data.get(CONF_HOST, ""))
        meta_any: Any = (coordinator.data or {}).get("meta", {})
        meta = cast(dict[str, Any], meta_any) if isinstance(meta_any, dict) else {}
        serial = str(meta.get("serial") or host or "apex").replace(":", "_")

        self._attr_unique_id = f"{serial}_{ref.key}".lower()
        self._attr_name = ref.name
        self._attr_icon = ref.icon
        self._attr_device_info = build_device_info(
            host=host,
            meta=meta,
            device_identifier=coordinator.device_identifier,
        )

        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )

    async def async_press(self) -> None:
        try:
            await cast(Any, self._ref.press_fn)(self._coordinator)
        except HomeAssistantError:
            raise
        except Exception as err:
            raise HomeAssistantError(f"Error running {self._ref.name}: {err}") from err

    def _handle_coordinator_update(self) -> None:
        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
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
