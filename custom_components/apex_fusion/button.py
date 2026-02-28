"""Buttons for Apex Fusion (Local).

This platform exposes controller/module refresh and Trident consumables controls.
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

from .apex_fusion import (
    ApexFusionContext,
    best_module_candidates_by_abaddr,
    hwtype_from_module,
)
from .const import (
    CONF_PASSWORD,
    DOMAIN,
    ICON_CUP_OUTLINE,
    ICON_FLASK_EMPTY_PLUS_OUTLINE,
    ICON_PUMP,
    ICON_REFRESH,
)
from .coordinator import (
    ApexNeptuneDataUpdateCoordinator,
    build_aquabus_child_device_info_from_data,
    build_device_info,
    build_trident_device_info,
)


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
    """Set up controller/module buttons.

    Args:
        hass: Home Assistant instance.
        entry: Config entry.
        async_add_entities: Callback used to register entities.

    Returns:
        None.
    """
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
                    icon=ICON_REFRESH,
                    press_fn=lambda c: c.async_refresh_config_now(),
                ),
            )
        ]
    )

    added_module_refresh: set[int] = set()

    def _add_module_refresh_buttons() -> None:
        data = coordinator.data or {}
        ctx = ApexFusionContext.from_entry_and_coordinator(entry, coordinator)

        new: list[ButtonEntity] = []

        candidates_by_abaddr = best_module_candidates_by_abaddr(
            data, include_trident=True
        )

        for abaddr, module in candidates_by_abaddr.items():
            abaddr_any: Any = module.get("abaddr")
            if not isinstance(abaddr_any, int):
                continue

            present_any: Any = module.get("present")
            present = bool(present_any) if isinstance(present_any, bool) else True
            if not present:
                continue

            hwtype = hwtype_from_module(module)

            if abaddr in added_module_refresh:
                continue

            module_name_hint: str | None = None
            name_any: Any = module.get("name")
            if isinstance(name_any, str) and name_any.strip():
                module_name_hint = name_any.strip()

            # Only add when we can resolve module device info without guessing.
            di = build_aquabus_child_device_info_from_data(
                host=ctx.host,
                controller_meta=ctx.meta,
                controller_device_identifier=coordinator.device_identifier,
                data=data,
                module_abaddr=abaddr_any,
                module_hwtype_hint=hwtype,
                module_name_hint=module_name_hint,
            )
            if not di:
                continue

            hwtype_final = str(di.get("model") or hwtype or "").strip().upper() or None

            # Only mark as added once we successfully create the module-attached button.
            added_module_refresh.add(abaddr)

            new.append(
                ApexModuleRefreshConfigButton(
                    coordinator,
                    entry,
                    module_abaddr=abaddr_any,
                    module_hwtype=hwtype_final,
                )
            )

        if new:
            async_add_entities(new)

    _add_module_refresh_buttons()
    entry.async_on_unload(coordinator.async_add_listener(_add_module_refresh_buttons))

    added_trident_abaddrs: set[int] = set()

    def _add_trident_buttons() -> None:
        data = coordinator.data or {}

        primary_abaddr: int | None = None
        primary_trident_any: Any = data.get("trident")
        if isinstance(primary_trident_any, dict):
            primary_abaddr_any: Any = cast(dict[str, Any], primary_trident_any).get(
                "abaddr"
            )
            if isinstance(primary_abaddr_any, int):
                primary_abaddr = primary_abaddr_any

        # Prefer multi-trident list; fall back to legacy single-trident dict.
        tridents_any: Any = data.get("tridents")
        if isinstance(tridents_any, list):
            from_tridents_list = True
            candidates: list[Any] = cast(list[Any], tridents_any)
        elif isinstance(primary_trident_any, dict):
            from_tridents_list = False
            candidates = [primary_trident_any]
        else:
            from_tridents_list = False
            candidates = []

        new: list[ButtonEntity] = []

        for item_any in candidates:
            if not isinstance(item_any, dict):
                continue
            trident = cast(dict[str, Any], item_any)

            hwtype_any: Any = trident.get("hwtype")
            hwtype = (
                str(hwtype_any).strip().upper()
                if isinstance(hwtype_any, str) and hwtype_any.strip()
                else None
            )
            is_tnp = hwtype == "TNP"

            # Some controllers report Trident NP with present=false even though it exists.
            # Keep legacy behavior for single-module non-NP setups, but do not gate on
            # present when we have a tridents list (multi-module) or when the module is NP.
            if (
                (not from_tridents_list)
                and (not is_tnp)
                and (not trident.get("present"))
            ):
                continue
            abaddr_any: Any = trident.get("abaddr")
            if not isinstance(abaddr_any, int):
                continue
            if abaddr_any in added_trident_abaddrs:
                continue

            # Preserve legacy keys/unique_ids for the primary module.
            key_prefix = (
                "trident"
                if abaddr_any == primary_abaddr
                else f"trident_addr{abaddr_any}"
            )

            if is_tnp:
                reagent_labels = ("1", "2", "3")
            else:
                reagent_labels = ("A", "B", "C")

            refs: list[_TridentButtonRef] = [
                _TridentButtonRef(
                    key=f"{key_prefix}_prime_reagent_{reagent_labels[0].lower()}",
                    name=f"Prime Reagent {reagent_labels[0]}",
                    icon=ICON_PUMP,
                    press_fn=lambda c, abaddr=abaddr_any: c.async_trident_prime_channel(
                        channel_index=0, trident_abaddr=abaddr
                    ),
                ),
                _TridentButtonRef(
                    key=f"{key_prefix}_prime_reagent_{reagent_labels[1].lower()}",
                    name=f"Prime Reagent {reagent_labels[1]}",
                    icon=ICON_PUMP,
                    press_fn=lambda c, abaddr=abaddr_any: c.async_trident_prime_channel(
                        channel_index=1, trident_abaddr=abaddr
                    ),
                ),
                _TridentButtonRef(
                    key=f"{key_prefix}_prime_reagent_{reagent_labels[2].lower()}",
                    name=f"Prime Reagent {reagent_labels[2]}",
                    icon=ICON_PUMP,
                    press_fn=lambda c, abaddr=abaddr_any: c.async_trident_prime_channel(
                        channel_index=2, trident_abaddr=abaddr
                    ),
                ),
                _TridentButtonRef(
                    key=f"{key_prefix}_prime_sample",
                    name="Prime Sample",
                    icon=ICON_PUMP,
                    press_fn=lambda c, abaddr=abaddr_any: c.async_trident_prime_channel(
                        channel_index=3, trident_abaddr=abaddr
                    ),
                ),
                _TridentButtonRef(
                    key=f"{key_prefix}_reset_reagent_{reagent_labels[0].lower()}",
                    name=f"Reset Reagent {reagent_labels[0]}",
                    icon=ICON_FLASK_EMPTY_PLUS_OUTLINE,
                    press_fn=lambda c, abaddr=abaddr_any: c.async_trident_reset_reagent(
                        reagent_index=0, trident_abaddr=abaddr
                    ),
                ),
                _TridentButtonRef(
                    key=f"{key_prefix}_reset_reagent_{reagent_labels[1].lower()}",
                    name=f"Reset Reagent {reagent_labels[1]}",
                    icon=ICON_FLASK_EMPTY_PLUS_OUTLINE,
                    press_fn=lambda c, abaddr=abaddr_any: c.async_trident_reset_reagent(
                        reagent_index=1, trident_abaddr=abaddr
                    ),
                ),
                _TridentButtonRef(
                    key=f"{key_prefix}_reset_reagent_{reagent_labels[2].lower()}",
                    name=f"Reset Reagent {reagent_labels[2]}",
                    icon=ICON_FLASK_EMPTY_PLUS_OUTLINE,
                    press_fn=lambda c, abaddr=abaddr_any: c.async_trident_reset_reagent(
                        reagent_index=2, trident_abaddr=abaddr
                    ),
                ),
                _TridentButtonRef(
                    key=f"{key_prefix}_reset_waste",
                    name="Reset Waste",
                    icon=ICON_CUP_OUTLINE,
                    press_fn=lambda c, abaddr=abaddr_any: c.async_trident_reset_waste(
                        trident_abaddr=abaddr
                    ),
                ),
            ]

            new.extend(
                [
                    ApexTridentButton(coordinator, entry, ref=r, trident=trident)
                    for r in refs
                ]
            )
            added_trident_abaddrs.add(abaddr_any)

        if new:
            async_add_entities(new)

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
        trident: dict[str, Any] | None = None,
    ) -> None:
        super().__init__()
        self._coordinator = coordinator
        self._entry = entry
        self._ref = ref
        self._unsub: Callable[[], None] | None = None

        ctx = ApexFusionContext.from_entry_and_coordinator(entry, coordinator)

        self._attr_unique_id = f"{ctx.serial_for_ids}_{ref.key}".lower()
        self._attr_name = ref.name
        self._attr_icon = ref.icon
        trident_any: Any = (
            trident
            if isinstance(trident, dict)
            else (coordinator.data or {}).get("trident")
        )
        trident_abaddr_any: Any = (
            cast(dict[str, Any], trident_any).get("abaddr")
            if isinstance(trident_any, dict)
            else None
        )
        if isinstance(trident_abaddr_any, int):
            trident_hwtype_any: Any = (
                cast(dict[str, Any], trident_any).get("hwtype")
                if isinstance(trident_any, dict)
                else None
            )
            trident_hwrev_any: Any = (
                cast(dict[str, Any], trident_any).get("hwrev")
                if isinstance(trident_any, dict)
                else None
            )
            trident_swrev_any: Any = (
                cast(dict[str, Any], trident_any).get("swrev")
                if isinstance(trident_any, dict)
                else None
            )
            trident_serial_any: Any = (
                cast(dict[str, Any], trident_any).get("serial")
                if isinstance(trident_any, dict)
                else None
            )
            self._attr_device_info = build_trident_device_info(
                host=ctx.host,
                meta=ctx.meta,
                controller_device_identifier=coordinator.device_identifier,
                trident_abaddr=trident_abaddr_any,
                trident_hwtype=(
                    str(trident_hwtype_any).strip().upper()
                    if isinstance(trident_hwtype_any, str)
                    and trident_hwtype_any.strip()
                    else None
                ),
                trident_hwrev=(
                    str(trident_hwrev_any).strip() or None
                    if trident_hwrev_any is not None
                    else None
                ),
                trident_swrev=(
                    str(trident_swrev_any).strip() or None
                    if trident_swrev_any is not None
                    else None
                ),
                trident_serial=(
                    str(trident_serial_any).strip() or None
                    if trident_serial_any is not None
                    else None
                ),
            )

            prefix_with_addr = f"trident_addr{trident_abaddr_any}_"
            if str(ref.key).startswith(prefix_with_addr):
                suffix = str(ref.key).removeprefix(prefix_with_addr)
            else:
                suffix = str(ref.key).removeprefix("trident_")
            self._attr_suggested_object_id = (
                f"{ctx.tank_slug}_trident_addr{trident_abaddr_any}_{suffix}"
            )
        else:
            self._attr_device_info = build_device_info(
                host=ctx.host,
                meta=ctx.meta,
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

        ctx = ApexFusionContext.from_entry_and_coordinator(entry, coordinator)

        self._attr_unique_id = f"{ctx.serial_for_ids}_{ref.key}".lower()
        self._attr_name = ref.name
        self._attr_icon = ref.icon
        self._attr_device_info = build_device_info(
            host=ctx.host,
            meta=ctx.meta,
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


class ApexModuleRefreshConfigButton(ButtonEntity):
    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(
        self,
        coordinator: ApexNeptuneDataUpdateCoordinator,
        entry: ConfigEntry,
        *,
        module_abaddr: int,
        module_hwtype: str | None,
    ) -> None:
        super().__init__()
        self._coordinator = coordinator
        self._entry = entry
        self._unsub: Callable[[], None] | None = None
        self._module_abaddr = module_abaddr
        self._module_hwtype = (module_hwtype or "").strip().upper() or None

        ctx = ApexFusionContext.from_entry_and_coordinator(entry, coordinator)

        self._attr_unique_id = f"{ctx.serial_for_ids}_module_{self._module_hwtype or 'module'}_{module_abaddr}_refresh_config".lower()
        self._attr_name = "Refresh Config Now"
        self._attr_icon = ICON_REFRESH

        self._attr_suggested_object_id = (
            f"{ctx.tank_slug}_addr{module_abaddr}_refresh_config"
        )

        module_device_info = build_aquabus_child_device_info_from_data(
            host=ctx.host,
            controller_meta=ctx.meta,
            controller_device_identifier=coordinator.device_identifier,
            data=coordinator.data or {},
            module_abaddr=module_abaddr,
            module_hwtype_hint=self._module_hwtype,
        )
        self._attr_device_info = module_device_info or build_device_info(
            host=ctx.host,
            meta=ctx.meta,
            device_identifier=coordinator.device_identifier,
        )

        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )

    async def async_press(self) -> None:
        try:
            await self._coordinator.async_refresh_config_now()
        except HomeAssistantError:
            raise
        except Exception as err:
            raise HomeAssistantError(
                f"Error running Refresh Config Now: {err}"
            ) from err

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
