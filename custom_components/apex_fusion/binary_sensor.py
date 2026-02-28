"""Binary sensors for Apex Fusion (Local).

This platform exposes diagnostic connectivity/config state from coordinator data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, cast

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util import slugify

from .apex_fusion import (
    ApexDiscovery,
    ApexFusionContext,
    DigitalProbeRef,
    DigitalValueCodec,
    network_bool,
    trident_is_testing,
    trident_is_testing_by_abaddr,
    trident_present_by_abaddr,
    trident_reagent_empty,
    trident_reagent_empty_by_abaddr,
    trident_waste_full,
    trident_waste_full_by_abaddr,
)
from .const import (
    DOMAIN,
    ICON_CUP_OFF,
    ICON_FLASK_EMPTY,
    ICON_LAN_CONNECT,
    ICON_TEST_TUBE,
    ICON_TOGGLE_SWITCH_OUTLINE,
    ICON_WIFI,
)
from .coordinator import (
    ApexNeptuneDataUpdateCoordinator,
    build_aquabus_child_device_info_from_data,
    build_device_info,
    build_trident_device_info,
)


@dataclass(frozen=True)
class _BinaryRef:
    """Reference to a coordinator boolean field."""

    key: str
    name: str
    icon: str | None
    value_fn: Callable[[dict[str, Any]], bool | None]


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up Apex Fusion binary sensors from a config entry.

    Args:
        hass: Home Assistant instance.
        entry: Config entry.
        async_add_entities: Callback used to register entities.

    Returns:
        None.
    """
    coordinator: ApexNeptuneDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]
    ctx = ApexFusionContext.from_entry_and_coordinator(entry, coordinator)

    added_digital_keys: set[str] = set()
    added_module_connected: set[int] = set()

    def _module_present_by_abaddr(
        module_abaddr: int,
    ) -> Callable[[dict[str, Any]], bool | None]:
        """Return a value_fn that indicates module presence/connectivity.

        Preference order:
        - If the raw REST payload exposes `present` for the module, use it.
        - If the module is present in the modules list but has no explicit flag,
          treat it as connected.
        - If the modules list exists but the module is not present, treat it as
          disconnected.
        - If raw data is unavailable, return None (unknown).
        """

        def _read(data: dict[str, Any]) -> bool | None:
            raw_any: Any = data.get("raw")
            raw = cast(dict[str, Any], raw_any) if isinstance(raw_any, dict) else {}

            def _modules_from_raw(r: dict[str, Any]) -> list[dict[str, Any]]:
                modules_any: Any = r.get("modules")
                if isinstance(modules_any, list):
                    return [
                        m for m in cast(list[Any], modules_any) if isinstance(m, dict)
                    ]
                for container_key in ("data", "status", "istat", "systat", "result"):
                    container_any: Any = r.get(container_key)
                    if not isinstance(container_any, dict):
                        continue
                    nested_any: Any = cast(dict[str, Any], container_any).get("modules")
                    if isinstance(nested_any, list):
                        return [
                            m
                            for m in cast(list[Any], nested_any)
                            if isinstance(m, dict)
                        ]
                return []

            modules = _modules_from_raw(raw)
            if not modules:
                return None

            for m in modules:
                if m.get("abaddr") != module_abaddr:
                    continue
                present_any: Any = m.get("present")
                if isinstance(present_any, bool):
                    return present_any
                return True

            return False

        return _read

    def _add_module_connected_entities() -> None:
        data = coordinator.data or {}
        config_any: Any = data.get("config")
        if not isinstance(config_any, dict):
            return
        mconf_any: Any = cast(dict[str, Any], config_any).get("mconf")
        if not isinstance(mconf_any, list):
            return

        tank_slug = ctx.tank_slug_with_entry_title(entry.title)
        new_entities: list[BinarySensorEntity] = []

        for item_any in cast(list[Any], mconf_any):
            if not isinstance(item_any, dict):
                continue
            item = cast(dict[str, Any], item_any)

            abaddr_any: Any = item.get("abaddr")
            if not isinstance(abaddr_any, int):
                continue
            if abaddr_any in added_module_connected:
                continue

            hwtype = str(item.get("hwtype") or item.get("hwType") or "").strip().upper()
            if not hwtype:
                continue
            # Trident-family modules have their own connected entity.
            if hwtype in {"TRI", "TNP"}:
                continue

            module_token = ctx.module_token(hwtype)
            addr_slug = f"{module_token}_addr{abaddr_any}"

            device_info = build_aquabus_child_device_info_from_data(
                host=ctx.host,
                controller_meta=ctx.meta,
                controller_device_identifier=ctx.controller_device_identifier,
                data=data,
                module_abaddr=abaddr_any,
                module_hwtype_hint=hwtype,
                module_name_hint=(
                    str(item.get("name")).strip()
                    if isinstance(item.get("name"), str)
                    else None
                ),
                tank_slug=tank_slug,
            )

            name_prefix = "" if device_info is not None else f"{hwtype} "

            new_entities.append(
                ApexModuleConnectedBinarySensor(
                    coordinator,
                    entry,
                    ref=_BinaryRef(
                        key=f"{addr_slug}_connected",
                        name=f"{name_prefix}Connected".strip(),
                        icon=ICON_LAN_CONNECT,
                        value_fn=_module_present_by_abaddr(abaddr_any),
                    ),
                    device_info=device_info,
                    suggested_object_id=ctx.object_id(
                        tank_slug, module_token, abaddr_any, "connected"
                    ),
                )
            )

            added_module_connected.add(abaddr_any)

        if new_entities:
            async_add_entities(new_entities)

    _add_module_connected_entities()
    remove_modules_connected = coordinator.async_add_listener(
        _add_module_connected_entities
    )
    entry.async_on_unload(remove_modules_connected)

    source = str(ctx.meta.get("source") or "").strip().lower()

    entities: list[BinarySensorEntity] = []
    if source == "rest":
        refs: list[_BinaryRef] = [
            _BinaryRef(
                key="dhcp",
                name="DHCP Enabled",
                icon=ICON_LAN_CONNECT,
                value_fn=network_bool("dhcp"),
            ),
            _BinaryRef(
                key="wifi_enable",
                name="Wi-Fi Enabled",
                icon=ICON_WIFI,
                value_fn=network_bool("wifi_enable"),
            ),
        ]
        entities.extend(
            ApexDiagnosticBinarySensor(coordinator, entry, ref=ref) for ref in refs
        )

    def _add_digital_probe_entities() -> None:
        data = coordinator.data or {}
        refs, seen_keys = ApexDiscovery.new_digital_probe_refs(
            data,
            already_added_keys=added_digital_keys,
        )
        new_entities: list[BinarySensorEntity] = [
            ApexDigitalProbeBinarySensor(coordinator, entry, ref=ref) for ref in refs
        ]
        if new_entities:
            async_add_entities(new_entities)
        added_digital_keys.update(seen_keys)

    _add_digital_probe_entities()
    remove = coordinator.async_add_listener(_add_digital_probe_entities)
    entry.async_on_unload(remove)

    if entities:
        async_add_entities(entities)

    added_trident_testing = False
    added_trident_waste_full = False
    added_trident_reagent_empty = False
    added_tridents: set[int] = set()

    def _get_trident_device_info(trident: dict[str, Any]) -> DeviceInfo | None:
        abaddr_any: Any = trident.get("abaddr")
        if not isinstance(abaddr_any, int):
            return None

        return build_trident_device_info(
            host=ctx.host,
            meta=ctx.meta,
            controller_device_identifier=ctx.controller_device_identifier,
            tank_slug=ctx.tank_slug_with_entry_title(entry.title),
            trident_abaddr=abaddr_any,
            trident_hwtype=(str(trident.get("hwtype") or "").strip().upper() or None),
            trident_hwrev=(str(trident.get("hwrev") or "").strip() or None),
            trident_swrev=(str(trident.get("swrev") or "").strip() or None),
            trident_serial=(str(trident.get("serial") or "").strip() or None),
        )

    def _add_trident_testing_entity() -> None:
        nonlocal added_trident_testing
        data = coordinator.data or {}

        tridents_any: Any = data.get("tridents")
        tridents_list: list[dict[str, Any]] = (
            [
                cast(dict[str, Any], t)
                for t in cast(list[Any], tridents_any)
                if isinstance(t, dict)
            ]
            if isinstance(tridents_any, list)
            else []
        )

        # Multi-Trident: prefer per-module entities (and skip the legacy
        # primary entities to avoid duplication).
        if len(tridents_list) > 1:
            new_entities: list[BinarySensorEntity] = []
            tank_slug = ctx.tank_slug_with_entry_title(entry.title)
            for t in tridents_list:
                abaddr_any: Any = t.get("abaddr")
                if not isinstance(abaddr_any, int):
                    continue
                if abaddr_any in added_tridents:
                    continue

                hwtype = str(t.get("hwtype") or "").strip().upper()
                label = "Trident NP" if hwtype == "TNP" else "Trident"
                addr_slug = f"trident_addr{abaddr_any}"
                device_info = _get_trident_device_info(t)
                name_prefix = "" if device_info is not None else f"{label} "

                new_entities.append(
                    ApexBinarySensor(
                        coordinator,
                        entry,
                        ref=_BinaryRef(
                            key=f"{addr_slug}_testing",
                            name=f"{name_prefix}Testing".strip(),
                            icon=ICON_TEST_TUBE,
                            value_fn=trident_is_testing_by_abaddr(abaddr_any),
                        ),
                        device_info=device_info,
                        suggested_object_id=ctx.object_id(
                            tank_slug, "trident", abaddr_any, "testing"
                        ),
                    )
                )

                new_entities.append(
                    ApexTridentConnectedBinarySensor(
                        coordinator,
                        entry,
                        ref=_BinaryRef(
                            key=f"{addr_slug}_connected",
                            name=f"{name_prefix}Connected".strip(),
                            icon=ICON_LAN_CONNECT,
                            value_fn=trident_present_by_abaddr(abaddr_any),
                        ),
                        device_info=device_info,
                        suggested_object_id=ctx.object_id(
                            tank_slug, "trident", abaddr_any, "connected"
                        ),
                    )
                )

                new_entities.append(
                    ApexTridentWasteFullBinarySensor(
                        coordinator,
                        entry,
                        ref=_BinaryRef(
                            key=f"{addr_slug}_waste_full",
                            name=f"{name_prefix}Waste Full".strip(),
                            icon=ICON_CUP_OFF,
                            value_fn=trident_waste_full_by_abaddr(abaddr_any),
                        ),
                        device_info=device_info,
                        suggested_object_id=ctx.object_id(
                            tank_slug, "trident", abaddr_any, "waste_full"
                        ),
                    )
                )

                # Reagent empty flags.
                reagent_names = (
                    ("Reagent 1", "reagent_a_empty"),
                    ("Reagent 2", "reagent_b_empty"),
                    ("Reagent 3", "reagent_c_empty"),
                )
                if hwtype != "TNP":
                    reagent_names = (
                        ("Reagent A", "reagent_a_empty"),
                        ("Reagent B", "reagent_b_empty"),
                        ("Reagent C", "reagent_c_empty"),
                    )

                for display, field in reagent_names:
                    new_entities.append(
                        ApexTridentReagentEmptyBinarySensor(
                            coordinator,
                            entry,
                            ref=_BinaryRef(
                                key=f"{addr_slug}_{field}",
                                name=f"{name_prefix}{display} Empty".strip(),
                                icon=ICON_FLASK_EMPTY,
                                value_fn=trident_reagent_empty_by_abaddr(
                                    abaddr_any, field
                                ),
                            ),
                            device_info=device_info,
                            suggested_object_id=ctx.object_id(
                                tank_slug, "trident", abaddr_any, field
                            ),
                        )
                    )

                added_tridents.add(abaddr_any)

            if new_entities:
                async_add_entities(new_entities)
            return

        trident_any: Any = data.get("trident")
        if isinstance(trident_any, dict):
            trident = cast(dict[str, Any], trident_any)
            if not added_trident_testing and (
                trident.get("present") is True
                or trident.get("status") is not None
                or trident.get("levels_ml") is not None
                or isinstance(trident.get("abaddr"), int)
                or (str(trident.get("hwtype") or "").strip() != "")
            ):
                trident_device_info = _get_trident_device_info(trident)
                trident_prefix = "" if trident_device_info is not None else "Trident "

                ref = _BinaryRef(
                    key="trident_testing",
                    name=f"{trident_prefix}Testing".strip(),
                    icon=ICON_TEST_TUBE,
                    value_fn=trident_is_testing,
                )

                connected_ref = _BinaryRef(
                    key="trident_connected",
                    name=f"{trident_prefix}Connected".strip(),
                    icon=ICON_LAN_CONNECT,
                    value_fn=lambda d: (
                        d.get("trident", {}).get("present")
                        if isinstance(d.get("trident"), dict)
                        and isinstance(
                            cast(dict[str, Any], d.get("trident")).get("present"), bool
                        )
                        else None
                    ),
                )
                tank_slug = ctx.tank_slug_with_entry_title(entry.title)
                abaddr = (
                    cast(int, trident.get("abaddr"))
                    if isinstance(trident.get("abaddr"), int)
                    else None
                )
                async_add_entities(
                    [
                        ApexBinarySensor(
                            coordinator,
                            entry,
                            ref=ref,
                            device_info=trident_device_info,
                            suggested_object_id=ctx.object_id(
                                tank_slug, "trident", abaddr, "testing"
                            ),
                        ),
                        ApexTridentConnectedBinarySensor(
                            coordinator,
                            entry,
                            ref=connected_ref,
                            device_info=trident_device_info,
                            suggested_object_id=ctx.object_id(
                                tank_slug, "trident", abaddr, "connected"
                            ),
                        ),
                    ]
                )
                added_trident_testing = True

    _add_trident_testing_entity()
    remove_trident = coordinator.async_add_listener(_add_trident_testing_entity)
    entry.async_on_unload(remove_trident)

    def _add_trident_waste_full_entity() -> None:
        nonlocal added_trident_waste_full
        if added_trident_waste_full:
            return

        data = coordinator.data or {}
        tridents_any: Any = data.get("tridents")
        if isinstance(tridents_any, list) and len(cast(list[Any], tridents_any)) > 1:
            return
        trident_any: Any = data.get("trident")
        if not isinstance(trident_any, dict):
            return
        trident = cast(dict[str, Any], trident_any)
        if not (
            trident.get("present") is True
            or trident.get("waste_full") is not None
            or trident.get("waste_percent") is not None
            or trident.get("waste_remaining_ml") is not None
            or trident.get("waste_used_ml") is not None
            or isinstance(trident.get("abaddr"), int)
            or (str(trident.get("hwtype") or "").strip() != "")
        ):
            return

        trident_device_info = _get_trident_device_info(trident)
        trident_prefix = "" if trident_device_info is not None else "Trident "

        ref = _BinaryRef(
            key="trident_waste_full",
            name=f"{trident_prefix}Waste Full".strip(),
            icon=ICON_CUP_OFF,
            value_fn=trident_waste_full,
        )
        tank_slug = ctx.tank_slug_with_entry_title(entry.title)
        abaddr = (
            cast(int, trident.get("abaddr"))
            if isinstance(trident.get("abaddr"), int)
            else None
        )
        async_add_entities(
            [
                ApexTridentWasteFullBinarySensor(
                    coordinator,
                    entry,
                    ref=ref,
                    device_info=trident_device_info,
                    suggested_object_id=ctx.object_id(
                        tank_slug, "trident", abaddr, "waste_full"
                    ),
                )
            ]
        )
        added_trident_waste_full = True

    _add_trident_waste_full_entity()
    remove_trident_waste = coordinator.async_add_listener(
        _add_trident_waste_full_entity
    )
    entry.async_on_unload(remove_trident_waste)

    def _add_trident_reagent_empty_entities() -> None:
        nonlocal added_trident_reagent_empty
        if added_trident_reagent_empty:
            return

        data = coordinator.data or {}
        tridents_any: Any = data.get("tridents")
        if isinstance(tridents_any, list) and len(cast(list[Any], tridents_any)) > 1:
            return
        trident_any: Any = data.get("trident")
        if not isinstance(trident_any, dict):
            return
        trident = cast(dict[str, Any], trident_any)
        if not (
            trident.get("present") is True
            or trident.get("reagent_a_empty") is not None
            or trident.get("reagent_b_empty") is not None
            or trident.get("reagent_c_empty") is not None
            or isinstance(trident.get("abaddr"), int)
            or (str(trident.get("hwtype") or "").strip() != "")
        ):
            return

        trident_device_info = _get_trident_device_info(trident)
        trident_prefix = "" if trident_device_info is not None else "Trident "

        refs = [
            _BinaryRef(
                key="trident_reagent_a_empty",
                name=f"{trident_prefix}Reagent A Empty".strip(),
                icon=ICON_FLASK_EMPTY,
                value_fn=trident_reagent_empty("reagent_a_empty"),
            ),
            _BinaryRef(
                key="trident_reagent_b_empty",
                name=f"{trident_prefix}Reagent B Empty".strip(),
                icon=ICON_FLASK_EMPTY,
                value_fn=trident_reagent_empty("reagent_b_empty"),
            ),
            _BinaryRef(
                key="trident_reagent_c_empty",
                name=f"{trident_prefix}Reagent C Empty".strip(),
                icon=ICON_FLASK_EMPTY,
                value_fn=trident_reagent_empty("reagent_c_empty"),
            ),
        ]

        tank_slug = ctx.tank_slug_with_entry_title(entry.title)
        abaddr = (
            cast(int, trident.get("abaddr"))
            if isinstance(trident.get("abaddr"), int)
            else None
        )
        async_add_entities(
            [
                ApexTridentReagentEmptyBinarySensor(
                    coordinator,
                    entry,
                    ref=r,
                    device_info=trident_device_info,
                    suggested_object_id=ctx.object_id(
                        tank_slug,
                        "trident",
                        abaddr,
                        r.key.removeprefix("trident_"),
                    ),
                )
                for r in refs
            ]
        )
        added_trident_reagent_empty = True

    _add_trident_reagent_empty_entities()
    remove_trident_reagent_empty = coordinator.async_add_listener(
        _add_trident_reagent_empty_entities
    )
    entry.async_on_unload(remove_trident_reagent_empty)


class ApexDigitalProbeBinarySensor(BinarySensorEntity):
    """Binary sensor for Apex digital inputs.

    Controller values are 0/1. For Home Assistant's `opening` device class,
    `on` means OPEN and `off` means CLOSED.

    On Apex controllers, digital inputs commonly report:
    - 0 => OPEN (no continuity)
    - 1 => CLOSED (continuity)
    """

    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_device_class = BinarySensorDeviceClass.OPENING
    _attr_icon = ICON_TOGGLE_SWITCH_OUTLINE

    def __init__(
        self,
        coordinator: ApexNeptuneDataUpdateCoordinator,
        entry: ConfigEntry,
        *,
        ref: DigitalProbeRef,
    ) -> None:
        super().__init__()
        self._coordinator = coordinator
        self._entry = entry
        self._ref = ref

        ctx = ApexFusionContext.from_entry_and_coordinator(entry, coordinator)

        self._attr_unique_id = f"{ctx.serial_for_ids}_digital_{ref.key}".lower()
        self._attr_name = ref.name

        first_probe = self._find_probe()
        module_abaddr_any: Any = first_probe.get("module_abaddr")
        module_abaddr = (
            module_abaddr_any if isinstance(module_abaddr_any, int) else None
        )

        module_hwtype_hint: str | None = None
        module_hwtype_any: Any = first_probe.get("module_hwtype")
        if isinstance(module_hwtype_any, str) and module_hwtype_any.strip():
            module_hwtype_hint = module_hwtype_any

        tank_slug = ctx.tank_slug_with_entry_title(entry.title)
        key_slug = str(ref.key or "").strip().lower() or slugify(ref.name) or "di"
        if isinstance(module_abaddr, int) and module_hwtype_hint:
            module_token = ctx.module_token(module_hwtype_hint)
            key_slug = ctx.normalize_module_suffix(
                module_token=module_token,
                module_abaddr=module_abaddr,
                suffix=key_slug,
            )
            self._attr_suggested_object_id = ctx.object_id(
                tank_slug,
                module_token,
                module_abaddr,
                key_slug,
            )
        else:
            self._attr_suggested_object_id = ctx.object_id(tank_slug, "apex", key_slug)

        module_device_info: DeviceInfo | None = (
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

        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
        self._refresh()

    def _find_probe(self) -> dict[str, Any]:
        data = self._coordinator.data or {}
        probes_any: Any = data.get("probes")
        if not isinstance(probes_any, dict):
            return {}
        probes = cast(dict[str, Any], probes_any)
        probe_any: Any = probes.get(self._ref.key)
        if isinstance(probe_any, dict):
            return cast(dict[str, Any], probe_any)
        return {}

    def _refresh(self) -> None:
        probe = self._find_probe()
        raw = probe.get("value")
        if raw is None:
            raw = probe.get("value_raw")

        v = DigitalValueCodec.as_int_0_1(raw)
        # HA convention for `opening`: True means OPEN.
        # Apex digital inputs: 0=open, 1=closed.
        self._attr_is_on = (v == 0) if v is not None else None

        self._attr_extra_state_attributes = {
            "value": raw,
            "type": str(probe.get("type") or "").strip() or None,
        }

    def _handle_coordinator_update(self) -> None:
        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
        self._refresh()
        self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(
            self._coordinator.async_add_listener(self._handle_coordinator_update)
        )
        self._handle_coordinator_update()


class ApexDiagnosticBinarySensor(BinarySensorEntity):
    """Binary sensor exposing diagnostic controller/network state."""

    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: ApexNeptuneDataUpdateCoordinator,
        entry: ConfigEntry,
        *,
        ref: _BinaryRef,
        device_info: DeviceInfo | None = None,
        suggested_object_id: str | None = None,
    ) -> None:
        """Initialize the binary sensor.

        Args:
            coordinator: Data coordinator.
            entry: Config entry.
            ref: Binary sensor reference.
            device_info: Optional device registry info.
            suggested_object_id: Optional suggested object id for entity_id.
        """
        super().__init__()
        self._coordinator = coordinator
        self._entry = entry
        self._ref = ref

        ctx = ApexFusionContext.from_entry_and_coordinator(entry, coordinator)

        self._attr_unique_id = f"{ctx.serial_for_ids}_diag_bool_{ref.key}".lower()
        self._attr_name = ref.name
        if suggested_object_id:
            self._attr_suggested_object_id = suggested_object_id
        self._attr_icon = ref.icon
        self._attr_device_info = device_info or build_device_info(
            host=ctx.host,
            meta=ctx.meta,
            device_identifier=ctx.controller_device_identifier,
            tank_slug=ctx.tank_slug_with_entry_title(entry.title),
        )

        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
        self._attr_is_on = self._read_value()

    def _read_value(self) -> bool | None:
        """Read boolean state from coordinator.

        Returns:
            Current boolean state, or None if unknown.
        """
        data = self._coordinator.data or {}
        return self._ref.value_fn(data)

    def _handle_coordinator_update(self) -> None:
        """Update state from coordinator."""
        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
        self._attr_is_on = self._read_value()
        self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        """Register coordinator listener."""
        self.async_on_remove(
            self._coordinator.async_add_listener(self._handle_coordinator_update)
        )
        self._handle_coordinator_update()


class ApexBinarySensor(ApexDiagnosticBinarySensor):
    """Binary sensor exposing non-diagnostic controller state."""

    _attr_entity_category = None

    def __init__(
        self,
        coordinator: ApexNeptuneDataUpdateCoordinator,
        entry: ConfigEntry,
        *,
        ref: _BinaryRef,
        device_info: DeviceInfo | None = None,
        suggested_object_id: str | None = None,
    ) -> None:
        super().__init__(
            coordinator,
            entry,
            ref=ref,
            device_info=device_info,
            suggested_object_id=suggested_object_id,
        )

        ctx = ApexFusionContext.from_entry_and_coordinator(entry, coordinator)

        # Use a distinct unique_id prefix so entity ids differ from diagnostics.
        self._attr_unique_id = f"{ctx.serial_for_ids}_bool_{ref.key}".lower()


class ApexTridentWasteFullBinarySensor(ApexDiagnosticBinarySensor):
    """Binary sensor for Trident waste-full condition."""

    _attr_device_class = BinarySensorDeviceClass.PROBLEM


class ApexTridentReagentEmptyBinarySensor(ApexDiagnosticBinarySensor):
    """Binary sensor for Trident reagent-empty condition."""

    _attr_device_class = BinarySensorDeviceClass.PROBLEM


class ApexTridentConnectedBinarySensor(ApexDiagnosticBinarySensor):
    """Binary sensor for Trident connectivity/presence."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY


class ApexModuleConnectedBinarySensor(ApexDiagnosticBinarySensor):
    """Binary sensor for Aquabus module connectivity/presence."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
