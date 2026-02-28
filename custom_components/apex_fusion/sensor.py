"""Sensors for Apex Fusion (Local).

This platform exposes:
- Probe/input sensors.
- Output/outlet status sensors.

Entities are coordinator-driven and do not poll independently.
"""

from __future__ import annotations

from typing import Any, Callable, cast

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    PERCENTAGE,
    EntityCategory,
    UnitOfVolume,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import StateType
from homeassistant.util import slugify

from .apex_fusion import (
    ApexDiscovery,
    ApexFusionContext,
    OutletIntensityRef,
    OutletMode,
    OutletRef,
    ProbeRef,
    as_float,
    network_field,
    section_field,
    trident_field_by_abaddr,
    trident_level_ml,
    trident_level_ml_by_abaddr,
    units_and_meta,
)
from .const import (
    CONF_NO_LOGIN,
    CONF_PASSWORD,
    DOMAIN,
    ICON_ALERT_CIRCLE_OUTLINE,
    ICON_BEAKER_OUTLINE,
    ICON_BRIGHTNESS_PERCENT,
    ICON_BUG_OUTLINE,
    ICON_CURRENT_AC,
    ICON_FLASH,
    ICON_FLASK,
    ICON_FLASK_OUTLINE,
    ICON_GAUGE,
    ICON_IP_NETWORK,
    ICON_IP_NETWORK_OUTLINE,
    ICON_LIGHTBULB,
    ICON_PH,
    ICON_POWER_SOCKET_US,
    ICON_PUMP,
    ICON_RADIATOR,
    ICON_ROUTER_NETWORK,
    ICON_SHAKER_OUTLINE,
    ICON_SIGNAL,
    ICON_TEST_TUBE,
    ICON_THERMOMETER,
    ICON_TRASH_CAN_OUTLINE,
    ICON_WIFI_SETTINGS,
    ICON_WIFI_STRENGTH_4,
)
from .coordinator import (
    ApexNeptuneDataUpdateCoordinator,
    build_aquabus_child_device_info_from_data,
    build_device_info,
    build_trident_device_info,
    module_abaddr_from_input_did,
    normalize_module_hwtype_from_outlet_type,
    unambiguous_module_abaddr_from_config,
)


def icon_for_probe_type(probe_type: str, probe_name: str) -> str | None:
    """Return an icon for a probe type/name.

    This is a Home Assistant UI concern, so the helper lives in the platform
    module that uses it.

    Args:
        probe_type: Probe type token.
        probe_name: Probe name.

    Returns:
        A Material Design Icon string.
    """

    t = (probe_type or "").strip().lower()
    n = (probe_name or "").strip().lower()

    if t in {"temp", "tmp"}:
        return ICON_THERMOMETER
    if t == "ph":
        return ICON_PH
    if t == "cond":
        return ICON_SHAKER_OUTLINE if n.startswith("salt") else ICON_FLASH
    if t == "amps":
        return ICON_CURRENT_AC
    if t == "alk":
        return ICON_TEST_TUBE
    if t == "ca":
        return ICON_FLASK
    if t == "mg":
        return ICON_FLASK_OUTLINE
    return ICON_GAUGE


def icon_for_outlet_type(outlet_type: str | None) -> str | None:
    """Return an icon for an outlet based on its device type.

    Args:
        outlet_type: Raw outlet type token.

    Returns:
        A Material Design Icon string.
    """

    t = (outlet_type or "").strip().upper()
    if "PUMP" in t:
        return ICON_PUMP
    if "LIGHT" in t:
        return ICON_LIGHTBULB
    if "HEATER" in t:
        return ICON_RADIATOR
    return ICON_POWER_SOCKET_US


_SIMPLE_REST_SINGLE_SENSOR_MODE = False


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up Apex Fusion sensors based on a config entry.

    Args:
        hass: Home Assistant instance.
        entry: The config entry.
        async_add_entities: Callback to add entities.
    """
    coordinator: ApexNeptuneDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]
    ctx = ApexFusionContext.from_entry_and_coordinator(entry, coordinator)

    # Developer toggle: when enabled, only expose a single REST debug sensor.
    if _SIMPLE_REST_SINGLE_SENSOR_MODE:
        async_add_entities([ApexRestDebugSensor(coordinator, entry)])
        return

    added_probe_keys: set[str] = set()
    added_outlet_intensity_dids: set[str] = set()
    added_outlet_mode_dids: set[str] = set()

    source = str(ctx.meta.get("source") or "").strip().lower()
    read_only = (
        bool(entry.data.get(CONF_NO_LOGIN, False))
        or not str(entry.data.get(CONF_PASSWORD, "") or "").strip()
    )

    # When the integration is read-only (no-login or no password) or when REST
    # is not active, we do not create control SelectEntities. Instead, expose a
    # read-only sensor that reports the current outlet mode.
    expose_outlet_mode_sensors = read_only or source != "rest"

    def _add_probe_and_outlet_entities() -> None:
        coordinator_data = coordinator.data or {}
        new_entities: list[SensorEntity] = []

        probe_refs, seen_probe_keys = ApexDiscovery.new_probe_refs(
            coordinator_data,
            already_added_keys=added_probe_keys,
        )
        new_entities.extend(
            ApexProbeSensor(coordinator, entry, ref=ref) for ref in probe_refs
        )
        added_probe_keys.update(seen_probe_keys)

        if new_entities:
            async_add_entities(new_entities)

        outlet_refs, seen_outlet_dids = ApexDiscovery.new_outlet_intensity_refs(
            coordinator_data,
            already_added_dids=added_outlet_intensity_dids,
        )
        outlet_entities: list[SensorEntity] = [
            ApexOutletIntensitySensor(coordinator, entry, ref=ref)
            for ref in outlet_refs
        ]
        if outlet_entities:
            async_add_entities(outlet_entities)
        added_outlet_intensity_dids.update(seen_outlet_dids)

        if expose_outlet_mode_sensors:
            outlet_mode_refs, seen_mode_dids = ApexDiscovery.new_outlet_select_refs(
                coordinator_data,
                already_added_dids=added_outlet_mode_dids,
            )
            mode_entities: list[SensorEntity] = [
                ApexOutletModeSensor(coordinator, entry, ref=ref)
                for ref in outlet_mode_refs
            ]
            if mode_entities:
                async_add_entities(mode_entities)
            added_outlet_mode_dids.update(seen_mode_dids)

    _add_probe_and_outlet_entities()
    remove = coordinator.async_add_listener(_add_probe_and_outlet_entities)
    entry.async_on_unload(remove)

    serial_for_ids = ctx.serial_for_ids

    diagnostic_entities: list[SensorEntity] = []
    # REST-only network diagnostics.
    if source == "rest":
        diagnostic_entities.extend(
            [
                ApexDiagnosticSensor(
                    coordinator,
                    entry,
                    unique_id=f"{serial_for_ids}_diag_ipaddr".lower(),
                    name="IP Address",
                    icon=ICON_IP_NETWORK,
                    value_fn=network_field("ipaddr"),
                ),
                ApexDiagnosticSensor(
                    coordinator,
                    entry,
                    unique_id=f"{serial_for_ids}_diag_gateway".lower(),
                    name="Gateway",
                    icon=ICON_ROUTER_NETWORK,
                    value_fn=network_field("gateway"),
                ),
                ApexDiagnosticSensor(
                    coordinator,
                    entry,
                    unique_id=f"{serial_for_ids}_diag_netmask".lower(),
                    name="Netmask",
                    icon=ICON_IP_NETWORK_OUTLINE,
                    value_fn=network_field("netmask"),
                ),
                ApexDiagnosticSensor(
                    coordinator,
                    entry,
                    unique_id=f"{serial_for_ids}_diag_ssid".lower(),
                    name="Wi-Fi SSID",
                    icon=ICON_WIFI_SETTINGS,
                    value_fn=network_field("ssid"),
                ),
                ApexDiagnosticSensor(
                    coordinator,
                    entry,
                    unique_id=f"{serial_for_ids}_diag_wifi_strength".lower(),
                    name="Wi-Fi Strength",
                    icon=ICON_WIFI_STRENGTH_4,
                    native_unit=PERCENTAGE,
                    value_fn=network_field("strength"),
                ),
                ApexDiagnosticSensor(
                    coordinator,
                    entry,
                    unique_id=f"{serial_for_ids}_diag_wifi_quality".lower(),
                    name="Wi-Fi Quality",
                    icon=ICON_SIGNAL,
                    native_unit=PERCENTAGE,
                    value_fn=network_field("quality"),
                ),
            ]
        )

    # Always-available diagnostics (when the controller reports them).
    diagnostic_entities.append(
        ApexDiagnosticSensor(
            coordinator,
            entry,
            unique_id=f"{serial_for_ids}_diag_alert_last".lower(),
            name="Last Alert Statement",
            icon=ICON_ALERT_CIRCLE_OUTLINE,
            value_fn=section_field("alerts", "last_statement"),
        )
    )

    async_add_entities(diagnostic_entities)

    added_trident_diags = False
    added_tridents_diags: set[int] = set()

    def _add_trident_diagnostics() -> None:
        nonlocal added_trident_diags
        data = coordinator.data or {}
        tank_slug = ctx.tank_slug

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

        # Multi-Trident diagnostics: create per-module entities only when
        # multiple Trident-family modules are detected.
        if len(tridents_list) > 1:
            for t in tridents_list:
                abaddr_any: Any = t.get("abaddr")
                if not isinstance(abaddr_any, int):
                    continue
                if abaddr_any in added_tridents_diags:
                    continue

                device_info = build_trident_device_info(
                    host=ctx.host,
                    meta=ctx.meta,
                    controller_device_identifier=ctx.controller_device_identifier,
                    trident_abaddr=abaddr_any,
                    trident_hwtype=(str(t.get("hwtype") or "").strip().upper() or None),
                    trident_hwrev=(str(t.get("hwrev") or "").strip() or None),
                    trident_swrev=(str(t.get("swrev") or "").strip() or None),
                    trident_serial=(str(t.get("serial") or "").strip() or None),
                )

                hwtype = str(t.get("hwtype") or "").strip().upper()
                label = "Trident NP" if hwtype == "TNP" else "Trident"

                addr_slug = f"trident_addr{abaddr_any}"
                prefix = f"{label} "

                multi_entities: list[SensorEntity] = [
                    ApexDiagnosticSensor(
                        coordinator,
                        entry,
                        unique_id=f"{serial_for_ids}_diag_{addr_slug}_status".lower(),
                        name=f"{prefix}Status".strip(),
                        suggested_object_id=f"{tank_slug}_{addr_slug}_status",
                        icon=ICON_FLASK_OUTLINE,
                        value_fn=trident_field_by_abaddr(abaddr_any, "status"),
                        entity_category=None,
                        device_info=device_info,
                    )
                ]

                # Container levels: create the standard set even when levels are
                # temporarily missing.
                levels_any: Any = t.get("levels_ml")
                level_count = (
                    len(cast(list[Any], levels_any))
                    if isinstance(levels_any, list)
                    else 5
                )
                level_count = max(level_count, 5)
                for i in range(level_count):
                    object_suffix = f"container_{i + 1}_level"
                    name = f"{prefix}Container {i + 1} Level".strip()
                    icon = ICON_BEAKER_OUTLINE
                    state_class: SensorStateClass | None = SensorStateClass.TOTAL

                    if i == 0:
                        name = f"{prefix}Waste Used".strip()
                        icon = ICON_TRASH_CAN_OUTLINE
                        state_class = SensorStateClass.TOTAL_INCREASING
                        object_suffix = "waste_used"
                    elif i == 1:
                        name = f"{prefix}Auxiliary Level".strip()
                        object_suffix = "auxiliary_level"
                    elif i == 2:
                        name = (
                            f"{prefix}Reagent 3 Remaining".strip()
                            if hwtype == "TNP"
                            else f"{prefix}Reagent C Remaining".strip()
                        )
                        object_suffix = "reagent_c_remaining"
                    elif i == 3:
                        name = (
                            f"{prefix}Reagent 2 Remaining".strip()
                            if hwtype == "TNP"
                            else f"{prefix}Reagent B Remaining".strip()
                        )
                        object_suffix = "reagent_b_remaining"
                    elif i == 4:
                        name = (
                            f"{prefix}Reagent 1 Remaining".strip()
                            if hwtype == "TNP"
                            else f"{prefix}Reagent A Remaining".strip()
                        )
                        object_suffix = "reagent_a_remaining"

                    multi_entities.append(
                        ApexDiagnosticSensor(
                            coordinator,
                            entry,
                            unique_id=f"{serial_for_ids}_diag_{addr_slug}_container_{i + 1}_level".lower(),
                            name=name,
                            suggested_object_id=f"{tank_slug}_{addr_slug}_{object_suffix}",
                            icon=icon,
                            native_unit=UnitOfVolume.MILLILITERS,
                            device_class=SensorDeviceClass.VOLUME,
                            state_class=state_class,
                            value_fn=trident_level_ml_by_abaddr(abaddr_any, i),
                            entity_category=None,
                            device_info=device_info,
                        )
                    )

                if multi_entities:
                    async_add_entities(multi_entities)
                    added_tridents_diags.add(abaddr_any)
            return

        trident_any: Any = data.get("trident")
        trident = (
            cast(dict[str, Any], trident_any) if isinstance(trident_any, dict) else {}
        )
        trident_detected = bool(
            isinstance(trident_any, dict)
            and (
                trident.get("present") is True
                or trident.get("status") is not None
                or trident.get("levels_ml") is not None
                or isinstance(trident.get("abaddr"), int)
                or (str(trident.get("hwtype") or "").strip() != "")
            )
        )

        # Primary (single-Trident) diagnostics.
        if trident_detected and not added_trident_diags:
            trident_device_info: DeviceInfo | None = None
            trident_abaddr_any: Any = trident.get("abaddr")
            if isinstance(trident_abaddr_any, int):
                trident_device_info = build_trident_device_info(
                    host=ctx.host,
                    meta=ctx.meta,
                    controller_device_identifier=ctx.controller_device_identifier,
                    trident_abaddr=trident_abaddr_any,
                    trident_hwtype=(
                        str(trident.get("hwtype") or "").strip().upper() or None
                    ),
                    trident_hwrev=(str(trident.get("hwrev") or "").strip() or None),
                    trident_swrev=(str(trident.get("swrev") or "").strip() or None),
                    trident_serial=(str(trident.get("serial") or "").strip() or None),
                )

            trident_prefix = "" if trident_device_info is not None else "Trident "

            trident_addr_slug = (
                f"trident_addr{trident_abaddr_any}"
                if isinstance(trident_abaddr_any, int)
                else "trident"
            )

            new_entities: list[SensorEntity] = [
                ApexDiagnosticSensor(
                    coordinator,
                    entry,
                    unique_id=f"{serial_for_ids}_diag_trident_status".lower(),
                    name=f"{trident_prefix}Status".strip(),
                    suggested_object_id=f"{tank_slug}_{trident_addr_slug}_status",
                    icon=ICON_FLASK_OUTLINE,
                    value_fn=section_field("trident", "status"),
                    entity_category=None,
                    device_info=trident_device_info,
                )
            ]

            # Firmware/software revision (diagnostic).
            new_entities.append(
                ApexDiagnosticSensor(
                    coordinator,
                    entry,
                    unique_id=f"{serial_for_ids}_diag_trident_firmware".lower(),
                    name=f"{trident_prefix}Firmware".strip(),
                    suggested_object_id=f"{tank_slug}_{trident_addr_slug}_firmware",
                    icon=None,
                    value_fn=section_field("trident", "swrev"),
                    entity_category=EntityCategory.DIAGNOSTIC,
                    device_info=trident_device_info,
                )
            )

            # Create the standard Trident container sensors even if `levels_ml`
            # is missing on the first refresh. Values will show as unknown until
            # the controller starts reporting them.
            levels_any: Any = trident.get("levels_ml")
            level_count = (
                len(cast(list[Any], levels_any)) if isinstance(levels_any, list) else 5
            )
            level_count = max(level_count, 5)
            for i in range(level_count):
                name = f"{trident_prefix}Container {i + 1} Level".strip()
                icon = ICON_BEAKER_OUTLINE
                state_class: SensorStateClass | None = SensorStateClass.TOTAL

                if i == 0:
                    name = f"{trident_prefix}Waste Used".strip()
                    icon = ICON_TRASH_CAN_OUTLINE
                    state_class = SensorStateClass.TOTAL_INCREASING
                    object_suffix = "waste_used"
                elif i == 1:
                    name = f"{trident_prefix}Auxiliary Level".strip()
                    object_suffix = "auxiliary_level"
                elif i == 2:
                    name = f"{trident_prefix}Reagent C Remaining".strip()
                    object_suffix = "reagent_c_remaining"
                elif i == 3:
                    name = f"{trident_prefix}Reagent B Remaining".strip()
                    object_suffix = "reagent_b_remaining"
                elif i == 4:
                    name = f"{trident_prefix}Reagent A Remaining".strip()
                    object_suffix = "reagent_a_remaining"
                else:
                    object_suffix = f"container_{i + 1}_level"

                new_entities.append(
                    ApexDiagnosticSensor(
                        coordinator,
                        entry,
                        unique_id=f"{serial_for_ids}_diag_trident_container_{i + 1}_level".lower(),
                        name=name,
                        suggested_object_id=f"{tank_slug}_{trident_addr_slug}_{object_suffix}",
                        icon=icon,
                        native_unit=UnitOfVolume.MILLILITERS,
                        device_class=SensorDeviceClass.VOLUME,
                        state_class=state_class,
                        value_fn=trident_level_ml(i),
                        entity_category=None,
                        device_info=trident_device_info,
                    )
                )

            if new_entities:
                async_add_entities(new_entities)
                added_trident_diags = True

    _add_trident_diagnostics()
    remove_trident = coordinator.async_add_listener(_add_trident_diagnostics)
    entry.async_on_unload(remove_trident)


class ApexRestDebugSensor(SensorEntity):
    """Single minimal sensor to validate REST status parsing."""

    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = ICON_BUG_OUTLINE

    def __init__(
        self,
        coordinator: ApexNeptuneDataUpdateCoordinator,
        entry: ConfigEntry,
    ) -> None:
        super().__init__()
        self._coordinator = coordinator
        self._entry = entry

        ctx = ApexFusionContext.from_entry_and_coordinator(entry, coordinator)

        self._attr_unique_id = f"{ctx.serial_for_ids}_rest_debug_keys".lower()
        self._attr_name = "REST Status Keys"
        self._attr_device_info = build_device_info(
            host=ctx.host,
            meta=ctx.meta,
            device_identifier=ctx.controller_device_identifier,
        )

        self._refresh_attrs()

    def _refresh_attrs(self) -> None:
        data = self._coordinator.data or {}
        meta_any = data.get("meta", {})
        meta = cast(dict[str, Any], meta_any) if isinstance(meta_any, dict) else {}
        source = str(meta.get("source") or "").strip().lower()

        # Only report available when REST is the current data source.
        self._attr_available = (
            bool(getattr(self._coordinator, "last_update_success", True))
            and source == "rest"
        )

        raw_any = data.get("raw")
        raw = cast(dict[str, Any], raw_any) if isinstance(raw_any, dict) else {}
        self._attr_native_value = len(raw) if self._attr_available else None

        probes_any = data.get("probes")
        probes_count = (
            len(cast(dict[str, Any], probes_any)) if isinstance(probes_any, dict) else 0
        )
        outlets_any = data.get("outlets")
        outlets_count = (
            len(cast(list[Any], outlets_any)) if isinstance(outlets_any, list) else 0
        )

        self._attr_extra_state_attributes = {
            "source": source or None,
            "raw_top_level_keys": sorted(list(raw.keys()))[:30],
            "probe_count": probes_count,
            "outlet_count": outlets_count,
        }

    def _handle_coordinator_update(self) -> None:
        self._refresh_attrs()

        # Only write state once the entity is added to hass.
        if getattr(self, "hass", None) is not None:
            self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(
            self._coordinator.async_add_listener(self._handle_coordinator_update)
        )
        self._handle_coordinator_update()


class ApexDiagnosticSensor(SensorEntity):
    """Diagnostic sensor exposing controller/network metadata."""

    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: ApexNeptuneDataUpdateCoordinator,
        entry: ConfigEntry,
        *,
        unique_id: str,
        name: str,
        value_fn: Callable[[dict[str, Any]], Any],
        suggested_object_id: str | None = None,
        native_unit: str | None = None,
        icon: str | None = None,
        device_class: SensorDeviceClass | None = None,
        state_class: SensorStateClass | None = None,
        entity_category: EntityCategory | None = EntityCategory.DIAGNOSTIC,
        device_info: DeviceInfo | None = None,
    ) -> None:
        """Initialize the diagnostic sensor.

        Args:
            coordinator: Data coordinator.
            entry: Config entry.
            unique_id: Stable unique ID.
            name: Entity name.
            value_fn: Function extracting value from coordinator data.
            native_unit: Optional unit.
        """
        super().__init__()
        self._coordinator = coordinator
        self._entry = entry
        self._value_fn = value_fn

        ctx = ApexFusionContext.from_entry_and_coordinator(entry, coordinator)

        self._attr_unique_id = unique_id
        self._attr_name = name
        if suggested_object_id:
            self._attr_suggested_object_id = suggested_object_id
        self._attr_native_unit_of_measurement = native_unit
        self._attr_icon = icon
        self._attr_device_class = device_class
        self._attr_state_class = state_class
        self._attr_entity_category = entity_category
        self._attr_device_info = device_info or build_device_info(
            host=ctx.host,
            meta=ctx.meta,
            device_identifier=ctx.controller_device_identifier,
        )

        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
        self._attr_native_value = self._read_value()

    def _read_value(self) -> StateType:
        """Read current value from coordinator data.

        Returns:
            Current sensor value in Home Assistant native format.
        """
        data = self._coordinator.data or {}
        value = self._value_fn(data)
        if value is None:
            return None
        # For numeric diagnostics (percentage, volumes, etc.), prefer native numeric
        # values so HA can handle units/statistics.
        if self._attr_native_unit_of_measurement is not None:
            numeric = as_float(value)
            if numeric is not None:
                return cast(StateType, numeric)
        if self._attr_native_unit_of_measurement == PERCENTAGE:
            return as_float(value)
        return str(value)

    def _handle_coordinator_update(self) -> None:
        """Update state from coordinator."""
        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
        self._attr_native_value = self._read_value()
        self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        """Register coordinator listener."""
        self.async_on_remove(
            self._coordinator.async_add_listener(self._handle_coordinator_update)
        )
        self._handle_coordinator_update()


class ApexProbeSensor(SensorEntity):
    """Sensor exposing a single probe/input value."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(
        self,
        coordinator: ApexNeptuneDataUpdateCoordinator,
        entry: ConfigEntry,
        *,
        ref: ProbeRef,
    ) -> None:
        """Initialize the probe sensor.

        Args:
            coordinator: Data coordinator.
            entry: The config entry.
            ref: Probe reference.
        """
        super().__init__()
        self._coordinator = coordinator
        self._entry = entry
        self._ref = ref
        self._unsub: Callable[[], None] | None = None

        ctx = ApexFusionContext.from_entry_and_coordinator(entry, coordinator)
        coordinator_data = coordinator.data or {}

        self._attr_unique_id = f"{ctx.serial_for_ids}_probe_{ref.key}".lower()
        self._attr_name = ref.name

        # Suggest entity ids that remain unique across multiple tanks while
        # keeping friendly names clean.
        tank_slug = ctx.tank_slug_with_entry_title(entry.title)
        key_slug = str(ref.key or "").strip().lower() or slugify(ref.name) or "probe"
        self._attr_suggested_object_id = f"{tank_slug}_probe_{key_slug}"

        # Prefer grouping probes under their backing Aquabus module when the
        # controller provides module identity fields (no heuristics).
        first_probe = self._read_probe()
        module_abaddr_any: Any = first_probe.get("module_abaddr")
        module_abaddr = (
            module_abaddr_any if isinstance(module_abaddr_any, int) else None
        )

        module_hwtype_hint: str | None = None
        module_hwtype_any: Any = first_probe.get("module_hwtype")
        if isinstance(module_hwtype_any, str) and module_hwtype_any.strip():
            module_hwtype_hint = module_hwtype_any

        module_device_info: DeviceInfo | None = (
            build_aquabus_child_device_info_from_data(
                host=ctx.host,
                controller_meta=ctx.meta,
                controller_device_identifier=ctx.controller_device_identifier,
                data=coordinator_data,
                module_abaddr=module_abaddr,
                module_hwtype_hint=module_hwtype_hint,
            )
            if isinstance(module_abaddr, int)
            else None
        )

        self._attr_device_info = module_device_info or build_device_info(
            host=ctx.host,
            meta=ctx.meta,
            device_identifier=ctx.controller_device_identifier,
        )
        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
        self._apply_probe_description()
        self._attr_native_value = self._read_native_value()

    def _read_probe(self) -> dict[str, Any]:
        """Return the current probe dict from coordinator data.

        Returns:
            Probe dict for this ref, or an empty dict if missing.
        """
        coordinator_data = self._coordinator.data or {}
        probes_any = coordinator_data.get("probes", {})
        if not isinstance(probes_any, dict):
            return {}
        probes = cast(dict[str, Any], probes_any)
        p_any = probes.get(self._ref.key, {})
        return cast(dict[str, Any], p_any) if isinstance(p_any, dict) else {}

    def _apply_probe_description(self) -> None:
        """Apply icon/unit/device_class/state_class based on probe type."""
        p = self._read_probe()
        probe_type = str(p.get("type") or "").strip()
        raw_value: Any = p.get("value")
        value_f = as_float(raw_value)

        unit, device_class, state_class = units_and_meta(
            probe_name=self._ref.name,
            probe_type=probe_type,
            value=value_f,
        )

        self._attr_native_unit_of_measurement = unit
        self._attr_device_class = device_class
        self._attr_state_class = state_class
        self._attr_icon = icon_for_probe_type(probe_type, self._ref.name)

    def _read_native_value(self) -> StateType:
        """Read the current probe value from the coordinator.

        Returns:
            Current probe value in Home Assistant native format.
        """
        p = self._read_probe()
        probe_type = str(p.get("type") or "").strip().lower()

        val: Any = p.get("value")
        raw: Any = p.get("value_raw")

        out: Any = val if val is not None else raw

        # For known numeric probe types, coerce strings to float for HA.
        if probe_type in {"amps", "temp", "tmp", "ph", "alk", "ca", "mg", "cond"}:
            coerced = as_float(out)
            if coerced is not None:
                return cast(StateType, coerced)

        return cast(StateType, out)

    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
        self._apply_probe_description()
        self._attr_native_value = self._read_native_value()
        self.async_write_ha_state()

    async def async_added_to_hass(self) -> None:
        """Register coordinator update listener."""
        self._unsub = self._coordinator.async_add_listener(
            self._handle_coordinator_update
        )
        self._handle_coordinator_update()

    async def async_will_remove_from_hass(self) -> None:
        """Remove coordinator listener."""
        if self._unsub is not None:
            self._unsub()
            self._unsub = None

    # NOTE: Do not override SensorEntity.native_value; we set `_attr_native_value`.


class ApexOutletModeSensor(SensorEntity):
    """Read-only sensor that reports an outlet's current mode (Off/Auto/On)."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(
        self,
        coordinator: ApexNeptuneDataUpdateCoordinator,
        entry: ConfigEntry,
        *,
        ref: OutletRef,
    ) -> None:
        super().__init__()
        self._coordinator = coordinator
        self._entry = entry
        self._ref = ref
        self._unsub: Callable[[], None] | None = None

        ctx = ApexFusionContext.from_entry_and_coordinator(entry, coordinator)

        self._attr_unique_id = (
            f"{ctx.serial_for_ids}_outlet_mode_{ref.dedupe_key}".lower()
        )
        self._attr_name = ref.name

        tank_slug = ctx.tank_slug_with_entry_title(entry.title)
        did_slug = str(ref.dedupe_key or "").strip().lower() or "outlet"
        self._attr_suggested_object_id = f"{tank_slug}_outlet_{did_slug}_mode"

        outlet = self._find_outlet()
        outlet_type_any: Any = outlet.get("type")
        outlet_type = outlet_type_any if isinstance(outlet_type_any, str) else None
        self._attr_icon = icon_for_outlet_type(outlet_type)

        # Prefer grouping under the backing Aquabus module device when the
        # mapping is unambiguous (mirrors the SelectEntity implementation).
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

        if module_abaddr is None and module_hwtype_hint:
            module_abaddr = unambiguous_module_abaddr_from_config(
                coordinator.data or {}, module_hwtype=module_hwtype_hint
            )

        module_device_info = (
            build_aquabus_child_device_info_from_data(
                host=ctx.host,
                controller_meta=ctx.meta,
                controller_device_identifier=ctx.controller_device_identifier,
                data=coordinator.data or {},
                module_abaddr=module_abaddr,
                module_hwtype_hint=module_hwtype_hint,
            )
            if isinstance(module_abaddr, int)
            else None
        )

        self._attr_device_info = module_device_info or build_device_info(
            host=ctx.host,
            meta=ctx.meta,
            device_identifier=ctx.controller_device_identifier,
        )

        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
        self._refresh()

    def _find_outlet(self) -> dict[str, Any]:
        data = self._coordinator.data or {}
        outlets_any: Any = data.get("outlets", [])
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

    def _refresh(self) -> None:
        outlet = self._find_outlet()
        raw_state = self._read_raw_state()

        self._attr_native_value = OutletMode.option_from_raw_state(raw_state)

        attrs: dict[str, Any] = {
            "state_code": raw_state or None,
            "effective_state": OutletMode.effective_state_from_raw_state(raw_state),
        }
        for key in ("output_id", "type", "gid", "status", "intensity"):
            if key in outlet:
                attrs[key] = outlet.get(key)
        self._attr_extra_state_attributes = attrs

    def _handle_coordinator_update(self) -> None:
        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
        outlet = self._find_outlet()
        outlet_type_any: Any = outlet.get("type")
        outlet_type = outlet_type_any if isinstance(outlet_type_any, str) else None
        self._attr_icon = icon_for_outlet_type(outlet_type)
        self._refresh()
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


class ApexOutletIntensitySensor(SensorEntity):
    """Sensor exposing intensity for variable/serial outlets (0-100%)."""

    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(
        self,
        coordinator: ApexNeptuneDataUpdateCoordinator,
        entry: ConfigEntry,
        *,
        ref: OutletIntensityRef,
    ) -> None:
        super().__init__()
        self._coordinator = coordinator
        self._entry = entry
        self._ref = ref
        self._unsub: Callable[[], None] | None = None

        ctx = ApexFusionContext.from_entry_and_coordinator(entry, coordinator)
        coordinator_data = coordinator.data or {}

        self._attr_unique_id = (
            f"{ctx.serial_for_ids}_outlet_intensity_{ref.dedupe_key}".lower()
        )
        self._attr_name = ref.name

        tank_slug = ctx.tank_slug_with_entry_title(entry.title)
        did_slug = str(ref.dedupe_key or "").strip().lower() or "outlet"
        self._attr_suggested_object_id = f"{tank_slug}_outlet_{did_slug}_intensity"

        outlet = self._find_outlet()
        outlet_type_any: Any = outlet.get("type")
        outlet_type = outlet_type_any if isinstance(outlet_type_any, str) else None
        self._attr_icon = icon_for_outlet_type(outlet_type) or ICON_BRIGHTNESS_PERCENT

        module_abaddr_any: Any = outlet.get("module_abaddr")
        module_abaddr = (
            module_abaddr_any if isinstance(module_abaddr_any, int) else None
        )

        module_device_info: DeviceInfo | None = (
            build_aquabus_child_device_info_from_data(
                host=ctx.host,
                controller_meta=ctx.meta,
                controller_device_identifier=ctx.controller_device_identifier,
                data=coordinator_data,
                module_abaddr=module_abaddr,
            )
            if isinstance(module_abaddr, int)
            else None
        )

        self._attr_device_info = module_device_info or build_device_info(
            host=ctx.host,
            meta=ctx.meta,
            device_identifier=ctx.controller_device_identifier,
        )

        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
        self._refresh()

    def _find_outlet(self) -> dict[str, Any]:
        data = self._coordinator.data or {}
        outlets_any: Any = data.get("outlets", [])
        if not isinstance(outlets_any, list):
            return {}
        for outlet_any in cast(list[Any], outlets_any):
            if not isinstance(outlet_any, dict):
                continue
            outlet = cast(dict[str, Any], outlet_any)
            if str(outlet.get("device_id") or "") == self._ref.did:
                return outlet
        return {}

    def _refresh(self) -> None:
        outlet = self._find_outlet()
        intensity_any: Any = outlet.get("intensity")
        if isinstance(intensity_any, (int, float)) and not isinstance(
            intensity_any, bool
        ):
            self._attr_native_value = float(intensity_any)
        else:
            self._attr_native_value = None

        attrs: dict[str, Any] = {}
        for key in ("state", "type", "output_id", "gid", "status"):
            if key in outlet:
                attrs[key] = outlet.get(key)
        self._attr_extra_state_attributes = attrs

    def _handle_coordinator_update(self) -> None:
        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
        outlet = self._find_outlet()
        outlet_type_any: Any = outlet.get("type")
        outlet_type = outlet_type_any if isinstance(outlet_type_any, str) else None
        self._attr_icon = icon_for_outlet_type(outlet_type) or ICON_BRIGHTNESS_PERCENT
        self._refresh()
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
