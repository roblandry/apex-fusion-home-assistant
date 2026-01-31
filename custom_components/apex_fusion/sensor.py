"""Sensors for Apex Fusion (Local).

This platform exposes:
- Probe/input sensors.
- Output/outlet status sensors.

Entities are coordinator-driven and do not poll independently.
"""

from __future__ import annotations

from dataclasses import dataclass
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
    UnitOfElectricCurrent,
    UnitOfTemperature,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import StateType

from .const import CONF_HOST, DOMAIN
from .coordinator import ApexNeptuneDataUpdateCoordinator

_SIMPLE_REST_SINGLE_SENSOR_MODE = False


def _icon_for_probe_type(probe_type: str, probe_name: str) -> str | None:
    """Return an icon for a probe based on its reported type/name.

    Args:
        probe_type: Probe type identifier from the controller.
        probe_name: Probe name.

    Returns:
        An mdi icon string.
    """
    t = (probe_type or "").strip().lower()
    n = (probe_name or "").strip().lower()

    if t in {"temp", "tmp"}:
        return "mdi:thermometer"
    if t == "ph":
        return "mdi:ph"
    if t == "cond":
        return "mdi:shaker-outline" if n.startswith("salt") else "mdi:flash"
    if t == "amps":
        return "mdi:current-ac"
    if t == "alk":
        return "mdi:test-tube"
    if t == "ca":
        return "mdi:flask"
    if t == "mg":
        return "mdi:flask-outline"
    return "mdi:gauge"


def _friendly_probe_name(*, name: str, probe_type: str | None) -> str:
    """Return a nicer display name for common probes.

    Args:
        name: Raw probe name from the controller.
        probe_type: Raw probe type.

    Returns:
        Friendly name.
    """
    n = (name or "").strip()
    t = (probe_type or "").strip().lower()
    if t in {"temp", "tmp"} and n.lower() in {"tmp", "temp"}:
        return "Temperature"
    return n


def pretty_model(s: str) -> str:
    """Prettify model tokens like 'Nero5' -> 'Nero 5'."""
    t = (s or "").strip()
    if not t:
        return t

    # Split first run of letters from trailing digits.
    split_at: int | None = None
    for idx, ch in enumerate(t):
        if ch.isdigit():
            split_at = idx
            break

    if split_at is None or split_at == 0:
        return t

    prefix = t[:split_at]
    suffix = t[split_at:]
    if suffix.isdigit() and prefix.isalpha():
        return f"{prefix} {suffix}"

    return t


def friendly_outlet_name(*, outlet_name: str, outlet_type: str | None) -> str:
    """Return a better entity name for an outlet/output.

    Examples:
        type='MXMPump|AI|Nero5', name='Nero_5_F' -> 'AI Nero 5 (Nero 5 F)'

    Args:
        outlet_name: Raw outlet name.
        outlet_type: Raw outlet type string.

    Returns:
        Friendly name.
    """
    raw_name = (outlet_name or "").strip()
    raw_type = (outlet_type or "").strip()
    if not raw_name:
        return raw_name

    # Nice display for common MXM types: MXMPump|AI|Nero5, etc.
    parts = [p.strip() for p in raw_type.split("|") if p.strip()]
    if len(parts) >= 3 and parts[0].upper().startswith("MXM"):
        vendor = parts[1]
        model = pretty_model(parts[2])
        pretty_name = raw_name.replace("_", " ").strip()
        label = f"{vendor} {model}".strip()
        if pretty_name and pretty_name.lower() not in label.lower():
            return f"{label} ({pretty_name})"
        return label

    return raw_name.replace("_", " ").strip()


def _temp_unit(value: float | None) -> UnitOfTemperature:
    """Choose temperature unit.

    Args:
        value: Current temperature value (if numeric).

    Returns:
        Home Assistant temperature unit.
    """
    # Heuristic: allow mixed °F/°C probes; values <= 45 usually mean °C.
    if value is not None and value <= 45:
        return UnitOfTemperature.CELSIUS
    return UnitOfTemperature.FAHRENHEIT


def _as_float(value: Any) -> float | None:
    """Best-effort conversion to float.

    Args:
        value: Any value.

    Returns:
        Float value if convertible, otherwise None.
    """
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        t = value.strip()
        if not t:
            return None
        try:
            return float(t)
        except ValueError:
            return None
    return None


def _units_and_meta(
    *,
    probe_name: str,
    probe_type: str,
    value: float | None,
) -> tuple[str | None, SensorDeviceClass | None, SensorStateClass | None]:
    """Return units and sensor metadata for a probe.

    Args:
        probe_name: Probe name.
        probe_type: Probe type identifier.
        value: Current value as float (if numeric).
    Returns:
        Tuple of (unit, device_class, state_class).
    """
    t = (probe_type or "").strip().lower()
    _ = (probe_name or "").strip().lower()

    if t == "amps":
        return (
            UnitOfElectricCurrent.AMPERE,
            SensorDeviceClass.CURRENT,
            SensorStateClass.MEASUREMENT,
        )
    if t == "ph":
        return None, None, SensorStateClass.MEASUREMENT
    if t == "alk":
        return "dKH", None, SensorStateClass.MEASUREMENT
    if t in ("ca", "mg"):
        return "ppm", None, SensorStateClass.MEASUREMENT
    if t == "cond":
        return "ppt", None, SensorStateClass.MEASUREMENT
    if t in {"temp", "tmp"}:
        return (
            _temp_unit(value),
            SensorDeviceClass.TEMPERATURE,
            SensorStateClass.MEASUREMENT,
        )

    return None, None, SensorStateClass.MEASUREMENT


def icon_for_outlet_type(outlet_type: str | None) -> str | None:
    """Return an icon for an outlet based on its device type."""
    t = (outlet_type or "").strip().upper()
    if "PUMP" in t:
        return "mdi:pump"
    if "LIGHT" in t:
        return "mdi:lightbulb"
    if "HEATER" in t:
        return "mdi:radiator"
    return "mdi:power-socket-us"


@dataclass(frozen=True)
class _ProbeRef:
    """Reference to a probe/input exposed by the controller."""

    key: str
    name: str


def _network_field(field: str) -> Callable[[dict[str, Any]], Any]:
    """Return a function that extracts a network field from coordinator data."""

    def _get(data: dict[str, Any]) -> Any:
        network_any = data.get("network")
        if isinstance(network_any, dict):
            network = cast(dict[str, Any], network_any)
            return network.get(field)
        return None

    return _get


def _meta_field(field: str) -> Callable[[dict[str, Any]], Any]:
    """Return a function that extracts a meta field from coordinator data."""

    def _get(data: dict[str, Any]) -> Any:
        meta_any = data.get("meta")
        if isinstance(meta_any, dict):
            meta = cast(dict[str, Any], meta_any)
            return meta.get(field)
        return None

    return _get


def _section_field(section: str, field: str) -> Callable[[dict[str, Any]], Any]:
    """Return a function that extracts a field from a nested section dict."""

    def _get(data: dict[str, Any]) -> Any:
        section_any = data.get(section)
        if isinstance(section_any, dict):
            section_dict = cast(dict[str, Any], section_any)
            return section_dict.get(field)
        return None

    return _get


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

    # Developer toggle: when enabled, only expose a single REST debug sensor.
    if _SIMPLE_REST_SINGLE_SENSOR_MODE:
        async_add_entities([ApexRestDebugSensor(coordinator, entry)])
        return

    host = str(entry.data.get(CONF_HOST, ""))

    added_probe_keys: set[str] = set()

    def _add_probe_and_outlet_entities() -> None:
        coordinator_data = coordinator.data or {}
        new_entities: list[SensorEntity] = []

        probes_any = coordinator_data.get("probes", {})
        if isinstance(probes_any, dict):
            probes = cast(dict[str, Any], probes_any)
            for key, probe_any in probes.items():
                key_str = str(key)
                if not key_str or key_str in added_probe_keys:
                    continue
                probe = (
                    cast(dict[str, Any], probe_any)
                    if isinstance(probe_any, dict)
                    else {}
                )
                probe_name = str(probe.get("name") or key_str)
                probe_type = str(probe.get("type") or "")
                if probe_type.strip().lower() == "digital":
                    # Digital probes are represented as open/closed binary sensors.
                    added_probe_keys.add(key_str)
                    continue
                new_entities.append(
                    ApexProbeSensor(
                        coordinator,
                        entry,
                        ref=_ProbeRef(
                            key=key_str,
                            name=_friendly_probe_name(
                                name=probe_name, probe_type=probe_type
                            ),
                        ),
                    )
                )
                added_probe_keys.add(key_str)

        if new_entities:
            async_add_entities(new_entities)

    _add_probe_and_outlet_entities()
    remove = coordinator.async_add_listener(_add_probe_and_outlet_entities)
    entry.async_on_unload(remove)

    coordinator_data = coordinator.data or {}
    meta_any = coordinator_data.get("meta", {})
    meta = cast(dict[str, Any], meta_any) if isinstance(meta_any, dict) else {}
    serial_for_ids = str(meta.get("serial") or host or "apex").replace(":", "_")

    diagnostic_entities: list[SensorEntity] = []
    # Always create diagnostic entities so they exist even if the first poll
    # falls back to legacy data; values will populate once REST fields appear.
    diagnostic_entities.extend(
        [
            ApexDiagnosticSensor(
                coordinator,
                entry,
                unique_id=f"{serial_for_ids}_diag_ipaddr".lower(),
                name="IP Address",
                icon="mdi:ip-network",
                value_fn=_network_field("ipaddr"),
            ),
            ApexDiagnosticSensor(
                coordinator,
                entry,
                unique_id=f"{serial_for_ids}_diag_gateway".lower(),
                name="Gateway",
                icon="mdi:router-network",
                value_fn=_network_field("gateway"),
            ),
            ApexDiagnosticSensor(
                coordinator,
                entry,
                unique_id=f"{serial_for_ids}_diag_netmask".lower(),
                name="Netmask",
                icon="mdi:ip-network-outline",
                value_fn=_network_field("netmask"),
            ),
            ApexDiagnosticSensor(
                coordinator,
                entry,
                unique_id=f"{serial_for_ids}_diag_ssid".lower(),
                name="Wi-Fi SSID",
                icon="mdi:wifi-settings",
                value_fn=_network_field("ssid"),
            ),
            ApexDiagnosticSensor(
                coordinator,
                entry,
                unique_id=f"{serial_for_ids}_diag_wifi_strength".lower(),
                name="Wi-Fi Strength",
                icon="mdi:wifi-strength-4",
                native_unit=PERCENTAGE,
                value_fn=_network_field("strength"),
            ),
            ApexDiagnosticSensor(
                coordinator,
                entry,
                unique_id=f"{serial_for_ids}_diag_wifi_quality".lower(),
                name="Wi-Fi Quality",
                icon="mdi:signal",
                native_unit=PERCENTAGE,
                value_fn=_network_field("quality"),
            ),
            ApexDiagnosticSensor(
                coordinator,
                entry,
                unique_id=f"{serial_for_ids}_diag_latest_firmware".lower(),
                name="Latest Firmware",
                icon="mdi:update",
                value_fn=_meta_field("firmware_latest"),
            ),
            ApexDiagnosticSensor(
                coordinator,
                entry,
                unique_id=f"{serial_for_ids}_diag_last_alert_statement".lower(),
                name="Last Alert Statement",
                icon="mdi:alert-circle-outline",
                value_fn=_section_field("alerts", "last_statement"),
            ),
            ApexDiagnosticSensor(
                coordinator,
                entry,
                unique_id=f"{serial_for_ids}_diag_trident_status".lower(),
                name="Trident Status",
                icon="mdi:flask-outline",
                value_fn=_section_field("trident", "status"),
            ),
        ]
    )

    if diagnostic_entities:
        async_add_entities(diagnostic_entities)


def build_device_info(
    *, host: str, meta: dict[str, Any], device_identifier: str
) -> DeviceInfo:
    """Build DeviceInfo for this controller.

    Args:
        host: Controller host/IP.
        meta: Coordinator meta dict.

    Returns:
        DeviceInfo instance.
    """
    serial = str(meta.get("serial") or "").strip() or None
    model = str(meta.get("type") or meta.get("hardware") or "Apex").strip() or "Apex"
    name = str(meta.get("hostname") or f"Apex ({host})")

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
    )


class ApexRestDebugSensor(SensorEntity):
    """Single minimal sensor to validate REST status parsing."""

    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:bug-outline"

    def __init__(
        self,
        coordinator: ApexNeptuneDataUpdateCoordinator,
        entry: ConfigEntry,
    ) -> None:
        super().__init__()
        self._coordinator = coordinator
        self._entry = entry

        host = str(entry.data.get(CONF_HOST, ""))
        meta_any = (coordinator.data or {}).get("meta", {})
        meta = cast(dict[str, Any], meta_any) if isinstance(meta_any, dict) else {}

        serial = str(meta.get("serial") or host or "apex").replace(":", "_")
        self._attr_unique_id = f"{serial}_rest_debug_keys".lower()
        self._attr_name = "REST Status Keys"
        self._attr_device_info = build_device_info(
            host=host,
            meta=meta,
            device_identifier=coordinator.device_identifier,
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
        native_unit: str | None = None,
        icon: str | None = None,
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

        host = str(entry.data.get(CONF_HOST, ""))
        meta = cast(dict[str, Any], (coordinator.data or {}).get("meta", {}))

        self._attr_unique_id = unique_id
        self._attr_name = name
        self._attr_native_unit_of_measurement = native_unit
        self._attr_icon = icon
        self._attr_device_info = build_device_info(
            host=host,
            meta=meta,
            device_identifier=coordinator.device_identifier,
        )

        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
        self._attr_native_value = self._read_value()

    def _read_value(self) -> StateType:
        """Read current value from coordinator data."""
        data = self._coordinator.data or {}
        value = self._value_fn(data)
        if value is None:
            return None
        if self._attr_native_unit_of_measurement == PERCENTAGE:
            return _as_float(value)
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
        ref: _ProbeRef,
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

        host = str(entry.data.get(CONF_HOST, ""))
        coordinator_data = coordinator.data or {}
        meta = cast(dict[str, Any], coordinator_data.get("meta", {}))
        serial = str(meta.get("serial") or host or "apex").replace(":", "_")

        self._attr_unique_id = f"{serial}_probe_{ref.key}".lower()
        self._attr_name = ref.name

        self._attr_device_info = build_device_info(
            host=host,
            meta=meta,
            device_identifier=coordinator.device_identifier,
        )
        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
        self._apply_probe_description()
        self._attr_native_value = self._read_native_value()

    def _read_probe(self) -> dict[str, Any]:
        """Return the current probe dict from coordinator data."""
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
        value_f = _as_float(raw_value)

        unit, device_class, state_class = _units_and_meta(
            probe_name=self._ref.name,
            probe_type=probe_type,
            value=value_f,
        )

        self._attr_native_unit_of_measurement = unit
        self._attr_device_class = device_class
        self._attr_state_class = state_class
        self._attr_icon = _icon_for_probe_type(probe_type, self._ref.name)

    def _read_native_value(self) -> StateType:
        """Read the current probe value from the coordinator."""
        p = self._read_probe()
        probe_type = str(p.get("type") or "").strip().lower()

        val: Any = p.get("value")
        raw: Any = p.get("value_raw")

        out: Any = val if val is not None else raw

        # For known numeric probe types, coerce strings to float for HA.
        if probe_type in {"amps", "temp", "tmp", "ph", "alk", "ca", "mg", "cond"}:
            coerced = _as_float(out)
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
