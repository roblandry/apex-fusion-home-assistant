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

from .const import CONF_HOST, DOMAIN
from .coordinator import ApexNeptuneDataUpdateCoordinator


@dataclass(frozen=True)
class _BinaryRef:
    """Reference to a coordinator boolean field."""

    key: str
    name: str
    icon: str | None
    value_fn: Callable[[dict[str, Any]], bool | None]


@dataclass(frozen=True)
class _DigitalProbeRef:
    key: str
    name: str


def _as_int_0_1(value: Any) -> int | None:
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, int):
        return value if value in (0, 1) else None
    if isinstance(value, float):
        if value in (0.0, 1.0):
            return int(value)
        return None
    if isinstance(value, str):
        t = value.strip()
        if t in {"0", "1"}:
            return int(t)
        return None
    return None


def _build_device_info(
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


def _network_bool(field: str) -> Callable[[dict[str, Any]], bool | None]:
    """Return a function that extracts a boolean-ish network field."""

    def _get(data: dict[str, Any]) -> bool | None:
        network_any: Any = data.get("network")
        if not isinstance(network_any, dict):
            return None
        network = cast(dict[str, Any], network_any)
        value: Any = network.get(field)
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return bool(value)
        return None

    return _get


def _trident_is_testing(data: dict[str, Any]) -> bool | None:
    trident_any: Any = data.get("trident")
    if not isinstance(trident_any, dict):
        return None
    trident = cast(dict[str, Any], trident_any)
    value: Any = trident.get("is_testing")
    if isinstance(value, bool):
        return value
    return None


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up Apex Fusion binary sensors from a config entry."""
    coordinator: ApexNeptuneDataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id]

    added_digital_keys: set[str] = set()

    refs: list[_BinaryRef] = [
        _BinaryRef(
            key="dhcp",
            name="DHCP Enabled",
            icon="mdi:lan-connect",
            value_fn=_network_bool("dhcp"),
        ),
        _BinaryRef(
            key="wifi_enable",
            name="Wi-Fi Enabled",
            icon="mdi:wifi",
            value_fn=_network_bool("wifi_enable"),
        ),
        _BinaryRef(
            key="trident_testing",
            name="Trident Testing",
            icon="mdi:test-tube",
            value_fn=_trident_is_testing,
        ),
    ]

    entities: list[BinarySensorEntity] = [
        ApexDiagnosticBinarySensor(coordinator, entry, ref=ref) for ref in refs
    ]

    def _add_digital_probe_entities() -> None:
        data = coordinator.data or {}
        probes_any: Any = data.get("probes")
        if not isinstance(probes_any, dict):
            return
        probes = cast(dict[str, Any], probes_any)

        new_entities: list[BinarySensorEntity] = []

        for key, probe_any in probes.items():
            key_str = str(key)
            if not key_str or key_str in added_digital_keys:
                continue
            if not isinstance(probe_any, dict):
                continue
            probe = cast(dict[str, Any], probe_any)
            probe_type = str(probe.get("type") or "").strip().lower()
            if probe_type != "digital":
                continue
            probe_name = str(probe.get("name") or key_str).strip() or key_str
            friendly = probe_name.replace("_", " ").strip()
            new_entities.append(
                ApexDigitalProbeBinarySensor(
                    coordinator,
                    entry,
                    ref=_DigitalProbeRef(key=key_str, name=friendly),
                )
            )
            added_digital_keys.add(key_str)

        if new_entities:
            async_add_entities(new_entities)

    _add_digital_probe_entities()
    remove = coordinator.async_add_listener(_add_digital_probe_entities)
    entry.async_on_unload(remove)

    async_add_entities(entities)


class ApexDigitalProbeBinarySensor(BinarySensorEntity):
    """Binary sensor for Apex digital inputs.

    Controller values are 0/1. For Home Assistant's `opening` device class,
    `on` means OPEN and `off` means CLOSED.
    """

    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_device_class = BinarySensorDeviceClass.OPENING
    _attr_icon = "mdi:toggle-switch-outline"

    def __init__(
        self,
        coordinator: ApexNeptuneDataUpdateCoordinator,
        entry: ConfigEntry,
        *,
        ref: _DigitalProbeRef,
    ) -> None:
        super().__init__()
        self._coordinator = coordinator
        self._entry = entry
        self._ref = ref

        host = str(entry.data.get(CONF_HOST, ""))
        meta_any: Any = (coordinator.data or {}).get("meta", {})
        meta = cast(dict[str, Any], meta_any) if isinstance(meta_any, dict) else {}
        serial = str(meta.get("serial") or host or "apex").replace(":", "_")

        self._attr_unique_id = f"{serial}_digital_{ref.key}".lower()
        self._attr_name = ref.name
        self._attr_device_info = _build_device_info(
            host=host,
            meta=meta,
            device_identifier=coordinator.device_identifier,
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

        v = _as_int_0_1(raw)
        # HA convention for `opening`: True means OPEN.
        self._attr_is_on = (v == 1) if v is not None else None

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
    ) -> None:
        """Initialize the binary sensor."""
        super().__init__()
        self._coordinator = coordinator
        self._entry = entry
        self._ref = ref

        host = str(entry.data.get(CONF_HOST, ""))
        meta_any: Any = (coordinator.data or {}).get("meta", {})
        meta = cast(dict[str, Any], meta_any) if isinstance(meta_any, dict) else {}
        serial = str(meta.get("serial") or host or "apex").replace(":", "_")

        self._attr_unique_id = f"{serial}_diag_bool_{ref.key}".lower()
        self._attr_name = ref.name
        self._attr_icon = ref.icon
        self._attr_device_info = _build_device_info(
            host=host,
            meta=meta,
            device_identifier=coordinator.device_identifier,
        )

        self._attr_available = bool(
            getattr(self._coordinator, "last_update_success", True)
        )
        self._attr_is_on = self._read_value()

    def _read_value(self) -> bool | None:
        """Read boolean state from coordinator."""
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
