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

from .const import CONF_HOST, DOMAIN
from .coordinator import (
    ApexNeptuneDataUpdateCoordinator,
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


def _trident_waste_full(data: dict[str, Any]) -> bool | None:
    trident_any: Any = data.get("trident")
    if not isinstance(trident_any, dict):
        return None
    trident = cast(dict[str, Any], trident_any)
    value: Any = trident.get("waste_full")
    if isinstance(value, bool):
        return value
    return None


def _trident_reagent_empty(field: str) -> Callable[[dict[str, Any]], bool | None]:
    def _get(data: dict[str, Any]) -> bool | None:
        trident_any: Any = data.get("trident")
        if not isinstance(trident_any, dict):
            return None
        trident = cast(dict[str, Any], trident_any)
        value: Any = trident.get(field)
        if isinstance(value, bool):
            return value
        return None

    return _get


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

    added_trident_testing = False
    added_trident_waste_full = False
    added_trident_reagent_empty = False

    def _get_trident_device_info(trident: dict[str, Any]) -> DeviceInfo | None:
        abaddr_any: Any = trident.get("abaddr")
        if not isinstance(abaddr_any, int):
            return None

        host = str(entry.data.get(CONF_HOST, ""))
        meta_any: Any = (coordinator.data or {}).get("meta", {})
        meta = cast(dict[str, Any], meta_any) if isinstance(meta_any, dict) else {}

        return build_trident_device_info(
            host=host,
            meta=meta,
            controller_device_identifier=coordinator.device_identifier,
            trident_abaddr=abaddr_any,
            trident_hwtype=(str(trident.get("hwtype") or "").strip().upper() or None),
            trident_hwrev=(str(trident.get("hwrev") or "").strip() or None),
            trident_swrev=(str(trident.get("swrev") or "").strip() or None),
            trident_serial=(str(trident.get("serial") or "").strip() or None),
        )

    def _add_trident_testing_entity() -> None:
        nonlocal added_trident_testing
        if added_trident_testing:
            return

        data = coordinator.data or {}
        trident_any: Any = data.get("trident")
        if not isinstance(trident_any, dict):
            return
        trident = cast(dict[str, Any], trident_any)
        if not trident.get("present"):
            return

        trident_device_info = _get_trident_device_info(trident)
        trident_prefix = "" if trident_device_info is not None else "Trident "

        ref = _BinaryRef(
            key="trident_testing",
            name=f"{trident_prefix}Testing".strip(),
            icon="mdi:test-tube",
            value_fn=_trident_is_testing,
        )
        tank_slug = slugify(str(entry.title or "tank").strip())
        abaddr = (
            cast(int, trident.get("abaddr"))
            if isinstance(trident.get("abaddr"), int)
            else None
        )
        addr_slug = f"trident_addr{abaddr}" if isinstance(abaddr, int) else "trident"
        async_add_entities(
            [
                ApexBinarySensor(
                    coordinator,
                    entry,
                    ref=ref,
                    device_info=trident_device_info,
                    suggested_object_id=f"{tank_slug}_{addr_slug}_testing",
                )
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
        trident_any: Any = data.get("trident")
        if not isinstance(trident_any, dict):
            return
        trident = cast(dict[str, Any], trident_any)
        if not trident.get("present"):
            return

        trident_device_info = _get_trident_device_info(trident)
        trident_prefix = "" if trident_device_info is not None else "Trident "

        ref = _BinaryRef(
            key="trident_waste_full",
            name=f"{trident_prefix}Waste Full".strip(),
            icon="mdi:trash-can-alert",
            value_fn=_trident_waste_full,
        )
        tank_slug = slugify(str(entry.title or "tank").strip())
        abaddr = (
            cast(int, trident.get("abaddr"))
            if isinstance(trident.get("abaddr"), int)
            else None
        )
        addr_slug = f"trident_addr{abaddr}" if isinstance(abaddr, int) else "trident"
        async_add_entities(
            [
                ApexTridentWasteFullBinarySensor(
                    coordinator,
                    entry,
                    ref=ref,
                    device_info=trident_device_info,
                    suggested_object_id=f"{tank_slug}_{addr_slug}_waste_full",
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
        trident_any: Any = data.get("trident")
        if not isinstance(trident_any, dict):
            return
        trident = cast(dict[str, Any], trident_any)
        if not trident.get("present"):
            return

        trident_device_info = _get_trident_device_info(trident)
        trident_prefix = "" if trident_device_info is not None else "Trident "

        refs = [
            _BinaryRef(
                key="trident_reagent_a_empty",
                name=f"{trident_prefix}Reagent A Empty".strip(),
                icon="mdi:flask-empty",
                value_fn=_trident_reagent_empty("reagent_a_empty"),
            ),
            _BinaryRef(
                key="trident_reagent_b_empty",
                name=f"{trident_prefix}Reagent B Empty".strip(),
                icon="mdi:flask-empty",
                value_fn=_trident_reagent_empty("reagent_b_empty"),
            ),
            _BinaryRef(
                key="trident_reagent_c_empty",
                name=f"{trident_prefix}Reagent C Empty".strip(),
                icon="mdi:flask-empty",
                value_fn=_trident_reagent_empty("reagent_c_empty"),
            ),
        ]

        tank_slug = slugify(str(entry.title or "tank").strip())
        abaddr = (
            cast(int, trident.get("abaddr"))
            if isinstance(trident.get("abaddr"), int)
            else None
        )
        addr_slug = f"trident_addr{abaddr}" if isinstance(abaddr, int) else "trident"

        async_add_entities(
            [
                ApexTridentReagentEmptyBinarySensor(
                    coordinator,
                    entry,
                    ref=r,
                    device_info=trident_device_info,
                    suggested_object_id=f"{tank_slug}_{addr_slug}_{r.key.removeprefix('trident_')}",
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
        self._attr_device_info = build_device_info(
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
        if suggested_object_id:
            self._attr_suggested_object_id = suggested_object_id
        self._attr_icon = ref.icon
        self._attr_device_info = device_info or build_device_info(
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

        host = str(entry.data.get(CONF_HOST, ""))
        meta_any: Any = (coordinator.data or {}).get("meta", {})
        meta = cast(dict[str, Any], meta_any) if isinstance(meta_any, dict) else {}
        serial = str(meta.get("serial") or host or "apex").replace(":", "_")

        # Use a distinct unique_id prefix so entity ids differ from diagnostics.
        self._attr_unique_id = f"{serial}_bool_{ref.key}".lower()


class ApexTridentWasteFullBinarySensor(ApexDiagnosticBinarySensor):
    """Binary sensor for Trident waste-full condition."""

    _attr_device_class = BinarySensorDeviceClass.PROBLEM


class ApexTridentReagentEmptyBinarySensor(ApexDiagnosticBinarySensor):
    """Binary sensor for Trident reagent-empty condition."""

    _attr_device_class = BinarySensorDeviceClass.PROBLEM
