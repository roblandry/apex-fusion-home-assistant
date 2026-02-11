"""Tests for Apex Fusion binary sensor platform."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, cast

from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.apex_fusion.const import CONF_HOST, DOMAIN


def test_binary_sensor_int_coercion_helpers_cover_branches():
    from custom_components.apex_fusion.apex_fusion import DigitalValueCodec

    assert DigitalValueCodec.as_int_0_1(False) == 0
    assert DigitalValueCodec.as_int_0_1(True) == 1
    assert DigitalValueCodec.as_int_0_1(0) == 0
    assert DigitalValueCodec.as_int_0_1(1) == 1
    assert DigitalValueCodec.as_int_0_1(2) is None
    assert DigitalValueCodec.as_int_0_1(100) == 1
    assert DigitalValueCodec.as_int_0_1(200) == 0
    assert DigitalValueCodec.as_int_0_1(0.0) == 0
    assert DigitalValueCodec.as_int_0_1(1.0) == 1
    assert DigitalValueCodec.as_int_0_1(0.5) is None
    assert DigitalValueCodec.as_int_0_1("0") == 0
    assert DigitalValueCodec.as_int_0_1(" 1 ") == 1
    assert DigitalValueCodec.as_int_0_1("100") == 1
    assert DigitalValueCodec.as_int_0_1("200") == 0
    assert DigitalValueCodec.as_int_0_1("nope") is None
    assert DigitalValueCodec.as_int_0_1(object()) is None


def test_trident_reagent_empty_extractor_returns_bool():
    from custom_components.apex_fusion.apex_fusion import trident_reagent_empty

    fn = trident_reagent_empty("reagent_a_empty")
    assert fn({"trident": {"reagent_a_empty": True}}) is True


@dataclass
class _CoordinatorStub:
    data: dict[str, Any]
    last_update_success: bool = True
    device_identifier: str = "TEST"
    listeners: list[Callable[[], None]] | None = None

    def async_add_listener(
        self, update_callback: Callable[[], None]
    ) -> Callable[[], None]:
        if self.listeners is not None:
            self.listeners.append(update_callback)

        # Immediately callable unsub.
        def _unsub() -> None:
            return None

        return _unsub


async def test_binary_sensor_setup_and_updates(hass, enable_custom_integrations):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    listeners: list[Callable[[], None]] = []
    coordinator = _CoordinatorStub(
        data={
            "meta": {"serial": "ABC", "source": "rest"},
            "network": {"dhcp": True, "wifi_enable": 1},
            "config": {"mconf": [{"abaddr": 3, "hwtype": "FMM", "name": "My FMM"}]},
            "trident": {
                "present": True,
                "abaddr": 5,
                "is_testing": True,
                "waste_full": True,
            },
            "probes": {
                "DI1": {
                    "name": "Door_1",
                    "type": "digital",
                    "value": 0,
                    "module_abaddr": 3,
                },
            },
        },
        last_update_success=True,
        device_identifier="ABC",
        listeners=listeners,
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import binary_sensor

    await binary_sensor.async_setup_entry(hass, cast(Any, entry), _add_entities)

    # Exercise platform listeners before entities are added to hass:
    # - re-running should be idempotent and cover the guard branch.
    for cb in list(listeners):
        cb()

    assert len(added) == 8

    digital = next(
        (e for e in added if isinstance(e, binary_sensor.ApexDigitalProbeBinarySensor)),
        None,
    )
    assert digital is not None
    assert digital.device_info is not None
    assert digital.device_info.get("name") == "My FMM"
    assert digital.device_info.get("via_device") == (DOMAIN, "ABC")

    # Trident binary sensors should be grouped under the Trident device when abaddr is known.
    trident_testing = next(
        (
            e
            for e in added
            if isinstance(e, binary_sensor.ApexDiagnosticBinarySensor)
            and getattr(e, "_attr_name", "") == "Testing"
        ),
        None,
    )
    assert trident_testing is not None
    assert trident_testing.device_info is not None
    assert trident_testing.device_info.get("name") == "Trident (5)"
    assert trident_testing.device_info.get("via_device") == (DOMAIN, "ABC")

    for ent in added:
        # Avoid requiring full entity platform state machine.
        ent.async_write_ha_state = lambda *args, **kwargs: None
        await ent.async_added_to_hass()

    # For device_class=openings: 0 -> on/open
    assert digital._attr_is_on is True

    # Drive coordinator update branches: bool, int->bool, and unsupported -> None.
    coordinator.last_update_success = False
    coordinator.data["network"]["dhcp"] = False
    coordinator.data["network"]["wifi_enable"] = "yes"  # unsupported
    coordinator.data["trident"]["is_testing"] = "nope"  # unsupported -> None
    coordinator.data["trident"]["waste_full"] = "nope"  # unsupported -> None
    coordinator.data["trident"]["reagent_a_empty"] = "nope"  # unsupported -> None
    coordinator.data["trident"]["reagent_b_empty"] = "nope"  # unsupported -> None
    coordinator.data["trident"]["reagent_c_empty"] = "nope"  # unsupported -> None
    coordinator.data["probes"]["DI1"]["value"] = 1

    for ent in added:
        ent._handle_coordinator_update()

    # For device_class=openings: 1 -> off/closed
    assert digital._attr_is_on is False

    # Cover branch where network section is not a dict.
    coordinator.data["network"] = "nope"
    for ent in added:
        ent._handle_coordinator_update()

    # Cover branch where trident section is not a dict.
    coordinator.data["trident"] = "nope"
    for ent in added:
        ent._handle_coordinator_update()

    # Cover branch where probes section is not a dict.
    coordinator.data["probes"] = "nope"
    for ent in added:
        ent._handle_coordinator_update()


async def test_binary_sensor_digital_probe_skips_and_fallbacks(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(
        data={
            "meta": {"serial": "ABC", "source": "rest"},
            "network": {"dhcp": True, "wifi_enable": 1},
            "trident": {"present": True, "is_testing": False},
            "probes": {
                "": {"name": "EmptyKey", "type": "digital", "value": 0},
                "DI_BAD": "nope",
                "DI_NOTDIG": {"name": "Tmp", "type": "tmp", "value": 0},
                1: {"name": "Door_2", "type": "digital", "value": False},
                "1": {"name": "Door_2_Dupe", "type": "digital", "value": 0},
                "DI_RAW": {
                    "name": "Door_3",
                    "type": "digital",
                    "value": None,
                    "value_raw": "0",
                    "module_abaddr": 7,
                    "module_hwtype": "PM2",
                },
            },
        },
        last_update_success=True,
        device_identifier="ABC",
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import binary_sensor

    await binary_sensor.async_setup_entry(hass, cast(Any, entry), _add_entities)

    # 2 network diagnostic entities + Trident Testing + Trident Waste Full
    # + 3 reagent-empty + 2 valid digital probes
    assert len(added) == 9

    for ent in added:
        ent.async_write_ha_state = lambda *args, **kwargs: None
        await ent.async_added_to_hass()

    raw = next(
        (
            e
            for e in added
            if isinstance(e, binary_sensor.ApexDigitalProbeBinarySensor)
            and getattr(getattr(e, "_ref", None), "key", None) == "DI_RAW"
        ),
        None,
    )
    assert raw is not None
    assert raw.device_info is not None
    assert raw.device_info.get("name") == "Salinity Probe Module (7)"
    assert raw.device_info.get("via_device") == (DOMAIN, "ABC")
    assert raw.device_info.get("identifiers") == {(DOMAIN, "ABC_module_PM2_7")}

    # Cover _find_probe branch where probe entry is not a dict.
    coordinator.data["probes"]["1"] = "nope"
    for ent in added:
        ent._handle_coordinator_update()


async def test_binary_sensor_setup_with_non_dict_probes_still_adds_diagnostics(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(
        data={
            "meta": {"serial": "ABC", "source": "rest"},
            "network": {"dhcp": True, "wifi_enable": 1},
            "trident": {"present": False, "is_testing": False},
            "probes": "nope",
        },
        last_update_success=True,
        device_identifier="ABC",
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import binary_sensor

    await binary_sensor.async_setup_entry(hass, cast(Any, entry), _add_entities)

    # Only the 2 network diagnostic entities should be added (no Trident present).
    assert len(added) == 2


async def test_binary_sensor_setup_with_non_dict_trident_adds_no_trident_testing(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(
        data={
            "meta": {"serial": "ABC", "source": "rest"},
            "network": {"dhcp": True, "wifi_enable": 1},
            "trident": "nope",
            "probes": {},
        },
        last_update_success=True,
        device_identifier="ABC",
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import binary_sensor

    await binary_sensor.async_setup_entry(hass, cast(Any, entry), _add_entities)

    # Only the 2 network diagnostic entities should be added.
    assert len(added) == 2
