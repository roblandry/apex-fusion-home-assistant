"""Tests for Apex Fusion sensor platform."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, cast

import pytest
from homeassistant.const import PERCENTAGE
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.apex_fusion.const import CONF_HOST, DOMAIN


@dataclass
class _CoordinatorStub:
    data: dict[str, Any]
    last_update_success: bool = True
    device_identifier: str = "TEST"

    def async_add_listener(
        self, update_callback: Callable[[], None]
    ) -> Callable[[], None]:
        def _unsub() -> None:
            return None

        return _unsub


def test_sensor_helpers_cover_all_branches():
    from custom_components.apex_fusion import sensor

    assert sensor._icon_for_probe_type("tmp", "Tmp") == "mdi:thermometer"
    assert sensor._icon_for_probe_type("ph", "pH") == "mdi:ph"
    assert sensor._icon_for_probe_type("cond", "salt") == "mdi:shaker-outline"
    assert sensor._icon_for_probe_type("cond", "conductivity") == "mdi:flash"
    assert sensor._icon_for_probe_type("amps", "Amps") == "mdi:current-ac"
    assert sensor._icon_for_probe_type("alk", "Alk") == "mdi:test-tube"
    assert sensor._icon_for_probe_type("ca", "Ca") == "mdi:flask"
    assert sensor._icon_for_probe_type("mg", "Mg") == "mdi:flask-outline"
    assert sensor._icon_for_probe_type("other", "x") == "mdi:gauge"

    assert sensor._friendly_probe_name(name="Tmp", probe_type="Tmp") == "Temperature"
    assert sensor._friendly_probe_name(name="Temp", probe_type="Temp") == "Temperature"
    assert sensor._friendly_probe_name(name="T1", probe_type="Tmp") == "T1"

    assert sensor.pretty_model("Nero5") == "Nero 5"
    assert sensor.pretty_model("Nero") == "Nero"
    assert sensor.pretty_model("123") == "123"
    assert sensor.pretty_model("A1B") == "A1B"
    assert sensor.pretty_model("") == ""

    assert (
        sensor.friendly_outlet_name(
            outlet_name="Nero_5_F", outlet_type="MXMPump|AI|Nero5"
        )
        == "AI Nero 5 (Nero 5 F)"
    )
    # pretty_name already included in label -> label only
    assert (
        sensor.friendly_outlet_name(
            outlet_name="Nero_5", outlet_type="MXMPump|AI|Nero5"
        )
        == "AI Nero 5"
    )
    assert (
        sensor.friendly_outlet_name(outlet_name="Heater_1", outlet_type=None)
        == "Heater 1"
    )
    assert sensor.friendly_outlet_name(outlet_name="", outlet_type="x") == ""

    assert sensor._temp_unit(25.0).endswith("C")
    assert sensor._temp_unit(80.0).endswith("F")

    assert sensor._as_float(1) == 1.0
    assert sensor._as_float(1.5) == 1.5
    assert sensor._as_float(" 2.5 ") == 2.5
    assert sensor._as_float(" ") is None
    assert sensor._as_float("nope") is None
    assert sensor._as_float(object()) is None

    assert (
        sensor._units_and_meta(probe_name="x", probe_type="amps", value=1.0)[0]
        is not None
    )
    assert sensor._units_and_meta(probe_name="x", probe_type="ph", value=8.1)[0] is None
    assert (
        sensor._units_and_meta(probe_name="x", probe_type="alk", value=7.0)[0] == "dKH"
    )
    assert (
        sensor._units_and_meta(probe_name="x", probe_type="ca", value=420.0)[0] == "ppm"
    )
    assert (
        sensor._units_and_meta(probe_name="x", probe_type="mg", value=1300.0)[0]
        == "ppm"
    )
    assert (
        sensor._units_and_meta(probe_name="salt", probe_type="cond", value=35.0)[0]
        == "ppt"
    )
    assert (
        sensor._units_and_meta(probe_name="cond", probe_type="cond", value=1.0)[0]
        is None
    )
    assert (
        sensor._units_and_meta(probe_name="Tmp", probe_type="tmp", value=25.0)[0]
        is not None
    )
    assert (
        sensor._units_and_meta(probe_name="x", probe_type="other", value=1.0)[0] is None
    )

    assert sensor.icon_for_outlet_type("pump") == "mdi:pump"
    assert sensor.icon_for_outlet_type("light") == "mdi:lightbulb"
    assert sensor.icon_for_outlet_type("heater") == "mdi:radiator"
    assert sensor.icon_for_outlet_type("other") == "mdi:power-socket-us"

    # network/meta field helpers
    nf = sensor._network_field("ipaddr")
    mf = sensor._meta_field("firmware_latest")
    assert nf({"network": {"ipaddr": "1.2.3.4"}}) == "1.2.3.4"
    assert nf({"network": "nope"}) is None
    assert mf({"meta": {"firmware_latest": "1.0"}}) == "1.0"
    assert mf({"meta": "nope"}) is None


async def test_sensor_setup_creates_entities_and_updates(
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
            "meta": {"serial": "ABC", "firmware_latest": "9.99", "hostname": "apex"},
            "network": {"ipaddr": "1.2.3.4", "strength": "75", "quality": 80},
            "probes": {
                "": {"name": "", "type": "Tmp", "value": "25", "value_raw": None},
                "T1": {"name": "Tmp", "type": "Tmp", "value": "25", "value_raw": None},
                "PH": {"name": "pH", "type": "pH", "value": 8.1, "value_raw": None},
                "BAD": "nope",
            },
            "outlets": [
                "nope",
                {"name": "MissingDid"},
                {
                    "name": "Nero_5_F",
                    "device_id": "O1",
                    "state": "AON",
                    "type": "MXMPump|AI|Nero5",
                    "output_id": "1",
                    "gid": "g",
                    "status": ["AON"],
                },
            ],
            "mxm_devices": {"Nero_5_F": {"rev": "1", "serial": "S", "status": "OK"}},
        },
        last_update_success=True,
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import sensor

    await sensor.async_setup_entry(hass, cast(Any, entry), _add_entities)

    # Probes (2) + diagnostics
    assert len(added) >= 3

    # Exercise entity update handlers and remove handlers.
    for ent in added:
        ent.async_write_ha_state = lambda *args, **kwargs: None
        await ent.async_added_to_hass()

    probe_entities = [e for e in added if isinstance(e, sensor.ApexProbeSensor)]
    assert probe_entities

    # Update probe values to hit coercion/branches.
    coordinator.data["probes"]["T1"]["value"] = 26
    coordinator.data["probes"]["T1"]["value_raw"] = "26"
    coordinator.last_update_success = False

    for ent in added:
        if hasattr(ent, "_handle_coordinator_update"):
            ent._handle_coordinator_update()
        if getattr(ent, "_attr_native_unit_of_measurement", None) == PERCENTAGE:
            # Ensure percentage string/int path exercised.
            assert ent._attr_native_value in (75.0, 80.0, None)

    # Cover probe/outlet internal branches when backing data changes type.
    coordinator.data["probes"] = "nope"
    probe_entities[0]._handle_coordinator_update()
    coordinator.data["probes"] = {"T1": "nope"}
    probe_entities[0]._handle_coordinator_update()

    # Ensure will_remove cleans up unsub on probe/outlet sensors.
    for ent in added:
        if hasattr(ent, "async_will_remove_from_hass"):
            await ent.async_will_remove_from_hass()


async def test_sensor_setup_without_network_or_firmware_adds_no_diagnostics(
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
            "meta": {"serial": "ABC"},
            "network": {},
            "probes": {},
            "outlets": [],
        },
        last_update_success=True,
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import sensor

    await sensor.async_setup_entry(hass, cast(Any, entry), _add_entities)

    # Diagnostic entities are always created (even if values are None) so they
    # don't disappear when the first poll falls back to legacy data.
    assert len(added) == 7


async def test_sensor_simple_rest_debug_mode_creates_one_entity_and_updates(
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
            "raw": {"k": 1},
            "probes": {"T1": {}},
            "outlets": [{"device_id": "O1"}],
        },
        last_update_success=True,
        device_identifier="ABC",
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import sensor

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(sensor, "_SIMPLE_REST_SINGLE_SENSOR_MODE", True)
        await sensor.async_setup_entry(hass, cast(Any, entry), _add_entities)

    assert len(added) == 1
    ent = added[0]
    assert isinstance(ent, sensor.ApexRestDebugSensor)

    # Cover coordinator update behavior both when entity isn't attached
    # to hass and when it is.
    ent.async_write_ha_state = lambda *args, **kwargs: None
    ent._handle_coordinator_update()

    await ent.async_added_to_hass()

    ent.hass = hass
    ent._handle_coordinator_update()

    # Source not rest -> unavailable
    coordinator.data["meta"]["source"] = "xml"
    ent._handle_coordinator_update()

    # Type handling: raw not dict, probes/outlets wrong types.
    coordinator.data["meta"]["source"] = "rest"
    coordinator.data["raw"] = "nope"
    coordinator.data["probes"] = "nope"
    coordinator.data["outlets"] = "nope"
    ent._handle_coordinator_update()
