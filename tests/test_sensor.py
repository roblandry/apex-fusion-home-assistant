"""Tests for the Apex Fusion sensor platform.

These tests validate that sensor discovery and entity state behavior are
schema-tolerant and coordinator-driven.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, cast

import pytest
from homeassistant.const import PERCENTAGE
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.apex_fusion.const import CONF_HOST, DOMAIN


@dataclass
class _CoordinatorStub:
    """Minimal coordinator stub used by platform tests.

    Attributes:
        data: Coordinator data payload exposed to entities.
        last_update_success: Whether the last update succeeded.
        device_identifier: Device identifier used by device info helpers.
        listeners: Listener callbacks registered by entities.
    """

    data: dict[str, Any]
    last_update_success: bool = True
    device_identifier: str = "TEST"
    listeners: list[Callable[[], None]] | None = None

    def async_add_listener(
        self, update_callback: Callable[[], None]
    ) -> Callable[[], None]:
        """Register an update listener.

        Args:
            update_callback: Callback invoked when the coordinator updates.

        Returns:
            Callable that unregisters the listener.
        """
        if self.listeners is not None:
            self.listeners.append(update_callback)

        def _unsub() -> None:
            return None

        return _unsub


def test_sensor_helpers_cover_all_branches():
    from custom_components.apex_fusion.apex_fusion import network_field, section_field
    from custom_components.apex_fusion.apex_fusion.outputs import (
        friendly_outlet_name,
        pretty_model,
    )
    from custom_components.apex_fusion.apex_fusion.probes import (
        ProbeMetaResolver,
        as_float,
        friendly_probe_name,
        units_and_meta,
    )
    from custom_components.apex_fusion.sensor import (
        icon_for_outlet_type,
        icon_for_probe_type,
    )

    assert icon_for_probe_type("tmp", "Tmp") == "mdi:thermometer"
    assert icon_for_probe_type("ph", "pH") == "mdi:ph"
    assert icon_for_probe_type("cond", "salt") == "mdi:shaker-outline"
    assert icon_for_probe_type("cond", "conductivity") == "mdi:flash"
    assert icon_for_probe_type("amps", "Amps") == "mdi:current-ac"
    assert icon_for_probe_type("alk", "Alk") == "mdi:test-tube"
    assert icon_for_probe_type("ca", "Ca") == "mdi:flask"
    assert icon_for_probe_type("mg", "Mg") == "mdi:flask-outline"
    assert icon_for_probe_type("other", "x") == "mdi:gauge"

    assert friendly_probe_name(name="Tmp", probe_type="Tmp") == "Tmp"
    assert friendly_probe_name(name="Temp", probe_type="Temp") == "Temperature"
    assert friendly_probe_name(name="Tmp_2", probe_type="Temp") == "Temperature"
    assert friendly_probe_name(name="Tmp2", probe_type="Tmp") == "Tmp2"
    assert friendly_probe_name(name="T1", probe_type="Tmp") == "T1"

    assert friendly_probe_name(name="Alkx4", probe_type="alk") == "Alkalinity"
    assert friendly_probe_name(name="Cax4", probe_type="ca") == "Calcium"
    assert friendly_probe_name(name="Mgx4", probe_type="mg") == "Magnesium"
    assert friendly_probe_name(name="Cond", probe_type="Cond") == "Conductivity"
    assert friendly_probe_name(name="Salinity", probe_type="cond") == "Conductivity"
    assert friendly_probe_name(name="ORP", probe_type="orp") == "ORP"
    assert friendly_probe_name(name="Redox", probe_type="orp") == "ORP"

    assert friendly_probe_name(name="NO3", probe_type="no3") == "Nitrogen"
    assert friendly_probe_name(name="Nitrogen", probe_type="nitrogen") == "Nitrogen"
    assert friendly_probe_name(name="PO4", probe_type="po4") == "Phosphate"

    assert pretty_model("Nero5") == "Nero 5"
    assert pretty_model("Nero") == "Nero"
    assert pretty_model("123") == "123"
    assert pretty_model("A1B") == "A1B"
    assert pretty_model("") == ""

    assert (
        friendly_outlet_name(outlet_name="Nero_5_F", outlet_type="MXMPump|AI|Nero5")
        == "AI Nero 5 (Nero 5 F)"
    )
    assert friendly_outlet_name(outlet_name="Alk_4_4", outlet_type="selector") == (
        "Alkalinity Testing"
    )
    assert friendly_outlet_name(outlet_name="Ca_4_5", outlet_type="selector") == (
        "Ca 4 5"
    )
    assert friendly_outlet_name(outlet_name="Mg_4_6", outlet_type="selector") == (
        "Mg 4 6"
    )
    assert friendly_outlet_name(outlet_name="TNP_5_1", outlet_type="selector") == (
        "Trident NP"
    )
    assert (
        friendly_outlet_name(outlet_name="Trident_4_3", outlet_type="selector")
        == "Combined Testing"
    )

    assert units_and_meta(probe_name="Tmp", probe_type="temp", value=20.0)[0] == "°C"
    assert units_and_meta(probe_name="Tmp", probe_type="temp", value=80.0)[0] == "°F"
    assert units_and_meta(probe_name="ORP", probe_type="orp", value=300.0)[0] == "mV"
    assert units_and_meta(probe_name="NO3", probe_type="no3", value=1.0)[0] == "ppm"
    assert units_and_meta(probe_name="PO4", probe_type="po4", value=0.1)[0] == "ppm"

    # pretty_name already included in label -> label only
    assert friendly_outlet_name(
        outlet_name="Nero_5", outlet_type="MXMPump|AI|Nero5"
    ) == ("AI Nero 5")
    assert friendly_outlet_name(outlet_name="Heater_1", outlet_type=None) == "Heater 1"
    assert friendly_outlet_name(outlet_name="", outlet_type="x") == ""

    assert ProbeMetaResolver.temp_unit(25.0).endswith("C")
    assert ProbeMetaResolver.temp_unit(80.0).endswith("F")

    assert as_float(1) == 1.0
    assert as_float(1.5) == 1.5
    assert as_float(" 2.5 ") == 2.5
    assert as_float(" ") is None
    assert as_float("nope") is None
    assert as_float(object()) is None

    assert units_and_meta(probe_name="x", probe_type="amps", value=1.0)[0] is None
    assert units_and_meta(probe_name="x", probe_type="ph", value=8.1)[0] is None
    assert units_and_meta(probe_name="x", probe_type="alk", value=7.0)[0] == "dKH"
    assert units_and_meta(probe_name="x", probe_type="ca", value=420.0)[0] == "ppm"
    assert units_and_meta(probe_name="x", probe_type="mg", value=1300.0)[0] == "ppm"
    assert units_and_meta(probe_name="salt", probe_type="cond", value=35.0)[0] == "ppt"
    assert units_and_meta(probe_name="cond", probe_type="cond", value=1.0)[0] == "ppt"
    assert units_and_meta(probe_name="Tmp", probe_type="tmp", value=25.0)[0] is None
    assert units_and_meta(probe_name="x", probe_type="other", value=1.0)[0] is None

    assert icon_for_outlet_type("pump") == "mdi:pump"
    assert icon_for_outlet_type("light") == "mdi:lightbulb"
    assert icon_for_outlet_type("heater") == "mdi:radiator"
    assert icon_for_outlet_type("other") == "mdi:power-socket-us"

    # network/meta field helpers
    nf = network_field("ipaddr")
    assert nf({"network": {"ipaddr": "1.2.3.4"}}) == "1.2.3.4"
    assert nf({"network": "nope"}) is None
    sf = section_field("alerts", "last_statement")
    assert sf({"alerts": "nope"}) is None
    assert sf({"alerts": {"last_statement": "x"}}) == "x"


def test_outlet_mode_sensor_handles_non_list_outlets() -> None:
    """Cover the guard branch when `outlets` is not a list."""

    from custom_components.apex_fusion.apex_fusion import OutletRef
    from custom_components.apex_fusion.sensor import ApexOutletModeSensor

    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )

    coordinator = _CoordinatorStub(
        data={
            "meta": {"serial": "ABC", "source": "rest"},
            "outlets": "nope",
        }
    )

    sensor = ApexOutletModeSensor(
        cast(Any, coordinator),
        cast(Any, entry),
        ref=OutletRef(did="D1", name="Return"),
    )
    assert sensor.native_value is None


def test_outlet_mode_sensor_skips_non_dict_outlet_entries() -> None:
    """Cover the loop-continue branch for invalid outlet entries."""

    from custom_components.apex_fusion.apex_fusion import OutletRef
    from custom_components.apex_fusion.sensor import ApexOutletModeSensor

    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )

    coordinator = _CoordinatorStub(
        data={
            "meta": {"serial": "ABC", "source": "rest"},
            "outlets": [
                "nope",
                {"device_id": "D1", "state": "ON", "type": "PUMP"},
            ],
        }
    )

    sensor = ApexOutletModeSensor(
        cast(Any, coordinator),
        cast(Any, entry),
        ref=OutletRef(did="D1", name="Return"),
    )
    assert sensor.native_value == "On"


def test_outlet_mode_sensor_returns_empty_when_did_not_found() -> None:
    """Cover the fall-through return branch when DID isn't present."""

    from custom_components.apex_fusion.apex_fusion import OutletRef
    from custom_components.apex_fusion.sensor import ApexOutletModeSensor

    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )

    coordinator = _CoordinatorStub(
        data={
            "meta": {"serial": "ABC", "source": "rest"},
            "outlets": [{"device_id": "OTHER", "state": "ON"}],
        }
    )

    sensor = ApexOutletModeSensor(
        cast(Any, coordinator),
        cast(Any, entry),
        ref=OutletRef(did="D1", name="Return"),
    )
    assert sensor.native_value is None


def test_trident_level_ml_helper_covers_branches():
    from custom_components.apex_fusion.apex_fusion.trident import trident_level_ml

    get0 = trident_level_ml(0)
    get1 = trident_level_ml(1)

    assert get0({}) is None
    assert get0({"trident": "nope"}) is None
    assert get0({"trident": {"levels_ml": "nope"}}) is None
    assert get0({"trident": {"levels_ml": []}}) is None
    assert get0({"trident": {"levels_ml": [1.0]}}) == 1.0
    assert get1({"trident": {"levels_ml": [1.0]}}) is None
    assert trident_level_ml(-1)({"trident": {"levels_ml": [1.0]}}) is None


def test_diagnostic_sensor_percentage_fallback_branch():
    from custom_components.apex_fusion import sensor

    coordinator = _CoordinatorStub(data={"meta": {"serial": "ABC"}})
    entry = cast(Any, MockConfigEntry(domain=DOMAIN, data={CONF_HOST: "1.2.3.4"}))

    ent = sensor.ApexDiagnosticSensor(
        cast(Any, coordinator),
        entry,
        unique_id="abc_diag_bad_pct",
        name="Bad Pct",
        icon=None,
        native_unit=PERCENTAGE,
        value_fn=lambda _data: "nope",
    )

    # native_unit is percentage but value is non-numeric -> explicit percentage path returns None
    assert ent.native_value is None


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

    listeners: list[Callable[[], None]] = []
    coordinator = _CoordinatorStub(
        data={
            "meta": {"serial": "ABC", "firmware_latest": "9.99", "hostname": "apex"},
            "network": {"ipaddr": "1.2.3.4", "strength": "75", "quality": 80},
            "trident": {
                "present": True,
                "abaddr": 5,
                "status": "Idle",
                "levels_ml": [232.7, 159.2, 226.63, 226.92, 222.94, 111.0],
            },
            "probes": {
                "": {"name": "", "type": "Tmp", "value": "25", "value_raw": None},
                "T1": {"name": "Tmp", "type": "Tmp", "value": "25", "value_raw": None},
                "PH": {"name": "pH", "type": "pH", "value": 8.1, "value_raw": None},
                "DI1": {
                    "name": "Door_1",
                    "type": "digital",
                    "value": 0,
                    "value_raw": None,
                },
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
        device_identifier="ABC",
        listeners=listeners,
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import sensor

    await sensor.async_setup_entry(hass, cast(Any, entry), _add_entities)

    # Exercise platform listeners before entities are added to hass:
    # - re-running the callback should be idempotent and cover the guard branch.
    for cb in list(listeners):
        cb()

    # Probes + diagnostics
    assert len(added) >= 3

    # Exercise entity update handlers and remove handlers.
    for ent in added:
        ent.async_write_ha_state = lambda *args, **kwargs: None
        await ent.async_added_to_hass()

    probe_entities = [e for e in added if isinstance(e, sensor.ApexProbeSensor)]
    # "DI1" is digital and excluded from sensor platform; "BAD" is invalid but is still
    # represented as a probe entity to exercise error-tolerant behavior.
    assert len(probe_entities) == 3

    trident_diags = [e for e in added if isinstance(e, sensor.ApexDiagnosticSensor)]
    waste = next((e for e in trident_diags if e._attr_name == "Waste Used"), None)
    assert waste is not None
    assert waste.entity_category is None
    assert waste._attr_device_class == sensor.SensorDeviceClass.VOLUME
    assert waste._attr_state_class == sensor.SensorStateClass.TOTAL_INCREASING

    status = next((e for e in trident_diags if e._attr_name == "Status"), None)
    assert status is not None
    assert status.entity_category is None

    # Trident diagnostics should be grouped under the Trident device when abaddr is known.
    assert waste.device_info is not None
    assert waste.device_info.get("name") == "Trident (5)"
    assert waste.device_info.get("via_device") == (DOMAIN, "ABC")

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


async def test_sensor_setup_trident_not_dict_is_ignored(
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
            "network": {"ipaddr": "1.2.3.4"},
            "trident": "nope",
            "probes": {},
            "outlets": [],
            "mxm_devices": {},
        },
        last_update_success=True,
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import sensor

    await sensor.async_setup_entry(hass, cast(Any, entry), _add_entities)

    # Trident is not a dict -> no Trident entities should be created.
    assert all(getattr(e, "_attr_name", "") not in {"Trident Status"} for e in added)


async def test_probe_sensor_attaches_to_module_device_when_probe_has_module_abaddr(
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
            "meta": {"serial": "ABC", "hostname": "apex"},
            "config": {
                "mconf": [
                    {"abaddr": 3, "hwtype": "FMM", "name": "My FMM"},
                ]
            },
            "network": {"ipaddr": "1.2.3.4"},
            "trident": {},
            "probes": {
                "T1": {
                    "name": "T1",
                    "type": "Tmp",
                    "value": "25",
                    "value_raw": "25",
                    "module_abaddr": 3,
                }
            },
            "outlets": [],
            "mxm_devices": {},
        },
        last_update_success=True,
        device_identifier="TEST",
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import sensor

    await sensor.async_setup_entry(hass, cast(Any, entry), _add_entities)

    probe_entities = [e for e in added if isinstance(e, sensor.ApexProbeSensor)]
    assert probe_entities
    t1 = next(e for e in probe_entities if e._ref.key == "T1")
    assert t1.device_info is not None
    assert t1.device_info.get("name") == "My FMM"
    assert t1.device_info.get("via_device") == (DOMAIN, "TEST")


async def test_probe_sensor_falls_back_to_module_hwtype_when_data_missing(
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
            "meta": {"serial": "ABC", "hostname": "apex"},
            "network": {"ipaddr": "1.2.3.4"},
            "trident": {},
            "probes": {
                "T1": {
                    "name": "T1",
                    "type": "Tmp",
                    "value": "25",
                    "value_raw": "25",
                    "module_abaddr": 3,
                    "module_hwtype": "FMM",
                }
            },
            "outlets": [],
            "mxm_devices": {},
        },
        last_update_success=True,
        device_identifier="TEST",
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import sensor

    await sensor.async_setup_entry(hass, cast(Any, entry), _add_entities)

    probe_entities = [e for e in added if isinstance(e, sensor.ApexProbeSensor)]
    assert probe_entities
    t1 = next(e for e in probe_entities if e._ref.key == "T1")
    assert t1.device_info is not None
    assert t1.device_info.get("name") == "Fluid Monitoring Module (3)"
    assert t1.device_info.get("via_device") == (DOMAIN, "TEST")
    assert t1.device_info.get("identifiers") == {(DOMAIN, "TEST_module_FMM_3")}


async def test_outlet_intensity_sensor_creates_vdm_module_device(
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
            "meta": {"serial": "ABC", "hostname": "80g_Frag_Tank"},
            "network": {},
            "trident": {},
            "config": {"mconf": [{"abaddr": 6, "hwtype": "VDM", "name": "VDM_6"}]},
            "probes": {},
            "outlets": [
                {
                    "name": "VarSpd3_6_3",
                    "device_id": "6_3",
                    "type": "variable",
                    "state": "PF3",
                    "intensity": 100,
                    "status": ["PF3", "100", "OK", ""],
                    "module_abaddr": 6,
                }
            ],
        },
        last_update_success=True,
        device_identifier="TEST",
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import sensor

    await sensor.async_setup_entry(hass, cast(Any, entry), _add_entities)

    intensity_entities = [
        e for e in added if isinstance(e, sensor.ApexOutletIntensitySensor)
    ]
    assert intensity_entities

    ent = next(e for e in intensity_entities if e._ref.did == "6_3")
    assert ent.device_info is not None
    assert ent.device_info.get("name") == "LED & Pump Control Module (6)"
    assert ent.device_info.get("via_device") == (DOMAIN, "TEST")
    assert ent.device_info.get("identifiers") == {(DOMAIN, "TEST_module_VDM_6")}


async def test_outlet_intensity_sensor_refresh_and_lifecycle_cover_branches():
    from custom_components.apex_fusion import sensor
    from custom_components.apex_fusion.apex_fusion import OutletIntensityRef

    listeners: list[Callable[[], None]] = []
    coordinator = _CoordinatorStub(
        data={
            "meta": {"serial": "ABC", "hostname": "tank"},
            "outlets": [
                "nope",
                {
                    "name": "VarSpd3_6_3",
                    "device_id": "6_3",
                    "type": "variable",
                    "state": "PF3",
                    "intensity": 100,
                    "status": ["PF3", "100", "OK", ""],
                    "module_abaddr": 6,
                },
            ],
        },
        last_update_success=True,
        device_identifier="TEST",
        listeners=listeners,
    )
    entry = MockConfigEntry(domain=DOMAIN, data={CONF_HOST: "1.2.3.4"})

    ent = sensor.ApexOutletIntensitySensor(
        cast(Any, coordinator),
        cast(Any, entry),
        ref=OutletIntensityRef(did="6_3", name="VarSpd3_6_3"),
    )
    ent.async_write_ha_state = lambda *args, **kwargs: None

    # Non-list outlets -> find_outlet returns empty + refresh sets None.
    coordinator.data["outlets"] = "nope"
    assert ent._find_outlet() == {}
    ent._refresh()
    assert ent.native_value is None

    # List outlets with no matching did: covers non-dict skip + final return {}.
    coordinator.data["outlets"] = ["nope", {"device_id": "other"}]
    assert ent._find_outlet() == {}
    ent._handle_coordinator_update()
    assert ent.native_value is None
    assert ent.icon == "mdi:power-socket-us"

    # Bool intensity should not be treated as numeric.
    coordinator.data["outlets"] = [
        {"device_id": "6_3", "intensity": True, "type": "variable"}
    ]
    ent._handle_coordinator_update()
    assert ent.native_value is None
    assert ent.icon == "mdi:power-socket-us"

    # Numeric intensity + outlet type should update icon and attributes.
    coordinator.data["outlets"] = [
        {
            "device_id": "6_3",
            "intensity": 50,
            "type": "light",
            "state": "PF3",
            "output_id": "3",
            "gid": "g",
            "status": ["PF3"],
        }
    ]
    ent._handle_coordinator_update()
    assert ent.native_value == 50.0
    assert ent.icon == "mdi:lightbulb"
    attrs = ent.extra_state_attributes or {}
    assert attrs.get("state") == "PF3"
    assert attrs.get("type") == "light"
    assert attrs.get("output_id") == "3"
    assert attrs.get("gid") == "g"
    assert attrs.get("status") == ["PF3"]

    await ent.async_added_to_hass()
    assert listeners
    await ent.async_will_remove_from_hass()
    assert ent._unsub is None


async def test_sensor_setup_without_network_or_meta_adds_no_diagnostics(
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
            "network": {},
            "trident": {"present": False},
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
    # remain stable across updates.
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
