"""Firmware comparison and real HA UpdateEntity state for the update platform."""

from __future__ import annotations

from typing import Any, cast

import pytest
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    MockEntityPlatform,  # pyright: ignore[reportAttributeAccessIssue]
)

from custom_components.apex_fusion import update
from custom_components.apex_fusion.const import CONF_HOST, DOMAIN
from tests.test_update import _CoordinatorStub, _device_model


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("5.15J_6B26", (5, 15, "6B26")),
        ("5.16_AC26", (5, 16, "AC26")),
        ("5.12L_CA25", (5, 12, "CA25")),
        ("  5.16_AC26 ", (5, 16, "AC26")),
        (None, None),
        ("", None),
        ("25", None),
        ("Update available", None),
        ("5.16", None),
        ("5.16JJ_AC26", None),
        ("5.16_", None),
    ],
)
def test_normalize_firmware(value, expected):
    assert update.normalize_firmware(value) == expected


@pytest.mark.parametrize(
    ("latest", "installed", "flag", "expected"),
    [
        # Nano: minor differs and the controller flag is stale (False).
        ("5.16_AC26", "5.15J_6B26", False, True),
        ("5.16_AC26", "5.15J_6B26", None, True),
        # Numeric, not lexical, comparison of major.minor.
        ("5.9_AC26", "5.10J_AC26", False, False),
        ("5.10_AC26", "5.9J_AC26", False, True),
        ("6.0_AC26", "5.99J_AC26", False, True),
        # Same release (family letter ignored), same build.
        ("5.16_AC26", "5.16J_AC26", False, False),
        ("5.16_AC26", "5.16J_AC26", None, False),
        # Same release, flag True: the flag decides -> update available.
        ("5.12_CA25", "5.12J_CA25", True, True),
        # Same major.minor, different build: update, order never inferred.
        ("5.16_AC27", "5.16J_AC26", False, True),
        ("5.16_AC25", "5.16J_AC26", False, True),
        # Older major.minor with a False flag is not an update.
        ("5.14_AC26", "5.15J_6B26", False, False),
        # Unparseable: fall back to string inequality when both are present.
        ("25", "24", False, True),
        ("25", "25", False, False),
        ("Update available", "5.16J_AC26", None, True),
        ("5.16_AC26", "weird", False, True),
        # Missing data: only a True flag reports an update.
        (None, "5.15J_6B26", False, False),
        (None, "5.15J_6B26", True, True),
        ("5.16_AC26", None, None, False),
    ],
)
def test_firmware_update_available(latest, installed, flag, expected):
    assert update.firmware_update_available(latest, installed, flag) is expected


def _entry() -> MockConfigEntry:
    return MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )


async def _entities(hass, data: dict[str, Any]) -> list[Any]:
    """Set up the update platform and register entities with a real platform.

    Registering through an `EntityPlatform` gives each entity a real entity id and
    lets `async_write_ha_state` publish to Home Assistant's state machine.
    """
    entry = _entry()
    entry.add_to_hass(hass)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = _CoordinatorStub(data=data)

    added: list[Any] = []

    def _collect(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    await update.async_setup_entry(hass, cast(Any, entry), _collect)

    platform = MockEntityPlatform(hass, domain="update", platform_name=DOMAIN)
    platform.config_entry = entry
    await platform.async_add_entities(added)
    return added


def _controller_data(
    installed: str, latest: str | None, flag: bool | None
) -> dict[str, Any]:
    nstat: dict[str, Any] = {}
    if latest is not None:
        nstat["latestFirmware"] = latest
    if flag is not None:
        nstat["updateFirmware"] = flag
    return {
        "meta": {
            "serial": "ABC",
            "hostname": "apex",
            "type": "AC6J",
            "software": installed,
            "firmware_latest": latest,
        },
        "raw": {"nstat": nstat},
    }


def _hass_state(hass, entity) -> str:
    """Read the state Home Assistant published for the entity."""
    state = hass.states.get(entity.entity_id)
    assert state is not None
    return state.state


@pytest.mark.parametrize(
    ("installed", "latest", "flag", "expected"),
    [
        # The reported Nano case: flag False, but 5.16 is newer than 5.15.
        ("5.15J_6B26", "5.16_AC26", False, "on"),
        # Same release, flag False.
        ("5.16J_AC26", "5.16_AC26", False, "off"),
        # Same release, flag True: flag decides (documented choice).
        ("5.12J_CA25", "5.12_CA25", True, "on"),
        # Build-only difference.
        ("5.16J_AC26", "5.16_AC27", False, "on"),
        # Identical strings are "off" in HA before version_is_newer is called,
        # even with the flag True. We do not invent a different latest.
        ("5.16J_AC26", "5.16J_AC26", True, "off"),
        # Unparseable strings fall back to inequality.
        ("weird", "other", False, "on"),
        ("weird", "weird", False, "off"),
    ],
)
async def test_controller_state_in_ha(
    hass, enable_custom_integrations, installed, latest, flag, expected
):
    added = await _entities(hass, _controller_data(installed, latest, flag))
    ent = next(e for e in added if _device_model(e) == "AC6J")

    # Raw strings are exposed unchanged.
    assert ent.installed_version == installed
    assert ent.latest_version == latest
    assert ent.state == expected
    assert _hass_state(hass, ent) == expected


async def test_controller_without_latest_is_unknown(hass, enable_custom_integrations):
    added = await _entities(hass, _controller_data("5.15J_6B26", None, True))
    ent = next(e for e in added if _device_model(e) == "AC6J")
    # No latest version reported: nothing is invented.
    assert ent.latest_version is None
    assert ent.state is None


async def test_module_state_with_reported_latest_and_stale_flag(
    hass, enable_custom_integrations
):
    data = {
        "meta": {"serial": "ABC", "hostname": "apex", "type": "AC6J"},
        "raw": {
            "nstat": {"updateFirmware": False},
            "modules": [
                {
                    "abaddr": 1,
                    "hwtype": "FMM",
                    "present": True,
                    "software": "1.4J_AB12",
                    "latestFirmware": "1.5_CD34",
                },
                {
                    "abaddr": 2,
                    "hwtype": "PM2",
                    "present": True,
                    "software": "1.4J_AB12",
                    "latestFirmware": "1.4_AB12",
                },
            ],
        },
        "config": {
            "mconf": [
                {"abaddr": 1, "hwtype": "FMM", "update": False},
                {"abaddr": 2, "hwtype": "PM2", "update": False},
            ]
        },
    }
    added = await _entities(hass, data)

    # Module config says update=False, but the reported latest is visibly newer.
    fmm = next(e for e in added if _device_model(e) == "FMM")
    assert fmm.latest_version == "1.5_CD34"
    assert fmm.state == "on"
    assert _hass_state(hass, fmm) == "on"

    # Same release, flag False -> off.
    pm2 = next(e for e in added if _device_model(e) == "PM2")
    assert pm2.state == "off"


async def test_module_swstat_old_same_release_and_no_latest(
    hass, enable_custom_integrations
):
    data = {
        "meta": {"serial": "ABC", "hostname": "apex", "type": "AC6J"},
        "raw": {
            "modules": [
                {
                    "abaddr": 1,
                    "hwtype": "FMM",
                    "present": True,
                    "software": "1.4J_AB12",
                    "latestFirmware": "1.4_AB12",
                    "swstat": "OLD",
                },
                {
                    "abaddr": 2,
                    "hwtype": "PM2",
                    "present": True,
                    "software": "1.4J_AB12",
                    "swstat": "OLD",
                },
                {
                    "abaddr": 3,
                    "hwtype": "VDM",
                    "present": True,
                    "software": "1.4J_AB12",
                    "swstat": "OK",
                },
            ],
        },
        "config": {
            "mconf": [
                {"abaddr": 1, "hwtype": "FMM", "update": False},
                {"abaddr": 2, "hwtype": "PM2", "update": False},
                {"abaddr": 3, "hwtype": "VDM", "update": True},
            ]
        },
    }
    added = await _entities(hass, data)

    # Same release but swstat OLD -> on.
    fmm = next(e for e in added if _device_model(e) == "FMM")
    assert fmm.state == "on"

    # swstat OLD and no latest -> placeholder keeps the existing behavior.
    pm2 = next(e for e in added if _device_model(e) == "PM2")
    assert pm2.latest_version == "Update available"
    assert pm2.state == "on"

    # swstat OK (mconf.update True is ignored) and no latest -> up to date, nothing invented.
    vdm = next(e for e in added if _device_model(e) == "VDM")
    assert vdm.latest_version == "1.4J_AB12"
    assert vdm.state == "off"


async def test_module_raw_path_uses_swstat_and_reported_latest(
    hass, enable_custom_integrations
):
    data = {
        "meta": {"serial": "ABC", "hostname": "apex", "type": "AC6J"},
        "raw": {
            "modules": [
                # No config: reported latest is newer.
                {
                    "abaddr": 1,
                    "hwtype": "FMM",
                    "present": True,
                    "software": "1.4J_AB12",
                    "latestFirmware": "1.5_CD34",
                    "swstat": "OK",
                },
                # swstat reports an update but no version.
                {
                    "abaddr": 2,
                    "hwtype": "PM2",
                    "present": True,
                    "swrev": 3,
                    "swstat": "OLD",
                },
                # Nothing to go on.
                {"abaddr": 3, "hwtype": "VDM", "present": True, "swrev": 3},
            ],
        },
    }
    added = await _entities(hass, data)

    assert next(e for e in added if _device_model(e) == "FMM").state == "on"
    pm2 = next(e for e in added if _device_model(e) == "PM2")
    assert pm2.state == "on"
    assert next(e for e in added if _device_model(e) == "VDM").state == "off"

    # Flag lookup miss when the module disappears from status.
    ref = next(r for r in update._module_refs(data, "ABC") if r.module_hwtype == "PM2")
    assert ref.update_flag_fn({"raw": {"modules": []}}) is None
    assert ref.update_flag_fn(data) is True
    # hwtype mismatch / id mismatch / did fallback in the lookup.
    other = {
        "raw": {
            "modules": [
                {"hwtype": "XXX", "abaddr": 2},
                {"hwtype": "PM2", "abaddr": 9},
                {"hwtype": "PM2", "did": "2", "swstat": "OLD"},
            ]
        }
    }
    assert ref.update_flag_fn(other) is True
