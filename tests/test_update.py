"""Tests for Apex Fusion update platform."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, cast

from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.apex_fusion.const import CONF_HOST, DOMAIN


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

        def _unsub() -> None:
            return None

        return _unsub


async def test_update_setup_creates_controller_update_entity(
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
            "meta": {
                "serial": "ABC",
                "hostname": "apex",
                "type": "AC6J",
                "software": "5.12J_CA25",
                "firmware_latest": "5.12_CA25",
            },
            "raw": {
                "nstat": {"latestFirmware": "5.12_CA25", "updateFirmware": True},
                "system": {"software": "5.12J_CA25"},
            },
        },
        listeners=listeners,
    )

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import update

    await update.async_setup_entry(hass, cast(Any, entry), _add_entities)

    assert len(added) == 1
    ent = added[0]
    assert ent.name == "AC6J Firmware"
    assert ent.installed_version == "5.12J_CA25"
    assert ent.latest_version == "5.12_CA25"
    assert ent.state == "on"

    # Cover entity listener wiring and update handler.
    ent.async_write_ha_state = lambda *args, **kwargs: None
    await ent.async_added_to_hass()

    # Cover coordinator listener path.
    for cb in list(listeners):
        cb()


async def test_update_setup_creates_module_update_entity_when_outdated(
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
            "meta": {"serial": "ABC", "hostname": "apex", "type": "AC6J"},
            "raw": {
                "nstat": {"updateFirmware": False},
                "modules": [
                    {
                        "abaddr": 1,
                        "hwtype": "FMM",
                        "present": True,
                        "swrev": 24,
                        "swstat": "UPDATE",
                        "latestFirmware": "25",
                    },
                    {
                        "abaddr": 2,
                        "hwtype": "PM2",
                        "present": True,
                        "swrev": 3,
                        "swstat": "OK",
                    },
                ],
            },
        },
        listeners=listeners,
    )

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import update

    await update.async_setup_entry(hass, cast(Any, entry), _add_entities)

    # Controller firmware update + module updates.
    assert len(added) == 3

    names = sorted(e.name for e in added)
    assert names == ["AC6J Firmware", "FMM Firmware", "PM2 Firmware"]

    fmm = next(e for e in added if e.name == "FMM Firmware")
    assert fmm.installed_version == "24"
    assert fmm.latest_version == "25"
    assert fmm.state == "on"

    pm2 = next(e for e in added if e.name == "PM2 Firmware")
    assert pm2.installed_version == "3"
    assert pm2.latest_version == "3"
    assert pm2.state == "off"

    fmm.async_write_ha_state = lambda *args, **kwargs: None
    await fmm.async_added_to_hass()

    # Cover the module entity de-duplication branch in async_setup_entry.
    for cb in list(listeners):
        cb()


async def test_update_controller_suppresses_latest_when_no_update(
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
            "meta": {
                "serial": "ABC",
                "hostname": "apex",
                "type": "AC6J",
                "software": "5.12J_CA25",
                "firmware_latest": "5.12_CA25",
            },
            "raw": {"nstat": {"updateFirmware": False}},
        }
    )

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import update

    await update.async_setup_entry(hass, cast(Any, entry), _add_entities)

    ent = next(e for e in added if e.name == "AC6J Firmware")
    # When the controller says there is no update, state should be off.
    assert ent.installed_version == "5.12J_CA25"
    assert ent.latest_version == "5.12J_CA25"
    assert ent.state == "off"
    # But we still expose the controller-reported latest as context.
    assert ent.release_summary == "Latest reported by controller: 5.12_CA25"


async def test_update_controller_prefers_nconf_update_flag_over_nstat(
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
            "meta": {
                "serial": "ABC",
                "hostname": "apex",
                "type": "AC6J",
                "software": "5.12J_CA25",
                "firmware_latest": "5.12_CA25",
            },
            # Status says update is available...
            "raw": {"nstat": {"updateFirmware": True}},
            # ...but config says no.
            "config": {"nconf": {"updateFirmware": False}},
        }
    )

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import update

    await update.async_setup_entry(hass, cast(Any, entry), _add_entities)

    ent = next(e for e in added if e.name == "AC6J Firmware")
    assert ent.latest_version == "5.12J_CA25"
    assert ent.state == "off"


async def test_update_modules_use_mconf_update_flags_when_present(
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
            "meta": {"serial": "ABC", "hostname": "apex", "type": "AC6J"},
            "raw": {
                "modules": [
                    {"abaddr": 1, "hwtype": "FMM", "present": True, "swrev": 24},
                    {"abaddr": 2, "hwtype": "PM2", "present": True, "swrev": 3},
                ],
                "nstat": {"updateFirmware": False},
            },
            "config": {
                "mconf": [
                    {"abaddr": 1, "hwtype": "FMM", "update": True, "updateStat": 1},
                    {"abaddr": 2, "hwtype": "PM2", "update": False, "updateStat": 0},
                ]
            },
        }
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import update

    await update.async_setup_entry(hass, cast(Any, entry), _add_entities)

    # Controller firmware + both module entities (driven by mconf)
    names = sorted(e.name for e in added)
    assert names == ["AC6J Firmware", "FMM Firmware", "PM2 Firmware"]

    fmm = next(e for e in added if e.name == "FMM Firmware")
    assert fmm.installed_version == "24"
    assert fmm.latest_version == "Update available"
    assert fmm.state == "on"
    assert fmm.release_summary == "updateStat=1"

    pm2 = next(e for e in added if e.name == "PM2 Firmware")
    assert pm2.installed_version == "3"
    assert pm2.latest_version == "3"
    assert pm2.state == "off"


def test_update_helpers_cover_branches():
    from custom_components.apex_fusion import update

    # raw missing / not a dict
    assert update._raw_nstat({}) == {}
    assert update._raw_modules({}) == []

    # nstat nested under a container
    assert update._raw_nstat(
        {"raw": {"data": {"nstat": {"updateFirmware": True}}}}
    ) == {"updateFirmware": True}
    # nstat direct
    assert update._raw_nstat({"raw": {"nstat": {"x": 1}}}) == {"x": 1}
    # nstat present but not dict
    assert update._raw_nstat({"raw": {"nstat": "nope"}}) == {}
    # nstat missing entirely -> fall-through path
    assert update._raw_nstat({"raw": {"data": {"other": 1}}}) == {}

    # config guards
    assert update._config_root({}) == {}
    assert update._config_nconf({}) == {}
    assert update._config_mconf_modules({}) == []

    # modules not a list
    assert update._raw_modules({"raw": {"modules": "nope"}}) == []
    # modules nested
    assert update._raw_modules(
        {"raw": {"status": {"modules": [{"hwtype": "FMM"}]}}}
    ) == [{"hwtype": "FMM"}]

    # module refs: skip empty hwtype, skip not present
    refs = update._module_refs(
        {
            "raw": {
                "modules": [
                    {},
                    {"hwtype": "FMM", "present": False, "latestFirmware": "25"},
                    {"hwtype": "PM2", "present": True, "swrev": 3},
                    # No reported latest, but swstat indicates update availability.
                    {"hwtype": "WXM", "present": True, "swrev": 2, "swstat": "UPDATE"},
                    # Valid module, uses hwType key and did fallback.
                    {
                        "hwType": "VDM",
                        "present": True,
                        "did": "vdm_1",
                        "swrev": 13,
                        "latestFirmware": "14",
                        "swstat": "OK",
                    },
                ]
            }
        },
        "ABC",
    )
    assert {r.name for r in refs} == {"PM2 Firmware", "WXM Firmware", "VDM Firmware"}

    vdm_ref = next(r for r in refs if r.name == "VDM Firmware")
    # Happy-path module lookup
    assert (
        vdm_ref.installed_fn(
            {
                "raw": {
                    "modules": [
                        {
                            "hwtype": "VDM",
                            "present": True,
                            "did": "vdm_1",
                            "swrev": 13,
                            "latestFirmware": "14",
                            "swstat": "OK",
                        }
                    ]
                }
            }
        )
        == "13"
    )
    assert (
        vdm_ref.latest_fn(
            {
                "raw": {
                    "modules": [
                        {
                            "hwtype": "VDM",
                            "present": True,
                            "did": "vdm_1",
                            "swrev": 13,
                            "latestFirmware": "14",
                            "swstat": "OK",
                        }
                    ]
                }
            }
        )
        == "14"
    )
    assert (
        vdm_ref.release_summary_fn(
            {
                "raw": {
                    "modules": [
                        {
                            "hwtype": "VDM",
                            "present": True,
                            "did": "vdm_1",
                            "swrev": 13,
                            "latestFirmware": "14",
                            "swstat": "OK",
                        }
                    ]
                }
            }
        )
        == "OK"
    )

    pm2_ref = next(r for r in refs if r.name == "PM2 Firmware")
    assert (
        pm2_ref.latest_fn(
            {
                "raw": {
                    "modules": [
                        # No swstat -> covers helper branch returning None.
                        {"hwtype": "PM2", "present": True, "swrev": 3}
                    ]
                }
            }
        )
        == "3"
    )

    # swstat blank -> helper returns None.
    assert (
        pm2_ref.latest_fn(
            {
                "raw": {
                    "modules": [
                        {"hwtype": "PM2", "present": True, "swrev": 3, "swstat": "   "}
                    ]
                }
            }
        )
        == "3"
    )

    # swstat unrecognized -> helper returns None.
    assert (
        pm2_ref.latest_fn(
            {
                "raw": {
                    "modules": [
                        {"hwtype": "PM2", "present": True, "swrev": 3, "swstat": "???"}
                    ]
                }
            }
        )
        == "3"
    )

    # No installed and no reported latest -> latest_fn returns None.
    assert (
        pm2_ref.latest_fn(
            {"raw": {"modules": [{"hwtype": "PM2", "present": True, "swstat": "???"}]}}
        )
        is None
    )

    wxm_ref = next(r for r in refs if r.name == "WXM Firmware")
    assert (
        wxm_ref.latest_fn(
            {
                "raw": {
                    "modules": [
                        {
                            "hwtype": "WXM",
                            "present": True,
                            "swrev": 2,
                            "swstat": "UPDATE",
                        }
                    ]
                }
            }
        )
        == "Update available"
    )

    # Module lookup miss -> None
    assert vdm_ref.installed_fn({"raw": {"modules": []}}) is None
    assert vdm_ref.latest_fn({"raw": {"modules": []}}) is None
    assert vdm_ref.release_summary_fn({"raw": {"modules": []}}) is None

    # meta not a dict guards
    assert update._controller_installed({"meta": "nope"}) is None
    assert update._controller_latest({"meta": "nope"}) is None

    # controller latest fallback to nconf
    assert (
        update._controller_latest(
            {
                "meta": {"firmware_latest": None},
                "config": {"nconf": {"latestFirmware": "X"}},
            }
        )
        == "X"
    )

    # module refs with config: cover skip paths and placeholder latest
    refs_cfg = update._module_refs(
        {
            "config": {
                "mconf": [
                    {},
                    {"hwtype": ""},
                    {
                        "hwtype": "FMM",
                        "abaddr": 99,
                        "update": True,
                    },  # no status -> skip
                    {"hwtype": "FMM", "abaddr": 1, "update": True, "updateStat": 2},
                    {"hwtype": "PM2", "abaddr": 2, "update": False},
                    {"hwtype": "VDM", "abaddr": 3, "update": False},
                ]
            },
            "raw": {
                "modules": [
                    {"hwtype": "FMM", "abaddr": 1, "present": True, "swrev": 24},
                    {
                        "hwtype": "PM2",
                        "abaddr": 2,
                        "present": True,
                        "swrev": 3,
                        "latestFirmware": "4",
                    },
                    {
                        "hwtype": "VDM",
                        "abaddr": 3,
                        "present": False,
                        "swrev": 13,
                        "latestFirmware": "14",
                    },
                ]
            },
        },
        "ABC",
    )
    # VDM skipped because present=False; FMM+PM2 included
    assert sorted(r.name for r in refs_cfg) == ["FMM Firmware", "PM2 Firmware"]

    fmm_ref = next(r for r in refs_cfg if r.name == "FMM Firmware")
    assert (
        fmm_ref.installed_fn(
            {"raw": {"modules": [{"hwtype": "FMM", "abaddr": 1, "swrev": 24}]}}
        )
        == "24"
    )
    assert (
        fmm_ref.latest_fn(
            {
                "config": {"mconf": [{"hwtype": "FMM", "abaddr": 1, "update": True}]},
                "raw": {
                    "modules": [
                        {"hwtype": "FMM", "abaddr": 1, "present": True, "swrev": 24}
                    ]
                },
            }
        )
        == "Update available"
    )
    assert (
        fmm_ref.release_summary_fn(
            {
                "config": {
                    "mconf": [
                        {"hwtype": "FMM", "abaddr": 1, "update": True, "updateStat": 2}
                    ]
                },
                "raw": {
                    "modules": [
                        {"hwtype": "FMM", "abaddr": 1, "present": True, "swrev": 24}
                    ]
                },
            }
        )
        == "updateStat=2"
    )

    pm2_ref = next(r for r in refs_cfg if r.name == "PM2 Firmware")
    # config says no update -> suppress latest
    assert (
        pm2_ref.latest_fn(
            {
                "config": {"mconf": [{"hwtype": "PM2", "abaddr": 2, "update": False}]},
                "raw": {
                    "modules": [
                        {
                            "hwtype": "PM2",
                            "abaddr": 2,
                            "present": True,
                            "swrev": 3,
                            "latestFirmware": "4",
                        }
                    ]
                },
            }
        )
        == "3"
    )

    # ...but still provide context about controller-reported latest
    assert (
        pm2_ref.release_summary_fn(
            {
                "config": {"mconf": [{"hwtype": "PM2", "abaddr": 2, "update": False}]},
                "raw": {
                    "modules": [
                        {
                            "hwtype": "PM2",
                            "abaddr": 2,
                            "present": True,
                            "swrev": 3,
                            "latestFirmware": "4",
                        }
                    ]
                },
            }
        )
        == "Latest reported by controller: 4"
    )

    # Cover: latest_fn returns None when module disappears or is not present.
    assert (
        fmm_ref.latest_fn(
            {
                "config": {"mconf": [{"hwtype": "FMM", "abaddr": 1, "update": True}]},
                "raw": {
                    "modules": [
                        {"hwtype": "FMM", "abaddr": 1, "present": False, "swrev": 24}
                    ]
                },
            }
        )
        is None
    )

    # Cover: latest_fn returns reported latest when update is True and a version exists.
    assert (
        fmm_ref.latest_fn(
            {
                "config": {"mconf": [{"hwtype": "FMM", "abaddr": 1, "update": True}]},
                "raw": {
                    "modules": [
                        {
                            "hwtype": "FMM",
                            "abaddr": 1,
                            "present": True,
                            "swrev": 24,
                            "latestFirmware": "25",
                        }
                    ]
                },
            }
        )
        == "25"
    )

    # Cover: helper lookup miss paths
    assert fmm_ref.installed_fn({"raw": {"modules": []}}) is None
    assert fmm_ref.latest_fn({"raw": {"modules": []}, "config": {"mconf": []}}) is None
    assert (
        fmm_ref.release_summary_fn({"raw": {"modules": []}, "config": {"mconf": []}})
        is None
    )

    # Cover: status module matching branches (hwtype mismatch, id mismatch, did fallback, software preferred)
    assert (
        fmm_ref.installed_fn(
            {
                "raw": {
                    "modules": [
                        {"hwtype": "XXX", "abaddr": 1, "swrev": 0},
                        {"hwtype": "FMM", "abaddr": 2, "swrev": 0},
                        {"hwtype": "FMM", "did": "1", "software": "S1"},
                    ]
                }
            }
        )
        == "S1"
    )

    # Cover: module_id fallback creation via did (no abaddr)
    refs_did = update._module_refs(
        {
            "config": {
                "mconf": [
                    {"hwtype": "VDM", "did": "other", "update": True},
                    {"hwtype": "VDM", "did": "vdm_1", "update": True},
                ]
            },
            "raw": {
                "modules": [
                    {"hwtype": "VDM", "did": "vdm_1", "present": True, "swrev": 13}
                ]
            },
        },
        "ABC",
    )
    assert len(refs_did) == 1
    vdm_ref = refs_did[0]
    assert vdm_ref.name == "VDM Firmware"
    assert (
        vdm_ref.installed_fn(
            {
                "raw": {
                    "modules": [
                        {"hwtype": "VDM", "did": "vdm_1", "present": True, "swrev": 13}
                    ]
                }
            }
        )
        == "13"
    )

    # Cover _find_mconf_module did-fallback and mismatch-continue paths.
    assert (
        vdm_ref.latest_fn(
            {
                "config": {
                    "mconf": [
                        {"hwtype": "VDM", "did": "other", "update": True},
                        {"hwtype": "VDM", "did": "vdm_1", "update": True},
                    ]
                },
                "raw": {
                    "modules": [
                        {
                            "hwtype": "VDM",
                            "did": "vdm_1",
                            "present": True,
                            "swrev": 13,
                            "latestFirmware": "14",
                        }
                    ]
                },
            }
        )
        == "14"
    )

    # If config lacks this module and no latest is reported, assume up-to-date.
    assert (
        vdm_ref.latest_fn(
            {
                "config": {
                    "mconf": [{"hwtype": "VDM", "did": "other", "update": True}]
                },
                "raw": {
                    "modules": [
                        {"hwtype": "VDM", "did": "vdm_1", "present": True, "swrev": 13}
                    ]
                },
            }
        )
        == "13"
    )

    # Cover additional module branches with abaddr-based IDs and fallbacks.
    refs2 = update._module_refs(
        {
            "raw": {
                "modules": [
                    {
                        "hwtype": "FMM",
                        "abaddr": 1,
                        "present": True,
                        "latestFirmware": "2",
                    }
                ]
            }
        },
        "ABC",
    )
    assert len(refs2) == 1
    ref2 = refs2[0]

    # hwtype mismatch continue + id mismatch + id fallback + software preferred + latestSw alt
    data2 = {
        "raw": {
            "modules": [
                {
                    "hwtype": "XXX",
                    "abaddr": 1,
                    "software": "IGNORED",
                    "latestFirmware": "3",
                },
                {
                    "hwtype": "FMM",
                    "abaddr": 2,
                    "software": "IGNORED",
                    "latestFirmware": "3",
                },
                # No abaddr -> id fallback via did, matching module_id "1"
                {
                    "hwtype": "FMM",
                    "did": "1",
                    "software": "S1",
                    "latestSw": "S2",
                    "swstat": "OK",
                },
            ]
        }
    }
    assert ref2.installed_fn(data2) == "S1"
    assert ref2.latest_fn(data2) == "S2"
    assert ref2.release_summary_fn(data2) == "OK"
