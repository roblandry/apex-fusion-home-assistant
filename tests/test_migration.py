"""Tests for the v1 -> v2 config entry migration."""

from __future__ import annotations

import logging
from typing import Any, cast
from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.helpers import device_registry as dr, entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.apex_fusion import async_migrate_entry
from custom_components.apex_fusion.const import (
    CONF_HOST,
    CONF_LAST_SOURCE,
    CONF_LEGACY_FORMAT,
    CONF_PASSWORD,
    CONF_SERIAL,
    CONF_TRANSPORT,
    DOMAIN,
    TRANSPORT_LEGACY,
    TRANSPORT_REST,
)
from custom_components.apex_fusion.migration import (
    CONFIG_ENTRY_VERSION,
    MigrationPlan,
    migrate_v1_to_v2,
)

SERIAL = "AC6:LREAL1"
TOKEN = "ac6_lreal1"
HOST = "192.0.2.43"


def _entry(hass, *, unique_id: str | None = SERIAL, **data: Any) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=1,
        data={CONF_HOST: HOST, CONF_PASSWORD: "pw", **data},
        unique_id=unique_id,
        title=f"Tank ({HOST})",
    )
    entry.add_to_hass(hass)
    return entry


def _uid(ent_reg, entity_id: str) -> str:
    found = ent_reg.async_get(entity_id)
    assert found is not None
    return found.unique_id


def _eid(ent_reg, entity_id: str) -> str:
    found = ent_reg.async_get(entity_id)
    assert found is not None
    return found.id


def _ids(dev_reg, device_id: str) -> set[tuple[str, str]]:
    found = dev_reg.async_get(device_id)
    assert found is not None
    return set(found.identifiers)


def _device(hass, entry, identifier: str, *, model: str = "AC6L", name: str = "dev"):
    return dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, identifier)},
        model=model,
        name=name,
    )


def _entity(
    hass,
    entry,
    domain: str,
    unique_id: str,
    object_id: str,
    *,
    device=None,
    disabled: bool = False,
):
    return er.async_get(hass).async_get_or_create(
        domain,
        DOMAIN,
        unique_id,
        config_entry=cast(Any, entry),
        device_id=device.id if device else None,
        suggested_object_id=object_id,
        disabled_by=er.RegistryEntryDisabler.INTEGRATION if disabled else None,
    )


def _rob_case(hass):
    """Registry state matching a REST controller that once fell through to legacy."""
    entry = _entry(hass, **{CONF_LAST_SOURCE: "cgi_json"})
    dev_reg = dr.async_get(hass)

    rest_dev = _device(hass, entry, SERIAL, name="Tank - APEX")
    rest_module = _device(hass, entry, f"{SERIAL}_module_FMM_3", name="FMM")
    orphan = _device(
        hass, entry, f"entry:{entry.entry_id}", model="APEX 1.0", name="Orphan"
    )
    orphan_module = _device(
        hass, entry, f"entry:{entry.entry_id}_module_FMM_3", name="Orphan FMM"
    )

    rest = {
        "temp": _entity(
            hass, entry, "sensor", f"{TOKEN}_probe_3_0", "tank_temp", device=rest_dev
        ),
        "ph": _entity(
            hass, entry, "sensor", f"{TOKEN}_probe_3_1", "tank_ph", device=rest_dev
        ),
        "update": _entity(
            hass,
            entry,
            "update",
            f"{TOKEN}_update_firmware",
            "tank_aos",
            device=rest_dev,
        ),
        "refresh": _entity(
            hass,
            entry,
            "button",
            f"{TOKEN}_module_fmm_3_refresh_config",
            "tank_fmm_refresh",
            device=rest_module,
        ),
    }
    legacy = {
        "temp_twin": _entity(
            hass, entry, "sensor", f"{HOST}_probe_3_0", "tank_temp_2", device=orphan
        ),
        "ph_twin": _entity(
            hass,
            entry,
            "sensor",
            f"{HOST}_probe_3_1",
            "tank_ph_2",
            device=orphan,
            disabled=True,
        ),
        "only": _entity(
            hass,
            entry,
            "sensor",
            f"{HOST}_probe_legacy_only",
            "tank_legacy_only",
            device=orphan,
        ),
        "module_twin": _entity(
            hass,
            entry,
            "button",
            f"{HOST}_module_fmm_3_refresh_config",
            "tank_fmm_refresh_2",
            device=orphan_module,
        ),
    }
    return entry, dev_reg, rest_dev, rest_module, orphan, orphan_module, rest, legacy


async def test_rob_case_keeps_rest_entities_and_removes_orphans(
    hass, enable_custom_integrations
):
    entry, dev_reg, rest_dev, rest_module, orphan, orphan_module, rest, legacy = (
        _rob_case(hass)
    )
    ent_reg = er.async_get(hass)
    rest_before = {k: (v.entity_id, v.unique_id) for k, v in rest.items()}

    assert await async_migrate_entry(hass, cast(Any, entry)) is True

    # REST entities: same entity_id, same unique_id, nothing renamed.
    for key, (entity_id, unique_id) in rest_before.items():
        current = ent_reg.async_get(entity_id)
        assert current is not None, key
        assert current.unique_id == unique_id
        assert current.id == rest[key].id
    # Orphan entities (twins and the legacy-only one) are gone.
    for ref in legacy.values():
        assert ent_reg.async_get(ref.entity_id) is None
    # Orphan devices are gone, the real ones stay.
    assert dev_reg.async_get(orphan.id) is None
    assert dev_reg.async_get(orphan_module.id) is None
    assert dev_reg.async_get(rest_dev.id) is not None
    assert dev_reg.async_get(rest_module.id) is not None

    assert entry.version == CONFIG_ENTRY_VERSION
    assert entry.data[CONF_TRANSPORT] == TRANSPORT_REST
    assert entry.data[CONF_SERIAL] == SERIAL
    assert CONF_LAST_SOURCE not in entry.data
    assert "last_control_enabled" not in entry.data


async def test_migration_is_idempotent(hass, enable_custom_integrations):
    entry, *_ = _rob_case(hass)
    await migrate_v1_to_v2(hass, cast(Any, entry))
    ent_reg = er.async_get(hass)
    dev_reg = dr.async_get(hass)
    snapshot = (
        sorted((e.entity_id, e.unique_id) for e in ent_reg.entities.values()),
        sorted(tuple(sorted(d.identifiers)) for d in dev_reg.devices.values()),
        dict(entry.data),
    )

    # Run it again, as if the version bump had not been persisted.
    plan = await migrate_v1_to_v2(hass, cast(Any, entry))

    assert plan.uid_rewrites == {}
    assert plan.twin_entities == []
    assert plan.orphan_entities == []
    assert plan.device_renames == {}
    assert plan.device_removals == []
    assert snapshot == (
        sorted((e.entity_id, e.unique_id) for e in ent_reg.entities.values()),
        sorted(tuple(sorted(d.identifiers)) for d in dev_reg.devices.values()),
        dict(entry.data),
    )
    # And the HA entry point does nothing for an up-to-date entry.
    assert await async_migrate_entry(hass, cast(Any, entry)) is True


async def test_dry_run_logs_summary_and_changes_nothing(
    hass, enable_custom_integrations, caplog
):
    entry, dev_reg, _, _, orphan, _, rest, legacy = _rob_case(hass)
    ent_reg = er.async_get(hass)
    before = sorted((e.entity_id, e.unique_id) for e in ent_reg.entities.values())

    with caplog.at_level(logging.DEBUG, logger="custom_components.apex_fusion"):
        plan = await migrate_v1_to_v2(hass, cast(Any, entry), dry_run=True)

    assert isinstance(plan, MigrationPlan)
    # twins: temp, ph, module button; leftover legacy-only sensor is an orphan.
    assert sorted(plan.twin_entities) == sorted(
        legacy[k].entity_id for k in ("temp_twin", "ph_twin", "module_twin")
    )
    assert plan.orphan_entities == [legacy["only"].entity_id]
    assert len(plan.device_removals) == 2
    assert entry.version == 1
    assert CONF_TRANSPORT not in entry.data
    assert before == sorted(
        (e.entity_id, e.unique_id) for e in ent_reg.entities.values()
    )
    assert dev_reg.async_get(orphan.id) is not None
    assert "(dry run)" in caplog.text
    assert "duplicate entities removed=3" in caplog.text
    assert "orphan entities removed=1" in caplog.text
    assert "orphan devices removed=2" in caplog.text
    assert "removing duplicate entity" in caplog.text


async def test_legacy_only_entry_is_renamed_in_place_and_keeps_entities(
    hass, enable_custom_integrations
):
    entry = _entry(hass, **{CONF_LAST_SOURCE: "xml"}, password="")
    dev_reg = dr.async_get(hass)
    ent_reg = er.async_get(hass)
    ctrl = _device(hass, entry, f"entry:{entry.entry_id}", model="APEX 1.0")
    module = _device(hass, entry, f"entry:{entry.entry_id}_module_FMM_3")
    probe = _entity(hass, entry, "sensor", f"{HOST}_probe_tmp", "tank_tmp", device=ctrl)
    refresh = _entity(
        hass,
        entry,
        "sensor",
        f"{HOST}_module_fmm_3_firmware",
        "fmm",
        device=module,
    )

    await migrate_v1_to_v2(hass, cast(Any, entry))

    assert entry.data[CONF_TRANSPORT] == TRANSPORT_LEGACY
    assert entry.data[CONF_LEGACY_FORMAT] == "xml"
    # Same entities, same entity_ids, only the unique_id prefix changed.
    assert _uid(ent_reg, probe.entity_id) == f"{TOKEN}_probe_tmp".lower()
    assert _uid(ent_reg, refresh.entity_id) == f"{TOKEN}_module_fmm_3_firmware"
    assert _eid(ent_reg, probe.entity_id) == probe.id
    # Devices are renamed in place (customizations survive), not recreated.
    assert _ids(dev_reg, ctrl.id) == {(DOMAIN, SERIAL)}
    assert _ids(dev_reg, module.id) == {(DOMAIN, f"{SERIAL}_module_FMM_3")}


async def test_duplicate_orphan_device_with_live_legacy_entities_is_kept(
    hass, enable_custom_integrations
):
    """Never remove a device that still has entities."""
    entry = _entry(hass, **{CONF_LAST_SOURCE: "xml"})
    dev_reg = dr.async_get(hass)
    ent_reg = er.async_get(hass)
    real = _device(hass, entry, SERIAL)
    orphan = _device(hass, entry, f"entry:{entry.entry_id}", model="APEX 1.0")
    twin = _entity(hass, entry, "sensor", f"{HOST}_probe_tmp", "tmp_2", device=orphan)
    _entity(hass, entry, "sensor", f"{TOKEN}_probe_tmp", "tmp", device=real)
    live = _entity(hass, entry, "sensor", f"{HOST}_probe_sal", "sal", device=orphan)

    await migrate_v1_to_v2(hass, cast(Any, entry))

    assert ent_reg.async_get(twin.entity_id) is None  # twin of a live entity
    assert _uid(ent_reg, live.entity_id) == f"{TOKEN}_probe_sal"
    assert dev_reg.async_get(orphan.id) is not None  # still holds `live`


async def test_two_legacy_entities_mapping_to_one_unique_id_keep_one(
    hass, enable_custom_integrations
):
    entry = _entry(hass, **{CONF_LAST_SOURCE: "xml"})
    ent_reg = er.async_get(hass)
    first = _entity(hass, entry, "sensor", f"{HOST}_probe_tmp", "tmp_a")
    second = _entity(
        hass, entry, "sensor", f"entry_{entry.entry_id.lower()}_probe_tmp", "tmp_b"
    )

    plan = await migrate_v1_to_v2(hass, cast(Any, entry))

    survivors = [
        e for e in (first, second) if ent_reg.async_get(e.entity_id) is not None
    ]
    assert len(survivors) == 1
    assert len(plan.twin_entities) == 1
    assert _uid(ent_reg, survivors[0].entity_id) == f"{TOKEN}_probe_tmp"


async def test_collision_with_another_entry_leaves_entity_untouched(
    hass, enable_custom_integrations
):
    entry = _entry(hass, **{CONF_LAST_SOURCE: "xml"})
    other = MockConfigEntry(domain=DOMAIN, data={CONF_HOST: "9.9.9.9"}, unique_id="x")
    other.add_to_hass(hass)
    ent_reg = er.async_get(hass)
    mine = _entity(hass, entry, "sensor", f"{HOST}_probe_tmp", "mine")
    _entity(hass, other, "sensor", f"{TOKEN}_probe_tmp", "theirs")

    await migrate_v1_to_v2(hass, cast(Any, entry))

    assert _uid(ent_reg, mine.entity_id) == f"{HOST}_probe_tmp".lower()


async def test_model_marked_duplicate_without_orphan_identifier_is_removed(
    hass, enable_custom_integrations
):
    entry = _entry(hass, **{CONF_LAST_SOURCE: "rest"})
    dev_reg = dr.async_get(hass)
    _device(hass, entry, SERIAL)
    odd = _device(hass, entry, "something-else", model="APEX 1.0")

    await migrate_v1_to_v2(hass, cast(Any, entry))

    assert dev_reg.async_get(odd.id) is None


async def test_serial_is_taken_from_device_identifier_when_unique_id_is_host(
    hass, enable_custom_integrations
):
    entry = _entry(hass, unique_id=HOST, **{CONF_LAST_SOURCE: "rest"})
    _device(hass, entry, SERIAL)
    _device(hass, entry, f"{SERIAL}_module_FMM_3")
    _device(hass, entry, f"entry:{entry.entry_id}", model="APEX 1.0")

    await migrate_v1_to_v2(hass, cast(Any, entry))

    assert entry.data[CONF_SERIAL] == SERIAL


async def test_serial_less_entry_keeps_its_unique_id_as_identity(
    hass, enable_custom_integrations
):
    entry = _entry(hass, unique_id=HOST, **{CONF_LAST_SOURCE: "xml"})
    ent_reg = er.async_get(hass)
    probe = _entity(hass, entry, "sensor", f"{HOST}_probe_tmp", "tmp")

    await migrate_v1_to_v2(hass, cast(Any, entry))

    assert entry.data[CONF_SERIAL] == HOST
    assert _uid(ent_reg, probe.entity_id) == f"{HOST}_probe_tmp".lower()


async def test_entry_without_any_identity_is_versioned_but_not_touched(
    hass, enable_custom_integrations
):
    entry = _entry(hass, unique_id=None)

    plan = await migrate_v1_to_v2(hass, cast(Any, entry))

    assert plan.serial is None
    assert entry.version == 2
    assert CONF_SERIAL not in entry.data
    assert CONF_TRANSPORT not in entry.data


async def test_downgrade_from_newer_version_is_refused(
    hass, enable_custom_integrations
):
    entry = _entry(hass)
    object.__setattr__(entry, "version", 3)

    assert await async_migrate_entry(hass, cast(Any, entry)) is False


async def test_unknown_source_and_no_evidence_leaves_transport_for_setup(
    hass, enable_custom_integrations
):
    entry = _entry(hass)

    await migrate_v1_to_v2(hass, cast(Any, entry))

    assert CONF_TRANSPORT not in entry.data


async def test_migration_end_to_end_keeps_rest_entity_ids_through_setup(
    hass, enable_custom_integrations
):
    """A v1 entry upgraded and set up: REST entities keep their entity_ids."""
    entry, dev_reg, rest_dev, _, orphan, _, rest, legacy = _rob_case(hass)
    ent_reg = er.async_get(hass)
    expected = {k: v.entity_id for k, v in rest.items()}

    payload: dict[str, Any] = {
        "meta": {
            "serial": SERIAL,
            "source": "rest",
            "hostname": "tank",
            "type": "AC6L",
        },
        "probes": {
            "3_0": {
                "name": "Temp",
                "type": "Temp",
                "value": 78.1,
                "value_raw": 78.1,
            },
            "3_1": {"name": "pH", "type": "pH", "value": 8.1, "value_raw": 8.1},
        },
        "outlets": [],
        "network": {},
        "alerts": {},
        "trident": {},
    }
    with patch(
        "custom_components.apex_fusion.coordinator."
        "ApexNeptuneDataUpdateCoordinator._async_update_rest",
        new=AsyncMock(return_value=payload),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

    assert entry.version == 2
    for key in ("temp", "ph"):
        current = ent_reg.async_get(expected[key])
        assert current is not None
        assert current.id == rest[key].id
        assert hass.states.get(expected[key]) is not None
    for ref in legacy.values():
        assert ent_reg.async_get(ref.entity_id) is None
    assert dev_reg.async_get(orphan.id) is None
    # No entity was created under a host- or entry-based identity.
    assert not [
        e
        for e in ent_reg.entities.values()
        if e.config_entry_id == entry.entry_id and e.unique_id.startswith(HOST)
    ]


@pytest.mark.parametrize("transport", [TRANSPORT_REST, TRANSPORT_LEGACY])
def test_plan_summary_mentions_counts(transport):
    plan = MigrationPlan(transport=transport, serial=SERIAL)
    assert "unique_ids rewritten=0" in plan.summary()
    assert f"transport={transport}" in plan.summary()


async def test_host_based_device_identifiers_are_renamed_to_the_serial(
    hass, enable_custom_integrations
):
    entry = _entry(hass, **{CONF_LAST_SOURCE: "cgi_json"}, password="")
    dev_reg = dr.async_get(hass)
    ctrl = _device(hass, entry, HOST, model="APEX 1.0")
    module = _device(hass, entry, f"{HOST}_module_FMM_3")

    await migrate_v1_to_v2(hass, cast(Any, entry))

    assert _ids(dev_reg, ctrl.id) == {(DOMAIN, SERIAL)}
    assert _ids(dev_reg, module.id) == {(DOMAIN, f"{SERIAL}_module_FMM_3")}
    assert entry.data[CONF_LEGACY_FORMAT] == "cgi_json"


async def test_apply_plan_skips_registry_items_that_disappeared(
    hass, enable_custom_integrations
):
    from custom_components.apex_fusion.migration import apply_plan, build_plan

    entry, dev_reg, _, _, orphan, _, rest, legacy = _rob_case(hass)
    plan = build_plan(hass, cast(Any, entry), transport=TRANSPORT_REST)
    # Something else removed these between planning and applying.
    er.async_get(hass).async_remove(legacy["only"].entity_id)
    dev_reg.async_remove_device(orphan.id)
    plan.device_renames["gone-device-id"] = {(DOMAIN, "x")}

    await apply_plan(hass, cast(Any, entry), plan)

    assert er.async_get(hass).async_get(rest["temp"].entity_id) is not None


async def test_foreign_entities_on_an_orphan_device_are_never_touched(
    hass, enable_custom_integrations
):
    entry = _entry(hass, **{CONF_LAST_SOURCE: "rest"})
    other = MockConfigEntry(domain=DOMAIN, data={CONF_HOST: "9.9.9.9"}, unique_id="x")
    other.add_to_hass(hass)
    dev_reg = dr.async_get(hass)
    ent_reg = er.async_get(hass)
    _device(hass, entry, SERIAL)
    orphan = _device(hass, entry, f"entry:{entry.entry_id}", model="APEX 1.0")
    foreign = _entity(hass, other, "sensor", "other_probe", "foreign", device=orphan)

    await migrate_v1_to_v2(hass, cast(Any, entry))

    assert ent_reg.async_get(foreign.entity_id) is not None
    assert dev_reg.async_get(orphan.id) is not None  # still holds an entity
