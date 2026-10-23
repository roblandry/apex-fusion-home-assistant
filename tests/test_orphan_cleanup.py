"""Tests for removing the old ``AC6:<token>`` controller device safely."""

from __future__ import annotations

from typing import Any, cast
from unittest.mock import AsyncMock, patch

from homeassistant.helpers import device_registry as dr, entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.apex_fusion import async_remove_config_entry_device
from custom_components.apex_fusion.const import (
    CONF_HOST,
    CONF_LAST_SOURCE,
    CONF_SERIAL,
    CONF_TRANSPORT,
    DOMAIN,
    TRANSPORT_REST,
)
from custom_components.apex_fusion.migration import (
    async_remove_orphan_controller_device,
    migrate_v1_to_v2,
)

LIVE = "AC6J:12345"
OLD = "AC6:12345"
HOST = "192.0.2.43"
LIVE_UID = "ac6j_12345_probe_3_0"
OLD_UID = "ac6_12345_probe_3_0"


def _payload() -> dict[str, Any]:
    return {
        "meta": {"serial": LIVE, "source": "rest", "hostname": "tank"},
        "probes": {
            "3_0": {"name": "Temp", "type": "Temp", "value": 78.1, "value_raw": 78.1}
        },
        "outlets": [],
        "network": {},
        "alerts": {},
        "trident": {},
    }


async def _setup(hass, entry) -> None:
    with patch(
        "custom_components.apex_fusion.coordinator."
        "ApexNeptuneDataUpdateCoordinator._async_update_rest",
        new=AsyncMock(return_value=_payload()),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()


def _entry(hass, *, live: str = LIVE, version: int = 2, **extra) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=version,
        data={
            CONF_HOST: HOST,
            CONF_TRANSPORT: TRANSPORT_REST,
            CONF_SERIAL: live,
            **extra,
        },
        unique_id=live,
        title=f"Tank ({HOST})",
    )
    entry.add_to_hass(hass)
    return entry


def _device(hass, entry, identifier: str, *, model: str = "AC6J", via=None):
    return dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, identifier)},
        model=model,
        name=identifier,
        via_device=(DOMAIN, via) if via else None,
    )


def _ent(hass, entry, uid, object_id, device):
    return er.async_get(hass).async_get_or_create(
        "sensor",
        DOMAIN,
        uid,
        config_entry=cast(Any, entry),
        device_id=device.id,
        suggested_object_id=object_id,
    )


def _seed(hass, entry, *, orphan_id: str = OLD, orphan_model: str = "1.0"):
    live = _device(hass, entry, LIVE)
    module = _device(hass, entry, f"{LIVE}_module_FMM_1", model="FMM", via=LIVE)
    orphan = _device(hass, entry, orphan_id, model=orphan_model)
    return live, module, orphan


def _idents(hass, entry) -> set[str]:
    return {
        next(iter(d.identifiers))[1]
        for d in dr.async_entries_for_config_entry(dr.async_get(hass), entry.entry_id)
    }


async def test_entity_free_orphan_is_removed(hass, enable_custom_integrations):
    entry = _entry(hass)
    _live, module, orphan = _seed(hass, entry)

    await _setup(hass, entry)

    assert _idents(hass, entry) == {LIVE, f"{LIVE}_module_FMM_1"}
    assert dr.async_get(hass).async_get(orphan.id) is None
    assert dr.async_get(hass).async_get(module.id) is not None


async def test_orphan_with_entities_is_left_untouched_and_removable(
    hass, enable_custom_integrations
):
    entry = _entry(hass)
    live, _module, orphan = _seed(hass, entry)
    ent_reg = er.async_get(hass)
    _ent(hass, entry, LIVE_UID, "tank_temp", live)
    _ent(hass, entry, OLD_UID, "tank_temp_2", orphan)
    disabled = _ent(hass, entry, "ac6_12345_probe_x", "tank_x", orphan)
    ent_reg.async_update_entity(
        disabled.entity_id, disabled_by=er.RegistryEntryDisabler.USER
    )

    await _setup(hass, entry)

    assert OLD in _idents(hass, entry)
    assert ent_reg.async_get("sensor.tank_temp_2") is not None
    assert ent_reg.async_get(disabled.entity_id) is not None
    assert ent_reg.async_get("sensor.tank_temp") is not None
    kept = dr.async_get(hass).async_get(orphan.id)
    assert kept is not None
    assert await async_remove_config_entry_device(hass, cast(Any, entry), kept)


async def test_second_setup_is_a_noop(hass, enable_custom_integrations):
    entry = _entry(hass)
    _seed(hass, entry)
    await _setup(hass, entry)
    before = _idents(hass, entry)

    with patch(
        "custom_components.apex_fusion.coordinator."
        "ApexNeptuneDataUpdateCoordinator._async_update_rest",
        new=AsyncMock(return_value=_payload()),
    ):
        assert await hass.config_entries.async_reload(entry.entry_id)
        await hass.async_block_till_done()

    assert _idents(hass, entry) == before
    assert OLD not in before


async def test_other_prefix_same_token_is_untouched(hass, enable_custom_integrations):
    entry = _entry(hass)
    _seed(hass, entry, orphan_id="OTHER:12345")

    await _setup(hass, entry)

    assert "OTHER:12345" in _idents(hass, entry)


async def test_prefix_change_ac6j_to_ac6l_is_untouched(
    hass, enable_custom_integrations
):
    entry = _entry(hass, live="AC6L:12345")
    _device(hass, entry, "AC6L:12345", model="AC6L")
    previous = _device(hass, entry, "AC6J:12345", model="AC6J")

    with patch(
        "custom_components.apex_fusion.coordinator."
        "ApexNeptuneDataUpdateCoordinator._async_update_rest",
        new=AsyncMock(return_value={**_payload(), "meta": {"serial": "AC6L:12345"}}),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

    assert dr.async_get(hass).async_get(previous.id) is not None


async def test_same_token_ambiguity_skips_everything(hass, enable_custom_integrations):
    entry = _entry(hass)
    _seed(hass, entry)
    ambiguous = _device(hass, entry, "AC6L:12345", model="AC6L")

    await _setup(hass, entry)

    assert OLD in _idents(hass, entry)
    assert dr.async_get(hass).async_get(ambiguous.id) is not None


async def test_wrong_model_or_extra_identifier_is_untouched(
    hass, enable_custom_integrations
):
    entry = _entry(hass)
    _seed(hass, entry, orphan_model="AC6")
    await _setup(hass, entry)
    assert OLD in _idents(hass, entry)


async def test_other_entries_and_shared_devices_are_untouched(
    hass, enable_custom_integrations
):
    entry = _entry(hass)
    _live, _module, orphan = _seed(hass, entry)
    other = MockConfigEntry(domain=DOMAIN, version=2, data={}, unique_id="x")
    other.add_to_hass(hass)
    foreign = _device(hass, other, "AC6:99999", model="1.0")
    dr.async_get(hass).async_update_device(
        orphan.id, add_config_entry_id=other.entry_id
    )

    await _setup(hass, entry)

    assert dr.async_get(hass).async_get(orphan.id) is not None
    assert dr.async_get(hass).async_get(foreign.id) is not None


async def test_foreign_entry_entity_on_orphan_keeps_the_device(
    hass, enable_custom_integrations
):
    entry = _entry(hass)
    _live, _module, orphan = _seed(hass, entry)
    other = MockConfigEntry(domain=DOMAIN, version=2, data={}, unique_id="x")
    other.add_to_hass(hass)
    _ent(hass, other, "foreign_uid", "foreign", orphan)

    await _setup(hass, entry)

    assert OLD in _idents(hass, entry)


async def test_unverified_identity_skips_cleanup(hass, enable_custom_integrations):
    """Persisted identity differs from the live controller: do nothing."""
    entry = _entry(hass, live="AC6J:99999")
    _seed(hass, entry)
    await _setup(hass, entry)
    assert OLD in _idents(hass, entry)


async def test_migration_does_not_pin_the_old_identity_when_listed_first(
    hass, enable_custom_integrations
):
    """Host-based unique id, old device enumerated first: pin the current one."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=1,
        data={CONF_HOST: HOST, CONF_LAST_SOURCE: "rest"},
        unique_id=HOST,
        title="Tank",
    )
    entry.add_to_hass(hass)
    _device(hass, entry, OLD, model="1.0")
    _device(hass, entry, LIVE)

    await migrate_v1_to_v2(hass, cast(Any, entry))

    assert entry.data[CONF_SERIAL] == LIVE


async def test_remove_device_allows_only_the_verified_orphan(
    hass, enable_custom_integrations
):
    entry = _entry(hass)
    live, module, orphan = _seed(hass, entry)

    # Entry not loaded: the stored identity is used.
    assert await async_remove_config_entry_device(hass, cast(Any, entry), orphan)
    for refused in (live, module):
        assert not await async_remove_config_entry_device(
            hass, cast(Any, entry), refused
        )

    await _setup(hass, entry)
    fresh = _device(hass, entry, OLD, model="1.0")
    assert await async_remove_config_entry_device(hass, cast(Any, entry), fresh)
    assert not await async_remove_config_entry_device(hass, cast(Any, entry), live)


async def test_remove_device_refuses_other_prefix_and_ambiguity(
    hass, enable_custom_integrations
):
    entry = _entry(hass)
    _live, _module, orphan = _seed(hass, entry)
    other_prefix = _device(hass, entry, "OTHER:12345")

    assert not await async_remove_config_entry_device(
        hass, cast(Any, entry), other_prefix
    )
    # Same-token ambiguity also refuses the orphan.
    assert not await async_remove_config_entry_device(hass, cast(Any, entry), orphan)


async def test_remove_device_refuses_unrelated_token(hass, enable_custom_integrations):
    entry = _entry(hass)
    _seed(hass, entry)
    unrelated = _device(hass, entry, "AC6:99999", model="1.0")

    assert not await async_remove_config_entry_device(hass, cast(Any, entry), unrelated)


async def test_remove_device_refuses_when_live_device_is_absent(
    hass, enable_custom_integrations
):
    entry = _entry(hass)
    sole = _device(hass, entry, OLD, model="1.0")

    assert not await async_remove_config_entry_device(hass, cast(Any, entry), sole)


async def test_unpaired_orphan_stays_removable_from_the_ui_when_loaded(
    hass, enable_custom_integrations
):
    """Owner's manual path: entities with no live pair block the auto-cleanup only."""
    entry = _entry(hass)
    live, _module, orphan = _seed(hass, entry)
    _ent(hass, entry, LIVE_UID, "tank_temp", live)
    _ent(hass, entry, "ac6_12345_probe_tmp", "tank_legacy", orphan)

    await _setup(hass, entry)

    kept = dr.async_get(hass).async_get(orphan.id)
    assert kept is not None
    assert await async_remove_config_entry_device(hass, cast(Any, entry), kept)


async def test_remove_device_fails_closed_without_identity(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(domain=DOMAIN, version=2, data={}, unique_id=None)
    entry.add_to_hass(hass)
    live = _device(hass, entry, LIVE)
    orphan = _device(hass, entry, OLD, model="1.0")

    assert not await async_remove_config_entry_device(hass, cast(Any, entry), live)
    assert not await async_remove_config_entry_device(hass, cast(Any, entry), orphan)


async def test_remove_device_refuses_a_live_controller_with_legacy_form(
    hass, enable_custom_integrations
):
    entry = _entry(hass, live=OLD)
    live = _device(hass, entry, OLD, model="1.0")

    assert not await async_remove_config_entry_device(hass, cast(Any, entry), live)


async def test_absent_live_device_defers_cleanup(hass, enable_custom_integrations):
    entry = _entry(hass)
    orphan = _device(hass, entry, OLD, model="1.0")

    assert not async_remove_orphan_controller_device(hass, cast(Any, entry), LIVE)
    assert dr.async_get(hass).async_get(orphan.id) is not None
