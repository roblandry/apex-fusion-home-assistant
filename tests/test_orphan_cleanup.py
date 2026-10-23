"""Tests for removing old-form controller devices left behind by earlier releases."""

from __future__ import annotations

from typing import Any, cast
from unittest.mock import AsyncMock, patch

from homeassistant.helpers import device_registry as dr, entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.apex_fusion import async_remove_config_entry_device
from custom_components.apex_fusion.const import (
    CONF_HOST,
    CONF_SERIAL,
    CONF_TRANSPORT,
    DOMAIN,
    TRANSPORT_REST,
)

LIVE = "AC6J:12345"
OLD = "AC6:12345"
HOST = "192.0.2.43"


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


def _entry(hass, *, unique_id: str = LIVE) -> MockConfigEntry:
    """An entry that is already at version 2, as after the beta migration."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        data={CONF_HOST: HOST, CONF_TRANSPORT: TRANSPORT_REST, CONF_SERIAL: LIVE},
        unique_id=unique_id,
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


def _state(hass, entry) -> set[str]:
    return {
        next(iter(d.identifiers))[1]
        for d in dr.async_entries_for_config_entry(dr.async_get(hass), entry.entry_id)
    }


def _seed(hass, entry):
    live = _device(hass, entry, LIVE)
    module = _device(hass, entry, f"{LIVE}_module_FMM_1", model="FMM", via=LIVE)
    orphan = _device(hass, entry, OLD, model="1.0")
    return live, module, orphan


async def test_v2_entry_with_orphan_is_cleaned_on_setup(
    hass, enable_custom_integrations
):
    entry = _entry(hass)
    _live, module, orphan = _seed(hass, entry)
    ent_reg = er.async_get(hass)
    stale = ent_reg.async_get_or_create(
        "sensor",
        DOMAIN,
        "ac6_12345_probe_tmp",
        config_entry=cast(Any, entry),
        device_id=orphan.id,
        suggested_object_id="tank_temp_2",
    )

    await _setup(hass, entry)

    ids = _state(hass, entry)
    assert OLD not in ids
    assert LIVE in ids
    assert f"{LIVE}_module_FMM_1" in ids
    assert dr.async_get(hass).async_get(orphan.id) is None
    assert dr.async_get(hass).async_get(module.id) is not None
    assert ent_reg.async_get(stale.entity_id) is None


async def test_second_setup_is_a_noop(hass, enable_custom_integrations):
    entry = _entry(hass)
    _seed(hass, entry)
    await _setup(hass, entry)
    before = _state(hass, entry)

    with patch(
        "custom_components.apex_fusion.coordinator."
        "ApexNeptuneDataUpdateCoordinator._async_update_rest",
        new=AsyncMock(return_value=_payload()),
    ):
        assert await hass.config_entries.async_reload(entry.entry_id)
        await hass.async_block_till_done()

    assert _state(hass, entry) == before
    assert OLD not in before


async def test_other_entries_and_unrelated_devices_are_untouched(
    hass, enable_custom_integrations
):
    entry = _entry(hass)
    _seed(hass, entry)
    other = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        data={CONF_HOST: "192.0.2.44", CONF_SERIAL: "AC6J:67890"},
        unique_id="AC6J:67890",
    )
    other.add_to_hass(hass)
    other_live = _device(hass, other, "AC6J:67890")
    # Same token as the entry's controller, but owned by another entry.
    foreign_twin = _device(hass, other, OLD, model="1.0")
    # Different serial token on this entry: not a twin of the live controller.
    unrelated = _device(hass, entry, "AC6:99999", model="1.0")

    await _setup(hass, entry)

    dev_reg = dr.async_get(hass)
    assert dev_reg.async_get(foreign_twin.id) is not None
    assert dev_reg.async_get(other_live.id) is not None
    assert dev_reg.async_get(unrelated.id) is not None


async def test_twin_shared_with_another_entry_is_left_in_place(
    hass, enable_custom_integrations
):
    entry = _entry(hass)
    _live, _module, orphan = _seed(hass, entry)
    other = MockConfigEntry(domain=DOMAIN, version=2, data={}, unique_id="x")
    other.add_to_hass(hass)
    dr.async_get(hass).async_update_device(
        orphan.id, add_config_entry_id=other.entry_id
    )

    await _setup(hass, entry)

    assert dr.async_get(hass).async_get(orphan.id) is not None


async def test_remove_device_allows_orphan_and_refuses_live(
    hass, enable_custom_integrations
):
    entry = _entry(hass)
    live, module, orphan = _seed(hass, entry)
    # Without a loaded coordinator the stored serial still identifies the live device.
    assert await async_remove_config_entry_device(hass, cast(Any, entry), orphan)
    assert not await async_remove_config_entry_device(hass, cast(Any, entry), live)
    assert not await async_remove_config_entry_device(hass, cast(Any, entry), module)

    await _setup(hass, entry)
    fresh_orphan = _device(hass, entry, OLD, model="1.0")
    assert await async_remove_config_entry_device(hass, cast(Any, entry), fresh_orphan)
    assert not await async_remove_config_entry_device(hass, cast(Any, entry), live)


async def test_device_with_extra_identifier_is_left_in_place(
    hass, enable_custom_integrations
):
    entry = _entry(hass)
    _seed(hass, entry)
    merged = dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, "AC6:12345"), (DOMAIN, "something-else")},
        model="1.0",
    )

    await _setup(hass, entry)

    assert dr.async_get(hass).async_get(merged.id) is not None


async def test_twin_holding_another_entries_entity_is_left_in_place(
    hass, enable_custom_integrations
):
    entry = _entry(hass)
    _live, _module, orphan = _seed(hass, entry)
    other = MockConfigEntry(domain=DOMAIN, version=2, data={}, unique_id="x")
    other.add_to_hass(hass)
    foreign = er.async_get(hass).async_get_or_create(
        "sensor",
        DOMAIN,
        "foreign_uid",
        config_entry=cast(Any, other),
        device_id=orphan.id,
    )

    await _setup(hass, entry)

    assert dr.async_get(hass).async_get(orphan.id) is not None
    assert er.async_get(hass).async_get(foreign.entity_id) is not None


async def test_remove_device_without_any_known_identity_is_allowed(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(domain=DOMAIN, version=2, data={}, unique_id=None)
    entry.add_to_hass(hass)
    device = _device(hass, entry, OLD, model="1.0")

    assert await async_remove_config_entry_device(hass, cast(Any, entry), device)
