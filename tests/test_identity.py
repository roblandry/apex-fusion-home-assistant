"""Tests for the stable, transport-independent controller identity."""

from __future__ import annotations

from typing import Any, cast
from unittest.mock import AsyncMock, patch

from homeassistant.helpers import device_registry as dr, entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.apex_fusion.apex_fusion.context import ApexFusionContext
from custom_components.apex_fusion.const import (
    CONF_HOST,
    CONF_SERIAL,
    CONF_TRANSPORT,
    DOMAIN,
    TRANSPORT_LEGACY,
    TRANSPORT_REST,
)
from custom_components.apex_fusion.coordinator import (
    ApexNeptuneDataUpdateCoordinator,
)

SERIAL = "AC6:LREAL1"


def _payload(*, serial: str | None, source: str) -> dict[str, Any]:
    return {
        "meta": {"serial": serial, "source": source, "hostname": "tank"},
        "probes": {
            "3_0": {"name": "Temp", "type": "Temp", "value": 78.1, "value_raw": 78.1}
        },
        "outlets": [],
        "network": {},
        "alerts": {},
        "trident": {},
    }


async def _setup(hass, entry, method: str, payload: dict[str, Any]) -> None:
    with patch(
        "custom_components.apex_fusion.coordinator."
        f"ApexNeptuneDataUpdateCoordinator.{method}",
        new=AsyncMock(return_value=payload),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()


def _entry(hass, transport: str, **data: Any) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "192.0.2.43", CONF_TRANSPORT: transport, **data},
        unique_id=SERIAL,
        title="Tank",
    )
    entry.add_to_hass(hass)
    return entry


async def test_serial_is_persisted_and_names_the_device(
    hass, enable_custom_integrations
):
    entry = _entry(hass, TRANSPORT_REST)

    await _setup(
        hass, entry, "_async_update_rest", _payload(serial=SERIAL, source="rest")
    )

    assert entry.data[CONF_SERIAL] == SERIAL
    dev = dr.async_get(hass).async_get_device(identifiers={(DOMAIN, SERIAL)})
    assert dev is not None
    probes = [
        e
        for e in er.async_get(hass).entities.values()
        if e.config_entry_id == entry.entry_id and "_probe_" in e.unique_id
    ]
    assert [p.unique_id for p in probes] == ["ac6_lreal1_probe_3_0"]


async def test_stored_serial_is_never_overwritten_by_the_data(
    hass, enable_custom_integrations
):
    entry = _entry(hass, TRANSPORT_REST, **{CONF_SERIAL: SERIAL})

    await _setup(
        hass,
        entry,
        "_async_update_rest",
        _payload(serial="SOMETHING-ELSE", source="rest"),
    )

    assert entry.data[CONF_SERIAL] == SERIAL
    assert (
        dr.async_get(hass).async_get_device(identifiers={(DOMAIN, SERIAL)}) is not None
    )


async def test_identity_is_the_same_on_rest_and_legacy_payloads(
    hass, enable_custom_integrations
):
    """The same physical controller maps to the same ids whatever the transport."""
    entry = _entry(hass, TRANSPORT_REST, **{CONF_SERIAL: SERIAL})
    coordinator = ApexNeptuneDataUpdateCoordinator(hass, entry=cast(Any, entry))

    ids = set()
    for serial, source in ((SERIAL, "rest"), (None, "cgi_json"), ("", "xml")):
        coordinator.data = _payload(serial=serial, source=source)
        ctx = ApexFusionContext.from_entry_and_coordinator(
            cast(Any, entry), coordinator
        )
        ids.add((ctx.controller_device_identifier, ctx.serial_for_ids))

    assert ids == {(SERIAL, "AC6_LREAL1")}


async def test_legacy_controller_without_serial_keeps_a_stable_identity(
    hass, enable_custom_integrations
):
    """No serial in the payload: identity is the entry's unique_id, never `entry:`."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "192.0.2.43", CONF_TRANSPORT: TRANSPORT_LEGACY},
        unique_id="192.0.2.43",
        title="Tank",
    )
    entry.add_to_hass(hass)

    await _setup(
        hass,
        entry,
        "_async_update_legacy",
        _payload(serial=None, source="cgi_json"),
    )

    assert entry.data[CONF_SERIAL] == "192.0.2.43"
    dev_reg = dr.async_get(hass)
    devices = dr.async_entries_for_config_entry(dev_reg, entry.entry_id)
    identifiers = {i[1] for d in devices for i in d.identifiers}
    assert "192.0.2.43" in identifiers
    assert not any(i.startswith("entry:") for i in identifiers)
    ent_reg = er.async_get(hass)
    unique_ids = {
        e.unique_id
        for e in ent_reg.entities.values()
        if e.config_entry_id == entry.entry_id
    }
    assert "192.0.2.43_probe_3_0" in unique_ids

    # Reloading keeps the same device and entities (nothing is recreated).
    before = (len(devices), len(unique_ids))
    with patch(
        "custom_components.apex_fusion.coordinator."
        "ApexNeptuneDataUpdateCoordinator._async_update_legacy",
        new=AsyncMock(return_value=_payload(serial=None, source="cgi_json")),
    ):
        assert await hass.config_entries.async_reload(entry.entry_id)
        await hass.async_block_till_done()
    after_devices = dr.async_entries_for_config_entry(dev_reg, entry.entry_id)
    after_ids = {
        e.unique_id
        for e in ent_reg.entities.values()
        if e.config_entry_id == entry.entry_id
    }
    assert (len(after_devices), len(after_ids)) == before
