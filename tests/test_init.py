"""Tests for integration setup/unload."""

from __future__ import annotations

from typing import Any, cast
from unittest.mock import AsyncMock, patch

from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.apex_fusion.const import CONF_HOST, DOMAIN


async def test_async_setup_entry_stores_coordinator_and_forwards_platforms(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = AsyncMock()
    coordinator.async_config_entry_first_refresh = AsyncMock(return_value=None)
    coordinator.data = {}
    coordinator.device_identifier = "entry:TEST"

    with (
        patch(
            "custom_components.apex_fusion.ApexNeptuneDataUpdateCoordinator",
            return_value=coordinator,
        ),
        patch.object(
            hass.config_entries,
            "async_forward_entry_setups",
            new=AsyncMock(return_value=None),
        ) as forward,
    ):
        from custom_components.apex_fusion import async_setup_entry

        assert await async_setup_entry(hass, cast(Any, entry)) is True

    assert hass.data[DOMAIN][entry.entry_id] is coordinator
    forward.assert_awaited()


async def test_async_setup_entry_updates_title_from_controller_hostname(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = AsyncMock()
    coordinator.async_config_entry_first_refresh = AsyncMock(return_value=None)
    coordinator.data = {"config": {"nconf": {"hostname": "200XL"}}}
    coordinator.device_identifier = "entry:TEST"

    with (
        patch(
            "custom_components.apex_fusion.ApexNeptuneDataUpdateCoordinator",
            return_value=coordinator,
        ),
        patch.object(
            hass.config_entries,
            "async_forward_entry_setups",
            new=AsyncMock(return_value=None),
        ),
        patch.object(hass.config_entries, "async_update_entry") as update_entry,
    ):
        from custom_components.apex_fusion import async_setup_entry

        assert await async_setup_entry(hass, cast(Any, entry)) is True

    assert any(
        call.kwargs.get("title") == "200XL (1.2.3.4)"
        for call in update_entry.mock_calls
    )


async def test_async_unload_entry_pops_data_when_unloaded(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = object()

    with patch.object(
        hass.config_entries,
        "async_unload_platforms",
        new=AsyncMock(return_value=True),
    ):
        from custom_components.apex_fusion import async_unload_entry

        assert await async_unload_entry(hass, cast(Any, entry)) is True

    assert entry.entry_id not in hass.data.get(DOMAIN, {})


async def test_async_unload_entry_keeps_data_when_not_unloaded(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    sentinel = object()
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = sentinel

    with patch.object(
        hass.config_entries,
        "async_unload_platforms",
        new=AsyncMock(return_value=False),
    ):
        from custom_components.apex_fusion import async_unload_entry

        assert await async_unload_entry(hass, cast(Any, entry)) is False

    assert hass.data[DOMAIN][entry.entry_id] is sentinel


async def test_async_setup_entry_updates_unique_id_to_serial(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = AsyncMock()
    coordinator.data = {"meta": {"serial": "SER123"}}
    coordinator.async_config_entry_first_refresh = AsyncMock(return_value=None)
    coordinator.device_identifier = "SER123"

    with (
        patch(
            "custom_components.apex_fusion.ApexNeptuneDataUpdateCoordinator",
            return_value=coordinator,
        ),
        patch.object(
            hass.config_entries,
            "async_forward_entry_setups",
            new=AsyncMock(return_value=None),
        ),
        patch.object(hass.config_entries, "async_entries", return_value=[entry]),
        patch.object(hass.config_entries, "async_update_entry") as update,
    ):
        from custom_components.apex_fusion import async_setup_entry

        assert await async_setup_entry(hass, cast(Any, entry)) is True

    update.assert_called_once()
    assert update.call_args.kwargs.get("unique_id") == "SER123"


async def test_async_setup_entry_duplicate_serial_logs_warning(
    hass, enable_custom_integrations, caplog
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    other = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.5"},
        unique_id="SER123",
        title="Apex (1.2.3.5)",
    )
    other.add_to_hass(hass)

    coordinator = AsyncMock()
    coordinator.data = {"meta": {"serial": "SER123"}}
    coordinator.async_config_entry_first_refresh = AsyncMock(return_value=None)
    coordinator.device_identifier = "SER123"

    with (
        patch(
            "custom_components.apex_fusion.ApexNeptuneDataUpdateCoordinator",
            return_value=coordinator,
        ),
        patch.object(
            hass.config_entries,
            "async_forward_entry_setups",
            new=AsyncMock(return_value=None),
        ),
        patch.object(hass.config_entries, "async_entries", return_value=[entry, other]),
        patch.object(hass.config_entries, "async_update_entry") as update,
    ):
        from custom_components.apex_fusion import async_setup_entry

        assert await async_setup_entry(hass, cast(Any, entry)) is True

    assert "Duplicate Apex config entries detected" in caplog.text
    update.assert_not_called()
