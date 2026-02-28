"""Tests for integration setup/unload."""

from __future__ import annotations

from typing import Any, cast
from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.const import Platform
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.apex_fusion.const import (
    CONF_HOST,
    CONF_LAST_CONTROL_ENABLED,
    CONF_LAST_SOURCE,
    CONF_NO_LOGIN,
    CONF_PASSWORD,
    DOMAIN,
)


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


async def test_async_setup_entry_forwards_rest_authenticated_platforms(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = AsyncMock()
    coordinator.async_config_entry_first_refresh = AsyncMock(return_value=None)
    coordinator.data = {"meta": {"serial": "SER123", "source": "rest"}}
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
        ) as forward,
    ):
        from custom_components.apex_fusion import async_setup_entry

        assert await async_setup_entry(hass, cast(Any, entry)) is True

    platforms = list(forward.call_args.args[1])
    assert "sensor" in platforms
    assert "binary_sensor" in platforms
    assert "update" in platforms
    assert "select" in platforms
    assert "switch" in platforms
    assert "button" in platforms
    assert "number" in platforms


async def test_async_setup_entry_forwards_rest_read_only_platforms(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_NO_LOGIN: True},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = AsyncMock()
    coordinator.async_config_entry_first_refresh = AsyncMock(return_value=None)
    coordinator.data = {"meta": {"serial": "SER123", "source": "rest"}}
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
        ) as forward,
    ):
        from custom_components.apex_fusion import async_setup_entry

        assert await async_setup_entry(hass, cast(Any, entry)) is True

    platforms = list(forward.call_args.args[1])
    assert platforms == ["sensor", "binary_sensor", "update"]


async def test_async_setup_entry_forwards_legacy_platforms(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = AsyncMock()
    coordinator.async_config_entry_first_refresh = AsyncMock(return_value=None)
    coordinator.data = {"meta": {"serial": "SER123", "source": "legacy"}}
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
        ) as forward,
    ):
        from custom_components.apex_fusion import async_setup_entry

        assert await async_setup_entry(hass, cast(Any, entry)) is True

    platforms = list(forward.call_args.args[1])
    assert platforms == ["sensor", "binary_sensor"]


async def test_async_setup_entry_purges_registry_on_source_change(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_LAST_SOURCE: "legacy"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    ent_reg = er.async_get(hass)
    created_entity = ent_reg.async_get_or_create(
        "sensor",
        DOMAIN,
        "uniq_purge",
        config_entry=cast(Any, entry),
        suggested_object_id="probe_t1",
    )
    assert ent_reg.async_get(created_entity.entity_id) is not None

    from homeassistant.helpers import device_registry as dr

    dev_reg = dr.async_get(hass)
    created_device = dev_reg.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, "dev_purge")},
        name="Apex Purge",
    )
    assert dev_reg.async_get(created_device.id) is not None

    coordinator = AsyncMock()
    coordinator.async_config_entry_first_refresh = AsyncMock(return_value=None)
    coordinator.data = {"meta": {"serial": "SER123", "source": "rest"}}
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
        patch.object(hass.config_entries, "async_update_entry") as update_entry,
    ):
        from custom_components.apex_fusion import async_setup_entry

        assert await async_setup_entry(hass, cast(Any, entry)) is True

    # Purge removed stale entries.
    assert ent_reg.async_get(created_entity.entity_id) is None
    assert dev_reg.async_get(created_device.id) is None

    # Entry data updated with the new source.
    assert any(
        call.kwargs.get("data", {}).get(CONF_LAST_SOURCE) == "rest"
        for call in update_entry.mock_calls
    )


async def test_async_setup_entry_purges_registry_on_control_change(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            CONF_HOST: "1.2.3.4",
            CONF_PASSWORD: "pw",
            CONF_LAST_SOURCE: "rest",
            CONF_LAST_CONTROL_ENABLED: False,
        },
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    ent_reg = er.async_get(hass)
    created_entity = ent_reg.async_get_or_create(
        "sensor",
        DOMAIN,
        "uniq_purge_control",
        config_entry=cast(Any, entry),
        suggested_object_id="probe_t1",
    )

    from homeassistant.helpers import device_registry as dr

    dev_reg = dr.async_get(hass)
    created_device = dev_reg.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, "dev_purge_control")},
        name="Apex Purge Control",
    )

    coordinator = AsyncMock()
    coordinator.async_config_entry_first_refresh = AsyncMock(return_value=None)
    coordinator.data = {"meta": {"serial": "SER123", "source": "rest"}}
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
        patch.object(hass.config_entries, "async_update_entry") as update_entry,
    ):
        from custom_components.apex_fusion import async_setup_entry

        assert await async_setup_entry(hass, cast(Any, entry)) is True

    assert ent_reg.async_get(created_entity.entity_id) is None
    assert dev_reg.async_get(created_device.id) is None
    assert any(
        call.kwargs.get("data", {}).get(CONF_LAST_CONTROL_ENABLED) is True
        for call in update_entry.mock_calls
    )


async def test_async_setup_entry_purge_swallows_exceptions(
    hass, enable_custom_integrations, caplog
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_LAST_SOURCE: "legacy"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    # Ensure there is something to purge so the remover is exercised.
    ent_reg = er.async_get(hass)
    ent_reg.async_get_or_create(
        "sensor",
        DOMAIN,
        "uniq_purge_boom",
        config_entry=cast(Any, entry),
        suggested_object_id="probe_t1",
    )

    coordinator = AsyncMock()
    coordinator.async_config_entry_first_refresh = AsyncMock(return_value=None)
    coordinator.data = {"meta": {"serial": "SER123", "source": "rest"}}
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
        patch(
            "homeassistant.helpers.entity_registry.EntityRegistry.async_remove",
            side_effect=ValueError("boom"),
        ),
    ):
        from custom_components.apex_fusion import async_setup_entry

        assert await async_setup_entry(hass, cast(Any, entry)) is True

    assert "Failed to purge entity/device registry" in caplog.text


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


async def test_async_setup_entry_title_cleans_underscores_in_hostname(
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
    coordinator.data = {"config": {"nconf": {"hostname": "80g_Frag_Tank"}}}
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
        call.kwargs.get("title") == "80g Frag Tank (1.2.3.4)"
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


async def test_async_unload_entry_uses_entry_platforms_when_present(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    # Pretend only sensor was ever loaded.
    setattr(entry, "platforms", {"sensor"})
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = object()

    with patch.object(
        hass.config_entries,
        "async_unload_platforms",
        new=AsyncMock(return_value=True),
    ) as unload:
        from custom_components.apex_fusion import async_unload_entry

        assert await async_unload_entry(hass, cast(Any, entry)) is True

    # Ensure we only attempted to unload the platforms actually loaded.
    args = unload.call_args.args
    assert list(args[1]) == ["sensor"]


async def test_async_unload_entry_accepts_platform_enum_items(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    setattr(entry, "platforms", {Platform.SENSOR})
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = object()

    with patch.object(
        hass.config_entries,
        "async_unload_platforms",
        new=AsyncMock(return_value=True),
    ) as unload:
        from custom_components.apex_fusion import async_unload_entry

        assert await async_unload_entry(hass, cast(Any, entry)) is True

    args = unload.call_args.args
    assert list(args[1]) == ["sensor"]


async def test_async_unload_entry_falls_back_to_stored_platforms(
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
    hass.data[DOMAIN].setdefault("_loaded_platforms", {})[entry.entry_id] = [
        Platform.SENSOR,
        Platform.BINARY_SENSOR,
    ]

    with patch.object(
        hass.config_entries,
        "async_unload_platforms",
        new=AsyncMock(return_value=True),
    ) as unload:
        from custom_components.apex_fusion import async_unload_entry

        assert await async_unload_entry(hass, cast(Any, entry)) is True

    args = unload.call_args.args
    assert list(args[1]) == ["sensor", "binary_sensor"]
    assert entry.entry_id not in hass.data[DOMAIN].get("_loaded_platforms", {})


async def test_async_unload_entry_last_resort_unloads_all_platforms(
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
    ) as unload:
        from custom_components.apex_fusion import async_unload_entry

        assert await async_unload_entry(hass, cast(Any, entry)) is True

    # Falls back to the integration's PLATFORMS list.
    from custom_components.apex_fusion.const import PLATFORMS

    args = unload.call_args.args
    assert list(args[1]) == [p.value for p in PLATFORMS]


async def test_async_unload_entry_retries_on_value_error_with_fallback(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    setattr(entry, "platforms", {"sensor"})
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = object()

    unload = AsyncMock(side_effect=[ValueError("boom"), True])
    with patch.object(hass.config_entries, "async_unload_platforms", new=unload):
        from custom_components.apex_fusion import async_unload_entry

        assert await async_unload_entry(hass, cast(Any, entry)) is True

    assert unload.await_count == 2


async def test_async_unload_entry_platforms_not_iterable_uses_stored_map(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    # Non-iterable shape for entry.platforms (covers the early-return branch).
    setattr(entry, "platforms", "sensor")

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = object()
    hass.data[DOMAIN].setdefault("_loaded_platforms", {})[entry.entry_id] = [
        Platform.SENSOR
    ]

    with patch.object(
        hass.config_entries,
        "async_unload_platforms",
        new=AsyncMock(return_value=True),
    ) as unload:
        from custom_components.apex_fusion import async_unload_entry

        assert await async_unload_entry(hass, cast(Any, entry)) is True

    args = unload.call_args.args
    assert list(args[1]) == ["sensor"]


async def test_async_unload_entry_ignores_invalid_platform_names(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    setattr(entry, "platforms", {"not-a-platform"})
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = object()

    with patch.object(
        hass.config_entries,
        "async_unload_platforms",
        new=AsyncMock(return_value=True),
    ) as unload:
        from custom_components.apex_fusion import async_unload_entry

        assert await async_unload_entry(hass, cast(Any, entry)) is True

    from custom_components.apex_fusion.const import PLATFORMS

    args = unload.call_args.args
    assert list(args[1]) == [p.value for p in PLATFORMS]


async def test_async_unload_entry_value_error_with_no_fallback_reraises(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    # Forces fallback to be empty in the exception handler.
    setattr(entry, "platforms", "sensor")
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = object()

    unload = AsyncMock(side_effect=ValueError("Config entry was never loaded!"))
    with patch.object(hass.config_entries, "async_unload_platforms", new=unload):
        from custom_components.apex_fusion import async_unload_entry

        with pytest.raises(ValueError):
            await async_unload_entry(hass, cast(Any, entry))


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


async def test_async_setup_entry_does_not_rename_existing_entity_ids(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    ent_reg = er.async_get(hass)
    created = ent_reg.async_get_or_create(
        "sensor",
        DOMAIN,
        "uniq1",
        config_entry=cast(Any, entry),
        suggested_object_id="probe_t1",
    )
    assert created.entity_id == "sensor.probe_t1"

    coordinator = AsyncMock()
    coordinator.async_config_entry_first_refresh = AsyncMock(return_value=None)
    coordinator.data = {"meta": {"hostname": "my_tank"}}
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
    ):
        from custom_components.apex_fusion import async_setup_entry

        assert await async_setup_entry(hass, cast(Any, entry)) is True

    assert ent_reg.async_get("sensor.probe_t1") is not None
    assert ent_reg.async_get("sensor.my_tank_probe_t1") is None
