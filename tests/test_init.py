"""Tests for integration setup/unload."""

from __future__ import annotations

from typing import Any, cast
from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import Platform
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.update_coordinator import UpdateFailed
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.apex_fusion.config_flow import CannotConnect, InvalidAuth
from custom_components.apex_fusion.const import (
    CONF_HOST,
    CONF_LAST_SOURCE,
    CONF_LEGACY_FORMAT,
    CONF_NO_LOGIN,
    CONF_PASSWORD,
    CONF_SERIAL,
    CONF_TRANSPORT,
    DOMAIN,
    TRANSPORT_LEGACY,
    TRANSPORT_REST,
)


async def test_async_setup_entry_stores_coordinator_and_forwards_platforms(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "192.0.2.4", CONF_TRANSPORT: TRANSPORT_REST},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
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
    coordinator.async_restore_install_window.assert_awaited_once()


async def test_async_setup_entry_reuses_cached_rest_sid_when_available(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "192.0.2.4", CONF_TRANSPORT: TRANSPORT_REST},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
    )
    entry.add_to_hass(hass)

    # Seed a cached SID under hass.data[DOMAIN].
    hass.data.setdefault(DOMAIN, {})["_rest_sid_by_host"] = {"192.0.2.4": "abc"}

    coordinator = AsyncMock()
    coordinator.async_config_entry_first_refresh = AsyncMock(return_value=None)
    coordinator.data = {}
    coordinator.device_identifier = "entry:TEST"

    with (
        patch(
            "custom_components.apex_fusion.ApexNeptuneDataUpdateCoordinator",
            return_value=coordinator,
        ) as ctor,
        patch.object(
            hass.config_entries,
            "async_forward_entry_setups",
            new=AsyncMock(return_value=None),
        ),
    ):
        from custom_components.apex_fusion import async_setup_entry

        assert await async_setup_entry(hass, cast(Any, entry)) is True

    assert ctor.call_args.kwargs.get("rest_sid_seed") == "abc"


async def test_async_setup_entry_handles_sid_cache_lookup_exception(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            CONF_HOST: "192.0.2.4",
            CONF_TRANSPORT: TRANSPORT_REST,
            CONF_SERIAL: "SER123",
        },
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
    )
    entry.add_to_hass(hass)

    class _BoomyData(dict[str, Any]):
        def get(self, _key, default=None):  # type: ignore[override]
            raise RuntimeError("boom")

    original_data = hass.data
    hass.data = _BoomyData()  # type: ignore[assignment]

    coordinator = AsyncMock()
    coordinator.async_config_entry_first_refresh = AsyncMock(return_value=None)
    coordinator.data = {}
    coordinator.device_identifier = "entry:TEST"

    try:
        with (
            patch(
                "custom_components.apex_fusion.ApexNeptuneDataUpdateCoordinator",
                return_value=coordinator,
            ) as ctor,
            patch.object(
                hass.config_entries,
                "async_forward_entry_setups",
                new=AsyncMock(return_value=None),
            ),
        ):
            from custom_components.apex_fusion import async_setup_entry

            assert await async_setup_entry(hass, cast(Any, entry)) is True

        assert ctor.call_args.kwargs.get("rest_sid_seed") is None
    finally:
        hass.data = original_data


async def test_async_setup_entry_forwards_rest_authenticated_platforms(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            CONF_HOST: "192.0.2.4",
            CONF_PASSWORD: "pw",
            CONF_TRANSPORT: TRANSPORT_REST,
        },
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
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
        data={
            CONF_HOST: "192.0.2.4",
            CONF_NO_LOGIN: True,
            CONF_TRANSPORT: TRANSPORT_REST,
        },
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
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
        data={
            CONF_HOST: "192.0.2.4",
            CONF_PASSWORD: "pw",
            CONF_TRANSPORT: TRANSPORT_LEGACY,
        },
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
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


async def test_setup_never_purges_registry_when_source_changes(
    hass, enable_custom_integrations
):
    """A changed data source must not delete devices or entities."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            CONF_HOST: "192.0.2.4",
            CONF_TRANSPORT: TRANSPORT_REST,
            CONF_LAST_SOURCE: "cgi_json",
        },
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
    )
    entry.add_to_hass(hass)

    ent_reg = er.async_get(hass)
    created_entity = ent_reg.async_get_or_create(
        "sensor",
        DOMAIN,
        "uniq_keep",
        config_entry=cast(Any, entry),
        suggested_object_id="probe_t1",
    )
    from homeassistant.helpers import device_registry as dr

    dev_reg = dr.async_get(hass)
    created_device = dev_reg.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, "dev_keep")},
        name="Apex Keep",
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
    ):
        from custom_components.apex_fusion import async_setup_entry

        assert await async_setup_entry(hass, cast(Any, entry)) is True

    assert ent_reg.async_get(created_entity.entity_id) is not None
    assert dev_reg.async_get(created_device.id) is not None
    # The stored transport is not rewritten from what the data happened to say.
    assert entry.data[CONF_TRANSPORT] == TRANSPORT_REST


async def _setup_with_stub_coordinator(hass, entry):
    coordinator = AsyncMock()
    coordinator.async_config_entry_first_refresh = AsyncMock(return_value=None)
    coordinator.data = {"meta": {"serial": "SER123"}}
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
    return list(forward.call_args.args[1])


@pytest.mark.parametrize(
    ("last_source", "expected"),
    [
        ("rest", TRANSPORT_REST),
        ("cgi_json", TRANSPORT_LEGACY),
        ("xml", TRANSPORT_LEGACY),
    ],
)
async def test_setup_infers_transport_from_last_source(
    hass, enable_custom_integrations, last_source, expected
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            CONF_HOST: "192.0.2.4",
            CONF_PASSWORD: "pw",
            CONF_LAST_SOURCE: last_source,
        },
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
    )
    entry.add_to_hass(hass)

    with patch("custom_components.apex_fusion.async_validate_input") as validate:
        platforms = await _setup_with_stub_coordinator(hass, entry)

    validate.assert_not_called()
    assert entry.data[CONF_TRANSPORT] == expected
    assert ("update" in platforms) is (expected == TRANSPORT_REST)


async def test_setup_detects_transport_once_when_nothing_is_stored(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "192.0.2.4", CONF_PASSWORD: "pw"},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
    )
    entry.add_to_hass(hass)

    with patch(
        "custom_components.apex_fusion.async_validate_input",
        new=AsyncMock(
            return_value={"title": "t", "unique_id": "u", "transport": TRANSPORT_REST}
        ),
    ) as validate:
        platforms = await _setup_with_stub_coordinator(hass, entry)

    validate.assert_awaited_once()
    assert entry.data[CONF_TRANSPORT] == TRANSPORT_REST
    assert "select" in platforms


@pytest.mark.parametrize(
    ("error", "expected"),
    [(CannotConnect(), ConfigEntryNotReady), (InvalidAuth(), ConfigEntryAuthFailed)],
)
async def test_setup_detection_failure_is_retry_or_reauth(
    hass, enable_custom_integrations, error, expected
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "192.0.2.4", CONF_PASSWORD: "pw"},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
    )
    entry.add_to_hass(hass)

    from custom_components.apex_fusion import async_setup_entry

    with patch(
        "custom_components.apex_fusion.async_validate_input",
        new=AsyncMock(side_effect=error),
    ):
        with pytest.raises(expected):
            await async_setup_entry(hass, cast(Any, entry))
    assert CONF_TRANSPORT not in entry.data


async def test_first_refresh_failure_leaves_entry_in_setup_retry(
    hass, enable_custom_integrations
):
    """An unreachable pinned transport retries later; it never switches."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={
            CONF_HOST: "192.0.2.4",
            CONF_PASSWORD: "pw",
            CONF_TRANSPORT: TRANSPORT_REST,
        },
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
    )
    entry.add_to_hass(hass)

    with (
        patch(
            "custom_components.apex_fusion.coordinator."
            "ApexNeptuneDataUpdateCoordinator._async_update_rest",
            new=AsyncMock(side_effect=UpdateFailed("down")),
        ) as rest,
        patch(
            "custom_components.apex_fusion.coordinator."
            "ApexNeptuneDataUpdateCoordinator._async_update_legacy",
            new=AsyncMock(),
        ) as legacy,
    ):
        assert not await hass.config_entries.async_setup(entry.entry_id)

    assert cast(Any, entry).state is ConfigEntryState.SETUP_RETRY
    rest.assert_awaited_once()
    legacy.assert_not_awaited()
    assert entry.data[CONF_TRANSPORT] == TRANSPORT_REST


async def test_async_setup_entry_updates_title_from_controller_hostname(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "192.0.2.4", CONF_TRANSPORT: TRANSPORT_REST},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
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
        call.kwargs.get("title") == "200XL (192.0.2.4)"
        for call in update_entry.mock_calls
    )


async def test_async_setup_entry_title_cleans_underscores_in_hostname(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "192.0.2.4", CONF_TRANSPORT: TRANSPORT_REST},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
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
        call.kwargs.get("title") == "80g Frag Tank (192.0.2.4)"
        for call in update_entry.mock_calls
    )


async def test_async_unload_entry_pops_data_when_unloaded(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "192.0.2.4", CONF_TRANSPORT: TRANSPORT_REST},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
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
        data={CONF_HOST: "192.0.2.4", CONF_TRANSPORT: TRANSPORT_REST},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
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
        data={CONF_HOST: "192.0.2.4", CONF_TRANSPORT: TRANSPORT_REST},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
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
        data={CONF_HOST: "192.0.2.4", CONF_TRANSPORT: TRANSPORT_REST},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
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
        data={CONF_HOST: "192.0.2.4", CONF_TRANSPORT: TRANSPORT_REST},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
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
        data={CONF_HOST: "192.0.2.4", CONF_TRANSPORT: TRANSPORT_REST},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
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
        data={CONF_HOST: "192.0.2.4", CONF_TRANSPORT: TRANSPORT_REST},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
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
        data={CONF_HOST: "192.0.2.4", CONF_TRANSPORT: TRANSPORT_REST},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
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
        data={CONF_HOST: "192.0.2.4", CONF_TRANSPORT: TRANSPORT_REST},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
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
        data={CONF_HOST: "192.0.2.4", CONF_TRANSPORT: TRANSPORT_REST},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
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
        data={CONF_HOST: "192.0.2.4", CONF_TRANSPORT: TRANSPORT_REST},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
    )
    entry.add_to_hass(hass)

    coordinator = AsyncMock()
    coordinator.data = {"meta": {"serial": "SER123"}}
    coordinator.device_identifier = "SER123"
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

    unique_id_calls = [c for c in update.call_args_list if "unique_id" in c.kwargs]
    assert len(unique_id_calls) == 1
    assert unique_id_calls[0].kwargs["unique_id"] == "SER123"


async def test_async_setup_entry_duplicate_serial_logs_warning(
    hass, enable_custom_integrations, caplog
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "192.0.2.4", CONF_TRANSPORT: TRANSPORT_REST},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
    )
    entry.add_to_hass(hass)

    other = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "192.0.2.5", CONF_TRANSPORT: TRANSPORT_REST},
        unique_id="SER123",
        title="Apex (192.0.2.5)",
    )
    other.add_to_hass(hass)

    coordinator = AsyncMock()
    coordinator.data = {"meta": {"serial": "SER123"}}
    coordinator.device_identifier = "SER123"
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
    assert not any("unique_id" in c.kwargs for c in update.call_args_list)


async def test_async_setup_entry_does_not_rename_existing_entity_ids(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "192.0.2.4", CONF_TRANSPORT: TRANSPORT_REST},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
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


@pytest.mark.parametrize("source", ["cgi_json", "xml"])
async def test_setup_pins_legacy_format_from_first_refresh(
    hass, enable_custom_integrations, source
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "192.0.2.4", CONF_TRANSPORT: TRANSPORT_LEGACY},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
    )
    entry.add_to_hass(hass)

    coordinator = AsyncMock()
    coordinator.async_config_entry_first_refresh = AsyncMock(return_value=None)
    coordinator.data = {"meta": {"serial": "SER123", "source": source}}
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
    ):
        from custom_components.apex_fusion import async_setup_entry

        assert await async_setup_entry(hass, cast(Any, entry)) is True

    assert entry.data[CONF_LEGACY_FORMAT] == source


async def test_setup_detection_records_legacy_format(hass, enable_custom_integrations):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "192.0.2.4", CONF_PASSWORD: ""},
        unique_id="192.0.2.4",
        title="Apex (192.0.2.4)",
    )
    entry.add_to_hass(hass)

    with patch(
        "custom_components.apex_fusion.async_validate_input",
        new=AsyncMock(
            return_value={
                "title": "t",
                "unique_id": "u",
                "transport": TRANSPORT_LEGACY,
                "legacy_format": "xml",
            }
        ),
    ):
        platforms = await _setup_with_stub_coordinator(hass, entry)

    assert entry.data[CONF_TRANSPORT] == TRANSPORT_LEGACY
    assert entry.data[CONF_LEGACY_FORMAT] == "xml"
    assert "update" not in platforms
