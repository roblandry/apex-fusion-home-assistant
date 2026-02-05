"""Tests for Apex Fusion number platform."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, cast
from unittest.mock import AsyncMock

from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.apex_fusion.const import CONF_HOST, CONF_PASSWORD, DOMAIN


@dataclass
class _CoordinatorStub:
    data: dict[str, Any]
    device_identifier: str = "TEST"
    last_update_success: bool = True
    listeners: list[Callable[[], None]] | None = None

    async_trident_set_waste_size_ml: AsyncMock = field(default_factory=AsyncMock)

    def async_add_listener(self, cb: Callable[[], None]) -> Callable[[], None]:
        if self.listeners is not None:
            self.listeners.append(cb)

        def _unsub() -> None:
            return None

        return _unsub


async def test_number_setup_adds_waste_size_and_sets_value(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    listeners: list[Callable[[], None]] = []
    coordinator = _CoordinatorStub(
        data={
            "meta": {"serial": "ABC"},
            "trident": {"present": True, "abaddr": 5, "waste_size_ml": 450.0},
        },
        device_identifier="ABC",
        listeners=listeners,
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import number

    await number.async_setup_entry(hass, cast(Any, entry), _add_entities)

    # Exercise idempotent guard.
    for cb in list(listeners):
        cb()

    assert len(added) == 1

    ent = added[0]
    ent.async_write_ha_state = lambda *args, **kwargs: None
    await ent.async_added_to_hass()

    assert ent._attr_native_value == 450.0

    await ent.async_set_native_value(500.0)
    coordinator.async_trident_set_waste_size_ml.assert_awaited_once()
    assert (
        coordinator.async_trident_set_waste_size_ml.await_args.kwargs["size_ml"]
        == 500.0
    )

    # Cover refresh branches and cleanup.
    coordinator.data["trident"]["waste_size_ml"] = "nope"
    ent._handle_coordinator_update()
    assert ent._attr_native_value is None
    coordinator.data["trident"] = "nope"
    ent._handle_coordinator_update()
    assert ent._attr_native_value is None

    await ent.async_will_remove_from_hass()


async def test_number_setup_skips_without_password(hass, enable_custom_integrations):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_PASSWORD: ""},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(data={"meta": {"serial": "ABC"}})
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import number

    await number.async_setup_entry(hass, cast(Any, entry), _add_entities)
    assert added == []


async def test_number_setup_skips_when_trident_missing_or_invalid(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(data={"meta": {"serial": "ABC"}, "trident": "nope"})
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import number

    await number.async_setup_entry(hass, cast(Any, entry), _add_entities)
    assert added == []

    coordinator.data["trident"] = {"present": False}
    await number.async_setup_entry(hass, cast(Any, entry), _add_entities)
    assert added == []

    coordinator.data["trident"] = {"present": True, "abaddr": "nope"}
    await number.async_setup_entry(hass, cast(Any, entry), _add_entities)
    assert added == []


async def test_number_set_value_wraps_unknown_error(hass, enable_custom_integrations):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(
        data={
            "meta": {"serial": "ABC"},
            "trident": {"present": True, "abaddr": 5, "waste_size_ml": 450.0},
        },
        device_identifier="ABC",
    )
    coordinator.async_trident_set_waste_size_ml.side_effect = RuntimeError("boom")
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    import pytest
    from homeassistant.exceptions import HomeAssistantError

    from custom_components.apex_fusion import number

    await number.async_setup_entry(hass, cast(Any, entry), _add_entities)
    ent = added[0]
    with pytest.raises(HomeAssistantError, match="Error setting Trident waste size"):
        await ent.async_set_native_value(500.0)


async def test_number_set_value_reraises_home_assistant_error(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(
        data={
            "meta": {"serial": "ABC"},
            "trident": {"present": True, "abaddr": 5, "waste_size_ml": 450.0},
        },
        device_identifier="ABC",
    )

    import pytest
    from homeassistant.exceptions import HomeAssistantError

    coordinator.async_trident_set_waste_size_ml.side_effect = HomeAssistantError("nope")
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import number

    await number.async_setup_entry(hass, cast(Any, entry), _add_entities)
    ent = added[0]
    with pytest.raises(HomeAssistantError, match="nope"):
        await ent.async_set_native_value(500.0)


async def test_number_trident_device_info_falls_back_without_abaddr(
    hass, enable_custom_integrations
):
    """Cover defensive device_info fallback when Trident abaddr is missing."""

    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(
        data={
            "meta": {"serial": "ABC"},
            "trident": {"present": True, "waste_size_ml": 450.0},
        },
        device_identifier="ABC",
    )

    from custom_components.apex_fusion.number import ApexTridentWasteSizeNumber

    ent = ApexTridentWasteSizeNumber(cast(Any, coordinator), cast(Any, entry))
    assert ent.device_info is not None
    assert ent.device_info.get("identifiers") == {(DOMAIN, "ABC")}
