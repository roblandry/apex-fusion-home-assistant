"""Tests for Apex Fusion button platform."""

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

    async_trident_prime_channel: AsyncMock = field(default_factory=AsyncMock)
    async_trident_reset_reagent: AsyncMock = field(default_factory=AsyncMock)
    async_trident_reset_waste: AsyncMock = field(default_factory=AsyncMock)
    async_refresh_config_now: AsyncMock = field(default_factory=AsyncMock)

    def async_add_listener(self, cb: Callable[[], None]) -> Callable[[], None]:
        if self.listeners is not None:
            self.listeners.append(cb)

        def _unsub() -> None:
            return None

        return _unsub


async def test_button_setup_adds_trident_buttons_and_presses(
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
            "trident": {"present": True, "abaddr": 5},
        },
        device_identifier="ABC",
        listeners=listeners,
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import button

    await button.async_setup_entry(hass, cast(Any, entry), _add_entities)

    # Exercise idempotent guard.
    for cb in list(listeners):
        cb()

    assert len(added) == 9

    for ent in added:
        ent.async_write_ha_state = lambda *args, **kwargs: None
        await ent.async_added_to_hass()

    # Press each button.
    for ent in added:
        await ent.async_press()

    assert coordinator.async_trident_prime_channel.await_count == 4
    assert [
        c.kwargs["channel_index"]
        for c in coordinator.async_trident_prime_channel.await_args_list
    ] == [
        0,
        1,
        2,
        3,
    ]

    assert coordinator.async_trident_reset_reagent.await_count == 3
    assert [
        c.kwargs["reagent_index"]
        for c in coordinator.async_trident_reset_reagent.await_args_list
    ] == [
        0,
        1,
        2,
    ]

    assert coordinator.async_trident_reset_waste.await_count == 1

    assert coordinator.async_refresh_config_now.await_count == 1

    # Cover cleanup branch.
    for ent in added:
        await ent.async_will_remove_from_hass()


async def test_button_setup_skips_without_password(hass, enable_custom_integrations):
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

    from custom_components.apex_fusion import button

    await button.async_setup_entry(hass, cast(Any, entry), _add_entities)
    assert added == []


async def test_button_setup_skips_when_trident_missing_or_invalid(
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
        data={"meta": {"serial": "ABC"}, "trident": "nope"},
        listeners=listeners,
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import button

    await button.async_setup_entry(hass, cast(Any, entry), _add_entities)

    # Controller-level refresh button is always added when password is configured,
    # even if Trident data is missing/invalid.
    assert len(added) == 1
    added[0].async_write_ha_state = lambda *args, **kwargs: None
    await added[0].async_added_to_hass()
    await added[0].async_press()
    assert coordinator.async_refresh_config_now.await_count == 1

    # When Trident becomes valid later, listener should add Trident buttons.
    coordinator.data["trident"] = {"present": True, "abaddr": 5}
    for cb in list(listeners):
        cb()
    assert len(added) == 9


async def test_button_setup_does_not_add_trident_buttons_when_not_present_or_no_abaddr(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    # Not present -> Trident buttons should not be added.
    coordinator = _CoordinatorStub(
        data={"meta": {"serial": "ABC"}, "trident": {"present": False, "abaddr": 5}}
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import button

    await button.async_setup_entry(hass, cast(Any, entry), _add_entities)
    assert len(added) == 1  # refresh button only

    # Present but missing/invalid abaddr -> still no Trident buttons.
    coordinator2 = _CoordinatorStub(
        data={"meta": {"serial": "ABC"}, "trident": {"present": True, "abaddr": "nope"}}
    )
    hass.data[DOMAIN][entry.entry_id] = coordinator2
    added2: list[Any] = []

    def _add_entities2(new_entities, update_before_add: bool = False):
        added2.extend(list(new_entities))

    await button.async_setup_entry(hass, cast(Any, entry), _add_entities2)
    assert len(added2) == 1  # refresh button only


async def test_button_press_wraps_unknown_error(hass, enable_custom_integrations):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(
        data={"meta": {"serial": "ABC"}, "trident": {"present": True, "abaddr": 5}}
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    import pytest
    from homeassistant.exceptions import HomeAssistantError

    from custom_components.apex_fusion.button import (
        ApexTridentButton,
        _TridentButtonRef,
    )

    async def _boom(_c):
        raise RuntimeError("boom")

    ent = ApexTridentButton(
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_TridentButtonRef(key="x", name="X", icon="mdi:test", press_fn=_boom),
    )
    with pytest.raises(HomeAssistantError, match="Error running"):
        await ent.async_press()


async def test_button_press_reraises_home_assistant_error(
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
        data={"meta": {"serial": "ABC"}, "trident": {"present": True, "abaddr": 5}}
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    import pytest
    from homeassistant.exceptions import HomeAssistantError

    from custom_components.apex_fusion.button import (
        ApexTridentButton,
        _TridentButtonRef,
    )

    async def _boom(_c):
        raise HomeAssistantError("nope")

    ent = ApexTridentButton(
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_TridentButtonRef(key="x", name="X", icon="mdi:test", press_fn=_boom),
    )
    with pytest.raises(HomeAssistantError, match="nope"):
        await ent.async_press()


async def test_controller_button_press_wraps_unknown_error(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(data={"meta": {"serial": "ABC"}})
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    import pytest
    from homeassistant.exceptions import HomeAssistantError

    from custom_components.apex_fusion.button import (
        ApexControllerButton,
        _ControllerButtonRef,
    )

    async def _boom(_c):
        raise RuntimeError("boom")

    ent = ApexControllerButton(
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_ControllerButtonRef(key="x", name="X", icon="mdi:test", press_fn=_boom),
    )
    with pytest.raises(HomeAssistantError, match="Error running"):
        await ent.async_press()


async def test_controller_button_press_reraises_home_assistant_error(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(data={"meta": {"serial": "ABC"}})
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    import pytest
    from homeassistant.exceptions import HomeAssistantError

    from custom_components.apex_fusion.button import (
        ApexControllerButton,
        _ControllerButtonRef,
    )

    async def _boom(_c):
        raise HomeAssistantError("nope")

    ent = ApexControllerButton(
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_ControllerButtonRef(key="x", name="X", icon="mdi:test", press_fn=_boom),
    )
    with pytest.raises(HomeAssistantError, match="nope"):
        await ent.async_press()
