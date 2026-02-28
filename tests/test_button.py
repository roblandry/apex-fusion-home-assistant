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

    async_rest_put_json: AsyncMock = field(default_factory=AsyncMock)
    async_request_refresh: AsyncMock = field(default_factory=AsyncMock)

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

    coordinator = _CoordinatorStub(
        data={
            "meta": {"serial": "ABC"},
            "raw": {"modules": [{"abaddr": 5, "hwtype": "TRI", "present": True}]},
            "trident": {"present": True, "abaddr": 5, "hwtype": "TRI"},
        },
        device_identifier="ABC",
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import button

    await button.async_setup_entry(hass, cast(Any, entry), _add_entities)

    # Controller refresh + Trident module refresh + 8 Trident buttons.
    assert len(added) == 10

    for ent in added:
        ent.async_write_ha_state = lambda *args, **kwargs: None
        await ent.async_added_to_hass()
        await ent.async_press()

    # 2 refresh buttons
    assert coordinator.async_refresh_config_now.await_count == 2
    # 4 prime buttons
    assert coordinator.async_trident_prime_channel.await_count == 4
    # 3 reagent resets
    assert coordinator.async_trident_reset_reagent.await_count == 3
    # 1 waste reset
    assert coordinator.async_trident_reset_waste.await_count == 1


async def test_button_setup_adds_trident_np_buttons_when_present_false(
    hass, enable_custom_integrations
):
    """Trident NP sometimes reports present=false even when installed.

    We still want the consumables controls to exist so the user can operate
    the module when the controller payload is inconsistent.
    """

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
            "trident": {"present": False, "abaddr": 3, "hwtype": "TNP"},
        },
        device_identifier="ABC",
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import button

    await button.async_setup_entry(hass, cast(Any, entry), _add_entities)

    # Controller refresh + 8 Trident consumables buttons.
    assert len(added) == 9

    for ent in added:
        ent.async_write_ha_state = lambda *args, **kwargs: None
        await ent.async_added_to_hass()
        await ent.async_press()

    # 1 refresh button
    assert coordinator.async_refresh_config_now.await_count == 1
    # 4 prime buttons
    assert coordinator.async_trident_prime_channel.await_count == 4
    # 3 reagent resets
    assert coordinator.async_trident_reset_reagent.await_count == 3
    # 1 waste reset
    assert coordinator.async_trident_reset_waste.await_count == 1


async def test_button_setup_adds_module_refresh_buttons_when_modules_present(
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
            "raw": {
                "modules": [
                    {"abaddr": 2, "hwtype": "FMM", "present": True},
                ]
            },
        },
        device_identifier="ABC",
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import button

    await button.async_setup_entry(hass, cast(Any, entry), _add_entities)

    # 1 controller refresh + 1 module refresh
    assert len(added) == 2
    for ent in added:
        ent.async_write_ha_state = lambda *args, **kwargs: None
        await ent.async_added_to_hass()

    # Press both refresh buttons.
    for ent in added:
        await ent.async_press()
    assert coordinator.async_refresh_config_now.await_count == 2


async def test_button_setup_adds_module_refresh_buttons_from_mconf(
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
            "config": {
                "mconf": [
                    {"abaddr": 2, "hwtype": "FMM", "name": "My FMM"},
                ]
            },
        },
        device_identifier="ABC",
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import button

    await button.async_setup_entry(hass, cast(Any, entry), _add_entities)

    # 1 controller refresh + 1 module refresh (from config)
    assert len(added) == 2
    for ent in added:
        ent.async_write_ha_state = lambda *args, **kwargs: None
        await ent.async_added_to_hass()

    for ent in added:
        await ent.async_press()
    assert coordinator.async_refresh_config_now.await_count == 2


async def test_button_setup_adds_trident_module_refresh_when_raw_modules_missing_hwtype(
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
            "raw": {
                "modules": [
                    {"abaddr": 5, "present": True},
                ]
            },
            "config": {"mconf": [{"abaddr": 5, "hwtype": "TRI"}]},
            "trident": {"present": True, "abaddr": 5, "hwtype": "TRI"},
        },
        device_identifier="ABC",
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import button

    await button.async_setup_entry(hass, cast(Any, entry), _add_entities)

    # 1 controller refresh + 1 module refresh (Trident) + 8 Trident consumables buttons
    assert len(added) == 10

    module_refresh = next(
        (
            e
            for e in added
            if isinstance(e, button.ApexModuleRefreshConfigButton)
            and getattr(e, "_module_abaddr", None) == 5
        ),
        None,
    )
    assert module_refresh is not None

    # Press both refresh buttons.
    for ent in added:
        ent.async_write_ha_state = lambda *args, **kwargs: None
        await ent.async_added_to_hass()
        await ent.async_press()

    assert coordinator.async_refresh_config_now.await_count == 2


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
    # 1 controller refresh (already present) + 1 module refresh + 8 Trident consumables buttons
    assert len(added) == 10


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

    coordinator = _CoordinatorStub(data={"meta": {"serial": "ABC"}})
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    import pytest
    from homeassistant.exceptions import HomeAssistantError

    from custom_components.apex_fusion.button import ApexModuleRefreshConfigButton

    coordinator.async_refresh_config_now.side_effect = HomeAssistantError("nope")

    ent = ApexModuleRefreshConfigButton(
        cast(Any, coordinator),
        cast(Any, entry),
        module_abaddr=1,
        module_hwtype=None,
    )

    with pytest.raises(HomeAssistantError, match="nope"):
        await ent.async_press()


async def test_module_refresh_button_press_wraps_unknown_error(
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

    from custom_components.apex_fusion.button import ApexModuleRefreshConfigButton

    coordinator.async_refresh_config_now.side_effect = RuntimeError("boom")

    ent = ApexModuleRefreshConfigButton(
        cast(Any, coordinator),
        cast(Any, entry),
        module_abaddr=1,
        module_hwtype=None,
    )

    with pytest.raises(HomeAssistantError, match="Error running Refresh Config Now"):
        await ent.async_press()


async def test_button_entities_unsubscribe_on_remove(hass, enable_custom_integrations):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(
        data={"meta": {"serial": "ABC"}, "trident": {"present": True, "abaddr": 5}},
        device_identifier="ABC",
    )

    from custom_components.apex_fusion.button import (
        ApexControllerButton,
        ApexModuleRefreshConfigButton,
        ApexTridentButton,
        _ControllerButtonRef,
        _TridentButtonRef,
    )

    async def _noop(_c):
        return None

    controller = ApexControllerButton(
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_ControllerButtonRef(key="x", name="X", icon="mdi:test", press_fn=_noop),
    )
    trident = ApexTridentButton(
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_TridentButtonRef(
            key="trident_x", name="X", icon="mdi:test", press_fn=_noop
        ),
    )
    module_refresh = ApexModuleRefreshConfigButton(
        cast(Any, coordinator),
        cast(Any, entry),
        module_abaddr=1,
        module_hwtype=None,
    )

    for ent in (controller, trident, module_refresh):
        ent.async_write_ha_state = lambda *args, **kwargs: None
        await ent.async_added_to_hass()
        await ent.async_will_remove_from_hass()


async def test_button_setup_defensive_module_refresh_branches(
    hass, enable_custom_integrations, monkeypatch
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(
        data={"meta": {"serial": "ABC"}}, device_identifier="ABC"
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    from custom_components.apex_fusion import button

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    # abaddr in candidate not int -> skip
    monkeypatch.setattr(
        button,
        "best_module_candidates_by_abaddr",
        lambda _data, include_trident=True: {1: {"abaddr": "nope", "present": True}},
    )
    await button.async_setup_entry(hass, cast(Any, entry), _add_entities)
    assert len(added) == 1

    # present flag false -> skip
    added.clear()
    monkeypatch.setattr(
        button,
        "best_module_candidates_by_abaddr",
        lambda _data, include_trident=True: {1: {"abaddr": 1, "present": False}},
    )
    await button.async_setup_entry(hass, cast(Any, entry), _add_entities)
    assert len(added) == 1

    # device info build returns None -> skip
    added.clear()
    monkeypatch.setattr(
        button,
        "best_module_candidates_by_abaddr",
        lambda _data, include_trident=True: {1: {"abaddr": 1, "present": True}},
    )
    monkeypatch.setattr(
        button, "build_aquabus_child_device_info_from_data", lambda **_: None
    )
    await button.async_setup_entry(hass, cast(Any, entry), _add_entities)
    assert len(added) == 1


async def test_button_setup_dedupes_module_refresh_and_trident_buttons(
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
            "raw": {"modules": [{"abaddr": 2, "hwtype": "FMM", "present": True}]},
            "trident": {"present": True, "abaddr": 5, "hwtype": "TRI"},
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
    initial_len = len(added)
    assert initial_len >= 1

    # Re-run listeners: should not duplicate module refresh or trident buttons.
    for cb in list(listeners):
        cb()
    assert len(added) == initial_len


async def test_trident_button_device_info_falls_back_without_abaddr(
    hass, enable_custom_integrations
):
    """Cover defensive device_info fallback when Trident abaddr is missing.

    Args:
        hass: Home Assistant fixture.
        enable_custom_integrations: Fixture enabling custom integrations.

    Returns:
        None.
    """

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
            "trident": {"present": True},
        },
        device_identifier="ABC",
    )

    from custom_components.apex_fusion.button import (
        ApexTridentButton,
        _TridentButtonRef,
    )

    async def _noop(_c):
        return None

    ent = ApexTridentButton(
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_TridentButtonRef(key="x", name="X", icon="mdi:test", press_fn=_noop),
    )
    assert ent.device_info is not None
    assert ent.device_info.get("identifiers") == {(DOMAIN, "ABC")}

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
