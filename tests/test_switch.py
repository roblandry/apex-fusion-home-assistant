"""Tests for Apex Fusion switch platform (Feed Mode)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, cast
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest
from homeassistant.exceptions import HomeAssistantError
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.apex_fusion.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
    DOMAIN,
)


@dataclass
class _CoordinatorStub:
    data: dict[str, Any]
    last_update_success: bool = True
    device_identifier: str = "TEST"
    async_request_refresh: AsyncMock = AsyncMock()
    async_rest_put_json: AsyncMock = AsyncMock()

    def __post_init__(self) -> None:
        self._listeners: list[Callable[[], None]] = []

    def async_add_listener(self, cb: Callable[[], None]) -> Callable[[], None]:
        self._listeners.append(cb)

        def _remove() -> None:
            if cb in self._listeners:
                self._listeners.remove(cb)

        return _remove

    def fire_update(self) -> None:
        for cb in list(self._listeners):
            cb()


class _Resp:
    def __init__(self, status: int, text: str = "") -> None:
        self.status = status
        self._text = text

    async def text(self) -> str:
        return self._text

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise aiohttp.ClientResponseError(
                request_info=cast(Any, None),
                history=(),
                status=self.status,
                message="err",
                headers=None,
            )

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _Session:
    def __init__(self, *, post_responses: list[_Resp] | None = None) -> None:
        self._post_responses = list(post_responses or [])
        self.post_calls: list[dict[str, Any]] = []

    def post(self, url: str, **kwargs: Any) -> _Resp:
        self.post_calls.append({"url": url, **kwargs})
        if not self._post_responses:
            return _Resp(200, "OK")
        return self._post_responses.pop(0)


def test_switch_to_int_helper_covers_float_and_none():
    from custom_components.apex_fusion.switch import _to_int

    assert _to_int(2.0) == 2
    assert _to_int("nope") is None


async def test_switch_setup_entry_creates_four_feed_switches(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_USERNAME: "admin", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(
        data={"meta": {"serial": "ABC"}, "feed": {"name": 2}}
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import switch

    await switch.async_setup_entry(hass, cast(Any, entry), _add_entities)

    assert len(added) == 4
    # Icon requirement.
    assert all(getattr(ent, "icon") == "mdi:shaker" for ent in added)

    # Feed B should be on with feed.name == 2.
    states = {ent.name: ent.is_on for ent in added}
    assert states["Feed B"] is True
    assert states["Feed A"] is False
    assert states["Feed C"] is False
    assert states["Feed D"] is False


async def test_switch_turn_on_uses_rest_and_refreshes(
    hass, enable_custom_integrations, monkeypatch
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_USERNAME: "admin", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(
        data={"meta": {"serial": "ABC"}, "feed": {"name": 0}}
    )
    coordinator.async_rest_put_json = AsyncMock(return_value=None)
    coordinator.async_request_refresh = AsyncMock(return_value=None)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    session = _Session()
    monkeypatch.setattr(
        "custom_components.apex_fusion.switch.async_get_clientsession",
        lambda _h: session,
    )

    from custom_components.apex_fusion.switch import ApexFeedModeSwitch, _FeedRef

    ent = ApexFeedModeSwitch(
        hass,
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_FeedRef(did="1", name="Feed A"),
    )

    await ent.async_turn_on()

    coordinator.async_rest_put_json.assert_awaited()
    kwargs = coordinator.async_rest_put_json.await_args.kwargs
    assert kwargs["path"] == "/rest/status/feed/1"
    assert kwargs["payload"]["active"] == 1

    # No legacy calls when REST succeeds.
    assert session.post_calls == []
    coordinator.async_request_refresh.assert_awaited()


async def test_switch_rest_404_falls_back_to_legacy_cgi(
    hass, enable_custom_integrations, monkeypatch
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_USERNAME: "admin", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(
        data={"meta": {"serial": "ABC"}, "feed": {"name": 0}}
    )
    coordinator.async_rest_put_json = AsyncMock(side_effect=FileNotFoundError())
    coordinator.async_request_refresh = AsyncMock(return_value=None)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    session = _Session(post_responses=[_Resp(200, "OK")])
    monkeypatch.setattr(
        "custom_components.apex_fusion.switch.async_get_clientsession",
        lambda _h: session,
    )

    from custom_components.apex_fusion.switch import ApexFeedModeSwitch, _FeedRef

    ent = ApexFeedModeSwitch(
        hass,
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_FeedRef(did="2", name="Feed B"),
    )

    await ent.async_turn_on()

    assert session.post_calls
    call = session.post_calls[-1]
    assert call["url"].endswith("/cgi-bin/status.cgi")
    assert "FeedSel=1" in str(call["data"])  # Feed B -> 1 in legacy mapping
    assert isinstance(call["auth"], aiohttp.BasicAuth)
    coordinator.async_request_refresh.assert_awaited()


async def test_switch_rest_error_falls_back_to_legacy_cgi(
    hass, enable_custom_integrations, monkeypatch
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_USERNAME: "admin", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(
        data={"meta": {"serial": "ABC"}, "feed": {"name": 1}}
    )
    coordinator.async_rest_put_json = AsyncMock(side_effect=HomeAssistantError("boom"))
    coordinator.async_request_refresh = AsyncMock(return_value=None)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    session = _Session(post_responses=[_Resp(200, "OK")])
    monkeypatch.setattr(
        "custom_components.apex_fusion.switch.async_get_clientsession",
        lambda _h: session,
    )

    from custom_components.apex_fusion.switch import ApexFeedModeSwitch, _FeedRef

    ent = ApexFeedModeSwitch(
        hass,
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_FeedRef(did="1", name="Feed A"),
    )

    await ent.async_turn_off()

    # Cancel maps to FeedSel=5.
    assert session.post_calls
    assert "FeedSel=5" in str(session.post_calls[-1]["data"])


async def test_switch_legacy_cgi_401_raises(
    hass, enable_custom_integrations, monkeypatch
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_USERNAME: "admin", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(
        data={"meta": {"serial": "ABC"}, "feed": {"name": 0}}
    )
    coordinator.async_rest_put_json = AsyncMock(side_effect=FileNotFoundError())
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    session = _Session(post_responses=[_Resp(401, "")])
    monkeypatch.setattr(
        "custom_components.apex_fusion.switch.async_get_clientsession",
        lambda _h: session,
    )

    from custom_components.apex_fusion.switch import ApexFeedModeSwitch, _FeedRef

    ent = ApexFeedModeSwitch(
        hass,
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_FeedRef(did="1", name="Feed A"),
    )

    with pytest.raises(HomeAssistantError, match="Invalid auth"):
        await ent.async_turn_on()


async def test_switch_legacy_cgi_404_raises(
    hass, enable_custom_integrations, monkeypatch
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_USERNAME: "admin", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(
        data={"meta": {"serial": "ABC"}, "feed": {"name": 0}}
    )
    coordinator.async_rest_put_json = AsyncMock(side_effect=FileNotFoundError())
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    session = _Session(post_responses=[_Resp(404, "")])
    monkeypatch.setattr(
        "custom_components.apex_fusion.switch.async_get_clientsession",
        lambda _h: session,
    )

    from custom_components.apex_fusion.switch import ApexFeedModeSwitch, _FeedRef

    ent = ApexFeedModeSwitch(
        hass,
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_FeedRef(did="1", name="Feed A"),
    )

    with pytest.raises(HomeAssistantError, match="endpoint not found"):
        await ent.async_turn_on()


async def test_switch_requires_password_for_control(hass, enable_custom_integrations):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_USERNAME: "admin"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(
        data={"meta": {"serial": "ABC"}, "feed": {"name": 0}}
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    from custom_components.apex_fusion.switch import ApexFeedModeSwitch, _FeedRef

    ent = ApexFeedModeSwitch(
        hass,
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_FeedRef(did="1", name="Feed A"),
    )

    with pytest.raises(HomeAssistantError, match="Password is required"):
        await ent.async_turn_on()


async def test_switch_listener_updates_state_and_unsubscribes(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_USERNAME: "admin", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(
        data={"meta": {"serial": "ABC"}, "feed": {"name": 0}}
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    from custom_components.apex_fusion.switch import ApexFeedModeSwitch, _FeedRef

    ent = ApexFeedModeSwitch(
        hass,
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_FeedRef(did="1", name="Feed A"),
    )

    write = MagicMock()
    ent.async_write_ha_state = write  # type: ignore[method-assign]

    await ent.async_added_to_hass()

    coordinator.data["feed"] = {"name": 1}
    coordinator.fire_update()
    assert ent.is_on is True
    assert write.called

    await ent.async_will_remove_from_hass()
    assert ent._unsub is None

    write.reset_mock()
    coordinator.data["feed"] = {"name": 0}
    coordinator.fire_update()
    assert write.called is False
