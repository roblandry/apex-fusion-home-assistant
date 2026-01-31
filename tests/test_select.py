"""Tests for Apex Fusion select platform."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, cast
from unittest.mock import AsyncMock

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

    def __post_init__(self) -> None:
        self._listeners: list[Callable[[], None]] = []
        self._disable_rest_calls: list[dict[str, Any]] = []

    def async_add_listener(
        self, update_callback: Callable[[], None]
    ) -> Callable[[], None]:
        self._listeners.append(update_callback)

        def _unsub() -> None:
            return None

        return _unsub

    def fire_update(self) -> None:
        for cb in list(self._listeners):
            cb()

    def _disable_rest(self, *, seconds: float, reason: str) -> None:
        self._disable_rest_calls.append({"seconds": seconds, "reason": reason})


class _Morsel:
    def __init__(self, value: str):
        self.value = value


class _CookieJar:
    def __init__(self, sid: str | None):
        self._sid = sid

    def filter_cookies(self, _url: Any) -> dict[str, Any]:
        if self._sid:
            return {"connect.sid": _Morsel(self._sid)}
        return {}


class _Resp:
    def __init__(self, status: int, text: str = "", headers: Any | None = None):
        self.status = status
        self._text = text
        self.headers = headers if headers is not None else {}

    async def text(self) -> str:
        return self._text

    def raise_for_status(self) -> None:
        return None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _Session:
    def __init__(
        self,
        *,
        cookie_sid: str | None = None,
        post_responses: list[_Resp] | None = None,
        put_responses: list[_Resp] | None = None,
        post_raises: Exception | None = None,
        put_raises: Exception | None = None,
    ):
        self.cookie_jar = _CookieJar(cookie_sid)
        self._post_iter = iter(post_responses or [])
        self._put_iter = iter(put_responses or [])
        self._post_raises = post_raises
        self._put_raises = put_raises
        self.post_calls: list[dict[str, Any]] = []
        self.put_calls: list[dict[str, Any]] = []

    def post(self, url: str, **kwargs: Any) -> _Resp:
        self.post_calls.append({"url": url, **kwargs})
        if self._post_raises is not None:
            raise self._post_raises
        return next(self._post_iter)

    def put(self, url: str, **kwargs: Any) -> _Resp:
        self.put_calls.append({"url": url, **kwargs})
        if self._put_raises is not None:
            raise self._put_raises
        return next(self._put_iter)


class _HeadersRaises:
    def get(self, _key: str) -> Any:  # pragma: no cover
        raise RuntimeError("boom")


def test_select_helpers_cover_all_branches():
    from custom_components.apex_fusion import select

    assert select._is_selectable_outlet({"state": "AON"}) is True
    assert select._is_selectable_outlet({"state": "AOF"}) is True
    assert select._is_selectable_outlet({"state": "TBL"}) is True
    assert select._is_selectable_outlet({"state": "ON"}) is True
    assert select._is_selectable_outlet({"state": "OFF"}) is True
    assert select._is_selectable_outlet({"state": "XXX"}) is False

    assert select._option_from_raw_state("ON") == "On"
    assert select._option_from_raw_state("OFF") == "Off"
    assert select._option_from_raw_state("AON") == "Auto"
    assert select._option_from_raw_state("AOF") == "Auto"
    assert select._option_from_raw_state("TBL") == "Auto"
    assert select._option_from_raw_state("???") is None

    assert select._effective_state_from_raw_state("") is None
    assert select._effective_state_from_raw_state("ON") == "On"
    assert select._effective_state_from_raw_state("AON") == "On"
    assert select._effective_state_from_raw_state("TBL") == "On"
    assert select._effective_state_from_raw_state("OFF") == "Off"
    assert select._effective_state_from_raw_state("AOF") == "Off"

    assert select._mode_from_option("Auto") == "AUTO"
    assert select._mode_from_option("On") == "ON"
    assert select._mode_from_option("Off") == "OFF"
    with pytest.raises(HomeAssistantError):
        select._mode_from_option("nope")


async def test_select_setup_entry_creates_selects_and_listener_adds_new(
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
        data={
            "meta": {"serial": "ABC"},
            "outlets": [
                "not-a-dict",
                {"name": "MissingDid", "state": "AON", "type": "EB832"},
                {
                    "name": "Outlet_1",
                    "device_id": "O1",
                    "state": "AON",
                    "type": "EB832",
                },
                {"name": "Ignored", "device_id": "OX", "state": "XXX", "type": "EB832"},
                {"name": "Bad", "device_id": "O2", "state": "TBL", "type": "EB832"},
            ],
        },
        last_update_success=True,
        device_identifier="ABC",
    )
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    added: list[Any] = []

    def _add_entities(new_entities, update_before_add: bool = False):
        added.extend(list(new_entities))

    from custom_components.apex_fusion import select

    await select.async_setup_entry(hass, cast(Any, entry), _add_entities)

    # O1 and O2 should get selects; missing did and XXX are ignored.
    assert len(added) == 2

    # Add a new outlet and fire coordinator listener; ensure it adds only the new one.
    coordinator.data["outlets"].append(
        {"name": "Outlet_3", "device_id": "O3", "state": "OFF", "type": "EB832"}
    )
    coordinator.fire_update()
    assert len(added) == 3


async def test_select_entity_attributes_include_raw_and_mxm(
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
        data={
            "meta": {"serial": "ABC"},
            "outlets": [
                {
                    "name": "Nero_5_F",
                    "device_id": "O1",
                    "state": "AOF",
                    "type": "MXMPump|AI|Nero5",
                    "output_id": "1",
                    "gid": "g",
                    "status": ["AOF"],
                }
            ],
            "mxm_devices": {"Nero_5_F": {"rev": "1", "serial": "S", "status": "OK"}},
        },
        device_identifier="ABC",
    )

    from custom_components.apex_fusion.select import ApexOutletModeSelect, _OutletRef

    ent = ApexOutletModeSelect(
        hass,
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_OutletRef(did="O1", name="AI Nero 5 (Nero 5 F)"),
    )

    ent.async_write_ha_state = lambda *args, **kwargs: None
    await ent.async_added_to_hass()

    assert ent.extra_state_attributes is not None
    attrs = cast(dict[str, Any], ent.extra_state_attributes)
    assert attrs["raw_state"] == "AOF"
    assert attrs["effective_state"] == "Off"
    assert attrs["raw_mode"] == "AUTO"
    assert attrs["mxm_rev"] == "1"
    assert attrs["mxm_serial"] == "S"
    assert attrs["mxm_status"] == "OK"

    await ent.async_will_remove_from_hass()


async def test_select_find_outlet_handles_non_list_and_non_dict(
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
        data={"meta": {"serial": "ABC"}, "outlets": "nope"},
        device_identifier="ABC",
    )

    from custom_components.apex_fusion.select import ApexOutletModeSelect, _OutletRef

    ent = ApexOutletModeSelect(
        hass,
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_OutletRef(did="O1", name="Outlet 1"),
    )
    assert ent._find_outlet() == {}
    assert ent._read_raw_state() == ""

    coordinator.data["outlets"] = ["not-a-dict", {"device_id": "O1", "state": "ON"}]
    assert ent._find_outlet().get("device_id") == "O1"

    ent2 = ApexOutletModeSelect(
        hass,
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_OutletRef(did="NO_MATCH", name="Outlet X"),
    )
    assert ent2._find_outlet() == {}


async def test_select_control_requires_password(hass, enable_custom_integrations):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_USERNAME: "admin"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(
        data={
            "meta": {"serial": "ABC"},
            "outlets": [{"device_id": "O1", "state": "OFF"}],
        },
        device_identifier="ABC",
    )

    from custom_components.apex_fusion.select import ApexOutletModeSelect, _OutletRef

    ent = ApexOutletModeSelect(
        hass,
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_OutletRef(did="O1", name="Outlet 1"),
    )

    with pytest.raises(HomeAssistantError, match="Password is required"):
        await ent.async_select_option("On")


async def test_select_control_invalid_mode_raises(
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
        data={
            "meta": {"serial": "ABC"},
            "outlets": [{"device_id": "O1", "state": "OFF"}],
        },
        device_identifier="ABC",
    )

    from custom_components.apex_fusion.select import ApexOutletModeSelect, _OutletRef

    ent = ApexOutletModeSelect(
        hass,
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_OutletRef(did="O1", name="Outlet 1"),
    )

    session = _Session(cookie_sid="abc", put_responses=[_Resp(200, "OK")])
    monkeypatch.setattr(
        "custom_components.apex_fusion.select.async_get_clientsession",
        lambda _h: session,
    )

    with pytest.raises(HomeAssistantError, match="Invalid outlet mode"):
        await ent._async_set_mode("NOPE")


async def test_select_control_uses_existing_cookie_sid_and_put_success(
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
        data={
            "meta": {"serial": "ABC"},
            "outlets": [{"device_id": "O1", "state": "OFF"}],
        },
        device_identifier="ABC",
    )

    from custom_components.apex_fusion.select import ApexOutletModeSelect, _OutletRef

    ent = ApexOutletModeSelect(
        hass,
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_OutletRef(did="O1", name="Outlet 1"),
    )

    session = _Session(cookie_sid="abc", put_responses=[_Resp(200, "OK")])
    monkeypatch.setattr(
        "custom_components.apex_fusion.select.async_get_clientsession",
        lambda _h: session,
    )

    await ent.async_select_option("On")

    assert not session.post_calls
    assert session.put_calls
    assert session.put_calls[0]["headers"]["Cookie"] == "connect.sid=abc"
    coordinator.async_request_refresh.assert_awaited()


async def test_select_control_login_candidates_401_then_success(
    hass, enable_custom_integrations, monkeypatch
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_USERNAME: "user", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)

    coordinator = _CoordinatorStub(
        data={
            "meta": {"serial": "ABC"},
            "outlets": [{"device_id": "O1", "state": "OFF"}],
        },
        device_identifier="ABC",
    )

    from custom_components.apex_fusion.select import ApexOutletModeSelect, _OutletRef

    ent = ApexOutletModeSelect(
        hass,
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_OutletRef(did="O1", name="Outlet 1"),
    )

    session = _Session(
        cookie_sid=None,
        post_responses=[
            _Resp(401, ""),
            _Resp(200, '{"connect.sid": "abc"}'),
        ],
        put_responses=[_Resp(200, "OK")],
    )
    monkeypatch.setattr(
        "custom_components.apex_fusion.select.async_get_clientsession",
        lambda _h: session,
    )

    await ent.async_select_option("Off")

    assert len(session.post_calls) == 2
    assert session.put_calls[0]["headers"]["Cookie"] == "connect.sid=abc"


async def test_select_control_login_404_raises(
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
        data={
            "meta": {"serial": "ABC"},
            "outlets": [{"device_id": "O1", "state": "OFF"}],
        },
        device_identifier="ABC",
    )

    from custom_components.apex_fusion.select import ApexOutletModeSelect, _OutletRef

    ent = ApexOutletModeSelect(
        hass,
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_OutletRef(did="O1", name="Outlet 1"),
    )

    session = _Session(cookie_sid=None, post_responses=[_Resp(404, "")])
    monkeypatch.setattr(
        "custom_components.apex_fusion.select.async_get_clientsession",
        lambda _h: session,
    )

    with pytest.raises(HomeAssistantError, match="REST API not supported"):
        await ent.async_select_option("On")


async def test_select_control_login_429_calls_disable_rest_and_raises(
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
        data={
            "meta": {"serial": "ABC"},
            "outlets": [{"device_id": "O1", "state": "OFF"}],
        },
        device_identifier="ABC",
    )

    from custom_components.apex_fusion.select import ApexOutletModeSelect, _OutletRef

    ent = ApexOutletModeSelect(
        hass,
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_OutletRef(did="O1", name="Outlet 1"),
    )

    session = _Session(
        cookie_sid=None, post_responses=[_Resp(429, "", headers=_HeadersRaises())]
    )
    monkeypatch.setattr(
        "custom_components.apex_fusion.select.async_get_clientsession",
        lambda _h: session,
    )

    with pytest.raises(HomeAssistantError, match="rate limited"):
        await ent.async_select_option("On")

    assert coordinator._disable_rest_calls
    assert coordinator._disable_rest_calls[0]["reason"] == "rate_limited_control"


async def test_select_control_login_429_retry_after_parsed(
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
        data={
            "meta": {"serial": "ABC"},
            "outlets": [{"device_id": "O1", "state": "OFF"}],
        },
        device_identifier="ABC",
    )

    from custom_components.apex_fusion.select import ApexOutletModeSelect, _OutletRef

    ent = ApexOutletModeSelect(
        hass,
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_OutletRef(did="O1", name="Outlet 1"),
    )

    session = _Session(
        cookie_sid=None, post_responses=[_Resp(429, "", headers={"Retry-After": "10"})]
    )
    monkeypatch.setattr(
        "custom_components.apex_fusion.select.async_get_clientsession",
        lambda _h: session,
    )

    with pytest.raises(HomeAssistantError, match="rate limited"):
        await ent.async_select_option("On")

    assert coordinator._disable_rest_calls
    assert coordinator._disable_rest_calls[0]["seconds"] == 10.0


async def test_select_control_login_429_disable_rest_exception_swallowed(
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
        data={
            "meta": {"serial": "ABC"},
            "outlets": [{"device_id": "O1", "state": "OFF"}],
        },
        device_identifier="ABC",
    )

    def _disable_raises(*, seconds: float, reason: str) -> None:
        raise RuntimeError("boom")

    coordinator._disable_rest = _disable_raises  # type: ignore[method-assign]

    from custom_components.apex_fusion.select import ApexOutletModeSelect, _OutletRef

    ent = ApexOutletModeSelect(
        hass,
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_OutletRef(did="O1", name="Outlet 1"),
    )

    session = _Session(
        cookie_sid=None, post_responses=[_Resp(429, "", headers={"Retry-After": "1"})]
    )
    monkeypatch.setattr(
        "custom_components.apex_fusion.select.async_get_clientsession",
        lambda _h: session,
    )

    with pytest.raises(HomeAssistantError, match="rate limited"):
        await ent.async_select_option("On")


async def test_select_control_login_json_decode_error_wrapped(
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
        data={
            "meta": {"serial": "ABC"},
            "outlets": [{"device_id": "O1", "state": "OFF"}],
        },
        device_identifier="ABC",
    )

    from custom_components.apex_fusion.select import ApexOutletModeSelect, _OutletRef

    ent = ApexOutletModeSelect(
        hass,
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_OutletRef(did="O1", name="Outlet 1"),
    )

    session = _Session(cookie_sid=None, post_responses=[_Resp(200, "not-json")])
    monkeypatch.setattr(
        "custom_components.apex_fusion.select.async_get_clientsession",
        lambda _h: session,
    )

    with pytest.raises(HomeAssistantError, match="Error logging into Apex REST API"):
        await ent.async_select_option("On")


async def test_select_control_put_branches_401_429_and_exception_wrapped(
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
        data={
            "meta": {"serial": "ABC"},
            "outlets": [{"device_id": "O1", "state": "OFF"}],
        },
        device_identifier="ABC",
    )

    from custom_components.apex_fusion.select import ApexOutletModeSelect, _OutletRef

    ent = ApexOutletModeSelect(
        hass,
        cast(Any, coordinator),
        cast(Any, entry),
        ref=_OutletRef(did="O1", name="Outlet 1"),
    )

    # No login required (cookie present), but PUT returns 401.
    session_401 = _Session(cookie_sid="abc", put_responses=[_Resp(401, "")])
    monkeypatch.setattr(
        "custom_components.apex_fusion.select.async_get_clientsession",
        lambda _h: session_401,
    )
    with pytest.raises(HomeAssistantError, match="Not authorized"):
        await ent.async_select_option("On")

    # PUT rate-limited: Retry-After is blank -> fallback to 300s.
    session_429 = _Session(
        cookie_sid="abc",
        put_responses=[_Resp(429, "", headers={"Retry-After": ""})],
    )
    monkeypatch.setattr(
        "custom_components.apex_fusion.select.async_get_clientsession",
        lambda _h: session_429,
    )
    with pytest.raises(HomeAssistantError, match="rate limited"):
        await ent.async_select_option("On")

    # PUT rate-limited: no Retry-After header -> fallback to 300s.
    session_429_missing = _Session(
        cookie_sid="abc",
        put_responses=[_Resp(429, "", headers={})],
    )
    monkeypatch.setattr(
        "custom_components.apex_fusion.select.async_get_clientsession",
        lambda _h: session_429_missing,
    )
    with pytest.raises(HomeAssistantError, match="rate limited"):
        await ent.async_select_option("On")

    # PUT raises a client error -> wrapped.
    session_err = _Session(cookie_sid="abc", put_raises=aiohttp.ClientError("boom"))
    monkeypatch.setattr(
        "custom_components.apex_fusion.select.async_get_clientsession",
        lambda _h: session_err,
    )
    with pytest.raises(HomeAssistantError, match="Error setting output mode"):
        await ent.async_select_option("On")
