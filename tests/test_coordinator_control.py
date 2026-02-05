"""Unit tests for coordinator REST control helpers."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, cast
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
from custom_components.apex_fusion.coordinator import ApexNeptuneDataUpdateCoordinator


class _Morsel:
    def __init__(self, value: str):
        self.value = value


class _CookieJar:
    def __init__(self, sid: str | None = None):
        self._sid = sid
        self.updated: dict[str, Any] | None = None

    def filter_cookies(self, _url: Any) -> dict[str, Any]:
        if self._sid is None:
            return {}
        return {"connect.sid": _Morsel(self._sid)}

    def update_cookies(
        self, cookies: dict[str, str], response_url: Any | None = None
    ) -> None:
        self.updated = {"cookies": cookies, "response_url": response_url}
        self._sid = cookies.get("connect.sid")


class _Resp:
    def __init__(
        self,
        status: int,
        *,
        text: str = "",
        headers: Any | None = None,
        cookie_sid: str | None = None,
    ) -> None:
        self.status = status
        self._text = text
        self.headers = headers or {}
        self.cookies: dict[str, Any] = {}
        if cookie_sid is not None:
            self.cookies["connect.sid"] = _Morsel(cookie_sid)

    async def text(self) -> str:
        return self._text

    def raise_for_status(self) -> None:
        if self.status >= 400 and self.status not in (401, 403, 404, 429):
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


@dataclass
class _Session:
    cookie_jar: _CookieJar
    post_responses: list[_Resp]
    put_responses: list[_Resp]
    get_responses: list[_Resp] = field(default_factory=list)
    post_raises: Exception | None = None
    put_raises: Exception | None = None
    get_raises: Exception | None = None

    def __post_init__(self) -> None:
        self.post_calls: list[dict[str, Any]] = []
        self.put_calls: list[dict[str, Any]] = []
        self.get_calls: list[dict[str, Any]] = []

    def post(self, url: str, **kwargs: Any) -> _Resp:
        self.post_calls.append({"url": url, **kwargs})
        if self.post_raises is not None:
            raise self.post_raises
        return self.post_responses.pop(0)

    def put(self, url: str, **kwargs: Any) -> _Resp:
        self.put_calls.append({"url": url, **kwargs})
        if self.put_raises is not None:
            raise self.put_raises
        return self.put_responses.pop(0)

    def get(self, url: str, **kwargs: Any) -> _Resp:
        self.get_calls.append({"url": url, **kwargs})
        if self.get_raises is not None:
            raise self.get_raises
        return self.get_responses.pop(0)


class _HeadersRaises:
    def get(self, _key: str) -> Any:  # pragma: no cover - used to hit exception branch
        raise RuntimeError("boom")


async def _make_coord(
    hass, *, password: str = "pw"
) -> ApexNeptuneDataUpdateCoordinator:
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_USERNAME: "user", CONF_PASSWORD: password},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)
    return ApexNeptuneDataUpdateCoordinator(hass, entry=cast(Any, entry))


async def test_parse_retry_after_seconds_variants(hass, enable_custom_integrations):
    coord = await _make_coord(hass)
    assert coord._parse_retry_after_seconds({"Retry-After": "10"}) == 10.0
    assert coord._parse_retry_after_seconds({"Retry-After": ""}) is None
    assert coord._parse_retry_after_seconds({}) is None
    assert coord._parse_retry_after_seconds(_HeadersRaises()) is None


async def test_get_trident_abaddr_requires_trident_module(
    hass, enable_custom_integrations
):
    coord = await _make_coord(hass)
    coord.data = {"meta": {"serial": "ABC"}}
    with pytest.raises(HomeAssistantError, match="Trident module not detected"):
        coord._get_trident_abaddr()


async def test_rest_login_requires_password(hass, enable_custom_integrations):
    coord = await _make_coord(hass, password="")
    sess = _Session(cookie_jar=_CookieJar(None), post_responses=[], put_responses=[])
    with pytest.raises(HomeAssistantError, match="Password is required"):
        await coord._async_rest_login(session=cast(Any, sess))


async def test_rest_login_uses_cached_sid(hass, enable_custom_integrations):
    coord = await _make_coord(hass)
    coord._rest_sid = "CACHED"
    sess = _Session(cookie_jar=_CookieJar(None), post_responses=[], put_responses=[])
    assert await coord._async_rest_login(session=cast(Any, sess)) == "CACHED"


async def test_rest_login_uses_cookie_jar_sid(hass, enable_custom_integrations):
    coord = await _make_coord(hass)
    sess = _Session(cookie_jar=_CookieJar("JAR"), post_responses=[], put_responses=[])
    assert await coord._async_rest_login(session=cast(Any, sess)) == "JAR"
    assert coord._rest_sid == "JAR"


async def test_rest_login_falls_back_to_admin_and_json_body(
    hass, enable_custom_integrations
):
    coord = await _make_coord(hass)
    # First candidate user -> 401, second (admin) -> 200 with JSON body.
    sess = _Session(
        cookie_jar=_CookieJar(None),
        post_responses=[
            _Resp(401, text="{}"),
            _Resp(200, text='{"connect.sid": "ABC"}'),
        ],
        put_responses=[],
    )

    sid = await coord._async_rest_login(session=cast(Any, sess))
    assert sid == "ABC"
    assert sess.cookie_jar.updated is not None
    assert sess.cookie_jar.updated["cookies"]["connect.sid"] == "ABC"


async def test_rest_login_429_disables_rest_and_raises(
    hass, enable_custom_integrations, freezer
):
    coord = await _make_coord(hass)
    sess = _Session(
        cookie_jar=_CookieJar(None),
        post_responses=[_Resp(429, headers={"Retry-After": "7"})],
        put_responses=[],
    )

    now = time.monotonic()
    with pytest.raises(HomeAssistantError, match="rate limited"):
        await coord._async_rest_login(session=cast(Any, sess))

    assert coord._rest_disabled_until >= now + 7.0


async def test_rest_login_404_raises_filenotfound(hass, enable_custom_integrations):
    coord = await _make_coord(hass)
    sess = _Session(
        cookie_jar=_CookieJar(None),
        post_responses=[_Resp(404, text="")],
        put_responses=[],
    )

    with pytest.raises(FileNotFoundError):
        await coord._async_rest_login(session=cast(Any, sess))


async def test_rest_login_accepts_set_cookie_sid(hass, enable_custom_integrations):
    coord = await _make_coord(hass)
    sess = _Session(
        cookie_jar=_CookieJar(None),
        post_responses=[_Resp(200, text="{}", cookie_sid="COOKIE")],
        put_responses=[],
    )

    sid = await coord._async_rest_login(session=cast(Any, sess))
    assert sid == "COOKIE"
    assert sess.cookie_jar.updated is not None
    assert sess.cookie_jar.updated["cookies"]["connect.sid"] == "COOKIE"


async def test_rest_login_client_error_wrapped(hass, enable_custom_integrations):
    coord = await _make_coord(hass)
    sess = _Session(
        cookie_jar=_CookieJar(None),
        post_responses=[],
        put_responses=[],
        post_raises=aiohttp.ClientError("boom"),
    )

    with pytest.raises(HomeAssistantError, match="Error logging into Apex REST API"):
        await coord._async_rest_login(session=cast(Any, sess))


async def test_rest_login_rejected_raises_http_status(hass, enable_custom_integrations):
    coord = await _make_coord(hass)
    # Both candidates reject auth; last_status should be set and last_error is None.
    sess = _Session(
        cookie_jar=_CookieJar(None),
        post_responses=[_Resp(401, text=""), _Resp(403, text="")],
        put_responses=[],
    )

    with pytest.raises(HomeAssistantError, match=r"REST login rejected \(HTTP 403\)"):
        await coord._async_rest_login(session=cast(Any, sess))


async def test_rest_put_json_happy_path_sets_cookie_header(
    hass, enable_custom_integrations, monkeypatch
):
    coord = await _make_coord(hass)

    sess = _Session(
        cookie_jar=_CookieJar(None),
        post_responses=[],
        put_responses=[_Resp(200, text="OK")],
    )
    monkeypatch.setattr(
        "custom_components.apex_fusion.coordinator.async_get_clientsession",
        lambda _h: sess,
    )

    coord._async_rest_login = AsyncMock(return_value="SID")  # type: ignore[method-assign]

    await coord.async_rest_put_json(path="/rest/status/outputs/O1", payload={"x": 1})

    assert sess.put_calls
    headers = sess.put_calls[-1]["headers"]
    assert headers["Cookie"] == "connect.sid=SID"


async def test_rest_put_json_permission_retries_login(
    hass, enable_custom_integrations, monkeypatch
):
    coord = await _make_coord(hass)

    sess = _Session(
        cookie_jar=_CookieJar(None),
        post_responses=[],
        put_responses=[_Resp(401), _Resp(200, text="OK")],
    )
    monkeypatch.setattr(
        "custom_components.apex_fusion.coordinator.async_get_clientsession",
        lambda _h: sess,
    )

    coord._async_rest_login = AsyncMock(side_effect=["S1", "S2"])  # type: ignore[method-assign]

    await coord.async_rest_put_json(path="rest/status/feed/1", payload={"x": 1})

    assert len(sess.put_calls) == 2
    assert sess.put_calls[0]["headers"]["Cookie"] == "connect.sid=S1"
    assert sess.put_calls[1]["headers"]["Cookie"] == "connect.sid=S2"


async def test_rest_put_json_404_raises_filenotfound(
    hass, enable_custom_integrations, monkeypatch
):
    coord = await _make_coord(hass)

    sess = _Session(
        cookie_jar=_CookieJar(None),
        post_responses=[],
        put_responses=[_Resp(404)],
    )
    monkeypatch.setattr(
        "custom_components.apex_fusion.coordinator.async_get_clientsession",
        lambda _h: sess,
    )

    coord._async_rest_login = AsyncMock(return_value="SID")  # type: ignore[method-assign]

    with pytest.raises(FileNotFoundError):
        await coord.async_rest_put_json(path="/rest/missing", payload={"x": 1})


async def test_rest_put_json_429_disables_rest(
    hass, enable_custom_integrations, monkeypatch
):
    coord = await _make_coord(hass)

    sess = _Session(
        cookie_jar=_CookieJar(None),
        post_responses=[],
        put_responses=[_Resp(429, headers={"Retry-After": ""})],
    )
    monkeypatch.setattr(
        "custom_components.apex_fusion.coordinator.async_get_clientsession",
        lambda _h: sess,
    )

    coord._async_rest_login = AsyncMock(return_value="SID")  # type: ignore[method-assign]

    now = time.monotonic()
    with pytest.raises(HomeAssistantError, match="rate limited"):
        await coord.async_rest_put_json(path="/rest/status/feed/1", payload={"x": 1})

    assert coord._rest_disabled_until >= now + 299.0


async def test_rest_put_json_transient_status_raises(
    hass, enable_custom_integrations, monkeypatch
):
    coord = await _make_coord(hass)

    sess = _Session(
        cookie_jar=_CookieJar(None),
        post_responses=[],
        put_responses=[_Resp(503)],
    )
    monkeypatch.setattr(
        "custom_components.apex_fusion.coordinator.async_get_clientsession",
        lambda _h: sess,
    )

    coord._async_rest_login = AsyncMock(return_value="SID")  # type: ignore[method-assign]

    with pytest.raises(HomeAssistantError, match="Transient REST control"):
        await coord.async_rest_put_json(path="/rest/status/feed/1", payload={"x": 1})


async def test_rest_put_json_client_error_wrapped(
    hass, enable_custom_integrations, monkeypatch
):
    coord = await _make_coord(hass)

    sess = _Session(
        cookie_jar=_CookieJar(None),
        post_responses=[],
        put_responses=[],
        put_raises=aiohttp.ClientError("boom"),
    )
    monkeypatch.setattr(
        "custom_components.apex_fusion.coordinator.async_get_clientsession",
        lambda _h: sess,
    )

    coord._async_rest_login = AsyncMock(return_value="SID")  # type: ignore[method-assign]

    with pytest.raises(HomeAssistantError, match="Error sending REST control"):
        await coord.async_rest_put_json(path="/rest/status/feed/1", payload={"x": 1})


async def test_rest_put_json_respects_rest_disabled_until(
    hass, enable_custom_integrations
):
    coord = await _make_coord(hass)
    coord._rest_disabled_until = time.monotonic() + 60
    with pytest.raises(HomeAssistantError, match="REST temporarily disabled"):
        await coord.async_rest_put_json(path="/rest/status/feed/1", payload={"x": 1})


async def test_rest_put_json_requires_password(hass, enable_custom_integrations):
    coord = await _make_coord(hass, password="")
    with pytest.raises(HomeAssistantError, match="Password is required"):
        await coord.async_rest_put_json(path="/rest/status/feed/1", payload={"x": 1})


async def test_rest_get_json_requires_password(hass, enable_custom_integrations):
    coord = await _make_coord(hass, password="")
    with pytest.raises(HomeAssistantError, match="Password is required"):
        await coord.async_rest_get_json(path="/rest/config")


async def test_rest_get_json_respects_rest_disabled_until(
    hass, enable_custom_integrations
):
    coord = await _make_coord(hass)
    coord._rest_disabled_until = time.monotonic() + 60
    with pytest.raises(HomeAssistantError, match="REST temporarily disabled"):
        await coord.async_rest_get_json(path="/rest/config")


async def test_rest_get_json_429_disables_rest_and_raises(
    hass, enable_custom_integrations, monkeypatch
):
    coord = await _make_coord(hass)

    sess = _Session(
        cookie_jar=_CookieJar(None),
        post_responses=[],
        put_responses=[],
        get_responses=[_Resp(429, headers={"Retry-After": "7"})],
    )
    monkeypatch.setattr(
        "custom_components.apex_fusion.coordinator.async_get_clientsession",
        lambda _h: sess,
    )
    coord._async_rest_login = AsyncMock(return_value="SID")  # type: ignore[method-assign]

    now = time.monotonic()
    with pytest.raises(HomeAssistantError, match="rate limited"):
        await coord.async_rest_get_json(path="/rest/config")

    assert coord._rest_disabled_until >= now + 7.0


async def test_rest_get_json_adds_leading_slash(
    hass, enable_custom_integrations, monkeypatch
):
    coord = await _make_coord(hass)
    sess = _Session(
        cookie_jar=_CookieJar(None),
        post_responses=[],
        put_responses=[],
        get_responses=[_Resp(200, text="{}")],
    )
    monkeypatch.setattr(
        "custom_components.apex_fusion.coordinator.async_get_clientsession",
        lambda _h: sess,
    )
    coord._async_rest_login = AsyncMock(return_value="SID")  # type: ignore[method-assign]

    await coord.async_rest_get_json(path="rest/config")
    assert sess.get_calls
    assert sess.get_calls[0]["url"].endswith("/rest/config")


async def test_rest_get_json_404_raises_filenotfound(
    hass, enable_custom_integrations, monkeypatch
):
    coord = await _make_coord(hass)
    sess = _Session(
        cookie_jar=_CookieJar(None),
        post_responses=[],
        put_responses=[],
        get_responses=[_Resp(404, text="{}")],
    )
    monkeypatch.setattr(
        "custom_components.apex_fusion.coordinator.async_get_clientsession",
        lambda _h: sess,
    )
    coord._async_rest_login = AsyncMock(return_value="SID")  # type: ignore[method-assign]

    with pytest.raises(FileNotFoundError):
        await coord.async_rest_get_json(path="/rest/config")


async def test_rest_get_json_permission_retries_login(
    hass, enable_custom_integrations, monkeypatch
):
    coord = await _make_coord(hass)
    coord._rest_sid = "CACHED"

    sess = _Session(
        cookie_jar=_CookieJar(None),
        post_responses=[],
        put_responses=[],
        get_responses=[_Resp(403, text="{}"), _Resp(200, text="{}")],
    )
    monkeypatch.setattr(
        "custom_components.apex_fusion.coordinator.async_get_clientsession",
        lambda _h: sess,
    )
    coord._async_rest_login = AsyncMock(side_effect=["SID1", "SID2"])  # type: ignore[method-assign]

    await coord.async_rest_get_json(path="/rest/config")
    assert coord._rest_sid is None
    assert coord._async_rest_login.await_count == 2
    assert len(sess.get_calls) == 2


async def test_rest_get_json_transient_http_error(
    hass, enable_custom_integrations, monkeypatch
):
    coord = await _make_coord(hass)
    sess = _Session(
        cookie_jar=_CookieJar(None),
        post_responses=[],
        put_responses=[],
        get_responses=[_Resp(503, text="{}")],
    )
    monkeypatch.setattr(
        "custom_components.apex_fusion.coordinator.async_get_clientsession",
        lambda _h: sess,
    )
    coord._async_rest_login = AsyncMock(return_value="SID")  # type: ignore[method-assign]

    with pytest.raises(HomeAssistantError, match="Transient"):
        await coord.async_rest_get_json(path="/rest/config")


async def test_rest_get_json_non_dict_json_raises(
    hass, enable_custom_integrations, monkeypatch
):
    coord = await _make_coord(hass)
    sess = _Session(
        cookie_jar=_CookieJar(None),
        post_responses=[],
        put_responses=[],
        get_responses=[_Resp(200, text="[]")],
    )
    monkeypatch.setattr(
        "custom_components.apex_fusion.coordinator.async_get_clientsession",
        lambda _h: sess,
    )
    coord._async_rest_login = AsyncMock(return_value="SID")  # type: ignore[method-assign]

    with pytest.raises(HomeAssistantError, match="not a JSON object"):
        await coord.async_rest_get_json(path="/rest/config")


async def test_rest_get_json_bad_json_is_wrapped(
    hass, enable_custom_integrations, monkeypatch
):
    coord = await _make_coord(hass)
    sess = _Session(
        cookie_jar=_CookieJar(None),
        post_responses=[],
        put_responses=[],
        get_responses=[_Resp(200, text="not-json")],
    )
    monkeypatch.setattr(
        "custom_components.apex_fusion.coordinator.async_get_clientsession",
        lambda _h: sess,
    )
    coord._async_rest_login = AsyncMock(return_value="SID")  # type: ignore[method-assign]

    with pytest.raises(HomeAssistantError, match="Error fetching REST data"):
        await coord.async_rest_get_json(path="/rest/config")


async def test_refresh_config_now_updates_data(hass, enable_custom_integrations):
    coord = await _make_coord(hass)
    coord.data = {
        "meta": {"serial": "ABC"},
        "trident": {"present": True, "abaddr": 4, "levels_ml": [0, 0, 0, 0, 0]},
    }  # type: ignore[assignment]

    coord.async_rest_get_json = AsyncMock(  # type: ignore[method-assign]
        return_value={
            "mconf": [
                {"abaddr": 4, "hwtype": "TRI", "extra": {"wasteSize": 450.0}},
                {
                    "hwtype": "MXM",
                    "extra": {
                        "status": "Nero 5(x) - Rev 1 Ser #: S1 - OK",
                    },
                },
            ],
            "nconf": {
                "latestFirmware": "5.12_CA25",
                "updateFirmware": False,
                "password": "pw",
            },
        }
    )

    await coord.async_refresh_config_now()

    cfg = coord.data.get("config")
    assert isinstance(cfg, dict)
    assert isinstance(cfg.get("mconf"), list)
    assert cfg.get("nconf") == {"latestFirmware": "5.12_CA25", "updateFirmware": False}

    mxm = coord.data.get("mxm_devices")
    assert isinstance(mxm, dict)
    assert "Nero 5" in mxm

    trident = coord.data.get("trident")
    assert isinstance(trident, dict)
    assert trident.get("waste_size_ml") == 450.0


async def test_refresh_config_now_skips_non_trident_or_bad_extra(
    hass, enable_custom_integrations
):
    coord = await _make_coord(hass)
    coord.data = {
        "meta": {"serial": "ABC"},
        "trident": {"present": True, "abaddr": 4, "levels_ml": [0, 0, 0, 0, 0]},
    }  # type: ignore[assignment]

    coord.async_rest_get_json = AsyncMock(  # type: ignore[method-assign]
        return_value={
            "mconf": [
                {"hwtype": "FMM", "extra": {}},
                {"hwtype": "TRI", "extra": "bad"},
            ]
        }
    )

    await coord.async_refresh_config_now()

    trident = coord.data.get("trident")
    assert isinstance(trident, dict)
    assert trident.get("waste_size_ml") is None


async def test_trident_controls_require_trident_address(
    hass, enable_custom_integrations
):
    coord = await _make_coord(hass)
    coord.data = {"meta": {"serial": "ABC"}, "trident": {"present": True}}  # type: ignore[assignment]
    with pytest.raises(HomeAssistantError, match="address"):
        await coord.async_trident_prime_channel(channel_index=0)


async def test_trident_set_waste_size_uses_per_module_endpoint(
    hass, enable_custom_integrations
):
    coord = await _make_coord(hass)
    coord.data = {"trident": {"present": True, "abaddr": 5}}  # type: ignore[assignment]
    coord.async_rest_put_json = AsyncMock()  # type: ignore[method-assign]
    coord.async_request_refresh = AsyncMock()  # type: ignore[method-assign]
    coord.async_refresh_config_now = AsyncMock()  # type: ignore[method-assign]

    await coord.async_trident_set_waste_size_ml(size_ml=450.0)

    coord.async_rest_put_json.assert_awaited_once_with(
        path="/rest/config/mconf/5",
        payload={"abaddr": 5, "extra": {"wasteSize": 450.0}},
    )
    coord.async_refresh_config_now.assert_awaited_once()


async def test_trident_set_waste_size_falls_back_to_bulk_endpoint(
    hass, enable_custom_integrations
):
    coord = await _make_coord(hass)
    coord.data = {"trident": {"present": True, "abaddr": 5}}  # type: ignore[assignment]
    coord.async_rest_put_json = AsyncMock(side_effect=[FileNotFoundError, None])  # type: ignore[method-assign]
    coord.async_request_refresh = AsyncMock()  # type: ignore[method-assign]
    coord.async_refresh_config_now = AsyncMock()  # type: ignore[method-assign]

    await coord.async_trident_set_waste_size_ml(size_ml=450.0)

    assert coord.async_rest_put_json.await_count == 2
    assert (
        coord.async_rest_put_json.await_args_list[0].kwargs["path"]
        == "/rest/config/mconf/5"
    )
    assert (
        coord.async_rest_put_json.await_args_list[1].kwargs["path"]
        == "/rest/config/mconf"
    )
    coord.async_refresh_config_now.assert_awaited_once()


async def test_trident_reset_and_prime_payloads(hass, enable_custom_integrations):
    coord = await _make_coord(hass)
    coord.data = {"trident": {"present": True, "abaddr": 5}}  # type: ignore[assignment]
    coord.async_rest_put_json = AsyncMock()  # type: ignore[method-assign]
    coord.async_request_refresh = AsyncMock()  # type: ignore[method-assign]

    await coord.async_trident_reset_waste()
    await coord.async_trident_reset_reagent(reagent_index=1)
    await coord.async_trident_prime_channel(channel_index=3)

    calls = coord.async_rest_put_json.await_args_list
    assert calls[0].kwargs["payload"]["extra"]["reset"] == [
        True,
        False,
        False,
        False,
        False,
    ]
    assert calls[1].kwargs["payload"]["extra"]["newReagent"] == [False, True, False]
    assert calls[2].kwargs["payload"]["extra"]["prime"] == [False, False, False, True]


async def test_trident_per_channel_and_per_reagent_guards(
    hass, enable_custom_integrations
):
    coord = await _make_coord(hass)
    coord.data = {"trident": {"present": True, "abaddr": 5}}  # type: ignore[assignment]

    with pytest.raises(HomeAssistantError, match="Invalid reagent index"):
        await coord.async_trident_reset_reagent(reagent_index=99)

    with pytest.raises(HomeAssistantError, match="Invalid prime channel"):
        await coord.async_trident_prime_channel(channel_index=-1)


async def test_trident_set_waste_size_rejects_non_positive(
    hass, enable_custom_integrations
):
    coord = await _make_coord(hass)
    with pytest.raises(HomeAssistantError, match="> 0"):
        await coord.async_trident_set_waste_size_ml(size_ml=0)
