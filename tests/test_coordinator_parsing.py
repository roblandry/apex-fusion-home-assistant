"""Unit tests for coordinator parsing/helpers."""

from __future__ import annotations

from typing import Any, cast

import pytest

from custom_components.apex_fusion import coordinator


def test_cookie_helpers_cover_exception_branches():
    class _BadJar:
        def filter_cookies(self, *_args, **_kwargs):
            raise RuntimeError("boom")

        def update_cookies(self, *_args, **_kwargs):
            raise RuntimeError("boom")

    class _Sess:
        cookie_jar = _BadJar()

    assert coordinator._session_has_connect_sid(cast(Any, _Sess()), "http://x") is False

    # _set_connect_sid_cookie: empty sid no-op
    coordinator._set_connect_sid_cookie(cast(Any, _Sess()), base_url="http://x", sid="")


def test_parse_mxm_devices_from_mconf_variants():
    assert coordinator._parse_mxm_devices_from_mconf({"mconf": "nope"}) == {}

    # Wrong hwtype gets skipped
    assert (
        coordinator._parse_mxm_devices_from_mconf({"mconf": [{"hwtype": "EB832"}]})
        == {}
    )

    # Missing/invalid extra
    assert (
        coordinator._parse_mxm_devices_from_mconf(
            {"mconf": [{"hwtype": "MXM", "extra": 1}]}
        )
        == {}
    )

    # Valid line + invalid lines
    mconf = {
        "mconf": [
            {
                "hwtype": "MXM",
                "extra": {
                    "status": "Nero 5(abc) - Rev 1 Ser #: S123 - OK\n(no match)\n",
                },
            }
        ]
    }
    out = coordinator._parse_mxm_devices_from_mconf(mconf)
    assert out["Nero 5"]["rev"] == "1"
    assert out["Nero 5"]["serial"] == "S123"
    assert out["Nero 5"]["status"] == "OK"

    # Covers: non-dict module entries and matched lines with empty names.
    mconf2 = {
        "mconf": [
            "nope",
            {"hwtype": "MXM", "extra": {"status": " (x) - Rev 1 Ser #: S1 - OK\n"}},
            {"hwtype": "MXM", "extra": {"status": " \n"}},
        ]
    }
    assert coordinator._parse_mxm_devices_from_mconf(mconf2) == {}


def test_to_number_and_url_builders():
    assert coordinator._to_number(None) is None
    assert coordinator._to_number("") is None
    assert coordinator._to_number(" 1.25 ") == 1.25
    assert coordinator._to_number("no") is None

    assert coordinator.build_base_url("1.2.3.4") == "http://1.2.3.4"
    assert coordinator.build_base_url("http://1.2.3.4/") == "http://1.2.3.4"

    assert (
        coordinator.build_status_url("1.2.3.4", "status.xml")
        == "http://1.2.3.4/status.xml"
    )
    assert (
        coordinator.build_status_url("http://1.2.3.4/", "/status.xml")
        == "http://1.2.3.4/status.xml"
    )


def test_parse_status_xml_and_rest_and_cgi_json():
    xml = """<status software='1.0' hardware='Apex'>
      <hostname>apex</hostname>
      <serial>ABC</serial>
      <timezone>UTC</timezone>
      <date>now</date>
      <probes>
        <probe><name></name><type>Tmp</type><value>1</value></probe>
        <probe><name>T1</name><type>Tmp</type><value>25</value></probe>
      </probes>
      <outlets>
        <outlet><name></name><outputID>1</outputID><state>AON</state><deviceID>O1</deviceID></outlet>
        <outlet><name>Outlet</name><outputID>1</outputID><state>AON</state><deviceID>O1</deviceID></outlet>
      </outlets>
    </status>"""
    parsed = coordinator.parse_status_xml(xml)
    assert parsed["meta"]["hostname"] == "apex"
    assert "T1" in parsed["probes"]
    assert parsed["outlets"][0]["name"] == "Outlet"

    rest_obj = {
        "nstat": {
            "hostname": "apex",
            "ipaddr": "1.2.3.4",
            "dhcp": 1,
            "wifiEnable": True,
            "ssid": "ssid",
            "strength": "75",
            "quality": 80,
        },
        "system": {"software": "1", "hardware": "Apex", "serial": "ABC", "type": "A3"},
        "inputs": [
            {"did": "T1", "name": "Tmp", "type": "Tmp", "value": "25"},
            "nope",
            {"did": "", "name": ""},
        ],
        "outputs": [
            {
                "did": "O1",
                "name": "Outlet",
                "ID": "1",
                "status": ["AON"],
                "type": "EB8",
                "gid": "g",
            },
            {"did": "", "name": ""},
            "nope",
        ],
        "modules": [
            {"hwtype": "EB832", "extra": {"status": "ignored"}},
            {"hwtype": "TRI", "extra": {"status": "testing Ca/Mg"}},
        ],
        "notifications": [
            {"statement": "pH is less than 7.8"},
        ],
    }
    rest_parsed = coordinator.parse_status_rest(rest_obj)
    assert rest_parsed["meta"]["source"] == "rest"
    assert rest_parsed["network"]["ipaddr"] == "1.2.3.4"
    assert "T1" in rest_parsed["probes"]
    assert rest_parsed["outlets"][0]["device_id"] == "O1"
    assert rest_parsed["trident"]["status"] == "testing Ca/Mg"
    assert rest_parsed["trident"]["is_testing"] is True
    assert rest_parsed["alerts"]["last_statement"] == "pH is less than 7.8"

    # Nested containers + int IDs + fallback from inputs->probes and outputs->outlets.
    rest_nested = {
        "data": {
            "nstat": {"ipaddr": "1.2.3.4"},
            "system": {"serial": "ABC"},
            "probes": [{"id": 123, "name": "Tmp", "type": "Tmp", "value": "25"}],
            "outlets": [
                {
                    "id": 7,
                    "name": "Outlet",
                    "output_id": "99",
                    "status": "AON",  # non-list -> status None
                }
            ],
            "modules": [{"hwtype": "TRI", "extra": {"status": "idle"}}],
            "alerts": ["Apex Fusion Alarm: X Statement: Alk is low"],
        }
    }
    rest_nested_parsed = coordinator.parse_status_rest(rest_nested)
    assert "123" in rest_nested_parsed["probes"]
    assert rest_nested_parsed["outlets"][0]["output_id"] == "99"
    assert rest_nested_parsed["outlets"][0]["status"] is None
    assert rest_nested_parsed["trident"]["status"] == "Idle"
    assert rest_nested_parsed["trident"]["is_testing"] is False
    assert rest_nested_parsed["alerts"]["last_statement"] == "Alk is low"

    cgi_obj = {
        "istat": {
            "hostname": "apex",
            "hardware": "Apex",
            "date": "now",
            "serialNO": 123,
            "inputs": [
                {"did": "T1", "name": "Tmp", "type": "Tmp", "value": "25"},
                {"did": "", "name": "Tmp"},
                "nope",
            ],
            "outputs": [
                {
                    "did": "O1",
                    "name": "Outlet",
                    "ID": "1",
                    "status": ["AON"],
                    "type": "EB8",
                    "gid": "g",
                },
                {"did": "", "name": "Outlet"},
                "nope",
            ],
        }
    }
    cgi_parsed = coordinator.parse_status_cgi_json(cgi_obj)
    assert cgi_parsed["meta"]["source"] == "cgi_json"
    assert cgi_parsed["meta"]["serial"] == "123"
    assert "T1" in cgi_parsed["probes"]
    assert cgi_parsed["outlets"][0]["device_id"] == "O1"

    # serial can also come from top-level system
    cgi_obj2 = {"system": {"serial": "SYS"}, "istat": {"outputs": [], "inputs": []}}
    cgi_parsed2 = coordinator.parse_status_cgi_json(cgi_obj2)
    assert cgi_parsed2["meta"]["serial"] == "SYS"

    # serial from istat string (covers strip() return branch)
    cgi_obj3 = {
        "system": {"serial": 999},
        "istat": {"serial": "  ABC  ", "outputs": [], "inputs": []},
    }
    cgi_parsed3 = coordinator.parse_status_cgi_json(cgi_obj3)
    assert cgi_parsed3["meta"]["serial"] == "ABC"

    # serial from system int (covers int->str return branch)
    cgi_obj4 = {"system": {"serial": 1234}, "istat": {"outputs": [], "inputs": []}}
    cgi_parsed4 = coordinator.parse_status_cgi_json(cgi_obj4)
    assert cgi_parsed4["meta"]["serial"] == "1234"


def test_parse_status_rest_with_non_dict_sections():
    out = coordinator.parse_status_rest({"nstat": "x", "system": "y"})
    assert out["meta"]["source"] == "rest"


def test_parse_status_cgi_json_with_non_dict_istat():
    out = coordinator.parse_status_cgi_json({"istat": "x"})
    assert out["meta"]["source"] == "cgi_json"


def test_parse_status_rest_outputs_state_none():
    rest_obj = {"outputs": [{"did": "O1", "status": [None]}]}
    out = coordinator.parse_status_rest(rest_obj)
    assert out["outlets"][0]["state"] is None


def test_parse_status_cgi_json_outputs_state_none():
    cgi_obj = {"istat": {"outputs": [{"did": "O1", "status": [None]}]}}
    out = coordinator.parse_status_cgi_json(cgi_obj)
    assert out["outlets"][0]["state"] is None


def test_parse_status_rest_ignores_non_list_inputs_outputs():
    out = coordinator.parse_status_rest({"inputs": "x", "outputs": "y"})
    assert out["probes"] == {}
    assert out["outlets"] == []


def test_parse_status_rest_trident_and_alert_variants():
    # Trident parsing: cover non-dict entries, wrong hwtype, bad extra, non-str status, blank status.
    out = coordinator.parse_status_rest(
        {
            "modules": [
                "nope",
                {"hwtype": "EB832", "extra": {"status": "ignored"}},
                {"hwtype": "TRI", "extra": 1},
                {"hwtype": "TRI", "extra": {"status": 1}},
                {"hwType": "TRI", "extra": {"status": "  \n"}},
            ]
        }
    )
    assert out["trident"]["status"] is None
    assert out["trident"]["is_testing"] is None

    out2 = coordinator.parse_status_rest(
        {
            "modules": [
                {"hwtype": "TRI", "extra": {"status": "Idle"}},
            ]
        }
    )
    assert out2["trident"]["status"] == "Idle"
    assert out2["trident"]["is_testing"] is False

    # Preserve short all-caps abbreviations.
    out2b = coordinator.parse_status_rest(
        {
            "modules": [
                {"hwtype": "TRI", "extra": {"status": "OK"}},
            ]
        }
    )
    assert out2b["trident"]["status"] == "OK"
    assert out2b["trident"]["is_testing"] is False

    # Alert parsing: dict message with Statement extraction, dict message without Statement,
    # and string message without Statement.
    out3 = coordinator.parse_status_rest(
        {
            "notifications": [
                {"message": "Apex Fusion Alarm: X Statement: Ca is low"},
            ]
        }
    )
    assert out3["alerts"]["last_statement"] == "Ca is low"
    assert out3["alerts"]["last_message"] == "Apex Fusion Alarm: X Statement: Ca is low"

    out4 = coordinator.parse_status_rest({"warnings": [{"message": "Just a warning"}]})
    assert out4["alerts"]["last_statement"] is None
    assert out4["alerts"]["last_message"] == "Just a warning"

    out5 = coordinator.parse_status_rest({"messages": ["No statement here"]})
    assert out5["alerts"]["last_statement"] is None
    assert out5["alerts"]["last_message"] == "No statement here"


def test_parse_status_cgi_json_ignores_non_list_inputs_outputs():
    out = coordinator.parse_status_cgi_json({"istat": {"inputs": "x", "outputs": "y"}})
    assert out["probes"] == {}
    assert out["outlets"] == []


def test_parse_status_xml_raises_on_invalid_xml():
    with pytest.raises(Exception):
        coordinator.parse_status_xml("<no")
