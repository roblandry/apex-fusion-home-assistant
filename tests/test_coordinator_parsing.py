"""Unit tests for coordinator parsing/helpers."""

from __future__ import annotations

from typing import Any, cast

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.apex_fusion import coordinator
from custom_components.apex_fusion.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
    DOMAIN,
)


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


def test_sanitize_config_helpers_cover_branches():
    assert coordinator._sanitize_mconf_for_storage({"mconf": "nope"}) == []

    out = coordinator._sanitize_mconf_for_storage(
        {
            "mconf": [
                "nope",
                {},
                {"hwtype": "", "abaddr": 1},
                {
                    "abaddr": 4,
                    "hwtype": "TRI",
                    "name": "TRI_4",
                    "update": False,
                    "updateStat": 0,
                    "extra": {"wasteSize": 450.0},
                },
                {
                    "hwtype": "MXM",
                    "extra": {"status": "Nero 5(x) - Rev 1 Ser #: S1 - OK"},
                },
            ]
        }
    )
    assert any(m.get("hwtype") == "TRI" for m in out)
    tri = next(m for m in out if m.get("hwtype") == "TRI")
    assert tri["extra"]["wasteSize"] == 450.0
    mxm = next(m for m in out if m.get("hwtype") == "MXM")
    assert "status" in mxm["extra"]

    assert coordinator._sanitize_nconf_for_storage({"nconf": "nope"}) == {}
    assert coordinator._sanitize_nconf_for_storage(
        {
            "nconf": {
                "latestFirmware": "5.12_CA25",
                "updateFirmware": False,
                "password": "pw",
            }
        }
    ) == {"latestFirmware": "5.12_CA25", "updateFirmware": False}


def test_to_number_and_url_builders():
    assert coordinator._to_number(None) is None
    assert coordinator._to_number("") is None
    assert coordinator._to_number(" 1.25 ") == 1.25
    assert coordinator._to_number("no") is None


async def test_finalize_trident_returns_when_trident_missing(
    hass, enable_custom_integrations
):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_USERNAME: "user", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)
    coord = coordinator.ApexNeptuneDataUpdateCoordinator(hass, entry=cast(Any, entry))

    data: dict[str, Any] = {"trident": "nope"}
    coord._finalize_trident(data)
    assert data["trident"] == "nope"


async def test_finalize_trident_computes_waste_fields(hass, enable_custom_integrations):
    entry = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_HOST: "1.2.3.4", CONF_USERNAME: "user", CONF_PASSWORD: "pw"},
        unique_id="1.2.3.4",
        title="Apex (1.2.3.4)",
    )
    entry.add_to_hass(hass)
    coord = coordinator.ApexNeptuneDataUpdateCoordinator(hass, entry=cast(Any, entry))

    data: dict[str, Any] = {
        "trident": {
            "levels_ml": [50.0],
            "waste_size_ml": 100.0,
        }
    }
    coord._finalize_trident(data)

    trident = cast(dict[str, Any], data["trident"])
    assert trident["waste_used_ml"] == 50.0
    assert trident["waste_size_ml"] == 100.0
    assert trident["waste_percent"] == 50.0
    assert trident["waste_full"] is False
    assert trident["waste_remaining_ml"] == 50.0

    # Cover 5-element list mapping and conservative waste-full margin.
    data2: dict[str, Any] = {
        "trident": {
            "levels_ml": [90.0, 123.0, 30.0, 10.0, 5.0],
            "waste_size_ml": 100.0,
        }
    }
    coord._finalize_trident(data2)
    trident2 = cast(dict[str, Any], data2["trident"])
    assert trident2["waste_remaining_ml"] == 10.0
    assert trident2["waste_full"] is True
    assert trident2["reagent_a_remaining_ml"] == 5.0
    assert trident2["reagent_b_remaining_ml"] == 10.0
    assert trident2["reagent_c_remaining_ml"] == 30.0
    assert trident2["reagent_a_empty"] is True
    assert trident2["reagent_b_empty"] is True
    assert trident2["reagent_c_empty"] is False

    # Cover 4-element list mapping (aux omitted) and invalid-type reagent entry.
    data3: dict[str, Any] = {
        "trident": {
            "levels_ml": [90.0, "nope", 10.0, 5.0],
            "waste_size_ml": 100.0,
        }
    }
    coord._finalize_trident(data3)
    trident3 = cast(dict[str, Any], data3["trident"])
    assert trident3["reagent_c_remaining_ml"] is None
    assert trident3["reagent_b_remaining_ml"] == 10.0
    assert trident3["reagent_a_remaining_ml"] == 5.0

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
        "feed": {"name": 2, "active": 1},
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
            }
        ],
        "modules": [
            {
                "hwtype": "TRI",
                "present": True,
                "abaddr": 4,
                "extra": {
                    "status": "testing Ca/Mg",
                    "levels": [232.7, 159.2],
                    "reagents": [75, 50, 25],
                    "waste_pct": "10%",
                },
            }
        ],
        "notifications": [{"statement": "pH is less than 7.8"}],
    }

    rest_parsed = coordinator.parse_status_rest(rest_obj)
    assert rest_parsed["meta"]["source"] == "rest"
    assert rest_parsed["network"]["ipaddr"] == "1.2.3.4"
    assert "T1" in rest_parsed["probes"]
    assert rest_parsed["outlets"][0]["device_id"] == "O1"
    assert rest_parsed["trident"]["status"] == "testing Ca/Mg"
    assert rest_parsed["trident"]["is_testing"] is True
    assert rest_parsed["trident"]["present"] is True
    assert rest_parsed["trident"]["reagent_a_remaining"] == 75
    assert rest_parsed["trident"]["reagent_b_remaining"] == 50
    assert rest_parsed["trident"]["reagent_c_remaining"] == 25
    assert rest_parsed["trident"]["waste_container_level"] == 10
    assert rest_parsed["trident"]["levels_ml"] == [232.7, 159.2]
    assert rest_parsed["alerts"]["last_statement"] == "pH is less than 7.8"
    assert rest_parsed["feed"]["name"] == 2
    assert rest_parsed["feed"]["active"] is True

    # Nested containers + int IDs + fallback from inputs->probes and outputs->outlets.
    rest_nested = {
        "data": {
            "nstat": {"ipaddr": "1.2.3.4"},
            "system": {"serial": "ABC"},
            "feed": {"name": "0", "active": 92},
            "probes": [{"id": 123, "name": "Tmp", "type": "Tmp", "value": "25"}],
            "outlets": [
                {
                    "id": 7,
                    "name": "Outlet",
                    "output_id": "99",
                    "status": "AON",  # non-list -> status None
                }
            ],
            "modules": [
                {"hwtype": "TRI", "present": True, "extra": {"status": "idle"}}
            ],
            "alerts": ["Apex Fusion Alarm: X Statement: Alk is low"],
        }
    }
    rest_nested_parsed = coordinator.parse_status_rest(rest_nested)
    assert "123" in rest_nested_parsed["probes"]
    assert rest_nested_parsed["outlets"][0]["output_id"] == "99"
    assert rest_nested_parsed["outlets"][0]["status"] is None
    assert rest_nested_parsed["trident"]["status"] == "Idle"
    assert rest_nested_parsed["trident"]["is_testing"] is False
    assert rest_nested_parsed["trident"]["present"] is True
    assert rest_nested_parsed["alerts"]["last_statement"] == "Alk is low"
    assert rest_nested_parsed["feed"]["name"] == 0
    assert rest_nested_parsed["feed"]["active"] is False

    cgi_obj = {
        "istat": {
            "hostname": "apex",
            "hardware": "Apex",
            "date": "now",
            "serialNO": 123,
            "feed": {"name": 3, "active": 1},
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
    assert cgi_parsed["feed"]["name"] == 3
    assert cgi_parsed["feed"]["active"] is True

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


def test_parse_status_rest_trident_consumables_variants():
    rest_obj = {
        "system": {"serial": "ABC"},
        "modules": [
            {
                "hwtype": "TRI",
                "extra": {
                    # Non-string status should not prevent consumables parsing.
                    "status": 1,
                    # Tuple path
                    "reagents": (10, "20%", 30),
                    # Nested dict path for flattening
                    "nested": {"waste_percent": "40%"},
                    # Edge cases for percent coercion
                    "reagentA": True,
                    "reagentB": None,
                    "wasteLevel": "",
                    "reagentC": "nope",
                    "reagent_2": "999",
                },
            }
        ],
    }

    out = coordinator.parse_status_rest(rest_obj)
    assert out["trident"]["status"] is None
    assert out["trident"]["is_testing"] is None
    assert out["trident"]["reagent_a_remaining"] == 10
    assert out["trident"]["reagent_b_remaining"] == 20
    assert out["trident"]["reagent_c_remaining"] == 30
    assert out["trident"]["waste_container_level"] == 40


def test_parse_status_rest_trident_consumables_reagents_list_and_empty_status():
    rest_obj = {
        "system": {"serial": "ABC"},
        "modules": [
            {
                "hwtype": "TRI",
                "extra": {
                    "status": " ",
                    "reagents": [11, 22, 33],
                    "waste_pct": "44%",
                },
            }
        ],
    }

    out = coordinator.parse_status_rest(rest_obj)
    assert out["trident"]["status"] is None
    assert out["trident"]["reagent_a_remaining"] == 11
    assert out["trident"]["reagent_b_remaining"] == 22
    assert out["trident"]["reagent_c_remaining"] == 33
    assert out["trident"]["waste_container_level"] == 44


def test_parse_status_rest_trident_consumables_from_flattened_keys_and_module_ids():
    rest_obj = {
        "system": {"serial": "ABC"},
        "modules": [
            {
                "hwtype": "TRI",
                "hwrev": " Rev-1 ",
                "swrev": 123,
                "serial": " TRI-SERIAL ",
                "present": True,
                "abaddr": 4,
                "extra": {
                    # Status not a string triggers the "status None" path, but should
                    # still parse levels + consumables.
                    "status": 1,
                    # Exercise levels parsing skips/coercions.
                    "levels": [None, True, 1, "2.5", "nope"],
                    # Exercise flattened-key parsing (no `reagents` list/tuple provided).
                    "nested": {"reagent_a_pct": "10%"},
                    "reagent2": 20,
                    "reagent-3": "30",
                    "wasteLevelPercent": "40%",
                },
            }
        ],
    }

    out = coordinator.parse_status_rest(rest_obj)
    trident = cast(dict[str, Any], out["trident"])
    assert trident["status"] is None
    assert trident["hwtype"] == "TRI"
    assert trident["hwrev"] == "Rev-1"
    assert trident["swrev"] == "123"
    assert trident["serial"] == "TRI-SERIAL"
    assert trident["levels_ml"] == [1.0, 2.5]
    assert trident["reagent_a_remaining"] == 10
    assert trident["reagent_b_remaining"] == 20
    assert trident["reagent_c_remaining"] == 30
    assert trident["waste_container_level"] == 40


def test_parse_status_rest_outputs_skips_invalid_entries_and_uses_name_fallback():
    out = coordinator.parse_status_rest(
        {
            "outputs": [
                "nope",  # non-dict -> skipped
                {"did": "", "name": ""},  # no did + no name -> skipped
                {"name": "Outlet", "status": ["AON"]},  # name fallback for did
            ]
        }
    )
    assert out["outlets"][0]["device_id"] == "Outlet"
    assert out["outlets"][0]["state"] == "AON"


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


def test_parse_feed_variants_cover_uncovered_branches():
    # REST feed: float should coerce to int.
    rest_float = {"system": {"serial": "ABC"}, "feed": 2.0}
    out_float = coordinator.parse_status_rest(rest_float)
    assert out_float["feed"]["name"] == 2
    assert out_float["feed"]["active"] is True

    # REST feed: bad string should return None.
    rest_bad = {"system": {"serial": "ABC"}, "feed": "nope"}
    out_bad = coordinator.parse_status_rest(rest_bad)
    assert out_bad["feed"] is None

    # REST feed: list branch picks first active item, skips non-dicts.
    rest_list = {
        "system": {"serial": "ABC"},
        "feed": [
            "nope",
            {"name": 1, "active": 0},
            {"name": 3, "active": True},
        ],
    }
    out_list = coordinator.parse_status_rest(rest_list)
    assert out_list["feed"]["name"] == 3
    assert out_list["feed"]["active"] is True

    # REST feed: dict boolean active.
    rest_bool = {"system": {"serial": "ABC"}, "feed": {"name": 1, "active": False}}
    out_rest_bool = coordinator.parse_status_rest(rest_bool)
    assert out_rest_bool["feed"]["name"] == 1
    assert out_rest_bool["feed"]["active"] is False

    # REST feed: dict without active uses feed_id-in-(1..4) fallback.
    rest_fallback = {"system": {"serial": "ABC"}, "feed": {"name": 2}}
    out_rest_fallback = coordinator.parse_status_rest(rest_fallback)
    assert out_rest_fallback["feed"]["name"] == 2
    assert out_rest_fallback["feed"]["active"] is True

    # REST feed: list branch int active uses numeric coercion.
    rest_list_int = {
        "system": {"serial": "ABC"},
        "feed": [
            {"name": 4, "active": 1},
        ],
    }
    out_list_int = coordinator.parse_status_rest(rest_list_int)
    assert out_list_int["feed"]["name"] == 4
    assert out_list_int["feed"]["active"] is True

    # CGI feed: float should coerce to int.
    cgi_float = {"istat": {"outputs": [], "inputs": [], "feed": 3.0}}
    out_cgi_float = coordinator.parse_status_cgi_json(cgi_float)
    assert out_cgi_float["feed"]["name"] == 3
    assert out_cgi_float["feed"]["active"] is True

    # CGI feed: dict with boolean active.
    cgi_bool = {
        "istat": {"outputs": [], "inputs": [], "feed": {"name": 1, "active": False}}
    }
    out_cgi_bool = coordinator.parse_status_cgi_json(cgi_bool)
    assert out_cgi_bool["feed"]["name"] == 1
    assert out_cgi_bool["feed"]["active"] is False

    # CGI feed: string digit should coerce.
    cgi_str = {"istat": {"outputs": [], "inputs": [], "feed": "3"}}
    out_cgi_str = coordinator.parse_status_cgi_json(cgi_str)
    assert out_cgi_str["feed"]["name"] == 3

    # CGI feed: bad string should return None.
    cgi_bad = {"istat": {"outputs": [], "inputs": [], "feed": "nope"}}
    out_cgi_bad = coordinator.parse_status_cgi_json(cgi_bad)
    assert out_cgi_bad["feed"] is None

    # CGI feed: dict without active uses feed_id-in-(1..4) fallback.
    cgi_fallback = {"istat": {"outputs": [], "inputs": [], "feed": {"name": 2}}}
    out_cgi_fallback = coordinator.parse_status_cgi_json(cgi_fallback)
    assert out_cgi_fallback["feed"]["name"] == 2
    assert out_cgi_fallback["feed"]["active"] is True

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
