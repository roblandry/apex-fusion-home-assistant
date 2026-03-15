"""Unit tests for update reference building."""

from __future__ import annotations


def test_update_module_refs_trident_disconnected_latest_returns_installed() -> None:
    from custom_components.apex_fusion.update import _module_refs

    data = {
        "config": {
            "mconf": [
                {"hwtype": "TNP", "abaddr": 5, "update": False, "extra": {}},
            ]
        },
        "raw": {
            "modules": [
                {
                    "hwtype": "TNP",
                    "abaddr": 5,
                    "present": False,
                    "software": "1.2.3",
                    "latestFirmware": "9.9.9",
                }
            ]
        },
    }

    refs = _module_refs(data, "SER")
    assert len(refs) == 1
    ref = refs[0]

    assert ref.installed_fn(data) == "1.2.3"
    # Disconnected Trident-family module should expose installed as latest,
    # suppressing update availability.
    assert ref.latest_fn(data) == "1.2.3"


def test_update_module_refs_skips_disconnected_trident_when_installed_missing() -> None:
    from custom_components.apex_fusion.update import _module_refs

    data = {
        "config": {"mconf": [{"hwtype": "TRI", "abaddr": 3}]},
        "raw": {
            "modules": [
                {
                    "hwtype": "TRI",
                    "abaddr": 3,
                    "present": False,
                    # No software/swrev.
                }
            ]
        },
    }

    assert _module_refs(data, "SER") == []


def test_update_module_refs_raw_skips_disconnected_trident_without_versions() -> None:
    from custom_components.apex_fusion.update import _module_refs

    data = {
        # No config.mconf -> raw modules path.
        "raw": {
            "modules": [
                {
                    "hwtype": "TRI",
                    "abaddr": 8,
                    "present": False,
                    "software": None,
                    "swrev": None,
                }
            ]
        }
    }

    assert _module_refs(data, "SER") == []
