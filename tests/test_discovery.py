"""Tests for discovery helpers in the internal apex_fusion package."""

from __future__ import annotations

from custom_components.apex_fusion.apex_fusion.discovery import ApexDiscovery


def test_new_probe_refs_returns_empty_when_probes_container_invalid() -> None:
    refs, seen = ApexDiscovery.new_probe_refs(
        {"probes": []},
        already_added_keys=set(),
    )
    assert refs == []
    assert seen == set()


def test_new_outlet_intensity_refs_returns_empty_when_outlets_container_invalid() -> (
    None
):
    refs, seen = ApexDiscovery.new_outlet_intensity_refs(
        {"outlets": {}},
        already_added_dids=set(),
    )
    assert refs == []
    assert seen == set()


def test_new_outlet_select_refs_returns_empty_when_outlets_container_invalid() -> None:
    refs, seen = ApexDiscovery.new_outlet_select_refs(
        {"outlets": "nope"},
        already_added_dids=set(),
    )
    assert refs == []
    assert seen == set()


def test_outlet_ref_dedupe_keys_cover_collision_branches() -> None:
    # DID collision (same did appears twice) should produce dedupe keys:
    # - did@abaddr when module_abaddr is available
    # - did@hwtype when module_abaddr is missing but module_hwtype exists
    # - raw did when neither identity is available
    outlets = [
        {
            "device_id": "D1",
            "intensity": 50,
            "module_abaddr": 5,
            "module_hwtype": "FMM",
        },
        {
            "device_id": "D1",
            "intensity": 60,
            "module_abaddr": None,
            "module_hwtype": "PM2",
        },
        {"device_id": "D1", "intensity": 70},
    ]

    refs, seen = ApexDiscovery.new_outlet_intensity_refs(
        {"outlets": outlets},
        already_added_dids=set(),
    )
    assert {r.dedupe_key for r in refs} == {"D1@5", "D1@PM2", "D1"}
    assert seen == {"D1@5", "D1@PM2", "D1"}

    # Cover the `continue` path when dedupe key is already added.
    refs2, seen2 = ApexDiscovery.new_outlet_intensity_refs(
        {"outlets": outlets},
        already_added_dids={"D1@5"},
    )
    assert "D1@5" not in {r.dedupe_key for r in refs2}
    assert "D1@5" not in seen2

    # Repeat for select refs (dedupe logic is duplicated).
    outlets_selectable = [
        {
            "device_id": "D2",
            "state": "AON",
            "type": "pump",
            "module_abaddr": 7,
            "module_hwtype": "FMM",
        },
        {
            "device_id": "D2",
            "state": "AOF",
            "type": "pump",
            "module_hwtype": "PM2",
        },
        {"device_id": "D2", "state": "TBL", "type": "pump"},
    ]

    refs3, seen3 = ApexDiscovery.new_outlet_select_refs(
        {"outlets": outlets_selectable},
        already_added_dids=set(),
    )
    assert {r.dedupe_key for r in refs3} == {"D2@7", "D2@PM2", "D2"}
    assert seen3 == {"D2@7", "D2@PM2", "D2"}


def test_new_outlet_doser_remaining_refs_discovers_dos_and_dqd():
    refs, seen = ApexDiscovery.new_outlet_doser_remaining_refs(
        {
            "outlets": [
                {
                    "device_id": "DOS_1",
                    "name": "DOS_1",
                    "type": "dqd",
                    "doser_remaining_ml": 863,
                    "doser_capacity_ml": 9000,
                },
                {
                    "device_id": "DOS_2",
                    "name": "Dose_2",
                    "type": "dos",
                    "doser_remaining_ml": 12.0,
                },
                # Wrong type.
                {
                    "device_id": "X",
                    "name": "X",
                    "type": "24v",
                    "doser_remaining_ml": 1,
                },
                # Missing remaining.
                {
                    "device_id": "DOS_3",
                    "name": "DOS_3",
                    "type": "dos",
                },
            ]
        },
        already_added_dids=set(),
    )

    assert {r.did for r in refs} == {"DOS_1", "DOS_2"}
    assert seen == {"DOS_1", "DOS_2"}


def test_new_outlet_doser_capacity_refs_discovers_dos_and_dqd():
    refs, seen = ApexDiscovery.new_outlet_doser_capacity_refs(
        {
            "outlets": [
                {
                    "device_id": "DOS_1",
                    "name": "DOS_1",
                    "type": "dqd",
                    "doser_capacity_ml": 9000,
                },
                {
                    "device_id": "DOS_2",
                    "name": "Dose_2",
                    "type": "dos",
                    "doser_capacity_ml": 12.0,
                },
                # Wrong type.
                {
                    "device_id": "X",
                    "name": "X",
                    "type": "24v",
                    "doser_capacity_ml": 1,
                },
                # Missing capacity.
                {
                    "device_id": "DOS_3",
                    "name": "DOS_3",
                    "type": "dos",
                },
            ]
        },
        already_added_dids=set(),
    )

    assert {r.did for r in refs} == {"DOS_1", "DOS_2"}
    assert seen == {"DOS_1", "DOS_2"}


def test_doser_discovery_dedupe_collision_and_already_added_skip() -> None:
    outlets = [
        {
            "device_id": "DOS_1",
            "name": "DOS_1",
            "type": "dos",
            "module_abaddr": 7,
            "module_hwtype": "DOS",
            "doser_remaining_ml": 1,
            "doser_capacity_ml": 10,
        },
        {
            "device_id": "DOS_1",
            "name": "DOS_1",
            "type": "dqd",
            "module_abaddr": None,
            "module_hwtype": "DOS",
            "doser_remaining_ml": 2,
            "doser_capacity_ml": 20,
        },
        {
            "device_id": "DOS_1",
            "name": "DOS_1",
            "type": "dqd",
            "doser_remaining_ml": 3,
            "doser_capacity_ml": 30,
        },
    ]

    rem_refs, rem_seen = ApexDiscovery.new_outlet_doser_remaining_refs(
        {"outlets": outlets},
        already_added_dids=set(),
    )
    cap_refs, cap_seen = ApexDiscovery.new_outlet_doser_capacity_refs(
        {"outlets": outlets},
        already_added_dids=set(),
    )

    assert {r.dedupe_key for r in rem_refs} == {"DOS_1@7", "DOS_1@DOS", "DOS_1"}
    assert rem_seen == {"DOS_1@7", "DOS_1@DOS", "DOS_1"}
    assert {r.dedupe_key for r in cap_refs} == {"DOS_1@7", "DOS_1@DOS", "DOS_1"}
    assert cap_seen == {"DOS_1@7", "DOS_1@DOS", "DOS_1"}

    # Cover already-added dedupe key skip branch.
    rem_refs2, rem_seen2 = ApexDiscovery.new_outlet_doser_remaining_refs(
        {"outlets": outlets},
        already_added_dids={"DOS_1@7"},
    )
    assert "DOS_1@7" not in {r.dedupe_key for r in rem_refs2}
    assert "DOS_1@7" not in rem_seen2


def test_new_outlet_doser_capacity_refs_returns_empty_on_non_list_outlets() -> None:
    refs, seen = ApexDiscovery.new_outlet_doser_capacity_refs(
        {"outlets": "nope"},
        already_added_dids=set(),
    )
    assert refs == []
    assert seen == set()
