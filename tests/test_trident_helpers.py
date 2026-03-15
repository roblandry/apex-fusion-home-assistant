"""Tests for Trident helper extractors.

These are pure helpers that don't require a Home Assistant runtime.
"""

from __future__ import annotations


def test_trident_helpers_single_module_extractors_cover_branches() -> None:
    from custom_components.apex_fusion.apex_fusion import (
        trident_is_testing,
        trident_level_ml,
        trident_reagent_empty,
        trident_waste_full,
    )

    # trident section missing / wrong type
    assert trident_is_testing({}) is None
    assert trident_is_testing({"trident": "nope"}) is None
    assert trident_waste_full({"trident": []}) is None

    # bool present / wrong type
    assert trident_is_testing({"trident": {"is_testing": True}}) is True
    assert trident_is_testing({"trident": {"is_testing": "nope"}}) is None
    assert trident_waste_full({"trident": {"waste_full": False}}) is False
    assert trident_waste_full({"trident": {"waste_full": 1}}) is None

    # reagent-empty extractor
    fn = trident_reagent_empty("reagent_a_empty")
    assert fn({"trident": {"reagent_a_empty": True}}) is True
    assert fn({"trident": {"reagent_a_empty": "nope"}}) is None
    assert fn({"trident": "nope"}) is None

    # levels_ml extractor: missing/not list/out of bounds
    level_0 = trident_level_ml(0)
    level_5 = trident_level_ml(5)
    level_neg = trident_level_ml(-1)
    assert level_0({"trident": {}}) is None
    assert level_0({"trident": {"levels_ml": "nope"}}) is None
    assert level_5({"trident": {"levels_ml": [1, 2, 3]}}) is None
    assert level_neg({"trident": {"levels_ml": [1, 2, 3]}}) is None
    assert level_0({"trident": {"levels_ml": [123]}}) == 123


def test_trident_helpers_multi_module_extractors_cover_branches() -> None:
    from custom_components.apex_fusion.apex_fusion import (
        trident_field_by_abaddr,
        trident_is_testing_by_abaddr,
        trident_level_ml_by_abaddr,
        trident_present_by_abaddr,
        trident_reagent_empty_by_abaddr,
        trident_waste_full_by_abaddr,
    )

    is_testing = trident_is_testing_by_abaddr(5)
    present = trident_present_by_abaddr(5)
    waste_full = trident_waste_full_by_abaddr(5)
    reagent_a = trident_reagent_empty_by_abaddr(5, "reagent_a_empty")
    level_1 = trident_level_ml_by_abaddr(5, 1)
    field_status = trident_field_by_abaddr(5, "status")

    # tridents section missing / wrong type
    assert is_testing({}) is None
    assert present({"tridents": "nope"}) is None

    data = {
        "tridents": [
            "nope",
            {"abaddr": 4, "present": True},
            {
                "abaddr": 5,
                "present": False,
                "waste_full": True,
                "is_testing": False,
                "reagent_a_empty": True,
                "levels_ml": [10, 20, 30],
                "status": "Idle",
            },
        ]
    }

    assert is_testing(data) is False
    assert present(data) is False
    assert waste_full(data) is True
    assert reagent_a(data) is True
    assert level_1(data) == 20
    assert field_status(data) == "Idle"

    # Not-found / wrong-type branches for multi-module helpers.
    assert trident_is_testing_by_abaddr(99)(data) is None
    assert trident_present_by_abaddr(99)(data) is None

    assert waste_full({"tridents": "nope"}) is None
    assert trident_waste_full_by_abaddr(99)(data) is None

    assert reagent_a({"tridents": "nope"}) is None
    assert trident_reagent_empty_by_abaddr(99, "reagent_a_empty")(data) is None

    assert level_1({"tridents": "nope"}) is None
    assert trident_level_ml_by_abaddr(99, 1)(data) is None

    assert trident_field_by_abaddr(99, "status")(data) is None

    # levels_ml out-of-range / wrong type
    bad_levels = {"tridents": [{"abaddr": 5, "levels_ml": "nope"}]}
    assert level_1(bad_levels) is None
    assert trident_level_ml_by_abaddr(5, 99)(data) is None
