"""Unit tests for ApexFusionContext helpers."""

from __future__ import annotations

from unittest.mock import patch


def _ctx():
    from custom_components.apex_fusion.apex_fusion.context import ApexFusionContext

    return ApexFusionContext(
        host="1.2.3.4",
        meta={"serial": "ABC"},
        controller_device_identifier="ABC",
        serial_for_ids="ABC",
        hostname_disp="apex",
        tank_slug="tank",
    )


def test_context_object_id_skips_empty_tokens_and_uses_cleaned_fallback() -> None:
    ctx = _ctx()

    # Covers: empty/whitespace token is skipped.
    assert ctx.object_id("tank", " ", None, "x") == "tank_x"

    # Covers: slugify returns empty -> cleaned fallback used.
    with patch(
        "custom_components.apex_fusion.apex_fusion.context.slugify",
        return_value="",
    ):
        assert ctx.object_id("A B", "C") == "ab_c"


def test_context_normalize_module_suffix_returns_empty_for_blank_suffix() -> None:
    ctx = _ctx()
    assert (
        ctx.normalize_module_suffix(module_token="fmm", module_abaddr=3, suffix="")
        == ""
    )
