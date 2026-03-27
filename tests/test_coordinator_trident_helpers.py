"""Tests for coordinator Trident helper functions.

These are pure helpers and don't require a Home Assistant runtime.
"""

from __future__ import annotations


def test_normalize_trident_status_covers_branches() -> None:
    from custom_components.apex_fusion.coordinator import _normalize_trident_status

    assert _normalize_trident_status(None) == (None, None, None)
    assert _normalize_trident_status("   ") == (None, None, None)

    assert _normalize_trident_status("ok") == ("OK", False, "ok")
    assert _normalize_trident_status("IDLE") == ("Idle", False, "idle")

    # Testing branch with analyte normalization.
    display, is_testing, key = _normalize_trident_status("testing no3")
    assert display == "Testing NO3"
    assert is_testing is True
    assert key == "testing_no3"

    # Testing branch without analyte.
    display, is_testing, key = _normalize_trident_status("testing")
    assert display == "Testing"
    assert is_testing is True
    assert key == "testing"

    # Prime branch.
    display, is_testing, key = _normalize_trident_status("prime 1")
    assert display == "Prime 1"
    assert is_testing is False
    assert key == "prime_1"

    # Generic fallback branch (sentence-case + analyte fixes).
    display, is_testing, key = _normalize_trident_status("hello no3")
    assert display == "Hello NO3"
    assert is_testing is False
    assert key == "hello_no3"


def test_trident_error_message_covers_branches() -> None:
    from custom_components.apex_fusion.coordinator import _trident_error_message

    assert _trident_error_message(None) is None
    assert _trident_error_message(False) is None
    assert _trident_error_message(True) is None
    assert _trident_error_message(0) is None
    assert _trident_error_message(-1) is None

    # Known bit.
    assert _trident_error_message(1024) == "Test B Failed"

    # Unknown-only.
    assert _trident_error_message(1) == "Error code 1"

    # Known + unknown.
    assert _trident_error_message(1024 | 1) == "Test B Failed, Error bits 1"
