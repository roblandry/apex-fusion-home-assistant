"""Apex Fusion input helpers.

This module contains helpers that normalize controller input values into stable
representations for Home Assistant entities.
"""

from __future__ import annotations

from typing import Any

# -----------------------------------------------------------------------------
# Digital Inputs
# -----------------------------------------------------------------------------


class DigitalValueCodec:
    """Normalization helpers for digital input values.

    The controller can encode digital values using multiple conventions
    (integers, booleans, floats, or strings). This codec performs conservative
    normalization for entity platforms.
    """

    @staticmethod
    def as_int_0_1(value: Any) -> int | None:
        """Convert common digital representations to 0/1.

        Args:
            value: Digital value from coordinator data.

        Returns:
            `1` for energized/true, `0` for de-energized/false, or `None` when
            the input value cannot be interpreted.
        """

        if isinstance(value, bool):
            return 1 if value else 0
        if isinstance(value, int):
            if value in (0, 1):
                return value
            # Observed for Apex/FMM optical level sensor:
            # 200 -> closed/wet (true).
            if value == 200:
                return 1
            return None
        if isinstance(value, float):
            if value in (0.0, 1.0):
                return int(value)
            return None
        if isinstance(value, str):
            t = value.strip()
            if t in {"0", "1"}:
                return int(t)
            if t == "200":
                return 1
            return None
        return None
