"""Apex Fusion probe helpers.

Centralized probe naming and unit/device_class selection.
"""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorStateClass,
)
from homeassistant.const import UnitOfTemperature

# -----------------------------------------------------------------------------
# Conversions
# -----------------------------------------------------------------------------


def as_float(value: Any) -> float | None:
    """Convert a value to a float when possible.

    Args:
        value: Value to convert.

    Returns:
        A float when the input is numeric or a numeric string; otherwise `None`.
    """

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        t = value.strip()
        if not t:
            return None
        try:
            return float(t)
        except ValueError:
            return None
    return None


class ProbeMetaResolver:
    """Resolve friendly names and metadata for probe values."""

    @staticmethod
    def friendly_probe_name(*, name: str, probe_type: str | None) -> str:
        """Return a friendly display name for a probe.

        Args:
            name: Raw probe name.
            probe_type: Raw probe type token.

        Returns:
            Friendly probe name for display.
        """
        n = (name or "").strip()
        t = (probe_type or "").strip().lower()

        if t == "ph":
            return "pH"
        if t == "temp":
            return "Temperature"
        if t == "cond":
            return "Conductivity"
        if t == "orp":
            return "ORP"

        if t == "alk":
            return "Alkalinity"
        if t == "ca":
            return "Calcium"
        if t == "mg":
            return "Magnesium"

        if t == "no3":
            return "Nitrate"
        if t == "po4":
            return "Phosphate"

        return n

    @staticmethod
    def temp_unit(value: float | None) -> UnitOfTemperature:
        """Choose a temperature unit based on the numeric value.

        Args:
            value: Numeric temperature reading.

        Returns:
            Temperature unit selected from the numeric range.
        """
        # TODO: see if there is a better way to determine this; maybe there is a unit
        # Issue URL: https://github.com/roblandry/apex-fusion-home-assistant/issues/17
        # field somewhere in the data?
        # Values <= 45 are treated as Celsius; higher values as Fahrenheit.
        if value is not None and value <= 45:
            return UnitOfTemperature.CELSIUS
        return UnitOfTemperature.FAHRENHEIT

    @staticmethod
    def units_and_meta(
        *,
        probe_name: str,
        probe_type: str,
        value: float | None,
    ) -> tuple[str | None, SensorDeviceClass | None, SensorStateClass | None]:
        """Resolve unit and Home Assistant metadata for a probe reading.

        Args:
            probe_name: Probe name.
            probe_type: Probe type token.
            value: Parsed numeric value.

        Returns:
            Tuple of (unit, device_class, state_class).
        """
        t = (probe_type or "").strip().lower()
        _ = (probe_name or "").strip().lower()

        if t == "ph":
            return None, None, SensorStateClass.MEASUREMENT
        if t == "temp":
            return (
                ProbeMetaResolver.temp_unit(value),
                SensorDeviceClass.TEMPERATURE,
                SensorStateClass.MEASUREMENT,
            )
        if t == "cond":
            return "ppt", None, SensorStateClass.MEASUREMENT
        if t == "orp":
            return "mV", None, SensorStateClass.MEASUREMENT

        if t == "alk":
            return "dKH", None, SensorStateClass.MEASUREMENT
        if t in ("ca", "mg"):
            return "ppm", None, SensorStateClass.MEASUREMENT

        if t in {"no3", "po4"}:
            return "ppm", None, SensorStateClass.MEASUREMENT

        return None, None, SensorStateClass.MEASUREMENT


def friendly_probe_name(*, name: str, probe_type: str | None) -> str:
    """Return a friendly display name for a probe.

    Args:
        name: Raw probe name.
        probe_type: Raw probe type token.

    Returns:
        Friendly probe name for display.
    """
    return ProbeMetaResolver.friendly_probe_name(name=name, probe_type=probe_type)


def units_and_meta(
    *,
    probe_name: str,
    probe_type: str,
    value: float | None,
) -> tuple[str | None, SensorDeviceClass | None, SensorStateClass | None]:
    """Resolve unit and Home Assistant metadata for a probe reading.

    Args:
        probe_name: Probe name.
        probe_type: Probe type token.
        value: Parsed numeric value.

    Returns:
        Tuple of (unit, device_class, state_class).
    """
    return ProbeMetaResolver.units_and_meta(
        probe_name=probe_name, probe_type=probe_type, value=value
    )
