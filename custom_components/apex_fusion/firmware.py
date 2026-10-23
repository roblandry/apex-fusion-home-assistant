"""Apex firmware version comparison, shared by the update entities and the coordinator."""

from __future__ import annotations

import re

# Apex firmware strings look like "5.15J_6B26" (installed) or "5.16_AC26"
# (latest): <major>.<minor>[family letter]_<build>. The optional J/L letter is the
# hardware family, not part of the release identity.
_FIRMWARE_RE = re.compile(r"^(\d+)\.(\d+)[A-Za-z]?_([0-9A-Za-z]+)$")


def normalize_firmware(value: str | None) -> tuple[int, int, str] | None:
    """Parse an Apex firmware string into (major, minor, build).

    The optional family letter (e.g. the "J" in "5.15J_6B26") is dropped.

    Returns:
        The normalized tuple, or None when the string is missing or unparseable.
    """
    if value is None:
        return None
    m = _FIRMWARE_RE.match(value.strip())
    if m is None:
        return None
    return int(m.group(1)), int(m.group(2)), m.group(3)


def firmware_update_available(
    latest: str | None, installed: str | None, flag: bool | None = None
) -> bool:
    """Decide whether `latest` represents an update over `installed`.

    Rules:
    - If major.minor differs, the numerically greater one is newer.
    - If major.minor is equal and the build code differs, an update is
      available. Build codes are opaque; their order is never inferred.
    - If the normalized versions are equal, the controller `flag` decides
      (True means update available; False/None means none).
    - If either string is unparseable, fall back to string inequality when both
      are present.
    - If either string is missing, only a True `flag` reports an update.

    A False flag never hides a visibly newer version.
    """
    if latest is None or installed is None:
        return flag is True

    new = normalize_firmware(latest)
    old = normalize_firmware(installed)
    if new is None or old is None:
        return latest != installed or flag is True

    if new[:2] != old[:2]:
        return new[:2] > old[:2] or flag is True
    if new[2] != old[2]:
        return True
    return flag is True


def firmware_is_newer(candidate: str | None, installed: str | None) -> bool:
    """Return whether ``candidate`` is verifiably newer than ``installed``.

    Stricter than ``firmware_update_available``: both strings must parse (an
    unparseable comparison is never "newer"), and it uses the same semantics
    otherwise: a greater major.minor is newer, a lower one never is, and the same
    major.minor with a different build code counts as newer because build codes
    are opaque and are never ordered. Equal versions are not newer.

    Args:
        candidate: The version just observed.
        installed: The version to compare against.

    Returns:
        True only when ``candidate`` can be shown to be a newer release.
    """
    if normalize_firmware(candidate) is None or normalize_firmware(installed) is None:
        return False
    return firmware_update_available(candidate, installed)
