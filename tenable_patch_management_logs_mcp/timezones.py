"""Which zone each log is written in, and the zone results are shown in.

TPM writes naive local timestamps: no offset, no zone name. That is fine while every
log comes from one machine, but a server in UTC and a client in Asia/Singapore put the
same moment eight hours apart in a merged timeline. This module lets each source or
device declare the zone its logs are written in, converts every timestamp into one
display zone, and reports what was converted so nothing shifts silently.

Configuration (environment, or ``timezone=`` on ``add_log_source``)::

    TPM_LOG_TIMEZONES=saas-server=UTC;WS-BAD07=Asia/Singapore;*=UTC
    TPM_DISPLAY_TIMEZONE=Asia/Singapore

Keys are matched against the source name first, then the device name, then ``*``.
Values are IANA names (``Asia/Singapore``), fixed offsets (``+08:00``, ``UTC-5``),
``UTC`` or ``local`` (this machine's zone). Named zones need the system tz database;
on Windows that is the ``tzdata`` package, which this project depends on.

Nothing is converted unless a display zone is resolved, so the default behaviour -
timestamps exactly as written - is unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any, Iterable, Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .errors import InputError

ENV_ZONES = "TPM_LOG_TIMEZONES"
ENV_DISPLAY = "TPM_DISPLAY_TIMEZONE"
DEFAULT_KEY = "*"
#: Display zone used when logs declare zones but no display zone is set.
IMPLICIT_DISPLAY = "UTC"
LOCAL = "local"

_OFFSET = re.compile(
    r"^(?:UTC|GMT)?(?P<sign>[+-])(?P<hours>\d{1,2})(?::?(?P<minutes>\d{2}))?$", re.IGNORECASE
)
_UTC_NAMES = frozenset({"utc", "gmt", "z", "zulu", "utc+0", "utc+00:00", "+00:00"})


@dataclass(frozen=True)
class Zone:
    """A time zone a log can be written in, or results shown in."""

    name: str
    tz: tzinfo | None  # None means "this machine's zone", resolved per timestamp

    def attach(self, naive: datetime) -> datetime:
        """Read ``naive`` as a wall-clock reading in this zone."""
        if self.tz is None:
            return naive.astimezone()  # a naive datetime is read as system local time
        return naive.replace(tzinfo=self.tz)

    def render(self, aware: datetime) -> datetime:
        """Wall-clock reading of ``aware`` in this zone, naive again."""
        return (aware.astimezone() if self.tz is None else aware.astimezone(self.tz)).replace(tzinfo=None)

    def now(self) -> datetime:
        return self.render(datetime.now(timezone.utc))

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


def parse_zone(text: str | None, *, name: str = "timezone") -> Zone | None:
    """``UTC``, ``+08:00``, ``Asia/Singapore`` or ``local`` -> a :class:`Zone`."""
    value = (text or "").strip()
    if not value:
        return None
    lowered = value.lower()
    if lowered == LOCAL:
        return Zone(LOCAL, None)
    if lowered in _UTC_NAMES:
        return Zone("UTC", timezone.utc)
    match = _OFFSET.match(value)
    if match:
        hours, minutes = int(match.group("hours")), int(match.group("minutes") or 0)
        if hours > 23 or minutes > 59:
            raise InputError(f"{name}='{value}' is not a valid UTC offset (maximum +/-23:59).")
        delta = timedelta(hours=hours, minutes=minutes)
        sign = match.group("sign")
        if sign == "-":
            delta = -delta
        return Zone(f"UTC{sign}{hours:02d}:{minutes:02d}", timezone(delta))
    try:
        return Zone(value, ZoneInfo(value))
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise InputError(
            f"{name}='{value}' is not a time zone this machine knows.",
            remediation="Use an IANA name (Asia/Singapore), a fixed offset (+08:00), UTC, or local. "
                        "Named zones need the system tz database; on Windows install the 'tzdata' package.",
        ) from exc


@dataclass(frozen=True)
class TimeShift:
    """Converts one file's timestamps into the display zone. Identity by default."""

    written_in: Zone | None = None
    shown_in: Zone | None = None

    @property
    def active(self) -> bool:
        """True when timestamps from this file are moved."""
        return self.shown_in is not None and self.written_in is not None and self.written_in != self.shown_in

    @property
    def key(self) -> str:
        """Cache key: two files with the same key convert identically."""
        if self.shown_in is None:
            return ""
        return f"{self.written_in.name if self.written_in else '?'}>{self.shown_in.name}"

    def apply(self, value: datetime | None, offset: timedelta | None = None) -> datetime | None:
        """The timestamp as it should be read in the display zone.

        ``offset`` is the UTC offset the log line itself carried, which wins over the
        configured zone: a line ending in ``+02:00`` says what it means.
        """
        if value is None or self.shown_in is None:
            return value
        if offset is not None:
            return self.shown_in.render(value.replace(tzinfo=timezone(offset)))
        if self.written_in is None or self.written_in == self.shown_in:
            return value
        return self.shown_in.render(self.written_in.attach(value))

    def to_dict(self) -> dict[str, Any]:
        return {
            "written_in": self.written_in.name if self.written_in else None,
            "shown_in": self.shown_in.name if self.shown_in else None,
        }


#: Leaves every timestamp exactly as written.
IDENTITY = TimeShift()


@dataclass
class TimeZoneConfig:
    """Zone per source or device, plus the display zone, read from the environment."""

    display: Zone | None = None
    zones: dict[str, Zone] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)
    configured: bool = False

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> TimeZoneConfig:
        config = cls()
        raw = (env.get(ENV_ZONES) or "").strip()
        for item in raw.split(";"):
            item = item.strip()
            if not item:
                continue
            if "=" not in item:
                config.problems.append(f"{ENV_ZONES}: expected name=zone, got '{item}'.")
                continue
            key, value = (part.strip().strip('"') for part in item.split("=", 1))
            try:
                zone = parse_zone(value, name=key or ENV_ZONES)
            except InputError as exc:
                config.problems.append(f"{ENV_ZONES}: {exc.message}")
                continue
            if zone is None:
                config.problems.append(f"{ENV_ZONES}: no zone given for '{key}'.")
                continue
            config.zones[key.lower()] = zone
        display_text = (env.get(ENV_DISPLAY) or "").strip()
        try:
            config.display = parse_zone(display_text, name=ENV_DISPLAY)
        except InputError as exc:
            config.problems.append(f"{ENV_DISPLAY}: {exc.message}")
        config.configured = bool(raw or display_text)
        if config.display is None and config.zones:
            config.display = parse_zone(IMPLICIT_DISPLAY)
        return config

    def shift_for(self, *, source: str | None = None, device: str | None = None,
                  source_zone: str | None = None) -> TimeShift:
        """The shift for one file: its own source setting first, then the env keys."""
        if self.display is None:
            return IDENTITY
        written: Zone | None = None
        if source and source.lower() in self.zones:
            written = self.zones[source.lower()]
        elif source_zone:
            try:
                written = parse_zone(source_zone, name=f"source '{source}' timezone")
            except InputError as exc:
                if exc.message not in self.problems:
                    self.problems.append(exc.message)
        if written is None and device and device.lower() in self.zones:
            written = self.zones[device.lower()]
        if written is None:
            written = self.zones.get(DEFAULT_KEY)
        return TimeShift(written, self.display)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "configured": self.configured,
            "display_timezone": self.display.name if self.display else None,
            "log_timezones": {key: zone.name for key, zone in sorted(self.zones.items())},
        }
        if self.problems:
            data["problems"] = self.problems
            data["remediation"] = (
                f"Fix {ENV_ZONES} / {ENV_DISPLAY}: name=zone pairs separated by ';', zones as IANA names "
                "(Asia/Singapore), fixed offsets (+08:00), UTC or local."
            )
        if not self.configured:
            data["note"] = (
                f"No zones configured: timestamps are shown exactly as written. Set {ENV_ZONES} "
                f"(and optionally {ENV_DISPLAY}) when logs from machines in different zones are mixed."
            )
        return data


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

BASE_NOTE = (
    "Timestamps are shown exactly as written in the logs. TPM 10.2 SaaS server logs and Windows client logs "
    "were observed to be written in UTC; on-prem servers may use the server's local time."
)


def display_zone(files: Iterable[Any]) -> Zone | None:
    """The display zone in force for a set of log files, if any."""
    for log_file in files:
        shift = getattr(log_file, "shift", None)
        if shift is not None and shift.shown_in is not None:
            return shift.shown_in
    return None


def now_in_display(files: Iterable[Any]) -> datetime:
    """Wall clock now, in the zone results are shown in (this machine's zone otherwise)."""
    zone = display_zone(files)
    return zone.now() if zone is not None else datetime.now()


def describe(files: Iterable[Any]) -> dict[str, Any]:
    """What was converted for these files, by device, and what was left as written."""
    shown: Zone | None = None
    converted: dict[str, set[str]] = {}
    as_written: set[str] = set()
    for log_file in files:
        shift = getattr(log_file, "shift", None) or IDENTITY
        device = getattr(log_file, "device", "?")
        if shift.shown_in is None:
            as_written.add(device)
            continue
        shown = shown or shift.shown_in
        if shift.written_in is None:
            as_written.add(device)
        else:
            converted.setdefault(shift.written_in.name, set()).add(device)
    if shown is None:
        return {"converted": False, "note": BASE_NOTE}
    data: dict[str, Any] = {
        "converted": bool(converted),
        "times_shown_in": shown.name,
        "converted_from": [
            {"written_in": zone, "devices": sorted(devices)[:20]} for zone, devices in sorted(converted.items())
        ],
    }
    if as_written:
        data["shown_as_written"] = sorted(as_written)[:20]
        data["note"] = (
            f"Times are shown in {shown.name}. Logs from {', '.join(sorted(as_written)[:10])} have no configured "
            f"zone and are shown as written, so they may not line up with the converted ones - set {ENV_ZONES} "
            "for them."
        )
    else:
        data["note"] = f"Times are shown in {shown.name}, converted from each log's configured zone."
    return data


def timestamp_note(files: Iterable[Any]) -> str:
    """One sentence for tool output: the base caveat, or what was converted."""
    described = describe(files)
    if not described.get("times_shown_in"):
        return BASE_NOTE
    return str(described["note"])
