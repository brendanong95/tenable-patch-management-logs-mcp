"""Zone parsing, conversion and the reporting that says what was converted."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from tenable_patch_management_logs_mcp import timezones
from tenable_patch_management_logs_mcp.errors import InputError


def _tz_database_available() -> bool:
    try:
        ZoneInfo("Asia/Singapore")
    except Exception:  # noqa: BLE001 - any failure means named zones are unusable here
        return False
    return True


# Named zones need a tz database: Windows gets it from the tzdata dependency, Linux
# usually from the system, but a minimal image may have neither.
needs_tz_database = pytest.mark.skipif(not _tz_database_available(),
                                       reason="no tz database on this machine (install tzdata)")


@dataclass
class FakeFile:
    """Only what the reporting helpers read off a log file."""

    device: str
    shift: timezones.TimeShift


UTC = timezones.parse_zone("UTC")
SG = timezones.parse_zone("+08:00")


# --------------------------------------------------------------------------- #
# parse_zone
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("text", "name"),
    [
        ("UTC", "UTC"), ("utc", "UTC"), ("Z", "UTC"), ("+00:00", "UTC"),
        ("+08:00", "UTC+08:00"), ("+0800", "UTC+08:00"), ("UTC+8", "UTC+08:00"),
        ("-05:30", "UTC-05:30"), ("GMT-5", "UTC-05:00"), ("local", "local"),
    ],
)
def test_zone_names_and_offsets_are_understood(text: str, name: str) -> None:
    zone = timezones.parse_zone(text)
    assert zone is not None and zone.name == name


def test_blank_is_no_zone_at_all() -> None:
    assert timezones.parse_zone(None) is None
    assert timezones.parse_zone("   ") is None


@needs_tz_database
def test_named_zones_use_the_tz_database() -> None:
    zone = timezones.parse_zone("Asia/Singapore")
    assert zone is not None and zone.name == "Asia/Singapore"
    # 2026-01-01 is +08:00 in Singapore, all year round.
    assert zone.attach(datetime(2026, 1, 1, 12, 0)).utcoffset() == timedelta(hours=8)


def test_a_zone_this_machine_does_not_know_is_a_clear_error() -> None:
    with pytest.raises(InputError) as raised:
        timezones.parse_zone("Mars/Olympus", name="timezone")
    assert "not a time zone this machine knows" in raised.value.message
    assert "tzdata" in (raised.value.remediation or "")
    with pytest.raises(InputError):
        timezones.parse_zone("+45:00")


# --------------------------------------------------------------------------- #
# TimeShift
# --------------------------------------------------------------------------- #


def test_a_shift_moves_naive_timestamps_into_the_display_zone() -> None:
    shift = timezones.TimeShift(UTC, SG)
    assert shift.active is True
    assert shift.apply(datetime(2026, 9, 17, 10, 0)) == datetime(2026, 9, 17, 18, 0)
    assert shift.key == "UTC>UTC+08:00"


def test_a_shift_between_the_same_zones_changes_nothing() -> None:
    shift = timezones.TimeShift(UTC, UTC)
    assert shift.active is False
    assert shift.apply(datetime(2026, 9, 17, 10, 0)) == datetime(2026, 9, 17, 10, 0)


def test_an_offset_on_the_line_itself_wins_over_the_configured_zone() -> None:
    shift = timezones.TimeShift(UTC, SG)
    # 10:00+02:00 is 08:00 UTC, which is 16:00 in +08:00.
    assert shift.apply(datetime(2026, 9, 17, 10, 0), timedelta(hours=2)) == datetime(2026, 9, 17, 16, 0)


def test_without_a_display_zone_nothing_is_converted() -> None:
    assert timezones.IDENTITY.apply(datetime(2026, 9, 17, 10, 0), timedelta(hours=2)) == datetime(2026, 9, 17, 10, 0)
    assert timezones.IDENTITY.apply(None) is None
    assert timezones.IDENTITY.key == ""


@needs_tz_database
def test_dst_is_followed_when_the_zone_has_it() -> None:
    berlin = timezones.parse_zone("Europe/Berlin")
    winter = timezones.TimeShift(berlin, UTC).apply(datetime(2026, 1, 15, 12, 0))
    summer = timezones.TimeShift(berlin, UTC).apply(datetime(2026, 7, 15, 12, 0))
    assert winter == datetime(2026, 1, 15, 11, 0)  # +01:00
    assert summer == datetime(2026, 7, 15, 10, 0)  # +02:00


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


def test_source_name_wins_over_device_name_and_the_default() -> None:
    config = timezones.TimeZoneConfig.from_env({
        "TPM_LOG_TIMEZONES": "saas-server=UTC;ws-bad07=+09:00;*=+01:00",
        "TPM_DISPLAY_TIMEZONE": "+08:00",
    })
    assert config.shift_for(source="saas-server", device="server").written_in.name == "UTC"
    assert config.shift_for(source="clients", device="WS-BAD07").written_in.name == "UTC+09:00"
    assert config.shift_for(source="clients", device="WS-GOOD01").written_in.name == "UTC+01:00"
    assert config.to_dict()["display_timezone"] == "UTC+08:00"


def test_a_source_setting_is_used_when_the_environment_does_not_name_it() -> None:
    config = timezones.TimeZoneConfig.from_env({"TPM_DISPLAY_TIMEZONE": "UTC"})
    shift = config.shift_for(source="clients", device="WS-BAD07", source_zone="+08:00")
    assert shift.written_in.name == "UTC+08:00"
    assert shift.apply(datetime(2026, 9, 17, 18, 0)) == datetime(2026, 9, 17, 10, 0)


def test_declaring_zones_without_a_display_zone_shows_everything_in_utc() -> None:
    config = timezones.TimeZoneConfig.from_env({"TPM_LOG_TIMEZONES": "clients=+08:00"})
    assert config.display is not None and config.display.name == "UTC"


def test_no_configuration_means_no_conversion_and_says_so() -> None:
    config = timezones.TimeZoneConfig.from_env({})
    assert config.display is None
    assert config.shift_for(source="any", device="any") is timezones.IDENTITY
    data = config.to_dict()
    assert data["configured"] is False
    assert "exactly as written" in data["note"]


def test_bad_entries_are_reported_and_the_rest_still_load() -> None:
    config = timezones.TimeZoneConfig.from_env({
        "TPM_LOG_TIMEZONES": "good=UTC;no-equals-sign;bad=Mars/Olympus;empty=",
        "TPM_DISPLAY_TIMEZONE": "Also/Nonsense",
    })
    data = config.to_dict()
    assert config.zones["good"].name == "UTC"
    assert len(data["problems"]) == 4
    assert any("no-equals-sign" in problem for problem in data["problems"])
    assert config.display.name == "UTC"  # the broken display zone falls back, and is reported


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


def test_the_note_names_the_display_zone_and_the_logs_left_as_written() -> None:
    converted = FakeFile("server", timezones.TimeShift(UTC, SG))
    untouched = FakeFile("WS-BAD07", timezones.TimeShift(None, SG))
    described = timezones.describe([converted, untouched])
    assert described["times_shown_in"] == "UTC+08:00"
    assert described["converted_from"] == [{"written_in": "UTC", "devices": ["server"]}]
    assert described["shown_as_written"] == ["WS-BAD07"]
    assert "WS-BAD07" in timezones.timestamp_note([converted, untouched])

    only_converted = timezones.describe([converted])
    assert "converted from each log's configured zone" in only_converted["note"]


def test_with_no_zones_the_note_is_the_plain_caveat() -> None:
    plain = FakeFile("server", timezones.IDENTITY)
    assert timezones.timestamp_note([plain]) == timezones.BASE_NOTE
    assert timezones.display_zone([plain]) is None


def test_now_is_read_in_the_display_zone() -> None:
    plain = FakeFile("server", timezones.IDENTITY)
    shifted = FakeFile("server", timezones.TimeShift(UTC, timezones.parse_zone("+14:00")))
    assert timezones.now_in_display([shifted]) > timezones.now_in_display([plain])
