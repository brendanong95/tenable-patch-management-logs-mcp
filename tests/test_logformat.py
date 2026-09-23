"""Line layouts, multi-line entries, encodings and time spans."""

from __future__ import annotations

import gzip
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from tenable_patch_management_logs_mcp.timezones import TimeShift, parse_zone
from tenable_patch_management_logs_mcp.logformat import (
    LAYOUT_ADAPTIVA,
    LAYOUT_BLOCKS,
    LAYOUT_MSI,
    LAYOUT_PLAIN,
    LAYOUT_TIMESTAMPED,
    LAYOUT_WORKFLOW,
    RUNAWAY_DETAIL_LINES,
    ParseStats,
    iter_entries,
    timestamp_offset,
    normalize_level,
    parse_timestamp,
    sniff_layout,
    time_span,
)
from tests.sample_logs import MSI_LOG, SERVICES_SENSOR_ENTRY


def write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8", newline="")
    return path


# --------------------------------------------------------------------------- #
# Adaptiva layout
# --------------------------------------------------------------------------- #


def test_adaptiva_line_splits_timestamp_level_component_and_thread(tmp_path):
    path = write(
        tmp_path,
        "adaptiva.log",
        "2026-09-12 18:00:25,141 - INFO - Currently processing policyId [100011] with policyVersion [1] - "
        "PolicyManager - TID=3340624, Name=PartialMembershipEvaluationMultiThinThread_201, GroupID= 201\n",
    )
    [entry] = list(iter_entries(path))
    assert entry.timestamp == datetime(2026, 9, 12, 18, 0, 25, 141000)
    assert entry.level == "INFO"
    assert entry.component == "PolicyManager"
    assert entry.tid == "3340624"
    assert entry.thread == "Name=PartialMembershipEvaluationMultiThinThread_201, GroupID= 201"
    assert entry.message == "Currently processing policyId [100011] with policyVersion [1]"
    assert entry.layout == LAYOUT_ADAPTIVA


def test_thread_names_containing_dashes_do_not_confuse_the_suffix(tmp_path):
    path = write(
        tmp_path,
        "Feeds.log",
        "2026-08-18 00:18:22,786 - INFO - publishInternetPatchContent[1021999001]:  - PatchContentPublisher - "
        "TID=1519, AdaptivaTimer - FeedUpdate. ExecutingTask-FeedServer$FeedUpdateTimerTask\n",
    )
    [entry] = list(iter_entries(path))
    assert entry.component == "PatchContentPublisher"
    assert entry.thread == "AdaptivaTimer - FeedUpdate. ExecutingTask-FeedServer$FeedUpdateTimerTask"
    assert entry.message == "publishInternetPatchContent[1021999001]:"


def test_suffix_on_a_later_line_still_sets_the_component(tmp_path):
    path = write(
        tmp_path,
        "Feeds.log",
        "2026-09-04 10:53:21,301 - INFO - [Periodic Feed Check] Package constructed.\n"
        "   === BEGIN PACKAGE CONTENTS ===\n"
        "      4 Adaptiva products installed\n"
        "   === END PACKAGE CONTENTS === - FeedServer - TID=1519, AdaptivaTimer - FeedUpdate\n"
        "2026-09-04 10:53:21,325 - INFO - [Periodic Feed Check] Feed instruction package received successfully. - "
        "FeedServer - TID=1519, AdaptivaTimer - FeedUpdate\n",
    )
    first, second = list(iter_entries(path))
    assert first.component == "FeedServer"
    assert first.message == "[Periodic Feed Check] Package constructed."
    assert len(first.detail) == 3
    assert second.line == 5


def test_multi_line_message_with_suffix_at_the_end_is_one_entry(tmp_path):
    path = write(tmp_path, "PatchingAdmin.log", "\n".join(SERVICES_SENSOR_ENTRY) + "\n")
    [entry] = list(iter_entries(path))
    assert entry.component == "PatchingAdmin"
    assert entry.tid == "91"
    assert entry.detail_count == 3
    assert "UnsatisfiedLinkError" in entry.text()


def test_stack_trace_lines_attach_to_the_entry_before_them(tmp_path):
    path = write(
        tmp_path,
        "adaptiva.err",
        "2026-08-20 00:04:20,514 - ERROR - Boom - FeedServer - TID=1519, AdaptivaTimer\n"
        "com.adaptiva.util.exceptions.AdaptivaException: Error Message = Could not complete REST API call.\n"
        "\tat com.adaptiva.X.y(X.java:1)\n"
        "Caused by: java.io.IOException: Failed to make HTTP request\n"
        "\t... 7 more\n"
        "2026-08-20 00:05:20,514 - ERROR - Second - FeedServer - TID=1519, AdaptivaTimer\n",
    )
    first, second = list(iter_entries(path))
    assert first.detail_count == 4
    assert first.end_line == 5
    assert second.message == "Second"


def test_entry_without_any_suffix_keeps_its_whole_message(tmp_path):
    path = write(
        tmp_path,
        "adaptiva.log",
        "2026-09-17 05:20:56,025 - ERROR - HHH000315: Exception executing batch [java.sql.BatchUpdateException]\n"
        "  Detail: Key (name)=(test) already exists.\n",
    )
    [entry] = list(iter_entries(path))
    assert entry.component is None
    assert entry.message.startswith("HHH000315")
    assert entry.detail == ["  Detail: Key (name)=(test) already exists."]


def test_crlf_line_endings_and_utf8_bom_are_handled(tmp_path):
    path = tmp_path / "adaptiva.log"
    path.write_bytes(
        b"\xef\xbb\xbf2026-09-12 18:00:25,141 - WARN - Hello - Comp - TID=1, t\r\n"
        b"2026-09-12 18:00:26,141 - INFO - World - Comp - TID=1, t\r\n"
    )
    entries = list(iter_entries(path))
    assert [e.message for e in entries] == ["Hello", "World"]
    assert entries[0].level == "WARN"


def test_unknown_levels_are_not_entry_starts(tmp_path):
    path = write(tmp_path, "adaptiva.log", "2026-09-12 18:00:25,141 - NOTALEVEL - text - Comp - TID=1, t\n")
    [entry] = list(iter_entries(path))
    assert entry.level is None  # parsed as a generic timestamped line instead
    assert entry.layout == LAYOUT_TIMESTAMPED


# --------------------------------------------------------------------------- #
# Other layouts
# --------------------------------------------------------------------------- #


def test_workflow_layout(tmp_path):
    path = write(
        tmp_path,
        "Policy Updated Workflow_10798_2306.log",
        "09-17-2026 11:33:22:8 : Prop: PolicyUpdate.WorkflowInstanceId, WHOLE NUMBER, Old: none, New: 2306\n"
        "09-17-2026 14:00:00:0 : Launching:Launched instance id [2308] Launched by[System]\n"
        "[\n"
        "1<[SinglePatchApproval, patchId:1021126111]>\n"
        "]\n"
        "09-17-2026 14:00:00:2 : Exec: Starting: Start1.Global_Approvals\n",
    )
    assert sniff_layout(path) == LAYOUT_WORKFLOW
    first, second, third = list(iter_entries(path))
    assert first.timestamp == datetime(2026, 9, 17, 11, 33, 22, 800000)
    assert first.component == "Prop"
    assert second.component == "Launching"
    assert second.detail_count == 3
    assert third.component == "Exec"


def test_sqluploader_block_markers(tmp_path):
    path = write(
        tmp_path,
        "SQLUploader.log",
        "-----------------\tSTART(2026-09-02T01:44:27.942)\t---------------\n"
        "-----------------\tEND(2026-09-02T01:44:27.957)\t---------------\n",
    )
    assert sniff_layout(path) == LAYOUT_BLOCKS
    start, end = list(iter_entries(path))
    assert start.timestamp == datetime(2026, 9, 2, 1, 44, 27, 942000)
    assert end.message.startswith("END(")


def test_msi_verbose_log_in_utf16_uses_header_date_nearest_the_file_date(tmp_path):
    path = tmp_path / "1021126111_ab12cd34.log"
    path.write_bytes(b"\xff\xfe" + MSI_LOG.encode("utf-16-le"))
    stamp = datetime(2026, 9, 10, 10, 1, 2).timestamp()
    import os

    os.utime(path, (stamp, stamp))
    assert sniff_layout(path) == LAYOUT_MSI
    entries = list(iter_entries(path))
    assert len(entries) == 8  # every MSI line is its own entry
    assert entries[1].timestamp == datetime(2026, 9, 10, 10, 1, 0, 100000)  # 9/10 read as 10 September
    custom_action = next(e for e in entries if e.message.startswith("CustomAction"))
    assert custom_action.time_inferred is True
    assert custom_action.timestamp is not None


def test_msi_log_that_runs_past_midnight_rolls_the_date(tmp_path):
    path = write(
        tmp_path,
        "x.log",
        "=== Verbose logging started: 9/10/2026  23:59:58  Build type: SHIP ===\n"
        "MSI (s) (A4:B8) [23:59:59:000]: before\n"
        "MSI (s) (A4:B8) [00:00:01:000]: after\n",
    )
    entries = list(iter_entries(path, LAYOUT_MSI))
    assert entries[2].timestamp == datetime(2026, 9, 11, 0, 0, 1)


def test_journalctl_short_iso_lines_are_timestamped_entries(tmp_path):
    path = write(
        tmp_path,
        "AdaptivaClientdService.log",
        "2026-09-10T08:15:02+0800 lnx01 adaptivaclientd[812]: ERROR starting client\n",
    )
    assert sniff_layout(path) == LAYOUT_TIMESTAMPED
    [entry] = list(iter_entries(path))
    assert entry.timestamp == datetime(2026, 9, 10, 8, 15, 2)
    assert entry.level == "ERROR"


def test_unrecognised_format_never_merges_lines(tmp_path):
    path = write(tmp_path, "mystery.log", "alpha\nbeta failed\ngamma\n")
    assert sniff_layout(path) == LAYOUT_PLAIN
    entries = list(iter_entries(path))
    assert [e.message for e in entries] == ["alpha", "beta failed", "gamma"]
    assert all(e.timestamp is None for e in entries)


def test_runaway_entries_are_split_and_counted(tmp_path):
    body = "2026-09-12 18:00:25,141 - INFO - start - Comp - TID=1, t\n" + "junk line\n" * (RUNAWAY_DETAIL_LINES + 10)
    path = write(tmp_path, "adaptiva.log", body)
    stats = ParseStats()
    entries = list(iter_entries(path, LAYOUT_ADAPTIVA, stats))
    assert stats.runaway_splits == 1
    assert entries[0].detail_count == RUNAWAY_DETAIL_LINES
    assert len(entries) == 1 + 10  # the lines past the split stay visible as their own entries
    assert entries[0].detail_dropped > 0


def test_gzip_rotated_logs_are_readable(tmp_path):
    path = tmp_path / "adaptiva.2.log.gz"
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        fh.write("2026-08-25 09:00:00,000 - INFO - Current Version: 10.2.973.9 - Bootstrap - TID=3, main\n")
    assert sniff_layout(path) == LAYOUT_ADAPTIVA
    [entry] = list(iter_entries(path))
    assert entry.component == "Bootstrap"
    assert time_span(path) == (datetime(2026, 8, 25, 9), datetime(2026, 8, 25, 9))


def test_time_span_reads_head_and_tail(tmp_path):
    lines = [f"2026-09-{day:02d} 10:00:00,000 - INFO - day {day} - Comp - TID=1, t" for day in range(1, 29)]
    path = write(tmp_path, "adaptiva.log", "\n".join(lines) + "\n")
    assert time_span(path) == (datetime(2026, 9, 1, 10), datetime(2026, 9, 28, 10))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2026-09-12 18:00:25,141", datetime(2026, 9, 12, 18, 0, 25, 141000)),
        ("2026-09-12T18:00:25.5", datetime(2026, 9, 12, 18, 0, 25, 500000)),
        ("09-17-2026 14:00:00:2", datetime(2026, 9, 17, 14, 0, 0, 200000)),
        ("9/17/2026 2:05:06 PM", datetime(2026, 9, 17, 14, 5, 6)),
        ("17/9/2026 14:05:06", datetime(2026, 9, 17, 14, 5, 6)),
        ("2026-13-45 99:99:99,000", None),
        ("not a time", None),
        ("", None),
    ],
)
def test_parse_timestamp_variants(text, expected):
    assert parse_timestamp(text) == expected


@pytest.mark.parametrize(
    ("token", "expected"),
    [("WARNING", "WARN"), ("severe", "ERROR"), ("INFO", "INFO"), ("nope", None), (None, None)],
)
def test_normalize_level(token, expected):
    assert normalize_level(token) == expected


# --------------------------------------------------------------------------- #
# Time zones
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2026-09-12T18:00:25+02:00", timedelta(hours=2)),
        ("2026-09-12T18:00:25-0530", timedelta(hours=-5, minutes=-30)),
        ("2026-09-12T18:00:25Z", timedelta(0)),
        ("2026-09-12 18:00:25,141", None),
        ("09-17-2026 14:00:00:2", None),
        ("", None),
    ],
)
def test_timestamp_offset_is_read_off_the_line(text, expected):
    assert timestamp_offset(text) == expected


def test_a_shift_converts_entries_as_they_are_read(tmp_path):
    path = tmp_path / "adaptiva.log"
    path.write_text(
        "2026-09-12 18:00:25,141 - INFO - one - Comp - TID=1, t\n"
        "2026-09-12 18:05:00,000 - ERROR - two - Comp - TID=1, t\n",
        encoding="utf-8",
    )
    shift = TimeShift(parse_zone("UTC"), parse_zone("+08:00"))
    times = [entry.timestamp for entry in iter_entries(path, shift=shift)]
    assert times == [datetime(2026, 9, 13, 2, 0, 25, 141000), datetime(2026, 9, 13, 2, 5)]
    assert time_span(path, shift=shift) == (times[0], times[-1])
    # Without a shift the file reads exactly as written.
    assert [entry.timestamp for entry in iter_entries(path)] == [
        datetime(2026, 9, 12, 18, 0, 25, 141000), datetime(2026, 9, 12, 18, 5)
    ]


def test_an_offset_written_on_the_line_beats_the_configured_zone(tmp_path):
    path = tmp_path / "install.log"
    path.write_text("2026-09-12T18:00:25+02:00 INFO setup started\n", encoding="utf-8")
    [entry] = list(iter_entries(path, shift=TimeShift(parse_zone("UTC"), parse_zone("UTC"))))
    assert entry.utc_offset == timedelta(hours=2)
    assert entry.timestamp == datetime(2026, 9, 12, 16, 0, 25)
