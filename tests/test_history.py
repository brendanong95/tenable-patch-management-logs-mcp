"""The recorded-baseline store: what it writes, what it gives back, and what it refuses to double count."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from tenable_patch_management_logs_mcp import history


def signature_row(device: str, day: str, count: int, signature: str = "upload failed", **extra: object) -> dict:
    return {
        "device": device,
        "component": "ContentPublisher",
        "signature": signature,
        "day": day,
        "known_id": None,
        "severity": "ERROR",
        "count": count,
        "first_seen": f"{day} 08:00:00.000",
        "last_seen": f"{day} 18:00:00.000",
        **extra,
    }


def log_row(device: str, day: str, entries: int, log: str = "adaptiva.log") -> dict:
    return {"device": device, "log": log, "day": day, "entries": entries}


def store_with(tmp_path: Path, signature_rows: list[dict], log_rows: list[dict]) -> history.BaselineStore:
    store = history.BaselineStore(tmp_path)
    store.record(signature_rows=signature_rows, log_rows=log_rows, sources="srv", devices="server",
                 window_from="2026-09-01 00:00:00.000", window_to="2026-09-03 00:00:00.000", events=sum(
                     row["count"] for row in signature_rows))
    return store


def test_nothing_is_recorded_until_a_snapshot_is_taken(tmp_path: Path) -> None:
    store = history.BaselineStore(tmp_path)
    assert store.exists is False
    stats = store.stats()
    assert stats["recorded"] is False
    assert "record_baseline_snapshot" in stats["note"]
    empty = store.read(days_by_device={"server": ["2026-09-01"]})
    assert empty.available is False and empty.days == 0


def test_recorded_days_come_back_as_counts_and_days(tmp_path: Path) -> None:
    store = store_with(
        tmp_path,
        [signature_row("server", "2026-09-01", 4), signature_row("server", "2026-09-02", 6)],
        [log_row("server", "2026-09-01", 900), log_row("server", "2026-09-02", 800)],
    )
    recorded = store.read(days_by_device={"server": ["2026-09-01", "2026-09-02"]})
    [(key, record)] = recorded.counts.items()
    assert key == ("server", "ContentPublisher", "upload failed")
    assert record["count"] == 10
    assert record["days"] == {"2026-09-01", "2026-09-02"}
    assert record["first_seen"] == "2026-09-01 08:00:00.000"
    assert recorded.log_entries[("server", "adaptiva.log")] == 1700
    assert recorded.coverage_pct("server", ["2026-09-01", "2026-09-02", "2026-09-03"]) == 66.7


def test_recording_the_same_day_twice_keeps_the_larger_count(tmp_path: Path) -> None:
    store = store_with(tmp_path, [signature_row("server", "2026-09-01", 4)], [log_row("server", "2026-09-01", 900)])
    store.record(signature_rows=[signature_row("server", "2026-09-01", 4)],
                 log_rows=[log_row("server", "2026-09-01", 900)],
                 sources="srv", devices="server", window_from=None, window_to=None, events=4)
    assert store.read(days_by_device={"server": ["2026-09-01"]}).counts[
        ("server", "ContentPublisher", "upload failed")]["count"] == 4

    # A later snapshot that saw more of the same day wins.
    store.record(signature_rows=[signature_row("server", "2026-09-01", 9)], log_rows=[],
                 sources="srv", devices="server", window_from=None, window_to=None, events=9)
    assert store.read(days_by_device={"server": ["2026-09-01"]}).counts[
        ("server", "ContentPublisher", "upload failed")]["count"] == 9


def test_each_device_only_gets_the_days_it_asked_for(tmp_path: Path) -> None:
    store = store_with(
        tmp_path,
        [signature_row("server", "2026-09-01", 3), signature_row("server", "2026-09-02", 5),
         signature_row("client-13", "2026-09-01", 7), signature_row("client-13", "2026-09-02", 11)],
        [log_row("server", "2026-09-01", 10), log_row("client-13", "2026-09-02", 20)],
    )
    recorded = store.read(days_by_device={"server": ["2026-09-01"], "client-13": ["2026-09-02"]})
    assert recorded.counts[("server", "ContentPublisher", "upload failed")]["count"] == 3
    assert recorded.counts[("client-13", "ContentPublisher", "upload failed")]["count"] == 11
    assert recorded.days_by_device == {"server": {"2026-09-01"}, "client-13": {"2026-09-02"}}
    assert recorded.log_entries == {("server", "adaptiva.log"): 10, ("client-13", "adaptiva.log"): 20}

    # A device that is not asked about contributes nothing.
    assert store.read(days_by_device={"server": ["2026-09-02"]}).counts.keys() == {
        ("server", "ContentPublisher", "upload failed")
    }


def test_stats_describe_what_is_held(tmp_path: Path) -> None:
    store = store_with(
        tmp_path,
        [signature_row("server", "2026-09-01", 3), signature_row("client-13", "2026-09-03", 4)],
        [log_row("server", "2026-09-01", 10)],
    )
    stats = store.stats()
    assert stats["recorded"] is True
    assert stats["signature_days"] == 2
    assert stats["devices"] == 2
    assert (stats["first_day"], stats["last_day"]) == ("2026-09-01", "2026-09-03")
    assert stats["snapshots_taken"] == 1
    assert stats["store"].endswith(history.DB_FILENAME)


def test_days_between_covers_whole_days_up_to_the_window(tmp_path: Path) -> None:
    days = history.days_between(datetime(2026, 9, 1, 13, 0), datetime(2026, 9, 4, 2, 0))
    assert days == ["2026-09-01", "2026-09-02", "2026-09-03", "2026-09-04"]
    assert history.days_between(datetime(2026, 9, 1, 13, 0), datetime(2026, 9, 1, 14, 0)) == ["2026-09-01"]
