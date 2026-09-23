"""Recorded baselines, so anomaly detection can look further back than the logs reach.

``detect_log_anomalies`` compares a window with the days before it *in the same logs*.
That is enough for a fresh bundle, but TPM rotates logs: on a busy server the last
adaptiva.log can be a few hours long, and the baseline then covers a fraction of the
period it claims. ``record_baseline_snapshot`` writes the daily counts it can see into
a small SQLite file next to the other data, and later runs read those days back, so a
baseline survives rotation and grows as the file is re-run against a live log folder.

What is stored is what the tools already report: a device name, a component, a
normalised and redacted signature, a day, and a count - no message bodies, no raw
lines. The file is local; deleting ``baselines.db`` deletes the history.

Counts are per day and idempotent: re-recording a day keeps the larger count, so
running this twice over overlapping windows cannot inflate a baseline.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

DB_FILENAME = "baselines.db"
#: Rows older than this are dropped when a snapshot is written.
KEEP_DAYS = 400
#: Rows accepted from one snapshot, newest days first.
MAX_ROWS_PER_SNAPSHOT = 200_000
SCHEMA_VERSION = 1
_TIMEOUT_SECONDS = 10.0

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS signature_days (
        device TEXT NOT NULL,
        component TEXT NOT NULL,
        signature TEXT NOT NULL,
        day TEXT NOT NULL,
        known_id TEXT,
        severity TEXT,
        count INTEGER NOT NULL,
        first_seen TEXT,
        last_seen TEXT,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (device, component, signature, day)
    )""",
    """CREATE TABLE IF NOT EXISTS log_days (
        device TEXT NOT NULL,
        log TEXT NOT NULL,
        day TEXT NOT NULL,
        entries INTEGER NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (device, log, day)
    )""",
    """CREATE TABLE IF NOT EXISTS snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        taken_at TEXT NOT NULL,
        sources TEXT,
        devices TEXT,
        window_from TEXT,
        window_to TEXT,
        signature_rows INTEGER,
        events INTEGER
    )""",
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)",
    "CREATE INDEX IF NOT EXISTS signature_days_day ON signature_days (day)",
    "CREATE INDEX IF NOT EXISTS log_days_day ON log_days (day)",
)


def day_key(value: datetime | date) -> str:
    return value.strftime("%Y-%m-%d")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class RecordedBaseline:
    """What the store knows about the period asked for."""

    counts: dict[tuple[str, str, str], dict[str, Any]]
    log_entries: dict[tuple[str, str], int]
    days_by_device: dict[str, set[str]]
    days: int

    @property
    def available(self) -> bool:
        return bool(self.counts or self.log_entries)

    def coverage_pct(self, device: str, expected_days: Iterable[str]) -> float:
        """Share of the days asked for that this device has recorded data for."""
        wanted = list(expected_days)
        if not wanted:
            return 0.0
        recorded = self.days_by_device.get(device, set())
        return round(len([day for day in wanted if day in recorded]) / len(wanted) * 100, 1)


class BaselineStore:
    """The SQLite file. Every call opens and closes its own connection."""

    def __init__(self, data_dir: Path) -> None:
        self.path = Path(data_dir) / DB_FILENAME

    # -- plumbing ----------------------------------------------------------------- #

    @contextmanager
    def _connect(self, *, create: bool = False) -> Iterator[sqlite3.Connection | None]:
        if not create and not self.path.exists():
            yield None
            return
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=_TIMEOUT_SECONDS)
        try:
            connection.row_factory = sqlite3.Row
            if create:
                with connection:
                    for statement in _SCHEMA:
                        connection.execute(statement)
                    connection.execute(
                        "INSERT INTO meta (key, value) VALUES ('schema_version', ?) "
                        "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                        (str(SCHEMA_VERSION),),
                    )
            yield connection
        finally:
            connection.close()

    @property
    def exists(self) -> bool:
        return self.path.exists()

    # -- writing ------------------------------------------------------------------ #

    def record(
        self,
        *,
        signature_rows: Iterable[Mapping[str, Any]],
        log_rows: Iterable[Mapping[str, Any]],
        sources: str,
        devices: str,
        window_from: str | None,
        window_to: str | None,
        events: int,
    ) -> dict[str, Any]:
        """Merge daily counts into the store; the larger count for a day wins."""
        stamp = _now()
        signature_rows = list(signature_rows)[:MAX_ROWS_PER_SNAPSHOT]
        log_rows = list(log_rows)[:MAX_ROWS_PER_SNAPSHOT]
        with self._connect(create=True) as connection:
            assert connection is not None  # create=True always yields a connection
            with connection:
                connection.executemany(
                    """INSERT INTO signature_days
                           (device, component, signature, day, known_id, severity, count,
                            first_seen, last_seen, updated_at)
                       VALUES (:device, :component, :signature, :day, :known_id, :severity, :count,
                               :first_seen, :last_seen, :updated_at)
                       ON CONFLICT (device, component, signature, day) DO UPDATE SET
                           count = MAX(signature_days.count, excluded.count),
                           severity = excluded.severity,
                           known_id = excluded.known_id,
                           first_seen = MIN(signature_days.first_seen, excluded.first_seen),
                           last_seen = MAX(signature_days.last_seen, excluded.last_seen),
                           updated_at = excluded.updated_at""",
                    [{**row, "updated_at": stamp} for row in signature_rows],
                )
                connection.executemany(
                    """INSERT INTO log_days (device, log, day, entries, updated_at)
                       VALUES (:device, :log, :day, :entries, :updated_at)
                       ON CONFLICT (device, log, day) DO UPDATE SET
                           entries = MAX(log_days.entries, excluded.entries),
                           updated_at = excluded.updated_at""",
                    [{**row, "updated_at": stamp} for row in log_rows],
                )
                cutoff = day_key(datetime.now(timezone.utc) - timedelta(days=KEEP_DAYS))
                connection.execute("DELETE FROM signature_days WHERE day < ?", (cutoff,))
                connection.execute("DELETE FROM log_days WHERE day < ?", (cutoff,))
                connection.execute(
                    """INSERT INTO snapshots
                           (taken_at, sources, devices, window_from, window_to, signature_rows, events)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (stamp, sources, devices, window_from, window_to, len(signature_rows), events),
                )
        return {
            "store": str(self.path),
            "recorded_at": stamp,
            "signature_days_written": len(signature_rows),
            "log_days_written": len(log_rows),
            "pruned_before": day_key(datetime.now(timezone.utc) - timedelta(days=KEEP_DAYS)),
        }

    # -- reading ------------------------------------------------------------------ #

    def read(self, *, days_by_device: Mapping[str, Iterable[str]]) -> RecordedBaseline:
        """Recorded counts, per device, for exactly the days that device is missing.

        The caller asks only for the days its logs no longer reach, so a recorded day
        is never added on top of the same day read from a log file.
        """
        wanted_days_by_device = {device: set(days) for device, days in days_by_device.items() if days}
        wanted = sorted(wanted_days_by_device)
        all_days = sorted({day for days in wanted_days_by_device.values() for day in days})
        counts: dict[tuple[str, str, str], dict[str, Any]] = {}
        log_entries: dict[tuple[str, str], int] = {}
        days_by_device_found: dict[str, set[str]] = {}
        if not wanted or not all_days:
            return RecordedBaseline(counts, log_entries, days_by_device_found, 0)
        first_day, last_day = all_days[0], all_days[-1]
        placeholders = ",".join("?" for _ in wanted)
        with self._connect() as connection:
            if connection is None:
                return RecordedBaseline(counts, log_entries, days_by_device_found, 0)
            with closing(connection.cursor()) as cursor:
                cursor.execute(
                    f"""SELECT device, component, signature, known_id, severity, day, count, first_seen, last_seen
                        FROM signature_days
                        WHERE day >= ? AND day <= ? AND device IN ({placeholders})""",
                    (first_day, last_day, *wanted),
                )
                for row in cursor.fetchall():
                    if row["day"] not in wanted_days_by_device.get(row["device"], ()):
                        continue  # the range query is inclusive; keep only each device's missing days
                    key = (row["device"], row["component"], row["signature"])
                    record = counts.setdefault(
                        key,
                        {"count": 0, "days": set(), "known_id": row["known_id"], "severity": row["severity"],
                         "first_seen": row["first_seen"], "last_seen": row["last_seen"]},
                    )
                    record["count"] += int(row["count"])
                    record["days"].add(row["day"])
                    if row["first_seen"] and (not record["first_seen"] or row["first_seen"] < record["first_seen"]):
                        record["first_seen"] = row["first_seen"]
                    if row["last_seen"] and (not record["last_seen"] or row["last_seen"] > record["last_seen"]):
                        record["last_seen"] = row["last_seen"]
                    days_by_device_found.setdefault(row["device"], set()).add(row["day"])
                cursor.execute(
                    f"""SELECT device, log, day, entries FROM log_days
                        WHERE day >= ? AND day <= ? AND device IN ({placeholders})""",
                    (first_day, last_day, *wanted),
                )
                for row in cursor.fetchall():
                    if row["day"] not in wanted_days_by_device.get(row["device"], ()):
                        continue
                    key = (row["device"], row["log"])
                    log_entries[key] = log_entries.get(key, 0) + int(row["entries"])
                    days_by_device_found.setdefault(row["device"], set()).add(row["day"])
        return RecordedBaseline(
            counts=counts,
            log_entries=log_entries,
            days_by_device=days_by_device_found,
            days=len({day for days in days_by_device_found.values() for day in days}),
        )

    def stats(self) -> dict[str, Any]:
        """What the store holds, for check_log_sources and the snapshot result."""
        if not self.exists:
            return {
                "recorded": False,
                "store": str(self.path),
                "note": "No recorded baselines yet. Call record_baseline_snapshot to start one, so anomaly "
                        "detection keeps a baseline after the logs rotate.",
            }
        with self._connect() as connection:
            if connection is None:  # pragma: no cover - removed between the two calls
                return {"recorded": False, "store": str(self.path)}
            with closing(connection.cursor()) as cursor:
                try:
                    cursor.execute(
                        "SELECT COUNT(*) AS rows_, COUNT(DISTINCT device) AS devices, COUNT(DISTINCT day) AS days, "
                        "MIN(day) AS first_day, MAX(day) AS last_day FROM signature_days"
                    )
                    signatures = dict(cursor.fetchone())
                    cursor.execute("SELECT COUNT(*) AS taken, MAX(taken_at) AS last FROM snapshots")
                    snapshots = dict(cursor.fetchone())
                except sqlite3.DatabaseError as exc:
                    return {"recorded": False, "store": str(self.path), "error": str(exc),
                            "remediation": f"Delete {self.path} and record a new snapshot."}
        return {
            "recorded": bool(signatures["rows_"]),
            "store": str(self.path),
            "size_kb": round(self.path.stat().st_size / 1024, 1),
            "signature_days": signatures["rows_"],
            "devices": signatures["devices"],
            "days_recorded": signatures["days"],
            "first_day": signatures["first_day"],
            "last_day": signatures["last_day"],
            "snapshots_taken": snapshots["taken"],
            "last_snapshot_at": snapshots["last"],
        }


def days_between(start: datetime, end: datetime) -> list[str]:
    """Day keys from ``start`` up to (not including) ``end``; always at least one."""
    days = []
    cursor = start.date()
    last = (end - timedelta(microseconds=1)).date() if end > start else start.date()
    while cursor <= last:
        days.append(day_key(cursor))
        cursor += timedelta(days=1)
    return days
