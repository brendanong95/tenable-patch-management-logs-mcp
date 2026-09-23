"""Window-versus-baseline comparison over the logs, plus recorded history.

The baseline is the period immediately before the window, read from the same logs, so
nothing has to be accumulated first: any bundle or live folder that reaches back far
enough works. Where the logs have rotated away, baselines recorded earlier by
``record_baseline_snapshot`` fill the gap (see :mod:`history`), and every finding says
which days came from where. Every threshold is a named constant here and is echoed back
in results, and every finding carries its evidence and a ``reasoning`` sentence.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, time, timedelta
from typing import Any

from . import classifier, history, timezones
from .analysis import Coverage, build_scope, file_span, scan, select_files, to_event
from .classifier import event_view, iso, severity_rank
from .errors import InputError
from .logformat import LEVEL_RANK

# --------------------------------------------------------------------------- #
# Tunable thresholds
# --------------------------------------------------------------------------- #

DEFAULT_WINDOW = "24h"
DEFAULT_BASELINE_DAYS = 7
MAX_BASELINE_DAYS = 90
#: Window events/day must exceed the baseline rate by this factor to flag a spike.
SPIKE_MULTIPLIER = 3.0
#: Below this many events in the window a spike is noise.
SPIKE_MIN_WINDOW_EVENTS = 10
#: A new ERROR signature with at least this many events is rated high.
NEW_SIGNATURE_HIGH_COUNT = 10
#: Below this share of the baseline period covered by logs, "new" findings are low confidence.
MIN_BASELINE_COVERAGE_PCT = 50.0
#: This many service starts inside the window is flagged.
RESTART_MIN_STARTS = 3
#: A log needs this many baseline entries before going quiet is notable.
SILENT_LOG_MIN_BASELINE_EVENTS = 50
MAX_FINDINGS = 50

SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
_SEVERITY_ORDER = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 2}

FINDING_NEW_SIGNATURE = "new_error_signature"
FINDING_SPIKE = "error_spike"
FINDING_RESTARTS = "service_restarts"
FINDING_SILENT_LOG = "log_went_quiet"


DEFAULT_SNAPSHOT_WINDOW = "30d"


def _signature_key(event: Any) -> tuple[str, str, str]:
    """One key per issue: wording variants of a known issue collapse into one row."""
    if event.known is not None:
        return (event.device, "-", f"known:{event.known.id}")
    return (event.device, event.entry.component or "-", event.signature)


def thresholds_snapshot() -> dict[str, Any]:
    return {
        "spike_multiplier": SPIKE_MULTIPLIER,
        "spike_min_window_events": SPIKE_MIN_WINDOW_EVENTS,
        "new_signature_high_count": NEW_SIGNATURE_HIGH_COUNT,
        "min_baseline_coverage_pct": MIN_BASELINE_COVERAGE_PCT,
        "restart_min_starts": RESTART_MIN_STARTS,
        "silent_log_min_baseline_events": SILENT_LOG_MIN_BASELINE_EVENTS,
    }


def _coverage_pct(earliest: datetime | None, baseline_start: datetime, baseline_end: datetime) -> float:
    total = (baseline_end - baseline_start).total_seconds()
    if earliest is None or total <= 0:
        return 0.0
    if earliest <= baseline_start:
        return 100.0
    covered = (baseline_end - earliest).total_seconds()
    return round(max(0.0, min(100.0, covered / total * 100)), 1)


def detect_log_anomalies(
    registry: Any,
    *,
    source: str | None = None,
    since: str | None = DEFAULT_WINDOW,
    until: str | None = None,
    anchor: str | None = None,
    baseline_days: int = DEFAULT_BASELINE_DAYS,
    device: str | None = None,
    role: str | None = None,
    use_history: bool = True,
) -> dict[str, Any]:
    try:
        baseline_days = max(1, min(MAX_BASELINE_DAYS, int(baseline_days)))
    except (TypeError, ValueError) as exc:
        raise InputError("baseline_days must be a whole number of days.") from exc
    sources, files = select_files(registry, source=source, device=device, role=role)
    window = build_scope(sources, files, since=since or DEFAULT_WINDOW, until=until, anchor=anchor)
    if window.start is None:
        raise InputError("since is required.")
    end = window.end or window.anchor or max(
        (file_span(f).last for f in files if file_span(f).last is not None), default=None
    )
    if end is None:
        raise InputError("No timestamps were found in the selected logs.")
    baseline_start = window.start - timedelta(days=baseline_days)
    scope = build_scope(sources, files, since=baseline_start, until=end)

    coverage = Coverage()
    signatures: dict[tuple[str, str, str], dict[str, Any]] = defaultdict(
        lambda: {"baseline": 0, "window": 0, "first": None, "last": None, "event": None, "severity": "WARN",
                 "logs": set()}
    )
    log_counts: dict[tuple[str, str], Counter] = defaultdict(Counter)
    device_window_events: Counter = Counter()
    starts: dict[str, set[tuple[datetime, str]]] = defaultdict(set)
    seen: set[tuple[Any, ...]] = set()

    for log_file, entry in scan(scope, coverage):
        stamp = entry.timestamp
        if stamp is None:
            continue
        period = "window" if stamp >= window.start else "baseline"
        log_counts[(log_file.device, log_file.display_name)][period] += 1
        if period == "window":
            device_window_events[log_file.device] += 1
            version = classifier.extract_version(entry)
            if version:
                starts[log_file.device].add((stamp, version))
        severity, _ = classifier.effective_severity(entry)
        if severity_rank(severity) < LEVEL_RANK["WARN"]:
            continue
        event = to_event(log_file, entry)
        if event.is_noise:
            continue
        # Wording variants of one known issue are a single finding.
        record = signatures[_signature_key(event)]
        record["logs"].add(log_file.display_name)
        key = event.dedupe_key()
        if key in seen:
            continue
        seen.add(key)
        record[period] += 1
        if period == "window":
            if record["first"] is None or stamp < record["first"]:
                record["first"] = stamp
            if record["last"] is None or stamp >= record["last"]:
                record["last"] = stamp
                record["event"] = event
            if severity_rank(event.severity) > severity_rank(record["severity"]):
                record["severity"] = event.severity

    # How far back each device's logs, and each log on a device, actually reach.
    earliest_device: dict[str, datetime | None] = {}
    earliest_log: dict[tuple[str, str], datetime | None] = {}
    for log_file in files:
        first = file_span(log_file).first
        for table, key in ((earliest_device, log_file.device), (earliest_log, (log_file.device, log_file.display_name))):
            current = table.get(key)
            if first is not None and (current is None or first < current):
                table[key] = first
            else:
                table.setdefault(key, current)
    baseline_coverage = {
        dev: _coverage_pct(first, baseline_start, window.start) for dev, first in earliest_device.items()
    }
    window_days = max((end - window.start).total_seconds() / 86400, 1 / 24)

    # Days the logs no longer reach can still be covered by earlier snapshots. Each
    # device is asked only for the days its own logs are missing, so nothing is counted
    # twice, and the day the window starts in is skipped when it holds both periods.
    store = history.BaselineStore(registry.data_dir)
    baseline_day_keys = history.days_between(baseline_start, window.start)
    if baseline_day_keys and window.start.time() != time.min:
        baseline_day_keys = baseline_day_keys[:-1]
    devices_in_scope = sorted({f.device for f in files})
    missing_days = {
        dev: [
            day for day in baseline_day_keys
            if earliest_device.get(dev) is None or day < history.day_key(earliest_device[dev])
        ]
        for dev in devices_in_scope
    }
    recorded = history.RecordedBaseline({}, {}, {}, 0)
    if use_history and baseline_day_keys:
        recorded = store.read(days_by_device=missing_days)
    history_coverage = {
        dev: recorded.coverage_pct(dev, baseline_day_keys) for dev in devices_in_scope
    } if recorded.available else {}
    for key, record in signatures.items():
        found = recorded.counts.get(key)
        if found:
            record["baseline"] += found["count"]
            record["baseline_from_history"] = found["count"]
            record["history_days"] = len(found["days"])
    for (dev, log_name), entries in recorded.log_entries.items():
        log_counts[(dev, log_name)]["baseline"] += entries

    findings: list[dict[str, Any]] = []
    for (dev, component, signature), record in signatures.items():
        if not record["window"] or record["event"] is None:
            continue
        event = record["event"]
        if event.known is not None:
            component, signature = event.entry.component or "-", event.signature
        title = event.known.title if event.known else signature
        is_error = record["severity"] in ("ERROR", "FATAL")
        # A signature is judged against the longest history among the logs it appears in,
        # or the days recorded for the device, whichever reaches further back.
        pct = max(
            (_coverage_pct(earliest_log.get((dev, log)), baseline_start, window.start) for log in record["logs"]),
            default=baseline_coverage.get(dev, 0.0),
        )
        # Recorded days sit before the logs reach, so the two coverages add up.
        pct = min(100.0, round(pct + history_coverage.get(dev, 0.0), 1))
        from_history = record.get("baseline_from_history", 0)
        if record["baseline"] == 0:
            high = is_error and (record["window"] >= NEW_SIGNATURE_HIGH_COUNT or (event.known and event.known.impact == "high"))
            low_confidence = pct < MIN_BASELINE_COVERAGE_PCT
            source_text = "day(s) of logs" if not recorded.available else "day(s) of logs or recorded history"
            reasoning = (
                f"'{title}' appeared {record['window']} time(s) on {dev} between {iso(record['first'])} and "
                f"{iso(record['last'])}, and not once in the preceding {baseline_days} {source_text}"
            )
            reasoning += (
                f", but the logs only cover {pct}% of that period, so it may simply predate them."
                if low_confidence
                else "."
            )
            findings.append(
                _finding(
                    FINDING_NEW_SIGNATURE,
                    SEVERITY_HIGH if high else (SEVERITY_MEDIUM if is_error else SEVERITY_LOW),
                    dev, component, signature, event, reasoning,
                    {"window_count": record["window"], "baseline_count": 0, "baseline_coverage_pct": pct,
                     "baseline_days_from_history": len(recorded.days_by_device.get(dev, ())),
                     "low_confidence": low_confidence},
                    {"baseline_days": baseline_days},
                )
            )
            continue
        effective_days = baseline_days * pct / 100
        if effective_days <= 0 or record["window"] < SPIKE_MIN_WINDOW_EVENTS:
            continue
        window_rate = record["window"] / window_days
        baseline_rate = record["baseline"] / effective_days
        ratio = window_rate / baseline_rate
        if ratio < SPIKE_MULTIPLIER:
            continue
        findings.append(
            _finding(
                FINDING_SPIKE,
                SEVERITY_HIGH if is_error and ratio >= SPIKE_MULTIPLIER * 2 else SEVERITY_MEDIUM,
                dev, component, signature, event,
                f"'{title}' ran at {round(window_rate, 1)}/day on {dev} in the window versus "
                f"{round(baseline_rate, 1)}/day over the baseline - {round(ratio, 1)}x, above the "
                f"{SPIKE_MULTIPLIER}x threshold.",
                {"window_count": record["window"], "baseline_count": record["baseline"],
                 "baseline_count_from_history": from_history,
                 "window_per_day": round(window_rate, 2), "baseline_per_day": round(baseline_rate, 2),
                 "ratio": round(ratio, 2), "baseline_coverage_pct": pct},
                {"spike_multiplier": SPIKE_MULTIPLIER, "spike_min_window_events": SPIKE_MIN_WINDOW_EVENTS},
            )
        )

    for dev, items in starts.items():
        if len(items) < RESTART_MIN_STARTS:
            continue
        ordered = sorted(items)
        findings.append(
            {
                "type": FINDING_RESTARTS,
                "severity": SEVERITY_HIGH if len(ordered) >= RESTART_MIN_STARTS * 2 else SEVERITY_MEDIUM,
                "device": dev,
                "title": "Service started repeatedly",
                "reasoning": f"The TPM service on {dev} started {len(ordered)} times in the window "
                             f"(threshold {RESTART_MIN_STARTS}). Use diagnose service_health for the errors "
                             "before each start.",
                "evidence": {"starts": [{"time": iso(t), "version": v} for t, v in ordered[-20:]]},
                "threshold": {"restart_min_starts": RESTART_MIN_STARTS},
            }
        )

    for (dev, log_name), counts in log_counts.items():
        if counts["baseline"] >= SILENT_LOG_MIN_BASELINE_EVENTS and counts["window"] == 0 and device_window_events[dev]:
            findings.append(
                {
                    "type": FINDING_SILENT_LOG,
                    "severity": SEVERITY_LOW,
                    "device": dev,
                    "title": f"{log_name} went quiet",
                    "reasoning": f"{log_name} on {dev} had {counts['baseline']} entries in the baseline but none in "
                                 "the window, while other logs on the device kept writing. The component may have "
                                 "stopped, or its log may have been reconfigured.",
                    "evidence": {"baseline_entries": counts["baseline"], "window_entries": 0},
                    "threshold": {"silent_log_min_baseline_events": SILENT_LOG_MIN_BASELINE_EVENTS},
                }
            )

    findings.sort(key=lambda f: (_SEVERITY_ORDER[f["severity"]], f["type"], f.get("device") or ""))
    shown = findings[:MAX_FINDINGS]
    known = {}
    for finding in shown:
        issue = finding.pop("_known", None)
        if issue is not None:
            known[issue.id] = issue.to_dict()
    for finding in findings[MAX_FINDINGS:]:
        finding.pop("_known", None)
    return {
        "ok": True,
        "window": {**window.window_dict(), "to": iso(end)},
        "baseline_window": {"from": iso(baseline_start), "to": iso(window.start), "days": baseline_days},
        "baseline_coverage_pct_by_device": baseline_coverage,
        "baseline_history": {
            **store.stats(),  # first: the note below is about this run, not about the store
            "used": bool(use_history and recorded.available),
            "baseline_days": len(baseline_day_keys),
            "days_missing_from_logs": {dev: len(days) for dev, days in missing_days.items() if days},
            "days_supplied_by_history": recorded.days,
            "coverage_pct_by_device": history_coverage,
            "note": _history_note(use_history, missing_days, recorded, store),
        },
        "finding_count": len(findings),
        "findings_by_severity": dict(Counter(f["severity"] for f in findings)),
        "findings_by_type": dict(Counter(f["type"] for f in findings)),
        "thresholds": thresholds_snapshot(),
        "findings": shown,
        "findings_not_shown": max(0, len(findings) - MAX_FINDINGS),
        "known_issues": known,
        "coverage": coverage.to_dict(),
        "timestamps_note": timezones.timestamp_note(files),
    }


def _history_note(
    use_history: bool,
    missing_days: dict[str, list[str]],
    recorded: history.RecordedBaseline,
    store: history.BaselineStore,
) -> str:
    """Say plainly whether recorded days were needed, used, or missing."""
    missing = {dev: days for dev, days in missing_days.items() if days}
    if not use_history:
        return "Recorded baselines were not used (use_history=false)."
    if not missing:
        return "The logs cover the whole baseline period, so no recorded days were needed."
    devices = ", ".join(sorted(missing)[:10])
    if recorded.available:
        return (
            f"The logs do not reach the start of the baseline for {devices}; "
            f"{recorded.days} day(s) came from earlier snapshots in {store.path.name}."
        )
    return (
        f"The logs do not reach the start of the baseline for {devices} and nothing is recorded for those days. "
        "Call record_baseline_snapshot now so the next run has them, and treat new-signature findings with "
        "low_confidence as unproven until then."
    )


def record_baseline_snapshot(
    registry: Any,
    *,
    source: str | None = None,
    since: str | None = DEFAULT_SNAPSHOT_WINDOW,
    until: str | None = None,
    anchor: str | None = None,
    device: str | None = None,
    role: str | None = None,
) -> dict[str, Any]:
    """Write the daily counts in the window to the store, so they outlive log rotation."""
    sources, files = select_files(registry, source=source, device=device, role=role)
    scope = build_scope(sources, files, since=since or DEFAULT_SNAPSHOT_WINDOW, until=until, anchor=anchor)
    coverage = Coverage()
    signature_rows: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    log_rows: Counter = Counter()
    seen: set[tuple[Any, ...]] = set()
    events = 0

    for log_file, entry in scan(scope, coverage):
        stamp = entry.timestamp
        if stamp is None:
            continue
        day = history.day_key(stamp)
        log_rows[(log_file.device, log_file.display_name, day)] += 1
        severity, _ = classifier.effective_severity(entry)
        if severity_rank(severity) < LEVEL_RANK["WARN"]:
            continue
        event = to_event(log_file, entry)
        if event.is_noise:
            continue
        key = event.dedupe_key()
        if key in seen:
            continue
        seen.add(key)
        events += 1
        dev, component, signature = _signature_key(event)
        row = signature_rows.setdefault(
            (dev, component, signature, day),
            {"device": dev, "component": component, "signature": signature, "day": day,
             "known_id": event.known.id if event.known else None, "severity": event.severity,
             "count": 0, "first_seen": None, "last_seen": None},
        )
        row["count"] += 1
        stamp_text = iso(stamp)
        if row["first_seen"] is None or stamp_text < row["first_seen"]:
            row["first_seen"] = stamp_text
        if row["last_seen"] is None or stamp_text > row["last_seen"]:
            row["last_seen"] = stamp_text
        if severity_rank(event.severity) > severity_rank(row["severity"]):
            row["severity"] = event.severity

    devices = sorted({f.device for f in files})
    store = history.BaselineStore(registry.data_dir)
    written = store.record(
        signature_rows=signature_rows.values(),
        log_rows=[{"device": dev, "log": log, "day": day, "entries": count}
                  for (dev, log, day), count in log_rows.items()],
        sources=", ".join(source.name for source in sources),
        devices=", ".join(devices),
        window_from=iso(scope.start),
        window_to=iso(scope.end or scope.anchor),
        events=events,
    )
    days = sorted({row["day"] for row in signature_rows.values()} | {day for _, _, day in log_rows})
    return {
        "ok": True,
        "message": (
            f"Recorded {len(signature_rows)} signature-day row(s) and {len(log_rows)} log-day row(s) across "
            f"{len(days)} day(s) for {len(devices)} device(s)."
        ),
        "window": scope.window_dict(),
        "devices": devices,
        "days": {"count": len(days), "first": days[0] if days else None, "last": days[-1] if days else None},
        "events_recorded": events,
        **written,
        "store_state": store.stats(),
        "coverage": coverage.to_dict(),
        "timestamps_note": timezones.timestamp_note(files),
        "next_step": (
            "Call detect_log_anomalies as usual: recorded days fill in what the logs no longer reach. Run this "
            "again after each collection, or on a schedule against a live log folder."
        ),
        "privacy_note": (
            "Only device names, components, normalised and redacted signatures, days and counts are stored, in "
            f"{written['store']}. Delete that file to remove the history."
        ),
    }


def _finding(
    finding_type: str,
    severity: str,
    device: str,
    component: str,
    signature: str,
    event: classifier.Event,
    reasoning: str,
    evidence: dict[str, Any],
    threshold: dict[str, Any],
) -> dict[str, Any]:
    return {
        "type": finding_type,
        "severity": severity,
        "device": device,
        "component": None if component == "-" else component,
        "title": event.known.title if event.known else signature,
        "signature": signature,
        "known_issue": event.known.id if event.known else None,
        "reasoning": reasoning,
        "evidence": evidence,
        "threshold": threshold,
        "latest_example": event_view(event, message_chars=500, detail_lines=2, detail_chars=200, include_codes=False),
        "_known": event.known,
    }
