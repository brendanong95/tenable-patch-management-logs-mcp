"""The log digging: scope resolution, bounded scanning, and every tool's rollup.

All functions return plain dicts. Counting, grouping, de-duplication across files
(TPM writes the same event to adaptiva.log, a component log and adaptiva.err) and
threshold comparisons happen here, so tools hand back finished results.

Files are read newest first, so anything that tracks "first" or "last" compares
timestamps instead of relying on reading order.
"""

from __future__ import annotations

import fnmatch
import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Iterator

from . import classifier, customknowledge, history, timezones
from .classifier import Event, classify, event_view, iso, redact, severity_rank
from .error_codes import decode_any
from .errors import InputError
from .knowledge import (
    FEATURE_UPDATE_MIN_FREE_BYTES,
    IMPACT_ORDER,
    KNOWN_ISSUES,
    KNOWN_ISSUES_BY_ID,
    LOG_ACQUISITION,
    LOG_CATALOG,
    PLAYBOOKS,
    VERSION_ADVISORIES,
    Playbook,
)
from .logformat import LAYOUT_PLAIN, LEVEL_RANK, LEVELS, LogEntry, iter_entries, sniff_layout, time_span
from .sources import DEPLOYMENT_ONPREM, ROLE_CLIENT, ROLE_SERVER, ROLES, LogFile, Source, SourceRegistry, logical_name

# --------------------------------------------------------------------------- #
# Tunable limits (echoed back in results)
# --------------------------------------------------------------------------- #

#: Bytes of log read per tool call; newest files are read first, so a cut drops the oldest.
MAX_BYTES_PER_CALL = 1024**3
MAX_FILES_PER_CALL = 5_000
#: A file's entries are assumed roughly chronological; reading stops this far past the window end.
OUT_OF_ORDER_SLACK = timedelta(minutes=5)
DEFAULT_SUMMARY_WINDOW = "7d"
DEFAULT_TIMELINE_WINDOW = "60m"
MAX_ISSUES = 100
MAX_SEARCH_RESULTS = 200
MAX_SEARCH_COLLECT = 10_000
MAX_CONTEXT_ENTRIES = 5
MAX_PATTERN_CHARS = 500
MAX_TIMELINE_ROWS = 1_000
MAX_TIMELINE_COLLECT = 100_000
MAX_LISTED_FILES = 1_000
#: What relative windows (24h, 7d) count back from.
ANCHOR_NEWEST = "newest_entry"
ANCHOR_NOW = "now"
ANCHOR_EXPLICIT = "explicit"
#: A device whose newest entry is this far behind the anchor is called out in results,
#: or this fraction of the window length if that is longer.
ANCHOR_LAG_MIN = timedelta(hours=1)
ANCHOR_LAG_WINDOW_FRACTION = 0.5
MAX_LAGGING_DEVICES = 10
#: compare_devices: a signature counts as "much more frequent" at this ratio and count.
COMPARE_RATIO = 3.0
COMPARE_MIN_EVENTS = 5
#: service_health: this many starts within RESTART_LOOP_WINDOW is a restart loop.
RESTART_LOOP_STARTS = 3
RESTART_LOOP_WINDOW = timedelta(hours=1)
#: Characters of an example message and detail line in grouped output.
EXAMPLE_MESSAGE_CHARS = 700
EXAMPLE_DETAIL_CHARS = 220


def limits_snapshot() -> dict[str, Any]:
    return {
        "max_mb_read_per_call": MAX_BYTES_PER_CALL // 1024**2,
        "max_files_per_call": MAX_FILES_PER_CALL,
        "max_search_results": MAX_SEARCH_RESULTS,
        "max_timeline_rows": MAX_TIMELINE_ROWS,
    }


# --------------------------------------------------------------------------- #
# File spans (cached)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class FileSpan:
    layout: str
    first: datetime | None
    last: datetime | None


_SPAN_CACHE: dict[tuple[str, int, float, str], FileSpan] = {}
_SPAN_CACHE_MAX = 20_000


def file_span(log_file: LogFile) -> FileSpan:
    # The zone conversion is part of the key: the same file can be read in two zones.
    key = (str(log_file.path), log_file.size, log_file.mtime, log_file.shift.key)
    cached = _SPAN_CACHE.get(key)
    if cached is not None:
        return cached
    layout = sniff_layout(log_file.path)
    first, last = time_span(log_file.path, layout, log_file.shift)
    span = FileSpan(layout, first, last)
    if len(_SPAN_CACHE) >= _SPAN_CACHE_MAX:
        _SPAN_CACHE.clear()
    _SPAN_CACHE[key] = span
    return span


# --------------------------------------------------------------------------- #
# Arguments
# --------------------------------------------------------------------------- #

_RELATIVE = re.compile(
    r"^\s*(\d+(?:\.\d+)?)\s*(m|min|mins|minutes?|h|hr|hrs|hours?|d|days?|w|wks?|weeks?)\s*$", re.IGNORECASE
)


_ANCHOR_NEWEST_WORDS = frozenset({"", "newest", "newest_entry", "newest-entry", "log", "logs", "auto", "default"})
_ANCHOR_NOW_WORDS = frozenset({"now", "clock", "wall_clock", "wall-clock", "today"})


def parse_anchor_arg(
    anchor: str | datetime | None, files: list[LogFile]
) -> tuple[str, datetime | None]:
    """Which clock relative windows count back from: the logs, this machine, or a time.

    Returns ``(mode, fixed_time)``; ``fixed_time`` is ``None`` for the newest-entry mode,
    where the time is only known once the file spans have been read.
    """
    if anchor is None:
        return ANCHOR_NEWEST, None
    if isinstance(anchor, datetime):
        return ANCHOR_EXPLICIT, anchor.replace(tzinfo=None)
    text = str(anchor).strip()
    lowered = text.lower()
    if lowered in _ANCHOR_NEWEST_WORDS:
        return ANCHOR_NEWEST, None
    if lowered in _ANCHOR_NOW_WORDS:
        # "now" means now where the results are read, so use the display zone.
        return ANCHOR_NOW, timezones.now_in_display(files).replace(microsecond=0)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InputError(
            f"anchor='{text}' is not a valid anchor.",
            remediation="Use 'newest' (the newest entry in the selected logs, the default), 'now' (this "
                        "machine's clock), or an ISO time such as 2026-09-17T08:00.",
        ) from exc
    return ANCHOR_EXPLICIT, parsed.replace(tzinfo=None)


def parse_time_arg(
    value: str | datetime | None, anchor: Callable[[], datetime | None], name: str
) -> tuple[datetime | None, bool]:
    """Parse an absolute ISO time or a relative span counted back from the anchor."""
    if isinstance(value, datetime):
        return value.replace(tzinfo=None), False
    if value is None or not str(value).strip():
        return None, False
    text = str(value).strip()
    relative = _RELATIVE.match(text)
    if relative:
        amount = float(relative.group(1))
        unit = relative.group(2).lower()[0]
        delta = {
            "m": timedelta(minutes=amount),
            "h": timedelta(hours=amount),
            "d": timedelta(days=amount),
            "w": timedelta(weeks=amount),
        }[unit]
        base = anchor()
        if base is None:
            raise InputError(
                f"{name}='{text}' is relative, but no timestamps were found in the selected logs to count back from.",
                remediation="Use an absolute time such as 2026-09-17T08:00, or anchor='now' to count back from "
                            "this machine's clock.",
            )
        return base - delta, True
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InputError(
            f"{name}='{text}' is not a valid time.",
            remediation="Use ISO-8601 (2026-09-17 or 2026-09-17T08:00) or a relative span such as 90m, 24h, 7d "
                        "or 2w, counted back from the newest log entry.",
        ) from exc
    return parsed.replace(tzinfo=None), False


def _severity_arg(value: str | None, name: str = "min_severity") -> int:
    level = (value or "INFO").strip().upper()
    level = {"WARNING": "WARN", "ERR": "ERROR"}.get(level, level)
    if level not in LEVEL_RANK:
        raise InputError(f"{name} must be one of {', '.join(LEVELS)} (got '{value}').")
    return LEVEL_RANK[level]


def _clamp(value: Any, low: int, high: int, name: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise InputError(f"{name} must be a whole number (got '{value}').") from exc
    return max(low, min(high, number))


def _as_list(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []
    items = value if isinstance(value, list) else re.split(r"[,;]", str(value))
    return [str(item).strip() for item in items if item and str(item).strip()]


def _track(record: dict[str, Any], stamp: datetime | None) -> bool:
    """Maintain ``first``/``last`` on ``record``; True when ``stamp`` is the newest so far."""
    if stamp is None:
        return False
    if record.get("first") is None or stamp < record["first"]:
        record["first"] = stamp
    if record.get("last") is None or stamp >= record["last"]:
        record["last"] = stamp
        return True
    return False


# --------------------------------------------------------------------------- #
# Scope and scanning
# --------------------------------------------------------------------------- #


@dataclass
class Scope:
    sources: list[Source]
    files: list[LogFile]
    start: datetime | None = None
    end: datetime | None = None
    anchor: datetime | None = None
    relative: bool = False
    anchor_mode: str = ANCHOR_NEWEST

    @property
    def windowed(self) -> bool:
        return self.start is not None or self.end is not None

    def window_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "from": iso(self.start),
            "to": iso(self.end) if self.end is not None else iso(self.anchor),
            "to_is_newest_entry": self.end is None and self.anchor_mode == ANCHOR_NEWEST,
            "relative_to_newest_entry": (
                iso(self.anchor) if self.relative and self.anchor_mode == ANCHOR_NEWEST else None
            ),
            "anchor": {"mode": self.anchor_mode, "time": iso(self.anchor)},
        }
        behind = self.devices_behind_anchor()
        if behind:
            data["devices_behind_anchor"] = behind
            data["anchor_note"] = (
                f"These devices' logs end before the window was measured from ({iso(self.anchor)}), so the "
                "window covers less of their history - or none of it. Filter by device or source, or pass "
                "an explicit since/until, to compare like with like."
            )
        return data

    def devices_behind_anchor(self) -> list[dict[str, Any]]:
        """Devices whose newest entry sits well behind the anchor a relative window used."""
        if self.start is None or self.anchor is None:
            return []
        if not self.relative and self.anchor_mode == ANCHOR_NEWEST:
            return []  # absolute window on the default anchor: nothing was measured from it
        threshold = max(ANCHOR_LAG_MIN, (self.anchor - self.start) * ANCHOR_LAG_WINDOW_FRACTION)
        newest: dict[str, datetime] = {}
        for log_file in self.files:
            last = file_span(log_file).last
            if last is None:
                continue
            if log_file.device not in newest or last > newest[log_file.device]:
                newest[log_file.device] = last
        behind = [
            {
                "device": device,
                "last_entry": iso(last),
                "hours_behind_anchor": round((self.anchor - last).total_seconds() / 3600, 1),
            }
            for device, last in newest.items()
            if self.anchor - last > threshold
        ]
        behind.sort(key=lambda row: -row["hours_behind_anchor"])
        return behind[:MAX_LAGGING_DEVICES]

    def summary(self) -> dict[str, Any]:
        return {
            "sources": [source.name for source in self.sources],
            "devices": sorted({f.device for f in self.files}),
            "roles": sorted({f.role for f in self.files}),
            "files_selected": len(self.files),
        }


def _file_matches(log_file: LogFile, pattern: str) -> bool:
    rel = log_file.rel.replace("\\", "/").lower()
    return any(
        fnmatch.fnmatch(candidate, pattern)
        for candidate in (log_file.log_key, log_file.display_name.lower(), log_file.path.name.lower(), rel)
    )


def select_files(
    registry: SourceRegistry,
    *,
    source: str | None = None,
    device: str | None = None,
    role: str | None = None,
    files: str | list[str] | None = None,
) -> tuple[list[Source], list[LogFile]]:
    sources = registry.select(source)
    all_files = [log_file for src in sources for log_file in registry.files(src)]
    if not all_files:
        raise InputError(
            "The selected sources contain no log files.",
            remediation="Check the paths with check_log_sources. " + LOG_ACQUISITION["client"],
        )
    selected = all_files
    if role:
        wanted_role = role.strip().lower()
        if wanted_role not in ROLES:
            raise InputError(f"role must be one of {', '.join(ROLES)} (got '{role}').")
        selected = [f for f in selected if f.role == wanted_role]
    if device:
        wanted = device.strip().lower()
        exact = [f for f in selected if f.device.lower() == wanted]
        selected = exact or [f for f in selected if wanted in f.device.lower()]
    patterns = [pattern.lower() for pattern in _as_list(files)]
    if patterns:
        selected = [f for f in selected if any(_file_matches(f, pattern) for pattern in patterns)]
    if not selected:
        devices = sorted({f.device for f in all_files})
        roles = sorted({f.role for f in all_files})
        raise InputError(
            "No log files match the filters.",
            remediation=f"Devices available: {', '.join(devices[:30])}. Roles available: {', '.join(roles)}. "
                        "Use list_log_files to see log names.",
        )
    selected.sort(key=lambda f: f.mtime, reverse=True)
    return sources, selected


def build_scope(
    sources: list[Source],
    files: list[LogFile],
    *,
    since: str | datetime | None = None,
    until: str | datetime | None = None,
    anchor: str | datetime | None = None,
) -> Scope:
    mode, fixed = parse_anchor_arg(anchor, files)
    cache: dict[str, datetime | None] = {}

    def anchor_time() -> datetime | None:
        if "value" not in cache:
            if fixed is not None:
                cache["value"] = fixed
            else:
                lasts = [file_span(f).last for f in files]
                cache["value"] = max((stamp for stamp in lasts if stamp is not None), default=None)
        return cache["value"]

    start, relative_start = parse_time_arg(since, anchor_time, "since")
    end, relative_end = parse_time_arg(until, anchor_time, "until")
    if start is not None and end is not None and end < start:
        raise InputError("until is earlier than since.")
    return Scope(
        sources=sources,
        files=files,
        start=start,
        end=end,
        anchor=anchor_time(),
        relative=relative_start or relative_end,
        anchor_mode=mode,
    )


def resolve_scope(
    registry: SourceRegistry,
    *,
    source: str | None = None,
    device: str | None = None,
    role: str | None = None,
    files: str | list[str] | None = None,
    since: str | datetime | None = None,
    until: str | datetime | None = None,
    anchor: str | datetime | None = None,
) -> Scope:
    sources, selected = select_files(registry, source=source, device=device, role=role, files=files)
    return build_scope(sources, selected, since=since, until=until, anchor=anchor)


@dataclass
class Coverage:
    files_selected: int = 0
    files_read: int = 0
    files_outside_window: int = 0
    files_not_read_size_limit: list[str] = field(default_factory=list)
    read_errors: list[str] = field(default_factory=list)
    bytes_read: int = 0
    entries_parsed: int = 0
    untimed_entries_skipped: int = 0
    layouts: Counter = field(default_factory=Counter)
    unrecognised_format_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "files_selected": self.files_selected,
            "files_read": self.files_read,
            "files_outside_window": self.files_outside_window,
            "mb_read": round(self.bytes_read / 1024**2, 1),
            "entries_parsed": self.entries_parsed,
            "layouts": dict(self.layouts),
            "truncated": bool(self.files_not_read_size_limit),
        }
        if self.files_not_read_size_limit:
            data["files_not_read"] = self.files_not_read_size_limit[:20]
            data["truncation_note"] = (
                f"Stopped after {MAX_BYTES_PER_CALL // 1024**2} MB / {MAX_FILES_PER_CALL} files; "
                f"{len(self.files_not_read_size_limit)} older file(s) were not read. Narrow since/until, "
                "device or files to cover them."
            )
        if self.untimed_entries_skipped:
            data["untimed_entries_skipped"] = self.untimed_entries_skipped
            data["untimed_note"] = (
                "Entries without a timestamp cannot be placed in a time window and were skipped; call without "
                "since/until to include them."
            )
        if self.unrecognised_format_files:
            data["unrecognised_format_files"] = self.unrecognised_format_files[:20]
            data["format_note"] = (
                "No known line layout was recognised in these files, so every line was treated as its own "
                "entry without a timestamp."
            )
        if self.read_errors:
            data["read_errors"] = self.read_errors[:10]
        return data


def scan(scope: Scope, coverage: Coverage) -> Iterator[tuple[LogFile, LogEntry]]:
    """Yield in-window entries from every selected file, newest files first."""
    coverage.files_selected = len(scope.files)
    for log_file in scope.files:
        over_budget = coverage.files_read and (
            coverage.bytes_read + log_file.size > MAX_BYTES_PER_CALL or coverage.files_read >= MAX_FILES_PER_CALL
        )
        if over_budget:
            coverage.files_not_read_size_limit.append(log_file.rel)
            continue
        try:
            span = file_span(log_file)
        except OSError as exc:
            coverage.read_errors.append(f"{log_file.rel}: {exc}")
            continue
        if scope.windowed and (
            (scope.start is not None and span.last is not None and span.last < scope.start)
            or (scope.end is not None and span.first is not None and span.first > scope.end)
        ):
            coverage.files_outside_window += 1
            continue
        coverage.files_read += 1
        coverage.bytes_read += log_file.size
        coverage.layouts[span.layout] += 1
        if span.layout == LAYOUT_PLAIN and log_file.size and log_file.log_key.endswith((".log", ".err")):
            coverage.unrecognised_format_files.append(log_file.rel)
        stop_after = scope.end + OUT_OF_ORDER_SLACK if scope.end is not None else None
        try:
            for entry in iter_entries(log_file.path, span.layout, shift=log_file.shift):
                coverage.entries_parsed += 1
                if scope.windowed:
                    stamp = entry.timestamp
                    if stamp is None:
                        coverage.untimed_entries_skipped += 1
                        continue
                    if scope.start is not None and stamp < scope.start:
                        continue
                    if scope.end is not None and stamp > scope.end:
                        if stop_after is not None and stamp > stop_after and not entry.time_inferred:
                            break
                        continue
                yield log_file, entry
        except OSError as exc:
            coverage.read_errors.append(f"{log_file.rel}: {exc}")


def to_event(log_file: LogFile, entry: LogEntry) -> Event:
    return classify(
        entry,
        source=log_file.source,
        device=log_file.device,
        role=log_file.role,
        file=log_file.rel,
        log_name=log_file.display_name,
    )


# --------------------------------------------------------------------------- #
# Issue grouping (shared by summaries, playbooks and comparisons)
# --------------------------------------------------------------------------- #


def _issue_title(issue_id: str) -> str:
    """Title for an issue id from either catalog; ids can come from a site file."""
    issue = classifier.known_issue_by_id(issue_id)
    return issue.title if issue is not None else issue_id


def _known_brief(known: Any) -> dict[str, Any] | None:
    if known is None:
        return None
    return {"id": known.id, "title": known.title, "impact": known.impact, "noise": known.is_noise}


class IssueGroups:
    """Groups classified events by (severity, component, signature), de-duplicated across files."""

    def __init__(self) -> None:
        self.groups: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.seen: set[tuple[Any, ...]] = set()
        self.duplicates = 0
        self.by_severity: Counter = Counter()
        self.by_component: Counter = Counter()
        self.by_log: Counter = Counter()
        self.noise: Counter = Counter()
        self.escalated = 0
        self.events = 0

    def add(self, event: Event, *, include_noise: bool = True) -> bool:
        key = event.dedupe_key()
        group_key = event.group_key()
        if key in self.seen:
            self.duplicates += 1
            group = self.groups.get(group_key)
            if group is not None:
                group["logs"].add(event.log_name)
            return False
        self.seen.add(key)
        self.events += 1
        self.by_severity[event.severity] += 1
        if event.is_noise:
            self.noise[event.known.id] += 1  # type: ignore[union-attr]
            if not include_noise:
                return False
        self.by_component[event.entry.component or "-"] += 1
        self.by_log[event.log_name] += 1
        if event.severity_reason:
            self.escalated += 1
        group = self.groups.get(group_key)
        if group is None:
            group = self.groups[group_key] = {
                "severity": event.severity,
                "component": event.entry.component,
                "signature": event.signature,
                "known": event.known,
                "count": 0,
                "first": None,
                "last": None,
                "devices": Counter(),
                "logs": set(),
                "codes": {},
                "causes": Counter(),
                "escalated": 0,
                "example": event,
            }
        group["count"] += 1
        group["devices"][event.device] += 1
        group["logs"].add(event.log_name)
        if event.severity_reason:
            group["escalated"] += 1
        for code in event.codes:
            if code.kind != "adaptiva":
                group["codes"].setdefault(code.key, code)
        cause = event.root_cause or event.exception
        if cause:
            group["causes"][classifier.cause_signature(cause)] += 1
        if _track(group, event.timestamp):
            group["example"] = event
        return True

    def ranked(self, *, noise_last: bool = True) -> list[dict[str, Any]]:
        def order(group: dict[str, Any]) -> tuple[Any, ...]:
            known = group["known"]
            impact = IMPACT_ORDER.get(known.impact, 1) if known else 1
            noise = 1 if (noise_last and known is not None and known.is_noise) else 0
            return (noise, -severity_rank(group["severity"]), impact, -group["count"])

        return sorted(self.groups.values(), key=order)

    @staticmethod
    def render(group: dict[str, Any], *, detail_lines: int = 4) -> dict[str, Any]:
        rendered = {
            "severity": group["severity"],
            "known_issue": _known_brief(group["known"]),
            "component": group["component"],
            "signature": group["signature"],
            "count": group["count"],
            "first_seen": iso(group["first"]),
            "last_seen": iso(group["last"]),
            "devices": [{"device": d, "count": n} for d, n in group["devices"].most_common(8)],
            "logs": sorted(group["logs"])[:8],
            "codes": [code.to_dict() for code in list(group["codes"].values())[:5]],
            "root_causes": [{"cause": c, "count": n} for c, n in group["causes"].most_common(3)],
            "latest_example": event_view(
                group["example"],
                message_chars=EXAMPLE_MESSAGE_CHARS,
                detail_lines=detail_lines,
                detail_chars=EXAMPLE_DETAIL_CHARS,
                include_codes=False,
            ),
        }
        if group["escalated"]:
            rendered["raised_from_lower_level"] = group["escalated"]
        return rendered

    def rollup_known(self) -> list[dict[str, Any]]:
        """Aggregate groups by known issue; noise last, then impact, severity and count."""
        by_id: dict[str, dict[str, Any]] = {}
        for group in self.groups.values():
            known = group["known"]
            if known is None:
                continue
            item = by_id.setdefault(
                known.id,
                {"known": known, "severity": group["severity"], "count": 0, "first": None, "last": None,
                 "devices": Counter(), "logs": set(), "variants": [], "codes": {}, "causes": Counter(),
                 "example": None},
            )
            item["count"] += group["count"]
            _track(item, group["first"])
            if _track(item, group["last"]) or item["example"] is None:
                item["example"] = group["example"]
            item["devices"].update(group["devices"])
            item["logs"] |= group["logs"]
            item["variants"].append((group["count"], group["component"] or "-", group["signature"]))
            item["codes"].update(group["codes"])
            item["causes"].update(group["causes"])
            if severity_rank(group["severity"]) > severity_rank(item["severity"]):
                item["severity"] = group["severity"]
        return sorted(
            by_id.values(),
            key=lambda i: (i["known"].is_noise, IMPACT_ORDER.get(i["known"].impact, 1), -severity_rank(i["severity"]),
                           -i["count"]),
        )

    @staticmethod
    def render_rollup(item: dict[str, Any], *, detail_lines: int = 3) -> dict[str, Any]:
        return {
            **item["known"].to_dict(),
            "severity": item["severity"],
            "count": item["count"],
            "first_seen": iso(item["first"]),
            "last_seen": iso(item["last"]),
            "devices": [{"device": d, "count": n} for d, n in item["devices"].most_common(8)],
            "logs": sorted(item["logs"])[:8],
            "variants": [
                {"component": None if c == "-" else c, "signature": s, "count": n}
                for n, c, s in sorted(item["variants"], reverse=True)[:3]
            ],
            "codes": [code.to_dict() for code in list(item["codes"].values())[:5]],
            "root_causes": [{"cause": c, "count": n} for c, n in item["causes"].most_common(3)],
            "latest_example": event_view(
                item["example"],
                message_chars=EXAMPLE_MESSAGE_CHARS,
                detail_lines=detail_lines,
                detail_chars=EXAMPLE_DETAIL_CHARS,
                include_codes=False,
            ),
        }

    def noise_summary(self) -> list[dict[str, Any]]:
        return [
            {"known_issue": issue_id, "title": _issue_title(issue_id), "count": count}
            for issue_id, count in self.noise.most_common(10)
        ]


# --------------------------------------------------------------------------- #
# summarize_errors
# --------------------------------------------------------------------------- #


def summarize_errors(
    registry: SourceRegistry,
    *,
    source: str | None = None,
    since: str | None = DEFAULT_SUMMARY_WINDOW,
    until: str | None = None,
    anchor: str | None = None,
    min_severity: str = "WARN",
    device: str | None = None,
    role: str | None = None,
    files: str | list[str] | None = None,
    include_noise: bool = False,
    top: int = 25,
) -> dict[str, Any]:
    floor = _severity_arg(min_severity)
    top = _clamp(top, 1, MAX_ISSUES, "top")
    scope = resolve_scope(registry, source=source, device=device, role=role, files=files, since=since,
                          until=until, anchor=anchor)
    coverage = Coverage()
    groups = IssueGroups()
    for log_file, entry in scan(scope, coverage):
        severity, _ = classifier.effective_severity(entry)
        if severity_rank(severity) < floor:
            continue
        groups.add(to_event(log_file, entry), include_noise=include_noise)
    ranked = groups.ranked()[:top]
    shown_known = {g["known"].id: g["known"] for g in ranked if g["known"] is not None}
    return {
        "ok": True,
        "window": scope.window_dict(),
        "scope": scope.summary(),
        "filters": {"min_severity": min_severity.upper(), "include_noise": include_noise},
        "totals": {
            "events": groups.events,
            "by_severity": dict(groups.by_severity),
            "distinct_issues": len(groups.groups),
            "noise_events": sum(groups.noise.values()),
            "noise_included": include_noise,
            "raised_from_lower_level": groups.escalated,
            "duplicate_lines_in_other_logs": groups.duplicates,
        },
        "issues": [{"rank": index + 1, **IssueGroups.render(group)} for index, group in enumerate(ranked)],
        "issues_not_shown": max(0, len(groups.groups) - top),
        "known_issues": {issue_id: known.to_dict() for issue_id, known in shown_known.items()},
        "noise": groups.noise_summary(),
        "top_components": [{"component": c, "count": n} for c, n in groups.by_component.most_common(10)],
        "top_logs": [{"log": log, "count": n} for log, n in groups.by_log.most_common(10)],
        "coverage": coverage.to_dict(),
        "limits": limits_snapshot(),
        "timestamps_note": timezones.timestamp_note(scope.files),
    }


# --------------------------------------------------------------------------- #
# search_logs
# --------------------------------------------------------------------------- #


def _compact(entry: LogEntry) -> dict[str, Any]:
    return {
        "timestamp": iso(entry.timestamp),
        "level": entry.level,
        "line": entry.line,
        "component": entry.component,
        "message": redact(entry.message)[:300],
    }


def search_logs(
    registry: SourceRegistry,
    pattern: str,
    *,
    regex: bool = False,
    case_sensitive: bool = False,
    source: str | None = None,
    since: str | None = None,
    until: str | None = None,
    anchor: str | None = None,
    min_severity: str | None = None,
    device: str | None = None,
    role: str | None = None,
    files: str | list[str] | None = None,
    component: str | None = None,
    context: int = 0,
    limit: int = 50,
    offset: int = 0,
    order: str = "newest",
) -> dict[str, Any]:
    if not pattern or not str(pattern).strip():
        raise InputError("pattern is required.")
    if len(pattern) > MAX_PATTERN_CHARS:
        raise InputError(f"pattern is longer than {MAX_PATTERN_CHARS} characters.")
    try:
        matcher = re.compile(pattern if regex else re.escape(pattern), 0 if case_sensitive else re.IGNORECASE)
    except re.error as exc:
        raise InputError(
            f"Invalid regular expression: {exc}",
            remediation="Fix the pattern, or pass regex=false for a literal search.",
        ) from exc
    if order not in ("newest", "oldest"):
        raise InputError("order must be 'newest' or 'oldest'.")
    floor = _severity_arg(min_severity) if min_severity else None
    context = _clamp(context, 0, MAX_CONTEXT_ENTRIES, "context")
    limit = _clamp(limit, 1, MAX_SEARCH_RESULTS, "limit")
    offset = _clamp(offset, 0, MAX_SEARCH_COLLECT, "offset")
    wanted_component = component.strip().lower() if component else None

    scope = resolve_scope(registry, source=source, device=device, role=role, files=files, since=since,
                          until=until, anchor=anchor)
    coverage = Coverage()
    records: list[dict[str, Any]] = []
    by_key: dict[tuple[Any, ...], dict[str, Any]] = {}
    total = 0
    capped = False
    current: LogFile | None = None
    before: deque[LogEntry] = deque(maxlen=max(context, 1))
    pending: list[dict[str, Any]] = []

    for log_file, entry in scan(scope, coverage):
        if log_file is not current:
            current = log_file
            before.clear()
            pending = []
        if pending:
            for record in pending:
                record["after"].append(_compact(entry))
            pending = [record for record in pending if len(record["after"]) < context]

        hit = matcher.search(entry.raw) or any(matcher.search(line) for line in entry.detail)
        if hit and wanted_component and (entry.component or "").lower() != wanted_component:
            hit = None
        if hit and floor is not None:
            severity, _ = classifier.effective_severity(entry)
            hit = hit if severity_rank(severity) >= floor else None
        if hit:
            event = to_event(log_file, entry)
            key = event.dedupe_key()
            if key in by_key:
                by_key[key]["also_in"].add(log_file.rel)
            else:
                total += 1
                if len(records) < MAX_SEARCH_COLLECT:
                    record = {
                        "event": event,
                        "before": [_compact(e) for e in before] if context else [],
                        "after": [],
                        "also_in": set(),
                    }
                    records.append(record)
                    by_key[key] = record
                    if context:
                        pending.append(record)
                else:
                    capped = True
        if context:
            before.append(entry)

    records.sort(
        key=lambda r: (r["event"].timestamp or datetime.min, r["event"].file, r["event"].entry.line),
        reverse=(order == "newest"),
    )
    page = records[offset: offset + limit]
    matches = []
    for record in page:
        view = event_view(record["event"], include_thread=True, detail_lines=4)
        if record["also_in"]:
            view["also_in"] = sorted(record["also_in"])[:5]
        if context:
            view["context_before"] = record["before"]
            view["context_after"] = record["after"]
        matches.append(view)
    available = min(total, MAX_SEARCH_COLLECT)
    next_offset = offset + len(matches) if offset + len(matches) < available else None
    return {
        "ok": True,
        "regex": regex,
        "window": scope.window_dict(),
        "scope": scope.summary(),
        "total_matches": total,
        "returned": len(matches),
        "offset": offset,
        "has_more": next_offset is not None,
        "next_offset": next_offset,
        "collection_capped": capped,
        "matches": matches,
        "coverage": coverage.to_dict(),
        "timestamps_note": timezones.timestamp_note(scope.files),
    }


# --------------------------------------------------------------------------- #
# build_timeline
# --------------------------------------------------------------------------- #


def build_timeline(
    registry: SourceRegistry,
    *,
    source: str | None = None,
    since: str | None = None,
    until: str | None = None,
    anchor: str | None = None,
    around: str | None = None,
    minutes_before: int = 15,
    minutes_after: int = 15,
    device: str | None = None,
    role: str | None = None,
    files: str | list[str] | None = None,
    min_severity: str = "INFO",
    keyword: str | None = None,
    include_noise: bool = False,
    collapse_repeats: bool = True,
    limit: int = 200,
) -> dict[str, Any]:
    floor = _severity_arg(min_severity)
    limit = _clamp(limit, 10, MAX_TIMELINE_ROWS, "limit")
    sources, selected = select_files(registry, source=source, device=device, role=role, files=files)
    if around:
        before_minutes = _clamp(minutes_before, 0, 7 * 24 * 60, "minutes_before")
        after_minutes = _clamp(minutes_after, 0, 7 * 24 * 60, "minutes_after")
        probe = build_scope(sources, selected, since=around, anchor=anchor)
        if probe.start is None:
            raise InputError("around is not a valid time.")
        scope = build_scope(
            sources,
            selected,
            since=probe.start - timedelta(minutes=before_minutes),
            until=probe.start + timedelta(minutes=after_minutes),
            anchor=anchor,
        )
        scope.relative = probe.relative
    else:
        scope = build_scope(
            sources, selected, since=since if since or until else DEFAULT_TIMELINE_WINDOW, until=until, anchor=anchor
        )
    needle = keyword.lower() if keyword else None
    coverage = Coverage()
    seen: set[tuple[Any, ...]] = set()
    rows: list[Event] = []
    noise_hidden = 0
    capped = False
    for log_file, entry in scan(scope, coverage):
        if entry.timestamp is None:
            continue
        severity, _ = classifier.effective_severity(entry)
        if severity_rank(severity) < floor:
            continue
        if needle and needle not in entry.text(40).lower():
            continue
        event = to_event(log_file, entry)
        key = event.dedupe_key()
        if key in seen:
            continue
        seen.add(key)
        if event.is_noise and not include_noise:
            noise_hidden += 1
            continue
        if len(rows) >= MAX_TIMELINE_COLLECT:
            capped = True
            break
        rows.append(event)

    rows.sort(key=lambda e: (e.timestamp, e.device, e.file, e.entry.line))
    collapsed: list[dict[str, Any]] = []
    for event in rows:
        previous = collapsed[-1] if collapsed else None
        row_key = (event.device, event.entry.component, event.signature, event.severity)
        if collapse_repeats and previous is not None and previous["_key"] == row_key:
            previous["repeats"] += 1
            previous["until"] = iso(event.timestamp)
            continue
        collapsed.append(
            {
                "_key": row_key,
                "_rank": severity_rank(event.severity),
                "time": iso(event.timestamp),
                "device": event.device,
                "severity": event.severity,
                "log": event.log_name,
                "component": event.entry.component,
                "message": redact(event.entry.message)[:400] or (event.exception or ""),
                "at": f"{event.file}:{event.entry.line}",
                "known_issue": event.known.id if event.known else None,
                "repeats": 1,
            }
        )

    sampled = len(collapsed) > limit
    if sampled:
        important = [row for row in collapsed if row["_rank"] >= LEVEL_RANK["WARN"]]
        others = [row for row in collapsed if row["_rank"] < LEVEL_RANK["WARN"]]
        keep = (
            _evenly(important, limit)
            if len(important) >= limit
            else important + _evenly(others, limit - len(important))
        )
        keep_ids = {id(row) for row in keep}
        collapsed = [row for row in collapsed if id(row) in keep_ids]
    for row in collapsed:
        row.pop("_key", None)
        row.pop("_rank", None)
        if row["repeats"] == 1:
            row.pop("repeats")
        if not row["known_issue"]:
            row.pop("known_issue")
    return {
        "ok": True,
        "window": scope.window_dict(),
        "scope": scope.summary(),
        "events_in_window": len(rows),
        "rows_returned": len(collapsed),
        "sampled": sampled,
        "sampling_note": (
            f"More than {limit} rows: every WARN and above is kept first, the rest are evenly sampled. Narrow the "
            "window, raise min_severity or add a keyword for the full sequence."
            if sampled
            else None
        ),
        "noise_hidden": noise_hidden,
        "collection_capped": capped,
        "rows": collapsed,
        "coverage": coverage.to_dict(),
        "timestamps_note": timezones.timestamp_note(scope.files),
    }


def _evenly(items: list[Any], count: int) -> list[Any]:
    if count <= 0 or not items:
        return []
    if len(items) <= count:
        return list(items)
    step = len(items) / count
    return [items[int(index * step)] for index in range(count)]


# --------------------------------------------------------------------------- #
# diagnose
# --------------------------------------------------------------------------- #

_CATCH_ALL_LOGS = frozenset({"adaptiva.log", "adaptiva.err"})
_CONTENT_ID = re.compile(r"\b(?:Policy_\d+|Product_\d+_(?:Client|Server)(?:\$\d+)*|AdaptivaObject_\d+|Workflow\$\d+)")
_VALIDATOR_LINE = re.compile(r"(?i)\b(passed|failed|not applicable|in progress)\b")
_PRODUCT = re.compile(r"Product: (?P<product>.+?) -- ")


def _playbook_files(files: list[LogFile], playbook: Playbook) -> list[LogFile]:
    """The playbook's own logs plus adaptiva.log / adaptiva.err, for the playbook's roles.

    Several components (for example the server's message retries) only write to the
    catch-all logs, so those are always read and filtered by component and pattern.
    """
    wanted_roles = set(playbook.roles) | {"unknown"}
    return [
        f for f in files
        if (f.role in wanted_roles and (f.log_key in playbook.logs or f.log_key in _CATCH_ALL_LOGS))
        or (f.role == "setup" and f.log_key in playbook.logs)
    ]


class _Diagnosis:
    """Collects the generic parts of a playbook run; playbook handlers add details."""

    def __init__(self, playbook: Playbook, scope: Scope) -> None:
        self.playbook = playbook
        self.scope = scope
        self.findings = IssueGroups()
        self.other = IssueGroups()
        self.details: dict[str, Any] = {}
        self.state: dict[str, Any] = defaultdict(Counter)

    def relevant(self, log_file: LogFile, entry: LogEntry, event: Event | None) -> bool:
        playbook = self.playbook
        if log_file.log_key in playbook.logs and log_file.log_key not in _CATCH_ALL_LOGS:
            return True
        if entry.component and entry.component in playbook.components:
            return True
        if event is not None and event.known is not None and event.known.id in playbook.issue_ids:
            if event.known.confidence != "generic" or playbook.generic_issues_anywhere:
                return True
        return any(pattern.search(entry.message) for pattern in playbook.compiled)


def diagnose(
    registry: SourceRegistry,
    symptom: str,
    *,
    source: str | None = None,
    since: str | None = DEFAULT_SUMMARY_WINDOW,
    until: str | None = None,
    anchor: str | None = None,
    device: str | None = None,
) -> dict[str, Any]:
    key = (symptom or "").strip().lower()
    playbook = PLAYBOOKS.get(key)
    if playbook is None:
        raise InputError(f"Unknown symptom '{symptom}'.", remediation="Use one of: " + ", ".join(PLAYBOOKS) + ".")
    sources, all_files = select_files(registry, source=source, device=device)
    chosen = _playbook_files(all_files, playbook)
    missing = _missing_logs(all_files, playbook, registry, sources)
    if not chosen:
        return {
            "ok": True,
            "symptom": playbook.id,
            "title": playbook.title,
            "verdict": "None of the logs this check needs are in the selected sources.",
            "missing_logs": missing,
            "advice": playbook.advice,
        }
    scope = build_scope(sources, chosen, since=since, until=until, anchor=anchor)
    run = _Diagnosis(playbook, scope)
    handler = _HANDLERS.get(playbook.id)
    coverage = Coverage()
    handled: set[tuple[Any, ...]] = set()
    for log_file, entry in scan(scope, coverage):
        severity, _ = classifier.effective_severity(entry)
        event = to_event(log_file, entry) if severity_rank(severity) >= LEVEL_RANK["WARN"] else None
        if not run.relevant(log_file, entry, event):
            continue
        if event is not None:
            if event.known is not None:
                run.findings.add(event)
            else:
                run.other.add(event)
        if handler is None:
            continue
        # The same event is often written to several logs; hand it to the playbook once.
        dedupe = (
            (log_file.device, entry.timestamp, entry.level, entry.tid, entry.message[:200])
            if entry.timestamp is not None
            else (log_file.device, log_file.rel, entry.line)
        )
        if dedupe not in handled:
            handled.add(dedupe)
            handler(run, log_file, entry, event)

    rolled = run.findings.rollup_known()
    finalize = _FINALIZERS.get(playbook.id)
    verdict = finalize(run, rolled) if finalize else _generic_verdict(run, rolled)
    return {
        "ok": True,
        "symptom": playbook.id,
        "title": playbook.title,
        "summary": playbook.summary,
        "verdict": verdict,
        "window": scope.window_dict(),
        "scope": {**scope.summary(), "logs_read": sorted({f.display_name for f in chosen})[:40]},
        "findings": [IssueGroups.render_rollup(item) for item in rolled[:12]],
        "other_warnings_and_errors": [IssueGroups.render(group, detail_lines=0) for group in run.other.ranked()[:8]],
        "other_groups_not_shown": max(0, len(run.other.groups) - 8),
        "details": run.details,
        "missing_logs": missing,
        "advice": playbook.advice,
        "coverage": coverage.to_dict(),
        "timestamps_note": timezones.timestamp_note(scope.files),
    }


def _missing_logs(
    files: list[LogFile], playbook: Playbook, registry: SourceRegistry, sources: list[Source]
) -> list[dict[str, str]]:
    present_roles = {f.role for f in files}
    present_logs = {f.log_key for f in files}
    missing = []
    deployments = {registry.deployment(src, [f for f in files if f.source == src.name])["value"] for src in sources}
    for role in playbook.roles:
        if role not in present_roles:
            if role == ROLE_SERVER:
                how = (LOG_ACQUISITION["onprem_server"] if deployments == {DEPLOYMENT_ONPREM}
                       else LOG_ACQUISITION["saas_server"])
            else:
                how = LOG_ACQUISITION["client"]
            missing.append({"what": f"{role} logs", "how_to_get_them": how})
    specific = [name for name in playbook.logs if name not in _CATCH_ALL_LOGS]
    if specific and not any(name in present_logs for name in specific) and not missing:
        missing.append(
            {
                "what": "component logs for this check (" + ", ".join(specific[:6]) + ")",
                "how_to_get_them": "Only adaptiva.log / adaptiva.err were available, so this check read those; "
                                   "component logs are in the componentlogs folder next to them. "
                                   + LOG_ACQUISITION["client"],
            }
        )
    return missing


def _significant(rolled: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return [i for i in rolled if not i["known"].is_noise], [i for i in rolled if i["known"].is_noise]


def _generic_verdict(run: _Diagnosis, rolled: list[dict[str, Any]]) -> str:
    significant, noise = _significant(rolled)
    others = run.other.ranked()
    parts = []
    if significant:
        top = significant[0]
        parts.append(
            f"{len(significant)} known issue(s); most significant: {top['known'].title} ({top['count']} event(s), "
            f"last {iso(top['last'])})."
        )
    if others:
        parts.append(
            f"{sum(g['count'] for g in others)} other related warning/error event(s) in {len(others)} group(s)."
        )
    if noise:
        parts.append(f"{sum(i['count'] for i in noise)} known-noise event(s) set aside (no action needed).")
    return " ".join(parts) or "No warnings or errors related to this symptom in the window."


# -- patch_install_failed ---------------------------------------------------------- #


def _handle_patch(run: _Diagnosis, log_file: LogFile, entry: LogEntry, event: Event | None) -> None:
    result = classifier.extract_patch_result(entry)
    if result:
        results = run.details.setdefault("_results", {})
        key = (log_file.device, result["request_id"])
        current = results.get(key)
        newer = current is None or (
            entry.timestamp is not None and (current["_time"] is None or entry.timestamp >= current["_time"])
        )
        if newer:
            result.update({"device": log_file.device, "_time": entry.timestamp, "at": f"{log_file.rel}:{entry.line}"})
            results[key] = result
    if log_file.log_key == "msilogs":
        failures = run.details.setdefault("_msi", {})
        state = failures.setdefault(log_file.rel, {"file": log_file.rel, "device": log_file.device})
        product = _PRODUCT.search(entry.message)
        if product:
            state["product"] = product.group("product")
        if "Return value 3." in entry.message and entry.message.startswith("Action ended"):
            state["failed_action"] = entry.message.split(": ", 1)[-1].split(". Return value")[0]
        for code in classifier.extract_codes(entry.message):
            if code.kind == "exit_code" and "error status" in code.raw.lower():
                state["exit_code"] = code.to_dict()
                state["time"] = iso(entry.timestamp)
    if event is not None:
        for code in event.codes:
            if code.kind in ("exit_code", "hresult") and not code.is_success:
                bucket = run.details.setdefault("_codes", {}).setdefault(
                    code.key, {"code": code.to_dict(), "count": 0, "devices": set(), "first": None, "last": None}
                )
                bucket["count"] += 1
                bucket["devices"].add(log_file.device)
                if _track(bucket, entry.timestamp):
                    bucket["latest_at"] = f"{log_file.rel}:{entry.line}"


def _patch_result_note() -> str:
    """Whether the undocumented PatchDeploymentResult values could be decoded here."""
    mapped = customknowledge.active().deployment_results
    base = ("PatchDeploymentResult status and reason values are shown as logged; Tenable does not document "
            "their meanings, so failure evidence is based on reason codes and exceptions.")
    if not mapped:
        return base + (" Add patch_deployment_results to a site knowledge file to have the values you know "
                       "decoded here.")
    return base + (" Values covered by your site knowledge file are decoded alongside them ("
                   + ", ".join(f"{name}: {len(values)}" for name, values in sorted(mapped.items())) + " mapped).")


def _finish_patch(run: _Diagnosis, rolled: list[dict[str, Any]]) -> str:
    results = list(run.details.pop("_results", {}).values())
    for result in results:
        result["time"] = iso(result.pop("_time"))
    results.sort(key=lambda r: r["time"] or "")
    failed = [r for r in results if r["failure_evidence"]]
    msi = [m for m in run.details.pop("_msi", {}).values() if "exit_code" in m and not m["exit_code"]["success"]]
    codes = sorted(run.details.pop("_codes", {}).values(), key=lambda b: -b["count"])
    run.details.update(
        {
            "deployment_results_seen": len(results),
            "deployment_results_with_failure_evidence": failed[-20:],
            "installer_failures": msi[:20],
            "error_codes": [
                {**{k: v for k, v in b.items() if k not in ("first", "last")}, "devices": sorted(b["devices"])[:10],
                 "first_seen": iso(b["first"]), "last_seen": iso(b["last"])}
                for b in codes[:10]
            ],
            "note": _patch_result_note(),
        }
    )
    significant, _ = _significant(rolled)
    if not failed and not msi and not codes and not significant:
        return "No failed deployment results, installer failures or error codes found in the window."
    parts = []
    if failed:
        devices = sorted({r["device"] for r in failed})
        parts.append(f"{len(failed)} deployment result(s) with failure evidence on {len(devices)} device(s).")
    if msi:
        parts.append(f"{len(msi)} Windows Installer log(s) ended in failure.")
    if codes:
        top = codes[0]["code"]
        parts.append(f"Most common error code: {top['code']} ({top['name'] or 'unknown'}), {codes[0]['count']} time(s).")
    if significant:
        parts.append(f"Known issue: {significant[0]['known'].title}.")
    return " ".join(parts)


# -- client_connectivity ------------------------------------------------------------ #


def _handle_connectivity(run: _Diagnosis, log_file: LogFile, entry: LogEntry, event: Event | None) -> None:
    message = entry.message
    if "HTTP connection disconnected" in message:
        run.state["disconnects"][log_file.device] += 1
    binding = classifier.extract_binding(entry)
    if binding:
        bindings = run.details.setdefault("_bindings", {})
        record = bindings.setdefault(log_file.device, {"url": None})
        if _track(record, entry.timestamp) or record["url"] is None:
            record["url"] = redact(binding)
    retry = classifier.extract_message_retry(entry)
    if retry:
        clients = run.details.setdefault("_retries", {})
        record = clients.setdefault(
            retry["receiver_client_id"],
            {"client_id": retry["receiver_client_id"], "max_retry_count": 0, "messages": set(), "first": None,
             "last": None},
        )
        record["max_retry_count"] = max(record["max_retry_count"], retry["retry_count"])
        record["messages"].add(retry["message"])
        _track(record, entry.timestamp)
    ip = classifier.extract_install_auth_ip(entry)
    if ip:
        rejections = run.details.setdefault("_rejections", {})
        _track(rejections.setdefault(ip, {"ip": ip, "count": 0}), entry.timestamp)
        rejections[ip]["count"] += 1
    validator_logs = ("clientsetupchecks.log", "adaptivaclientvalidator.log", "clientvalidatorresults.txt")
    if log_file.log_key in validator_logs and _VALIDATOR_LINE.search(message):
        run.details.setdefault("_validator", []).append((entry.timestamp or datetime.min, log_file.device, message))


def _finish_connectivity(run: _Diagnosis, rolled: list[dict[str, Any]]) -> str:
    retries = sorted(run.details.pop("_retries", {}).values(), key=lambda r: -r["max_retry_count"])
    rejections = sorted(run.details.pop("_rejections", {}).values(), key=lambda r: -r["count"])
    bindings = run.details.pop("_bindings", {})
    validator = sorted(run.details.pop("_validator", []))[-20:]
    run.details.update(
        {
            "unacknowledged_messages_by_client": [
                {"client_id": r["client_id"], "max_retry_count": r["max_retry_count"],
                 "messages": sorted(r["messages"]), "first_seen": iso(r["first"]), "last_seen": iso(r["last"])}
                for r in retries[:25]
            ],
            "install_auth_rejections": [
                {"ip": r["ip"], "count": r["count"], "last_seen": iso(r["last"])} for r in rejections[:25]
            ],
            "client_server_bindings": {device: r["url"] for device, r in bindings.items()},
            "routine_reconnects_by_device": dict(run.state["disconnects"]),
            "client_validator_lines": [
                {"time": iso(t) if t != datetime.min else None, "device": d, "line": redact(m)[:200]}
                for t, d, m in validator
            ],
        }
    )
    parts = []
    if retries:
        ids = ", ".join(r["client_id"] for r in retries[:8])
        parts.append(
            f"Server is retrying messages to {len(retries)} client(s) that are not acknowledging (client IDs {ids})."
        )
    if rejections:
        parts.append(
            f"{sum(r['count'] for r in rejections)} client registration(s) rejected for missing install "
            f"authentication from {len(rejections)} IP address(es)."
        )
    channel = [i for i in rolled if i["known"].id == "client_server_channel_closed"]
    if channel:
        parts.append(f"Clients lost their connection to the server {channel[0]['count']} time(s).")
    if run.state["disconnects"]:
        total = sum(run.state["disconnects"].values())
        parts.append(f"{total} routine HTTP reconnect message(s) on {len(run.state['disconnects'])} device(s).")
    return " ".join(parts) or _generic_verdict(run, rolled)


# -- vm_integration ----------------------------------------------------------------- #


def _latest(times: dict[str, datetime], name: str, stamp: datetime | None) -> None:
    if stamp is not None and (name not in times or stamp > times[name]):
        times[name] = stamp


#: Updates logged within this long of a "not provided" warning belong to the same run.
_SAME_RUN = timedelta(minutes=5)


def _handle_vm(run: _Diagnosis, log_file: LogFile, entry: LogEntry, event: Event | None) -> None:
    message = entry.message
    counts = run.state["counts"]
    times = run.details.setdefault("_times", {})
    if "Testing validity of access settings" in message:
        counts["key_validation_attempts"] += 1
        _latest(times, "last_key_validation_attempt", entry.timestamp)
    elif "Update for tenable completed successfully" in message:
        counts["updates_completed"] += 1
        _latest(times, "last_update_completed", entry.timestamp)
    elif "Tenable access settings have not been provided yet" in message:
        counts["runs_without_access_settings"] += 1
        _latest(times, "last_run_without_access_settings", entry.timestamp)
    elif "Tenable access settings are not configured for TSC instance" in message:
        counts["security_center_not_configured"] += 1
    detections = classifier.extract_detections(entry)
    if detections:
        run.state["detections"][detections[0]] += detections[1]
    if event is not None and event.known and event.known.id in ("tvm_invalid_credentials", "tvm_keys_not_linked_to_container"):
        _latest(times, "last_key_failure", entry.timestamp)


def _finish_vm(run: _Diagnosis, rolled: list[dict[str, Any]]) -> str:
    counts = run.state["counts"]
    times: dict[str, datetime] = run.details.pop("_times", {})
    run.details.update({name: iso(stamp) for name, stamp in sorted(times.items())})
    run.details["counts"] = dict(counts)
    run.details["vulnerability_detections_processed"] = dict(run.state["detections"])
    failures = [i for i in rolled if i["known"].id in ("tvm_invalid_credentials", "tvm_keys_not_linked_to_container")]
    parts = []
    last_missing = times.get("last_run_without_access_settings")
    last_update = times.get("last_update_completed")
    if last_missing and (not last_update or last_missing >= last_update - _SAME_RUN):
        parts.append(
            "Integration is not configured: the latest vulnerability update runs had no Tenable access settings, "
            "so they 'completed successfully' without importing any data."
        )
    if failures:
        total = sum(i["count"] for i in failures)
        first = min(i["first"] for i in failures if i["first"])
        last = max(i["last"] for i in failures if i["last"])
        parts.append(
            f"API key validation failed {total} time(s) between {iso(first)} and {iso(last)} "
            f"({failures[0]['known'].title})."
        )
    if not parts:
        new = run.state["detections"].get("NEW", 0)
        if counts.get("updates_completed"):
            parts.append(
                f"Integration updates are completing (last {iso(last_update)}); {new} new detection(s) processed."
            )
        else:
            parts.append("No Tenable integration activity found in the window.")
    return " ".join(parts)


# -- feeds ---------------------------------------------------------------------------- #


def _handle_feeds(run: _Diagnosis, log_file: LogFile, entry: LogEntry, event: Event | None) -> None:
    message = entry.message
    counts = run.state["counts"]
    times = run.details.setdefault("_times", {})
    if "[Periodic Feed Check] Started" in message:
        counts["checks_started"] += 1
    elif "[Periodic Feed Check] Feed instruction package received successfully" in message:
        counts["checks_succeeded"] += 1
        _latest(times, "last_successful_check", entry.timestamp)
    elif "No new feeds found" in message or "Server is now up to date" in message:
        counts["up_to_date_results"] += 1
    if event is not None and event.known and event.known.id == "feed_check_failed":
        counts["checks_failed"] += 1
        _latest(times, "last_failed_check", entry.timestamp)
        if entry.timestamp is not None:
            run.state["failures_by_day"][entry.timestamp.date().isoformat()] += 1
        cause = event.root_cause or event.exception or "unknown"
        run.state["failure_causes"][classifier.cause_signature(cause)] += 1


def _finish_feeds(run: _Diagnosis, rolled: list[dict[str, Any]]) -> str:
    counts = run.state["counts"]
    times: dict[str, datetime] = run.details.pop("_times", {})
    last_ok = times.get("last_successful_check")
    last_fail = times.get("last_failed_check")
    run.details.update(
        {
            "last_successful_check": iso(last_ok),
            "last_failed_check": iso(last_fail),
            "counts": dict(counts),
            "failures_by_day": dict(sorted(run.state["failures_by_day"].items())),
            "failure_root_causes": [{"cause": c, "count": n} for c, n in run.state["failure_causes"].most_common(5)],
        }
    )
    if not counts.get("checks_started") and not counts.get("checks_failed"):
        return "No periodic feed checks found in the window (feed checks run on the server; server logs are needed)."
    if last_ok is None:
        return f"No successful feed check in the window; {counts.get('checks_failed', 0)} failure(s), last at {iso(last_fail)}."
    parts = [f"Last successful feed check: {iso(last_ok)}"]
    reference = run.scope.end or run.scope.anchor
    if reference is not None:
        hours = round((reference - last_ok).total_seconds() / 3600, 1)
        parts[-1] += f" ({hours} hour(s) before the newest log entry)."
    else:
        parts[-1] += "."
    failed = counts.get("checks_failed", 0)
    if failed:
        top = run.state["failure_causes"].most_common(1)
        cause = f" Most common cause: {top[0][0]}." if top else ""
        recovered = " Checks have succeeded since the last failure." if last_fail and last_ok > last_fail else ""
        parts.append(
            f"{failed} of {counts.get('checks_started', failed)} check(s) failed in the window, last at "
            f"{iso(last_fail)}.{recovered}{cause}"
        )
    else:
        parts.append("No failed checks in the window.")
    return " ".join(parts)


# -- content_publication --------------------------------------------------------------- #


def _handle_publication(run: _Diagnosis, log_file: LogFile, entry: LogEntry, event: Event | None) -> None:
    if entry.level == "INFO" and "[Bunny Storage APIs :: Upload" in entry.message:
        run.state["counts"]["upload_log_lines"] += 1
    if event is not None and event.known and event.known.id == "cdn_content_publication_failed":
        for content_id in set(_CONTENT_ID.findall(entry.text(10))):
            record = run.details.setdefault("_failed", {}).setdefault(
                content_id, {"content_id": content_id, "failures": 0, "first": None, "last": None}
            )
            record["failures"] += 1
            _track(record, entry.timestamp)


def _finish_publication(run: _Diagnosis, rolled: list[dict[str, Any]]) -> str:
    failed = sorted(run.details.pop("_failed", {}).values(), key=lambda r: (-r["failures"], r["content_id"]))
    run.details["failed_content"] = [
        {"content_id": r["content_id"], "failures": r["failures"], "first_seen": iso(r["first"]),
         "last_seen": iso(r["last"])}
        for r in failed[:25]
    ]
    run.details["counts"] = dict(run.state["counts"])
    if failed:
        return (
            f"Publication failed for {len(failed)} content item(s); most affected: {failed[0]['content_id']} "
            f"({failed[0]['failures']} failure event(s), last {iso(failed[0]['last'])}). Search for the content ID "
            "to confirm it later published successfully."
        )
    return _generic_verdict(run, rolled)


# -- service_health ------------------------------------------------------------------ #


def _handle_service(run: _Diagnosis, log_file: LogFile, entry: LogEntry, event: Event | None) -> None:
    version = classifier.extract_version(entry)
    if version and entry.timestamp is not None:
        run.details.setdefault("_starts", defaultdict(set))[log_file.device].add((entry.timestamp, version))


def _finish_service(run: _Diagnosis, rolled: list[dict[str, Any]]) -> str:
    starts: dict[str, set[tuple[datetime, str]]] = run.details.pop("_starts", {})
    crash_files = sorted({f.rel for f in run.scope.files if f.log_key == "hs_err_pid.log"})
    loops = []
    rendered = {}
    for device, items in starts.items():
        ordered = sorted(items)
        rendered[device] = [{"time": iso(t), "version": v} for t, v in ordered[-20:]]
        for index in range(len(ordered) - RESTART_LOOP_STARTS + 1):
            window = ordered[index: index + RESTART_LOOP_STARTS]
            if window[-1][0] - window[0][0] <= RESTART_LOOP_WINDOW:
                loops.append({"device": device, "from": iso(window[0][0]), "to": iso(window[-1][0])})
                break
    run.details.update({"service_starts": rendered, "restart_loops": loops, "java_crash_reports": crash_files})
    parts = []
    total_starts = sum(len(v) for v in rendered.values())
    if total_starts:
        parts.append(f"{total_starts} service start(s) in the window.")
    if loops:
        parts.append(f"Restart loop on {', '.join(sorted({loop['device'] for loop in loops}))}.")
    if crash_files:
        parts.append(f"{len(crash_files)} Java crash report(s) (hs_err_pid) present.")
    oom = [i for i in rolled if i["known"].id == "jvm_out_of_memory"]
    if oom:
        parts.append(f"{oom[0]['count']} out-of-memory error(s).")
    return " ".join(parts) or "No service restarts, crashes or memory errors in the window."


# -- client_upgrade ---------------------------------------------------------------------- #


def _handle_upgrade(run: _Diagnosis, log_file: LogFile, entry: LogEntry, event: Event | None) -> None:
    version = classifier.extract_version(entry)
    if version and entry.timestamp is not None:
        versions = run.details.setdefault("_versions", defaultdict(dict))
        seen = versions[log_file.device].get(version)
        if seen is None or entry.timestamp < seen:
            versions[log_file.device][version] = entry.timestamp


def _finish_upgrade(run: _Diagnosis, rolled: list[dict[str, Any]]) -> str:
    versions: dict[str, dict[str, datetime]] = run.details.pop("_versions", {})
    run.details["versions_seen_by_device"] = {
        device: [{"version": v, "first_seen": iso(t)} for v, t in sorted(items.items(), key=lambda kv: kv[1])]
        for device, items in versions.items()
    }
    changed = sorted(d for d, items in versions.items() if len(items) > 1)
    prefix = f"Version changed during the window on: {', '.join(changed)}. " if changed else ""
    return prefix + _generic_verdict(run, rolled)


# -- feature_update_readiness ------------------------------------------------------------ #


def _handle_feature_update(run: _Diagnosis, log_file: LogFile, entry: LogEntry, event: Event | None) -> None:
    free = classifier.extract_free_space(entry)
    if free:
        drive, value = free
        readings = run.details.setdefault("_free_space", {})
        record = readings.setdefault((log_file.device, drive or "?"), {"device": log_file.device, "drive": drive})
        if _track(record, entry.timestamp) or "free_bytes" not in record:
            record.update(
                {
                    "free_bytes": value,
                    "free_gb": round(value / 1024**3, 1),
                    "meets_50gb_requirement": value > FEATURE_UPDATE_MIN_FREE_BYTES,
                }
            )
    if "Scanned status [NOT INSTALLED]" in entry.message:
        run.state["not_installed"][log_file.device] += 1


def _finish_feature_update(run: _Diagnosis, rolled: list[dict[str, Any]]) -> str:
    readings = [
        {k: v for k, v in r.items() if k not in ("first", "last")} | {"time": iso(r.get("last"))}
        for r in run.details.pop("_free_space", {}).values()
    ]
    run.details["latest_free_space"] = readings
    run.details["not_installed_scan_results"] = dict(run.state["not_installed"])
    low = [r for r in readings if not r["meets_50gb_requirement"]]
    if not readings and not run.state["not_installed"]:
        return "No free-space checks or feature update scan results found in the window."
    parts = []
    if low:
        parts.append(
            f"{len(low)} drive reading(s) below the 50 GB feature update requirement: "
            + ", ".join(f"{r['device']} {r['drive'] or ''} {r['free_gb']} GB".replace("  ", " ") for r in low[:5])
            + "."
        )
    elif readings:
        parts.append("Latest free-space readings meet the 50 GB requirement.")
    if run.state["not_installed"]:
        parts.append(f"'Scanned status [NOT INSTALLED]' results on {len(run.state['not_installed'])} device(s).")
    return " ".join(parts)


_HANDLERS: dict[str, Callable[[_Diagnosis, LogFile, LogEntry, Event | None], None]] = {
    "patch_install_failed": _handle_patch,
    "client_connectivity": _handle_connectivity,
    "vm_integration": _handle_vm,
    "feeds": _handle_feeds,
    "content_publication": _handle_publication,
    "service_health": _handle_service,
    "client_upgrade": _handle_upgrade,
    "feature_update_readiness": _handle_feature_update,
}
_FINALIZERS: dict[str, Callable[[_Diagnosis, list[dict[str, Any]]], str]] = {
    "patch_install_failed": _finish_patch,
    "client_connectivity": _finish_connectivity,
    "vm_integration": _finish_vm,
    "feeds": _finish_feeds,
    "content_publication": _finish_publication,
    "service_health": _finish_service,
    "client_upgrade": _finish_upgrade,
    "feature_update_readiness": _finish_feature_update,
}


# --------------------------------------------------------------------------- #
# compare_devices
# --------------------------------------------------------------------------- #


def compare_devices(
    registry: SourceRegistry,
    healthy_device: str,
    problem_device: str,
    *,
    source: str | None = None,
    since: str | None = DEFAULT_SUMMARY_WINDOW,
    until: str | None = None,
    anchor: str | None = None,
    min_severity: str = "WARN",
    include_noise: bool = False,
    top: int = 25,
) -> dict[str, Any]:
    if not healthy_device or not problem_device:
        raise InputError("Both healthy_device and problem_device are required.")
    floor = _severity_arg(min_severity)
    top = _clamp(top, 1, MAX_ISSUES, "top")
    sources, all_files = select_files(registry, source=source)
    devices = {f.device.lower(): f.device for f in all_files}
    resolved = []
    for label, wanted in (("healthy_device", healthy_device), ("problem_device", problem_device)):
        name = devices.get(wanted.strip().lower())
        if name is None:
            raise InputError(
                f"{label} '{wanted}' is not a device in the selected sources.",
                remediation="Devices available: " + ", ".join(sorted(devices.values())[:40]),
            )
        resolved.append(name)
    healthy, problem = resolved
    if healthy == problem:
        raise InputError("healthy_device and problem_device are the same device.")
    files = [f for f in all_files if f.device in (healthy, problem)]
    scope = build_scope(sources, files, since=since, until=until, anchor=anchor)
    coverage = Coverage()
    per_device = {healthy: IssueGroups(), problem: IssueGroups()}
    for log_file, entry in scan(scope, coverage):
        severity, _ = classifier.effective_severity(entry)
        if severity_rank(severity) >= floor:
            per_device[log_file.device].add(to_event(log_file, entry), include_noise=include_noise)

    def signature_key(group: dict[str, Any]) -> tuple[str, str]:
        return (group["component"] or "-", group["signature"])

    healthy_groups = {signature_key(g): g for g in per_device[healthy].groups.values()}
    problem_groups = {signature_key(g): g for g in per_device[problem].groups.values()}
    only_problem = sorted(
        (g for k, g in problem_groups.items() if k not in healthy_groups),
        key=lambda g: (-severity_rank(g["severity"]), -g["count"]),
    )
    more_on_problem = sorted(
        (
            {**IssueGroups.render(g, detail_lines=2), "healthy_count": healthy_groups[k]["count"]}
            for k, g in problem_groups.items()
            if k in healthy_groups
            and g["count"] >= COMPARE_MIN_EVENTS
            and g["count"] >= COMPARE_RATIO * healthy_groups[k]["count"]
        ),
        key=lambda g: -g["count"],
    )
    roles = {device: sorted({f.role for f in files if f.device == device}) for device in (healthy, problem)}
    return {
        "ok": True,
        "healthy_device": healthy,
        "problem_device": problem,
        "roles": roles,
        "role_warning": (
            "The two devices do not have the same role, so differences may be expected."
            if roles[healthy] != roles[problem]
            else None
        ),
        "window": scope.window_dict(),
        "healthy_distinct_issues": len(healthy_groups),
        "problem_distinct_issues": len(problem_groups),
        "shared_issues": len(set(healthy_groups) & set(problem_groups)),
        "only_on_problem_device": [IssueGroups.render(g, detail_lines=3) for g in only_problem[:top]],
        "more_frequent_on_problem_device": more_on_problem[:top],
        "thresholds": {"ratio": COMPARE_RATIO, "min_events": COMPARE_MIN_EVENTS},
        "coverage": coverage.to_dict(),
        "timestamps_note": timezones.timestamp_note(scope.files),
    }


# --------------------------------------------------------------------------- #
# Source checks and listings
# --------------------------------------------------------------------------- #


def check_sources(registry: SourceRegistry) -> dict[str, Any]:
    sources = registry.sources()
    configuration = {
        "data_dir": str(registry.data_dir),
        "auto_discover": registry.auto_discover_enabled(),
        "deployment_setting": registry.global_deployment_hint(),
        "env_sources_configured": bool((registry.env.get("TPM_LOG_SOURCES") or "").strip()),
        "time_zones": registry.timezones.to_dict(),
        "site_knowledge": customknowledge.active(registry.env).to_dict(),
        "baseline_history": history.BaselineStore(registry.data_dir).stats(),
    }
    if not sources:
        return {
            "ok": False,
            "error": "no_sources",
            "message": "No log sources are configured and no TPM installation was found on this machine.",
            "remediation": "Add logs with add_log_source(name, path), or set TPM_LOG_SOURCES. "
                           + LOG_ACQUISITION["saas_server"] + " " + LOG_ACQUISITION["client"],
            "configuration": configuration,
        }
    report = []
    total_files = 0
    all_files: list[LogFile] = []
    all_roles: set[str] = set()
    deployments: set[str] = set()
    for source in sources:
        item = source.to_dict()
        if not source.available:
            item["remediation"] = "Fix or remove this source (remove_log_source for runtime sources)."
            report.append(item)
            continue
        files = registry.files(source)
        total_files += len(files)
        all_files.extend(files)
        devices: dict[str, dict[str, Any]] = {}
        unrecognised = []
        for log_file in files:
            span = file_span(log_file)
            record = devices.setdefault(
                log_file.device,
                {"device": log_file.device, "roles": Counter(), "files": 0, "size_mb": 0.0, "first": None, "last": None},
            )
            record["roles"][log_file.role] += 1
            record["files"] += 1
            record["size_mb"] += log_file.size / 1024**2
            _track(record, span.first)
            _track(record, span.last)
            if span.layout == LAYOUT_PLAIN and log_file.size and log_file.log_key.endswith((".log", ".err")):
                unrecognised.append(log_file.rel)
        deployment = registry.deployment(source, files)
        deployments.add(deployment["value"])
        all_roles |= {f.role for f in files}
        advisories = []
        for version in deployment["versions"]:
            for advisory in VERSION_ADVISORIES:
                if advisory.applies(version["version"]):
                    advisories.append({"version": version["version"], **advisory.to_dict()})
        item.update(
            {
                "files": len(files),
                "size_mb": round(sum(f.size for f in files) / 1024**2, 1),
                "devices": [
                    {
                        "device": d["device"],
                        "roles": dict(d["roles"]),
                        "files": d["files"],
                        "size_mb": round(d["size_mb"], 1),
                        "first_entry": iso(d["first"]),
                        "last_entry": iso(d["last"]),
                    }
                    for d in sorted(devices.values(), key=lambda d: d["device"].lower())[:50]
                ],
                "device_count": len(devices),
                "deployment": deployment,
                "version_advisories": advisories,
                "unrecognised_format_files": unrecognised[:20],
            }
        )
        if not files:
            item["remediation"] = "No log files found at this path."
        report.append(item)

    guidance = []
    if ROLE_SERVER not in all_roles:
        how = LOG_ACQUISITION["onprem_server"] if deployments == {DEPLOYMENT_ONPREM} else LOG_ACQUISITION["saas_server"]
        guidance.append("No server logs configured. " + how)
    if ROLE_CLIENT not in all_roles:
        guidance.append("No client logs configured. " + LOG_ACQUISITION["client"])
    available = [s for s in sources if s.available]
    ok = bool(available) and total_files > 0
    return {
        "ok": ok,
        "message": (
            f"{len(available)} of {len(sources)} source(s) readable, {total_files} log file(s)."
            if ok
            else "Sources are configured but no readable log files were found."
        ),
        "sources": report,
        "guidance": guidance,
        "configuration": configuration,
        "timestamps_note": timezones.timestamp_note(all_files),
    }


def list_log_files(
    registry: SourceRegistry,
    *,
    source: str | None = None,
    device: str | None = None,
    role: str | None = None,
    name: str | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    limit = _clamp(limit, 1, MAX_LISTED_FILES, "limit")
    _, selected = select_files(registry, source=source, device=device, role=role, files=name)
    selected.sort(key=lambda f: (f.source, f.device.lower(), f.role, f.log_key, f.rotation))
    rows = []
    for log_file in selected[:limit]:
        span = file_span(log_file)
        rows.append(
            {**log_file.to_dict(), "layout": span.layout, "first_entry": iso(span.first), "last_entry": iso(span.last)}
        )
    return {
        "ok": True,
        "file_count": len(selected),
        "returned": len(rows),
        "truncated": len(selected) > limit,
        "devices": dict(Counter(f.device for f in selected)),
        "roles": dict(Counter(f.role for f in selected)),
        "logs": dict(Counter(f.display_name for f in selected).most_common(60)),
        "files": rows,
    }


# --------------------------------------------------------------------------- #
# explain
# --------------------------------------------------------------------------- #


def explain(topic: str | None = None) -> dict[str, Any]:
    custom = customknowledge.active()
    if not topic or not topic.strip():
        return {
            "ok": True,
            "type": "index",
            "symptoms": {pid: pb.title for pid, pb in PLAYBOOKS.items()},
            "known_issues": {issue.id: issue.title for issue in (*custom.issues, *KNOWN_ISSUES)},
            "site_known_issues": [issue.id for issue in custom.issues],
            "logs": sorted(info.name for info in LOG_CATALOG.values()),
            "usage": "Pass a log file name, an error code (0x80070643, -2147467259, 1603, http 407), a symptom id "
                     "or a known issue id.",
        }
    text = topic.strip()
    lower = text.lower()
    if lower in PLAYBOOKS:
        return {"ok": True, "type": "symptom", **PLAYBOOKS[lower].to_dict()}
    site_issue = custom.issue_by_id(lower)
    if site_issue is not None:
        return {"ok": True, "type": "known_issue", "from_site_knowledge_file": True, **site_issue.to_dict()}
    if lower in KNOWN_ISSUES_BY_ID:
        return {"ok": True, "type": "known_issue", **KNOWN_ISSUES_BY_ID[lower].to_dict()}
    filename = re.split(r"[\\/]", text)[-1]
    key, _, rotation, client_id = logical_name(filename)
    info = LOG_CATALOG.get(key)
    if info is not None:
        return {
            "ok": True,
            "type": "log",
            **info.to_dict(),
            "rotation_index": rotation or None,
            "client_id": client_id,
            "used_by_symptoms": [pid for pid, pb in PLAYBOOKS.items() if key in pb.logs],
        }
    code = decode_any(text)
    if code is not None:
        return {"ok": True, "type": "error_code", **code.to_dict()}
    logs = [i.to_dict() for i in LOG_CATALOG.values() if lower in i.name.lower() or lower in (i.purpose() or "").lower()]
    issues = [
        {"id": i.id, "title": i.title}
        for i in (*custom.issues, *KNOWN_ISSUES)
        if lower in i.title.lower() or lower in i.explanation.lower()
    ]
    symptoms = [
        {"id": p.id, "title": p.title} for p in PLAYBOOKS.values() if lower in p.title.lower() or lower in p.summary.lower()
    ]
    if logs or issues or symptoms:
        return {"ok": True, "type": "search", "logs": logs[:15], "known_issues": issues[:15], "symptoms": symptoms}
    raise InputError(
        f"Nothing known about '{topic}'.",
        remediation="Try a log file name (e.g. _SDMErrors.log), an error code (e.g. 0x80070643 or 1603), a symptom "
                    "(e.g. patch_install_failed) or a known issue id. Call explain with no topic for the index.",
    )
