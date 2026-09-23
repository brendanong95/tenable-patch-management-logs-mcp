"""Parse Tenable Patch Management log files into entries.

The layouts below were taken from real TPM 10.2.973.9 logs (a SaaS "Download All
Server Logs" bundle and a Windows client adaptiva.log), plus the standard Windows
Installer verbose log that TPM clients keep in msiLogs/.

* ``adaptiva`` - the Java service layout used by adaptiva.log, adaptiva.err and every
  component log, on both server and client::

      2026-09-12 18:00:25,141 - INFO - <message> - <Component> - TID=3340624, <thread>

  A message may span several lines, in which case the ``- Component - TID=n, thread``
  suffix sits at the end of a later line. Stack traces follow the entry.
* ``workflow`` - workflowlogs/<Workflow name>_<id>_<seq>.log::

      09-17-2026 14:00:00:2 : Exec: Starting: Start1.Global_Approvals

* ``blocks`` - SQLUploader.log ``----- START(2026-09-02T01:44:27.942) -----`` markers.
* ``msi`` - msiexec verbose logs.
* ``timestamped`` - any other line that starts with an ISO-like timestamp (setup logs,
  exported journalctl output).
* ``plain`` - fallback where every non-empty line is its own entry, so an unrecognised
  format can never collapse a whole file into a single entry.

Timestamps are returned naive, exactly as written in the file, with any UTC offset the
line carried kept separately in ``LogEntry.utc_offset``. Callers that mix logs from
several machines pass a ``shift`` (see ``timezones.TimeShift``) to have every timestamp
converted into one zone as it is read.
"""

from __future__ import annotations

import codecs
import gzip
import io
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import IO, Any, Iterator

# --------------------------------------------------------------------------- #
# Tunable constants
# --------------------------------------------------------------------------- #

#: Lines read from the top of a file to decide its layout.
SNIFF_LINES = 400
#: Continuation lines stored per entry; further lines are counted but not kept.
MAX_DETAIL_LINES = 200
#: An entry this long is split so a wrong layout guess cannot swallow a file.
RUNAWAY_DETAIL_LINES = 5_000
#: Bytes read from the end of a file to find its newest timestamp.
TAIL_BYTES = 262_144
#: Compressed files above this size are not fully decompressed just to find a time span.
MAX_GZ_SPAN_BYTES = 20 * 1024 * 1024

LEVELS = ("TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL")
LEVEL_RANK = {level: rank for rank, level in enumerate(LEVELS)}
_LEVEL_ALIASES = {
    "WARNING": "WARN",
    "SEVERE": "ERROR",
    "ERR": "ERROR",
    "CRITICAL": "FATAL",
    "VERBOSE": "DEBUG",
}

LAYOUT_ADAPTIVA = "adaptiva"
LAYOUT_WORKFLOW = "workflow"
LAYOUT_BLOCKS = "blocks"
LAYOUT_MSI = "msi"
LAYOUT_TIMESTAMPED = "timestamped"
LAYOUT_PLAIN = "plain"
#: Tie-break order when sniffing: the most specific layout wins.
_LAYOUT_PRIORITY = (
    LAYOUT_ADAPTIVA,
    LAYOUT_WORKFLOW,
    LAYOUT_BLOCKS,
    LAYOUT_MSI,
    LAYOUT_TIMESTAMPED,
)

# --------------------------------------------------------------------------- #
# Patterns
# --------------------------------------------------------------------------- #

_ADAPTIVA_START = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?) - "
    r"(?P<level>[A-Za-z]+) - (?P<rest>.*)$"
)
#: Greedy body, so the match anchors on the last `` - Component - TID=`` in the line.
_SUFFIX = re.compile(
    r"^(?P<body>.*) - (?P<component>\S+) - TID=(?P<tid>\d+),\s?(?P<thread>.*)$"
)
_WORKFLOW_START = re.compile(
    r"^(?P<ts>\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}:\d{1,3}) : (?P<rest>.*)$"
)
_WORKFLOW_KIND = re.compile(r"^(?P<kind>[A-Za-z][A-Za-z ]{0,30}?):")
_BLOCK_MARK = re.compile(
    r"^-{3,}\s*(?P<kind>START|END)\((?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,6})?)\)\s*-{3,}\s*$"
)
_MSI_HEADER = re.compile(
    r"^=== (?:Verbose )?[Ll]ogging (?P<what>started|stopped): "
    r"(?P<date>\d{1,2}[/.-]\d{1,2}[/.-]\d{4})\s+(?P<time>\d{1,2}:\d{2}:\d{2})"
)
_MSI_LINE = re.compile(
    r"^MSI \((?P<ctx>[A-Za-z])\) \((?P<pid>[0-9A-Fa-f]{1,8})[:!](?P<tid>[0-9A-Fa-f]{1,8})\) "
    r"\[(?P<time>\d{2}:\d{2}:\d{2}):(?P<ms>\d{3})\]: (?P<msg>.*)$"
)
_MSI_ACTION = re.compile(r"^Action (?:start|ended) (?P<time>\d{1,2}:\d{2}:\d{2}): (?P<msg>.*)$")
_GENERIC_START = re.compile(
    r"^\[?(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|\d{1,2}/\d{1,2}/\d{4}[ ,]+\d{1,2}:\d{2}:\d{2}(?:[.,:]\d{1,6})?(?:\s?[AaPp][Mm])?)\]?"
    r"(?P<rest>.*)$"
)
_LEVEL_WORD = re.compile(r"\b(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|ERR|FATAL|SEVERE|CRITICAL)\b")

#: Trailing UTC offset on an ISO timestamp (journalctl exports, some setup logs).
_TS_OFFSET = re.compile(r"(?:(?P<z>Z)|(?P<sign>[+-])(?P<hours>\d{2}):?(?P<minutes>\d{2}))$")

_TS_ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,9}))?")
_TS_WORKFLOW = re.compile(r"^(\d{2})-(\d{2})-(\d{4}) (\d{2}):(\d{2}):(\d{2}):(\d{1,3})")
_TS_SLASH = re.compile(
    r"^(\d{1,2})/(\d{1,2})/(\d{4})[ ,]+(\d{1,2}):(\d{2}):(\d{2})(?:[.,:](\d{1,6}))?(?:\s?([AaPp][Mm]))?"
)


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class LogEntry:
    """One logical log record: its first line plus any continuation lines."""

    line: int
    timestamp: datetime | None
    level: str | None
    message: str
    raw: str
    layout: str
    component: str | None = None
    thread: str | None = None
    tid: str | None = None
    detail: list[str] = field(default_factory=list)
    detail_dropped: int = 0
    end_line: int = 0
    time_inferred: bool = False
    #: UTC offset written on the line itself, when it had one.
    utc_offset: timedelta | None = None

    @property
    def detail_count(self) -> int:
        return len(self.detail) + self.detail_dropped

    def text(self, max_detail: int | None = None) -> str:
        """First line plus stored continuation lines, for searching and matching."""
        if not self.detail:
            return self.raw
        detail = self.detail if max_detail is None else self.detail[:max_detail]
        return "\n".join((self.raw, *detail))


@dataclass(slots=True)
class ParseStats:
    """Per-file parse counters, reported so format problems are never silent."""

    layout: str = LAYOUT_PLAIN
    lines: int = 0
    blank_lines: int = 0
    entries: int = 0
    detail_lines: int = 0
    timestamped_entries: int = 0
    runaway_splits: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "layout": self.layout,
            "lines": self.lines,
            "entries": self.entries,
            "continuation_lines": self.detail_lines,
            "timestamped_entry_pct": (
                round(self.timestamped_entries / self.entries * 100, 1) if self.entries else 0.0
            ),
            "runaway_splits": self.runaway_splits,
        }


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def normalize_level(token: str | None) -> str | None:
    """Map a level token onto TRACE/DEBUG/INFO/WARN/ERROR/FATAL, else None."""
    if not token:
        return None
    upper = token.strip().upper()
    upper = _LEVEL_ALIASES.get(upper, upper)
    return upper if upper in LEVEL_RANK else None


def level_rank(level: str | None) -> int:
    """Rank for comparisons; unknown levels sort with INFO."""
    return LEVEL_RANK.get(level or "INFO", LEVEL_RANK["INFO"])


def _micro(fraction: str | None) -> int:
    """Fractional-second digits ("141", "2", "123456789") to microseconds."""
    if not fraction:
        return 0
    return int((fraction + "000000")[:6])


def parse_timestamp(text: str | None) -> datetime | None:
    """Parse the timestamp shapes that appear in TPM logs, naive and as written.

    Returns ``None`` instead of raising: one malformed line must not break a report.
    """
    if not text:
        return None
    value = text.strip()
    try:
        match = _TS_ISO.match(value)
        if match:
            y, mo, d, h, mi, s, frac = match.groups()
            return datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), _micro(frac))
        match = _TS_WORKFLOW.match(value)
        if match:
            mo, d, y, h, mi, s, frac = match.groups()
            return datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), _micro(frac))
        match = _TS_SLASH.match(value)
        if match:
            a, b, y, h, mi, s, frac, meridiem = match.groups()
            month, day = (int(a), int(b)) if int(a) <= 12 else (int(b), int(a))
            hour = int(h)
            if meridiem:
                if meridiem.lower() == "pm" and hour < 12:
                    hour += 12
                elif meridiem.lower() == "am" and hour == 12:
                    hour = 0
            return datetime(int(y), month, day, hour, int(mi), int(s), _micro(frac))
    except ValueError:
        return None
    return None


def timestamp_offset(text: str | None) -> timedelta | None:
    """The UTC offset a timestamp carried, if any: ``2026-09-17T08:00:00+02:00`` -> +2h."""
    if not text:
        return None
    match = _TS_OFFSET.search(text.strip())
    if not match:
        return None
    if match.group("z"):
        return timedelta(0)
    delta = timedelta(hours=int(match.group("hours")), minutes=int(match.group("minutes")))
    return -delta if match.group("sign") == "-" else delta


class _NoShift:
    """Default time conversion: none. Mirrors ``timezones.TimeShift``."""

    @staticmethod
    def apply(value: datetime | None, offset: timedelta | None = None) -> datetime | None:
        return value


NO_SHIFT = _NoShift()


def _apply_suffix(entry: LogEntry, text: str, *, set_message: bool) -> bool:
    """Read ``- Component - TID=n, thread`` from ``text`` into ``entry``."""
    if " - TID=" not in text:
        return False
    match = _SUFFIX.match(text)
    if not match:
        return False
    entry.component = match.group("component")
    entry.tid = match.group("tid")
    entry.thread = match.group("thread").strip() or None
    if set_message:
        entry.message = match.group("body").rstrip()
    return True


def _msi_header_date(text: str, reference: date | None) -> date | None:
    """MSI header dates follow the machine locale; pick the reading nearest the file date."""
    parts = re.split(r"[/.-]", text)
    try:
        first, second, year = int(parts[0]), int(parts[1]), int(parts[2])
    except (IndexError, ValueError):
        return None
    candidates: list[date] = []
    for month, day in ((first, second), (second, first)):
        try:
            candidate = date(year, month, day)
        except ValueError:
            continue
        if candidate not in candidates:
            candidates.append(candidate)
    if not candidates:
        return None
    if reference is not None and len(candidates) > 1:
        return min(candidates, key=lambda d: abs((d - reference).days))
    return candidates[0]


# --------------------------------------------------------------------------- #
# File access
# --------------------------------------------------------------------------- #


def _read_head_bytes(path: Path, size: int = 4096) -> bytes:
    if path.name.lower().endswith(".gz"):
        with gzip.open(path, "rb") as fh:
            return fh.read(size)
    with open(path, "rb") as fh:
        return fh.read(size)


def _encodings(path: Path) -> tuple[str, str]:
    """Return ``(stream_codec, raw_codec)``: one for reading from the start of the
    file (handles a BOM), one for decoding a chunk from the middle of it."""
    try:
        head = _read_head_bytes(path)
    except (OSError, EOFError):
        return "utf-8", "utf-8"
    if head.startswith(codecs.BOM_UTF8):
        return "utf-8-sig", "utf-8"
    if head.startswith(codecs.BOM_UTF16_LE):
        return "utf-16", "utf-16-le"
    if head.startswith(codecs.BOM_UTF16_BE):
        return "utf-16", "utf-16-be"
    if head and head.count(0) > len(head) // 4:
        little = head[1::2].count(0) >= head[0::2].count(0)
        codec = "utf-16-le" if little else "utf-16-be"
        return codec, codec
    return "utf-8", "utf-8"


def open_text(path: Path) -> IO[str]:
    """Open a (possibly gzipped, possibly UTF-16) log file as text."""
    stream_codec, _ = _encodings(path)
    if path.name.lower().endswith(".gz"):
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding=stream_codec, errors="replace")
    return open(path, "r", encoding=stream_codec, errors="replace")


def _mtime_date(path: Path) -> date | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime).date()
    except (OSError, ValueError, OverflowError):
        return None


# --------------------------------------------------------------------------- #
# Layout detection and entry assembly
# --------------------------------------------------------------------------- #


def classify_line(line: str) -> str | None:
    """Which layout's entry-start pattern ``line`` matches, if any."""
    match = _ADAPTIVA_START.match(line)
    if match and normalize_level(match.group("level")):
        return LAYOUT_ADAPTIVA
    if _WORKFLOW_START.match(line):
        return LAYOUT_WORKFLOW
    if _BLOCK_MARK.match(line):
        return LAYOUT_BLOCKS
    if _MSI_LINE.match(line) or _MSI_HEADER.match(line) or _MSI_ACTION.match(line):
        return LAYOUT_MSI
    match = _GENERIC_START.match(line)
    if match and parse_timestamp(match.group("ts")) is not None:
        return LAYOUT_TIMESTAMPED
    return None


def sniff_layout(path: Path) -> str:
    """Pick a file's layout from the entry-start lines in its first lines."""
    votes: Counter[str] = Counter()
    try:
        with open_text(path) as fh:
            for index, raw in enumerate(fh):
                if index >= SNIFF_LINES:
                    break
                line = raw.rstrip("\r\n").lstrip("﻿")
                if not line.strip():
                    continue
                layout = classify_line(line)
                if layout:
                    votes[layout] += 1
    except (OSError, EOFError, gzip.BadGzipFile):
        return LAYOUT_PLAIN
    if not votes:
        return LAYOUT_PLAIN
    return max(
        _LAYOUT_PRIORITY,
        key=lambda name: (votes[name], -_LAYOUT_PRIORITY.index(name)),
    )


class _Parser:
    """Builds entries for one file; holds the little state some layouts need."""

    def __init__(self, layout: str, reference_date: date | None = None) -> None:
        self.layout = layout
        self.reference_date = reference_date
        self.msi_date: date | None = None
        self.msi_last: datetime | None = None

    def start(self, line: str, line_no: int) -> LogEntry | None:
        """Return a new entry when ``line`` begins one, else ``None``."""
        if self.layout == LAYOUT_PLAIN:
            return self.plain(line, line_no)
        if self.layout == LAYOUT_MSI:
            return self._msi(line, line_no)

        match = _ADAPTIVA_START.match(line)
        if match:
            level = normalize_level(match.group("level"))
            if level:
                entry = LogEntry(
                    line=line_no,
                    timestamp=parse_timestamp(match.group("ts")),
                    level=level,
                    message=match.group("rest"),
                    raw=line,
                    layout=LAYOUT_ADAPTIVA,
                    end_line=line_no,
                )
                _apply_suffix(entry, match.group("rest"), set_message=True)
                return entry

        if self.layout == LAYOUT_WORKFLOW:
            match = _WORKFLOW_START.match(line)
            if match:
                rest = match.group("rest")
                kind = _WORKFLOW_KIND.match(rest)
                return LogEntry(
                    line=line_no,
                    timestamp=parse_timestamp(match.group("ts")),
                    level="INFO",
                    message=rest,
                    raw=line,
                    layout=LAYOUT_WORKFLOW,
                    component=kind.group("kind").strip() if kind else None,
                    end_line=line_no,
                )

        if self.layout == LAYOUT_BLOCKS:
            match = _BLOCK_MARK.match(line)
            if match:
                return LogEntry(
                    line=line_no,
                    timestamp=parse_timestamp(match.group("ts")),
                    level="INFO",
                    message=f"{match.group('kind')}({match.group('ts')})",
                    raw=line,
                    layout=LAYOUT_BLOCKS,
                    end_line=line_no,
                )

        match = _GENERIC_START.match(line)
        if match:
            stamp = parse_timestamp(match.group("ts"))
            if stamp is not None:
                rest = match.group("rest").strip(" -|:,\t")
                word = _LEVEL_WORD.search(rest[:60])
                return LogEntry(
                    line=line_no,
                    timestamp=stamp,
                    level=normalize_level(word.group(1)) if word else None,
                    message=rest,
                    raw=line,
                    layout=LAYOUT_TIMESTAMPED,
                    end_line=line_no,
                    utc_offset=timestamp_offset(match.group("ts")),
                )
        return None

    def plain(self, line: str, line_no: int) -> LogEntry:
        word = _LEVEL_WORD.search(line[:120])
        return LogEntry(
            line=line_no,
            timestamp=None,
            level=normalize_level(word.group(1)) if word else None,
            message=line.strip(),
            raw=line,
            layout=LAYOUT_PLAIN,
            end_line=line_no,
        )

    def _msi_time(self, clock: str, millis: str | None) -> datetime | None:
        if self.msi_date is None:
            return None
        try:
            hour, minute, second = (int(part) for part in clock.split(":"))
            stamp = datetime(
                self.msi_date.year,
                self.msi_date.month,
                self.msi_date.day,
                hour,
                minute,
                second,
                int(millis) * 1000 if millis else 0,
            )
        except ValueError:
            return None
        if self.msi_last is not None and stamp < self.msi_last - timedelta(hours=12):
            stamp += timedelta(days=1)  # the log ran past midnight
            self.msi_date = stamp.date()
        self.msi_last = stamp
        return stamp

    def _msi(self, line: str, line_no: int) -> LogEntry:
        header = _MSI_HEADER.match(line)
        if header:
            self.msi_date = _msi_header_date(header.group("date"), self.reference_date)
            self.msi_last = None
            return LogEntry(
                line=line_no,
                timestamp=self._msi_time(header.group("time"), None),
                level="INFO",
                message=line.strip("= "),
                raw=line,
                layout=LAYOUT_MSI,
                component="msiexec",
                end_line=line_no,
            )
        match = _MSI_LINE.match(line)
        if match:
            return LogEntry(
                line=line_no,
                timestamp=self._msi_time(match.group("time"), match.group("ms")),
                level=None,
                message=match.group("msg"),
                raw=line,
                layout=LAYOUT_MSI,
                component=f"MSI ({match.group('ctx')})",
                tid=match.group("tid"),
                end_line=line_no,
            )
        match = _MSI_ACTION.match(line)
        if match:
            return LogEntry(
                line=line_no,
                timestamp=self._msi_time(match.group("time"), None),
                level=None,
                message=line.strip(),
                raw=line,
                layout=LAYOUT_MSI,
                component="MSI action",
                end_line=line_no,
            )
        return LogEntry(
            line=line_no,
            timestamp=self.msi_last,
            level=None,
            message=line.strip(),
            raw=line,
            layout=LAYOUT_MSI,
            end_line=line_no,
            time_inferred=self.msi_last is not None,
        )


def iter_entries(
    path: Path,
    layout: str | None = None,
    stats: ParseStats | None = None,
    shift: Any = NO_SHIFT,
) -> Iterator[LogEntry]:
    """Stream entries from one file. Memory use is bounded by a single entry.

    ``shift`` converts each timestamp into a common zone as the entry is finished; the
    default leaves it exactly as written.
    """
    layout = layout or sniff_layout(path)
    stats = stats if stats is not None else ParseStats()
    stats.layout = layout
    parser = _Parser(layout, _mtime_date(path))
    current: LogEntry | None = None
    runaway = False

    def finish(entry: LogEntry) -> LogEntry:
        stats.entries += 1
        if entry.timestamp is not None:
            stats.timestamped_entries += 1
            entry.timestamp = shift.apply(entry.timestamp, entry.utc_offset)
        return entry

    with open_text(path) as fh:
        for line_no, raw in enumerate(fh, start=1):
            stats.lines += 1
            line = raw.rstrip("\r\n")
            if line_no == 1:
                line = line.lstrip("﻿")
            if not line.strip():
                stats.blank_lines += 1
                continue

            entry = parser.start(line, line_no)
            if entry is not None:
                runaway = False
                if current is not None:
                    yield finish(current)
                current = entry
                continue

            if current is None or runaway:
                # A line before the first entry, or past a runaway split: keep it visible.
                if current is not None:
                    yield finish(current)
                current = parser.plain(line, line_no)
                continue

            stats.detail_lines += 1
            current.end_line = line_no
            if current.component is None and current.layout == LAYOUT_ADAPTIVA:
                _apply_suffix(current, line, set_message=False)
            if len(current.detail) < MAX_DETAIL_LINES:
                current.detail.append(line)
            else:
                current.detail_dropped += 1
            if current.detail_count >= RUNAWAY_DETAIL_LINES:
                stats.runaway_splits += 1
                runaway = True

    if current is not None:
        yield finish(current)


def _tail_timestamp(path: Path, layout: str, shift: Any = NO_SHIFT) -> datetime | None:
    """Newest timestamp, read from the last ``TAIL_BYTES`` of the file."""
    _, raw_codec = _encodings(path)
    width = 2 if raw_codec.startswith("utf-16") else 1
    size = path.stat().st_size
    start = max(0, size - TAIL_BYTES)
    start -= start % width
    with open(path, "rb") as fh:
        fh.seek(start)
        chunk = fh.read()
    lines = chunk.decode(raw_codec, errors="replace").splitlines()
    if start > 0 and lines:
        lines = lines[1:]  # the first line is probably cut in half
    parser = _Parser(layout)
    for line in reversed(lines):
        if not line.strip():
            continue
        entry = parser.start(line.lstrip("﻿"), 0)
        if entry is not None and entry.timestamp is not None:
            return shift.apply(entry.timestamp, entry.utc_offset)
    return None


def time_span(
    path: Path, layout: str | None = None, shift: Any = NO_SHIFT
) -> tuple[datetime | None, datetime | None]:
    """``(first, last)`` timestamps of a file without parsing all of it."""
    layout = layout or sniff_layout(path)
    compressed = path.name.lower().endswith(".gz")
    try:
        if layout == LAYOUT_MSI or compressed:
            if compressed and path.stat().st_size > MAX_GZ_SPAN_BYTES:
                return _head_timestamp(path, layout, shift), None
            first = last = None
            for entry in iter_entries(path, layout, shift=shift):
                if entry.timestamp is not None:
                    first = first or entry.timestamp
                    last = entry.timestamp
            return first, last
        return _head_timestamp(path, layout, shift), _tail_timestamp(path, layout, shift)
    except (OSError, EOFError, gzip.BadGzipFile):
        return None, None


def _head_timestamp(path: Path, layout: str, shift: Any = NO_SHIFT) -> datetime | None:
    parser = _Parser(layout, _mtime_date(path))
    with open_text(path) as fh:
        for index, raw in enumerate(fh):
            if index >= SNIFF_LINES * 5:
                break
            line = raw.rstrip("\r\n").lstrip("﻿")
            if not line.strip():
                continue
            entry = parser.start(line, index + 1)
            if entry is not None and entry.timestamp is not None:
                return shift.apply(entry.timestamp, entry.utc_offset)
    return None
