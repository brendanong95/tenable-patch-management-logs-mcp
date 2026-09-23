"""Per-entry enrichment: redaction, severity, signatures, codes and known issues.

Everything here is pure Python over already-parsed entries - no file access, no
network - so every tool returns finished, grouped results instead of raw lines.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from . import customknowledge
from .error_codes import DecodedCode, extract_codes
from .knowledge import KNOWN_ISSUES, KnownIssue
from .logformat import LEVEL_RANK, LogEntry

# --------------------------------------------------------------------------- #
# Tunable constants
# --------------------------------------------------------------------------- #

#: Signatures longer than this are cut; they only need to group, not to be read in full.
SIGNATURE_MAX_CHARS = 200
#: Continuation lines considered when matching known issues and extracting codes.
MATCH_DETAIL_LINES = 60
#: Characters kept of a masked secret.
REDACTION_KEEP_CHARS = 4
#: Default size limits for entries rendered into tool output.
OUTPUT_MESSAGE_CHARS = 1_200
OUTPUT_DETAIL_LINES = 8
OUTPUT_DETAIL_CHARS = 300

SEVERITY_ORDER = ("FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE")

# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #

#: Tenable API keys are 64 hex characters; TPM writes the access key into its logs.
_HEX_KEY = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?P<key>access[_ -]?key|secret[_ -]?key|api[_ -]?key|apikey|x-apikeys|password|passwd|pwd|"
    r"client[_ -]?secret|secret|auth[_ -]?token|access[_ -]?token|refresh[_ -]?token|token|"
    r"session[_ -]?id|sessionid)"
    r"(?P<sep>\s*[:=]\s*[\"']?)(?P<value>[^\s\"',;&\])]+)"
)
_AUTH_HEADER = re.compile(r"(?i)\b(?P<scheme>Bearer|Basic)\s+(?P<value>[A-Za-z0-9._~+/=-]{8,})")
_URL_PASSWORD = re.compile(r"(?i)(?P<prefix>\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)(?P<value>[^@\s/]+)(?=@)")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def mask(value: str, keep: int = REDACTION_KEEP_CHARS) -> str:
    """``"abcdef123456"`` -> ``"****3456"``; short values are fully masked."""
    if len(value) <= keep * 2:
        return "****"
    return "****" + value[-keep:]


def redact(text: str | None) -> str:
    """Mask anything that looks like credential material.

    Hostnames, IP addresses, e-mail addresses, GUIDs and client IDs are kept: they are
    what troubleshooting needs, and they are not secrets.
    """
    if not text:
        return text or ""
    if "PRIVATE KEY-----" in text and _PRIVATE_KEY.search(text):
        return "[private key block redacted]"
    text = _HEX_KEY.sub(lambda m: mask(m.group(0)), text)
    text = _SECRET_ASSIGNMENT.sub(
        lambda m: m.group("key") + m.group("sep") + mask(m.group("value")), text
    )
    text = _AUTH_HEADER.sub(lambda m: m.group("scheme") + " " + mask(m.group("value")), text)
    text = _URL_PASSWORD.sub(lambda m: m.group("prefix") + "****", text)
    return text


# --------------------------------------------------------------------------- #
# Signatures
# --------------------------------------------------------------------------- #

_NORMALISERS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"), "<guid>"),
    (re.compile(r"\*{4}[0-9A-Za-z]{0,4}"), "<secret>"),
    (re.compile(r"(?i)\b(https?://[^/\s\"'<>\]]+)/[^\s\"'\])>]*"), r"\1/<path>"),
    (re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "<email>"),
    (re.compile(r"/?\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"(?i)\b0x[0-9a-f]{9,}\b"), "<hex>"),
    (re.compile(r"(?i)\b[0-9a-f]{16,}\b"), "<hex>"),
    (re.compile(r"\[[A-Za-z0-9_-]{16,}\]"), "[<id>]"),
    # Windows paths, allowing single spaces inside folder names ("C:\Program Files\Tenable\...").
    (re.compile(r"(?i)(?<![\w<])(?:[a-z]:\\|\\\\)(?:[^\s\\\"'\[\]()<>,;]+(?: [^\s\\\"'\[\]()<>,;]+)*\\)*"
                r"[^\s\"'\[\]()<>,;]*"), "<path>"),
    (re.compile(r"(?<![\w<:/])/(?:[\w.$@-]*/)+[\w.$@-]*"), "<path>"),
    (re.compile(r"(?<![\w.])-?\d+(?:\.\d+)*(?!\w)"), "<n>"),
)
_WHITESPACE = re.compile(r"\s+")
_EXCEPTION_HEAD = re.compile(
    r"^\s*(?:Caused by:\s*)?(?P<cls>(?:[a-zA-Z_$][\w$]*\.)+[A-Z][\w$]*(?:Exception|Error|Throwable)|"
    r"[A-Z][\w$]*(?:Exception|Error))\b(?P<rest>.*)$"
)
_STACK_FRAME = re.compile(r"^\s+at [\w$.<>]+\(")
_FQ_EXCEPTION = re.compile(r"\b(?:[a-z_$][\w$]*\.)+[A-Z][\w$]*(?:Exception|Error)\b")
_ADAPTIVA_ERROR_CODE = re.compile(r"Error Code = (-?\d+)")
_MSI_FAILURE = re.compile(
    r"(?i)(?:\bReturn value 3\.|-- Installation (?:operation )?failed|"
    r"\berror status: (?!0\b|1641\b|3010\b)\d+|^Error \d{4}\.)"
)
_FAILURE_WORDS = re.compile(r"(?i)\b(?:exception|error|failed|failure|fatal)\b")


_ADAPTIVA_EXCEPTION_TAIL = re.compile(r",?\s*Error Code = -?\d+ \(0x[0-9A-Fa-f]+\)(?:,\s*Source Object = [^,\]]*)?")


def cause_signature(text: str) -> str:
    """Normalised root cause, without Adaptiva's ``Error Message = ... Error Code = n`` wrapper."""
    value = _ADAPTIVA_EXCEPTION_TAIL.sub("", text).replace("Error Message = ", "")
    return normalize_signature(value)


def normalize_signature(text: str) -> str:
    """Collapse the variable parts of a message so repeats group together.

    HRESULT-style codes (``0x80070643``) are kept: different codes are different problems.
    """
    value = redact(text)
    for pattern, replacement in _NORMALISERS:
        value = pattern.sub(replacement, value)
    value = _WHITESPACE.sub(" ", value).strip(" -:")
    return value[:SIGNATURE_MAX_CHARS] or "(empty message)"


def exception_head(entry: LogEntry) -> str | None:
    """The first exception line attached to the entry (not a ``Caused by``)."""
    for line in entry.detail[:MATCH_DETAIL_LINES]:
        stripped = line.strip()
        if stripped.startswith("Caused by:") or _STACK_FRAME.match(line):
            continue
        if _EXCEPTION_HEAD.match(stripped):
            return stripped
    match = _FQ_EXCEPTION.search(entry.message)
    return match.group(0) if match else None


def root_cause(entry: LogEntry) -> str | None:
    """The deepest ``Caused by:`` line of an attached stack trace."""
    cause = None
    for line in entry.detail:
        stripped = line.strip()
        if stripped.startswith("Caused by:"):
            cause = stripped[len("Caused by:"):].strip()
    return cause


def effective_severity(entry: LogEntry) -> tuple[str, str | None]:
    """Severity to rank on, and why it differs from the written level (if it does).

    TPM sometimes logs real failures at INFO - the documented Services sensor issue is
    an INFO line carrying an exception - so strong failure evidence raises the level.
    """
    level = entry.level
    if level in ("WARN", "ERROR", "FATAL"):
        return level, None

    has_trace = any(
        _STACK_FRAME.match(line) or line.lstrip().startswith("Caused by:")
        for line in entry.detail[:MATCH_DETAIL_LINES]
    )
    if has_trace:
        return "ERROR", f"{level or 'untagged'} entry carries a stack trace"
    code = _ADAPTIVA_ERROR_CODE.search(entry.message) or next(
        (m for m in (_ADAPTIVA_ERROR_CODE.search(line) for line in entry.detail[:MATCH_DETAIL_LINES]) if m),
        None,
    )
    if code and code.group(1) != "0":
        return "ERROR", f"{level or 'untagged'} entry reports Error Code = {code.group(1)}"
    if _MSI_FAILURE.search(entry.message):
        return "ERROR", "Windows Installer reported a failure"
    exception = _FQ_EXCEPTION.search(entry.message)
    if exception:
        return "WARN", f"{level or 'untagged'} entry mentions {exception.group(0)}"
    if level is None and _FAILURE_WORDS.search(entry.message[:300]):
        return "WARN", "untagged line contains a failure keyword"
    return level or "INFO", None


def severity_rank(severity: str | None) -> int:
    return LEVEL_RANK.get(severity or "INFO", LEVEL_RANK["INFO"])


# --------------------------------------------------------------------------- #
# Known issues
# --------------------------------------------------------------------------- #

#: One pattern that matches anything any built-in issue could match: a cheap pre-filter.
_BUILTIN_ANY = re.compile(
    "|".join(f"(?:{issue.pattern.pattern})" for issue in KNOWN_ISSUES),
    re.IGNORECASE | re.DOTALL,
)
#: (knowledge version, pre-filter or None, catalog) - rebuilt when the site file changes.
_CATALOG_CACHE: tuple[int, re.Pattern[str] | None, tuple[KnownIssue, ...]] | None = None


def known_issue_catalog() -> tuple[re.Pattern[str] | None, tuple[KnownIssue, ...]]:
    """Site-specific issues first, then the built-ins, with a combined pre-filter."""
    global _CATALOG_CACHE
    custom = customknowledge.active()
    if _CATALOG_CACHE is None or _CATALOG_CACHE[0] != custom.version:
        if custom.issues:
            replaced = {issue.id.lower() for issue in custom.issues}
            catalog = custom.issues + tuple(i for i in KNOWN_ISSUES if i.id.lower() not in replaced)
            try:
                union: re.Pattern[str] | None = re.compile(
                    "|".join(f"(?:{issue.pattern.pattern})" for issue in catalog), re.IGNORECASE | re.DOTALL
                )
            except re.error:
                union = None  # a site pattern the union cannot hold: match one by one instead
        else:
            catalog, union = KNOWN_ISSUES, _BUILTIN_ANY
        _CATALOG_CACHE = (custom.version, union, catalog)
    return _CATALOG_CACHE[1], _CATALOG_CACHE[2]


def match_haystack(entry: LogEntry) -> str:
    if not entry.detail:
        return entry.message
    return entry.message + "\n" + "\n".join(entry.detail[:MATCH_DETAIL_LINES])


def known_issue_by_id(issue_id: str | None) -> KnownIssue | None:
    """Look an issue up by id, site knowledge file first."""
    wanted = (issue_id or "").strip().lower()
    if not wanted:
        return None
    _, catalog = known_issue_catalog()
    return next((issue for issue in catalog if issue.id.lower() == wanted), None)


def match_known_issue(entry: LogEntry, haystack: str | None = None) -> KnownIssue | None:
    """First known issue (in catalog priority order) whose pattern matches."""
    haystack = haystack if haystack is not None else match_haystack(entry)
    union, catalog = known_issue_catalog()
    if union is not None and not union.search(haystack):
        return None
    for issue in catalog:
        if issue.pattern.search(haystack):
            return issue
    return None


# --------------------------------------------------------------------------- #
# Enriched event
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class Event:
    """A parsed entry plus everything the tools compute about it."""

    entry: LogEntry
    source: str
    device: str
    role: str
    file: str
    log_name: str
    severity: str
    severity_reason: str | None
    signature: str
    exception: str | None
    root_cause: str | None
    codes: list[DecodedCode]
    known: KnownIssue | None

    @property
    def timestamp(self) -> datetime | None:
        return self.entry.timestamp

    @property
    def is_noise(self) -> bool:
        return self.known is not None and self.known.is_noise

    def dedupe_key(self) -> tuple[Any, ...]:
        """Identity across files: TPM writes the same event to several logs."""
        entry = self.entry
        if entry.timestamp is None:
            return (self.device, self.file, entry.line)
        return (self.device, entry.timestamp, entry.level, entry.tid, entry.message[:200])

    def group_key(self) -> tuple[str, str, str]:
        return (self.severity, self.entry.component or "-", self.signature)


def classify(entry: LogEntry, *, source: str, device: str, role: str, file: str, log_name: str) -> Event:
    """Enrich one entry. Cheap enough to run on every entry a tool keeps."""
    severity, reason = effective_severity(entry)
    haystack = match_haystack(entry)
    head = exception_head(entry)
    cause = root_cause(entry)
    base = entry.message.strip()
    if len(base) < 12 and head:
        base = f"{base} | {head}" if base else head
    return Event(
        entry=entry,
        source=source,
        device=device,
        role=role,
        file=file,
        log_name=log_name,
        severity=severity,
        severity_reason=reason,
        signature=normalize_signature(base),
        exception=redact(head) if head else None,
        root_cause=redact(cause) if cause else None,
        codes=extract_codes(haystack),
        known=match_known_issue(entry, haystack),
    )


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat(sep=" ", timespec="milliseconds")


def event_view(
    event: Event,
    *,
    message_chars: int = OUTPUT_MESSAGE_CHARS,
    detail_lines: int = OUTPUT_DETAIL_LINES,
    detail_chars: int = OUTPUT_DETAIL_CHARS,
    include_thread: bool = False,
    include_codes: bool = True,
) -> dict[str, Any]:
    """A redacted, size-limited rendering of one event for tool output."""
    entry = event.entry
    view: dict[str, Any] = {
        "timestamp": iso(entry.timestamp),
        "level": entry.level,
        "severity": event.severity,
        "device": event.device,
        "log": event.file,
        "line": entry.line,
        "component": entry.component,
        "message": redact(entry.message)[:message_chars],
    }
    if event.severity_reason:
        view["severity_reason"] = event.severity_reason
    if include_thread and entry.thread:
        view["thread"] = redact(entry.thread)[:200]
    if entry.time_inferred:
        view["time_inferred"] = True
    if entry.detail and detail_lines > 0:
        view["detail"] = [redact(line)[:detail_chars] for line in entry.detail[:detail_lines]]
        if entry.detail_count > detail_lines:
            view["detail_lines_not_shown"] = entry.detail_count - detail_lines
    if event.root_cause:
        view["root_cause"] = event.root_cause[:OUTPUT_DETAIL_CHARS]
    if include_codes and event.codes:
        view["codes"] = [code.to_dict() for code in event.codes[:6]]
    if event.known:
        view["known_issue"] = event.known.id
    return view


# --------------------------------------------------------------------------- #
# Structured extractions used by the playbooks
# --------------------------------------------------------------------------- #

_PATCH_RESULT = re.compile(
    r"Completion status for patch \[(?P<patch>[^\]]*)\], request \[(?P<request>[^\]]*)\] is "
    r"\[PatchDeploymentResult"
)
_RESULT_FIELD = {
    name: re.compile(rf"\b{name}=\[?(-?[\w.]+)\]?")
    for name in ("operation", "softwareDeploymentOperationStatus", "reasonCode", "wuaRebootRequired")
}
_REASON_MESSAGE = re.compile(r"reasonMessage='(?P<msg>.*?)(?:'\s*,\s*\w+=|'\s*\]|$)", re.DOTALL)


def extract_patch_result(entry: LogEntry) -> dict[str, Any] | None:
    """Fields of a ``PatchDeploymentResult`` completion line.

    Tenable does not document what the status and reason numbers mean, so they are
    reported as logged; a site knowledge file can map them (``patch_deployment_results``)
    and the meanings are then attached here.
    """
    if "PatchDeploymentResult" not in entry.message:
        return None
    text = entry.text(MATCH_DETAIL_LINES)
    match = _PATCH_RESULT.search(text)
    if not match:
        return None
    fields = {name: (m.group(1) if (m := pattern.search(text)) else None) for name, pattern in _RESULT_FIELD.items()}
    reason = _REASON_MESSAGE.search(text)
    reason_text = reason.group("msg").strip() if reason else ""
    evidence = []
    if fields["reasonCode"] not in (None, "0"):
        evidence.append(f"reasonCode={fields['reasonCode']}")
    exception = _FQ_EXCEPTION.search(reason_text)
    if exception:
        evidence.append(f"reasonMessage mentions {exception.group(0)}")
    result = {
        "patch_id": match.group("patch"),
        "request_id": match.group("request"),
        "operation": fields["operation"],
        "operation_status": fields["softwareDeploymentOperationStatus"],
        "reason_code": fields["reasonCode"],
        "reboot_required": fields["wuaRebootRequired"],
        "reason_message": redact(_WHITESPACE.sub(" ", reason_text))[:400] or None,
        "failure_evidence": evidence,
    }
    custom = customknowledge.active()
    if custom.deployment_results:
        meanings = {
            f"{name}_meaning": meaning
            for name in ("operation", "operation_status", "reason_code", "reboot_required")
            if (meaning := custom.decode_result(name, result.get(name))) is not None
        }
        result.update(meanings)
    return result


_MESSAGE_RETRY = re.compile(
    r"The message has been retried (?P<count>\d+) times \. Message is :Name of the message: (?P<name>\w+)"
    r".*?Receiver ID: (?P<receiver>\d+)"
)
_INSTALL_AUTH_IP = re.compile(r"install attempted without auth information: /?(?P<ip>[\w.:%-]+)")
_BINDING = re.compile(r"Started with binding \[(?P<url>[^\]]+)\]")
_VERSION = re.compile(r"Current Version: (?P<version>\d+(?:\.\d+){2,3})")
_FREE_SPACE = re.compile(r"Drive \[(?P<drive>\w+)\].{0,80}?actualFreeSpace\D{0,60}?(?P<bytes>\d{4,})|"
                         r"actualFreeSpace\D{0,60}?(?P<bytes2>\d{4,})")
_DETECTIONS = re.compile(
    r"Processing (?P<count>\d+) vulnerability detections that were marked as (?P<kind>NEW|REMOVED/FIXED/CLOSED)"
)


def extract_message_retry(entry: LogEntry) -> dict[str, Any] | None:
    match = _MESSAGE_RETRY.search(entry.message)
    if not match:
        return None
    return {
        "receiver_client_id": match.group("receiver"),
        "message": match.group("name"),
        "retry_count": int(match.group("count")),
    }


def extract_install_auth_ip(entry: LogEntry) -> str | None:
    match = _INSTALL_AUTH_IP.search(entry.message)
    return match.group("ip") if match else None


def extract_binding(entry: LogEntry) -> str | None:
    match = _BINDING.search(entry.message)
    return match.group("url") if match else None


def extract_version(entry: LogEntry) -> str | None:
    match = _VERSION.search(entry.message)
    return match.group("version") if match else None


def extract_free_space(entry: LogEntry) -> tuple[str | None, int] | None:
    match = _FREE_SPACE.search(entry.message)
    if not match:
        return None
    raw = match.group("bytes") or match.group("bytes2")
    return match.group("drive"), int(raw)


def extract_detections(entry: LogEntry) -> tuple[str, int] | None:
    match = _DETECTIONS.search(entry.message)
    if not match:
        return None
    return match.group("kind"), int(match.group("count"))
