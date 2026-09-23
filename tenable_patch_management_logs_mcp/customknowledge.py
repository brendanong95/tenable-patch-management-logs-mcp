"""Site-specific known issues and value mappings, loaded from a file.

The built-in catalog in :mod:`knowledge` is a starting point: it cannot know your
environment's own recurring errors, the noise you have already decided to ignore, or
what the undocumented ``PatchDeploymentResult`` numbers mean in your console. A
knowledge file adds those without touching the code, and is picked up on the next
call after it changes.

Where it is read from, in order:

1. ``TPM_KNOWLEDGE_FILE`` - a .json/.yaml file, a folder of them, or several paths
   separated by ``;``
2. ``known_issues.json`` / ``.yaml`` in the data dir (``TPM_MCP_DATA_DIR``, default
   ``data/`` beside the package)

Shape (YAML needs PyYAML installed; JSON always works)::

    {
      "known_issues": [
        {
          "id": "acme_proxy_407",                  # required, unique
          "title": "Proxy rejects client downloads",   # required
          "pattern": "HTTP/1.1 407 Proxy Authentication Required",   # required, regex
          "impact": "high",                        # high | medium | low | none (noise)
          "category": "connectivity",
          "explanation": "...",
          "remediation": "...",
          "applies_to": "client",                  # client | server | both
          "confidence": "site",                    # site | documented | observed | generic
          "source": "https://acme.example/runbook/407"
        }
      ],
      "patch_deployment_results": {
        "operation": {"1": "Install"},
        "operation_status": {"3": "Failed"},
        "reason_code": {"3010": "Success, reboot required"}
      }
    }

Custom issues are matched before the built-in ones, so an entry that reuses a built-in
id replaces it. Everything loaded is reported by ``check_log_sources``, including the
entries that were rejected and why - a knowledge file never fails silently.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .knowledge import IMPACT_ORDER, KNOWN_ISSUES_BY_ID, KnownIssue

ENV_FILE = "TPM_KNOWLEDGE_FILE"
DEFAULT_BASENAMES = ("known_issues", "tpm_known_issues")
JSON_SUFFIXES = (".json",)
YAML_SUFFIXES = (".yaml", ".yml")
#: A changed file is picked up on the first call this many seconds after the last check.
RELOAD_INTERVAL_SECONDS = 5.0
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_ISSUES = 500
MAX_PATTERN_CHARS = 500
MAX_TEXT_CHARS = 4_000
MAX_MAPPING_ENTRIES = 500
CONFIDENCES = ("site", "documented", "observed", "generic")
APPLIES_TO = ("both", "client", "server")
RESULT_FIELDS = ("operation", "operation_status", "reason_code", "reboot_required")
#: Sections a knowledge file may hold; anything else is reported (keys starting with _ are notes).
_TOP_LEVEL_KEYS = frozenset({"known_issues", "patch_deployment_results"})

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
DEFAULT_EXPLANATION = "Site-specific signature from the knowledge file."
DEFAULT_REMEDIATION = "See your own runbook for this signature."
DEFAULT_SOURCE = "site knowledge file"


@dataclass
class CustomKnowledge:
    """What a knowledge file contributed, and what it got wrong."""

    issues: tuple[KnownIssue, ...] = ()
    deployment_results: dict[str, dict[str, str]] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    overrides: list[str] = field(default_factory=list)
    loaded_at: str | None = None
    #: Bumped on every load so caches built from these issues can tell they are stale.
    version: int = 0

    @property
    def configured(self) -> bool:
        return bool(self.files or self.problems)

    def issue_by_id(self, issue_id: str) -> KnownIssue | None:
        wanted = (issue_id or "").strip().lower()
        return next((issue for issue in self.issues if issue.id.lower() == wanted), None)

    def decode_result(self, field_name: str, value: str | None) -> str | None:
        """Meaning of a PatchDeploymentResult value, when the site has mapped it."""
        if value is None:
            return None
        return self.deployment_results.get(field_name, {}).get(str(value).strip())

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "configured": self.configured,
            "files": self.files,
            "known_issues_loaded": len(self.issues),
            "patch_deployment_result_mappings": {
                name: len(values) for name, values in sorted(self.deployment_results.items())
            },
            "loaded_at": self.loaded_at,
        }
        if self.overrides:
            data["built_in_issues_replaced"] = self.overrides
        if self.problems:
            data["problems"] = self.problems
            data["remediation"] = (
                "Fix the entries listed above; the rest of the file was still loaded. Each known issue needs "
                "id, title and a valid regular expression in pattern."
            )
        if not self.configured:
            data["note"] = (
                f"No knowledge file. Add your own signatures, noise and PatchDeploymentResult meanings in "
                f"{ENV_FILE} or known_issues.json in the data dir."
            )
        return data


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #


def _data_dir(env: Mapping[str, str]) -> Path:
    from .sources import default_data_dir  # deferred: sources imports knowledge, not this module

    return default_data_dir(env)


def candidate_files(env: Mapping[str, str]) -> list[Path]:
    """Every knowledge file the configuration points at, in load order."""
    paths: list[Path] = []
    configured = (env.get(ENV_FILE) or "").strip()
    for item in configured.split(";"):
        item = item.strip().strip('"')
        if not item:
            continue
        path = Path(item).expanduser()
        if path.is_dir():
            paths.extend(sorted(p for p in path.iterdir()
                                if p.is_file() and p.suffix.lower() in JSON_SUFFIXES + YAML_SUFFIXES))
        else:
            paths.append(path)
    if not configured:
        data_dir = _data_dir(env)
        for basename in DEFAULT_BASENAMES:
            for suffix in JSON_SUFFIXES + YAML_SUFFIXES:
                candidate = data_dir / f"{basename}{suffix}"
                if candidate.is_file():
                    paths.append(candidate)
    return paths


def _read_document(path: Path, problems: list[str]) -> Any:
    try:
        size = path.stat().st_size
    except OSError as exc:
        problems.append(f"{path}: {exc}")
        return None
    if size > MAX_FILE_BYTES:
        problems.append(f"{path}: larger than {MAX_FILE_BYTES // 1024**2} MB; not loaded.")
        return None
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        problems.append(f"{path}: {exc}")
        return None
    if path.suffix.lower() in YAML_SUFFIXES:
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError:
            problems.append(f"{path}: YAML needs PyYAML installed (pip install pyyaml), or use JSON.")
            return None
        try:
            return yaml.safe_load(text)
        except Exception as exc:  # noqa: BLE001 - any parse error, reported not raised
            problems.append(f"{path}: invalid YAML - {exc}")
            return None
    try:
        return json.loads(text)
    except ValueError as exc:
        problems.append(f"{path}: invalid JSON - {exc}")
        return None


def _text(record: Mapping[str, Any], key: str, default: str = "") -> str:
    value = record.get(key, default)
    return str(value).strip()[:MAX_TEXT_CHARS] if value is not None else ""


def _build_issue(record: Any, where: str, problems: list[str]) -> KnownIssue | None:
    if not isinstance(record, Mapping):
        problems.append(f"{where}: expected an object with id, title and pattern.")
        return None
    issue_id = _text(record, "id")
    if not _ID.match(issue_id):
        problems.append(f"{where}: id '{issue_id or '(missing)'}' must be 1-64 letters, digits, '.', '_' or '-'.")
        return None
    title = _text(record, "title")
    if not title:
        problems.append(f"{where}: '{issue_id}' has no title.")
        return None
    pattern = _text(record, "pattern")
    if not pattern:
        problems.append(f"{where}: '{issue_id}' has no pattern.")
        return None
    if len(pattern) > MAX_PATTERN_CHARS:
        problems.append(f"{where}: '{issue_id}' pattern is longer than {MAX_PATTERN_CHARS} characters.")
        return None
    try:
        compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
    except re.error as exc:
        problems.append(f"{where}: '{issue_id}' pattern is not a valid regular expression - {exc}")
        return None
    impact = _text(record, "impact", "medium").lower() or "medium"
    if impact not in IMPACT_ORDER:
        problems.append(f"{where}: '{issue_id}' impact must be one of {', '.join(IMPACT_ORDER)} (got '{impact}').")
        return None
    confidence = _text(record, "confidence", "site").lower() or "site"
    if confidence not in CONFIDENCES:
        problems.append(
            f"{where}: '{issue_id}' confidence must be one of {', '.join(CONFIDENCES)} (got '{confidence}')."
        )
        return None
    applies_to = _text(record, "applies_to", "both").lower() or "both"
    if applies_to not in APPLIES_TO:
        problems.append(f"{where}: '{issue_id}' applies_to must be one of {', '.join(APPLIES_TO)}.")
        return None
    return KnownIssue(
        id=issue_id,
        title=title,
        pattern=compiled,
        category=_text(record, "category", "site") or "site",
        impact=impact,
        explanation=_text(record, "explanation") or DEFAULT_EXPLANATION,
        remediation=_text(record, "remediation") or DEFAULT_REMEDIATION,
        confidence=confidence,
        applies_to=applies_to,
        source=_text(record, "source") or DEFAULT_SOURCE,
    )


def _build_mappings(record: Any, where: str, problems: list[str]) -> dict[str, dict[str, str]]:
    if record is None:
        return {}
    if not isinstance(record, Mapping):
        problems.append(f"{where}: patch_deployment_results must be an object keyed by field name.")
        return {}
    mappings: dict[str, dict[str, str]] = {}
    for name, values in record.items():
        field_name = str(name).strip().lower()
        if field_name not in RESULT_FIELDS:
            problems.append(
                f"{where}: patch_deployment_results.{name} is not a known field "
                f"({', '.join(RESULT_FIELDS)})."
            )
            continue
        if not isinstance(values, Mapping):
            problems.append(f"{where}: patch_deployment_results.{field_name} must map values to meanings.")
            continue
        table = mappings.setdefault(field_name, {})
        for key, meaning in list(values.items())[:MAX_MAPPING_ENTRIES]:
            table[str(key).strip()] = str(meaning).strip()[:MAX_TEXT_CHARS]
    return mappings


def load(env: Mapping[str, str] | None = None) -> CustomKnowledge:
    """Read every configured knowledge file. Never raises: problems are collected."""
    env = os.environ if env is None else env
    problems: list[str] = []
    issues: list[KnownIssue] = []
    seen: dict[str, str] = {}
    overrides: list[str] = []
    mappings: dict[str, dict[str, str]] = {}
    files: list[str] = []
    for path in candidate_files(env):
        if not path.is_file():
            problems.append(f"{path}: not found.")
            continue
        document = _read_document(path, problems)
        if document is None:
            continue
        if not isinstance(document, Mapping):
            problems.append(f"{path}: expected an object with known_issues and/or patch_deployment_results.")
            continue
        files.append(str(path))
        unknown = [str(key) for key in document if str(key) not in _TOP_LEVEL_KEYS and not str(key).startswith("_")]
        if unknown:
            problems.append(
                f"{path.name}: ignored unknown section(s) {', '.join(sorted(unknown))}; expected "
                f"{' and/or '.join(sorted(_TOP_LEVEL_KEYS))}."
            )
        records = document.get("known_issues") or []
        if not isinstance(records, Iterable) or isinstance(records, (str, bytes, Mapping)):
            problems.append(f"{path}: known_issues must be a list.")
            records = []
        for index, record in enumerate(list(records)[:MAX_ISSUES], start=1):
            issue = _build_issue(record, f"{path.name}[{index}]", problems)
            if issue is None:
                continue
            key = issue.id.lower()
            if key in seen:
                problems.append(f"{path.name}[{index}]: id '{issue.id}' already defined in {seen[key]}; skipped.")
                continue
            seen[key] = path.name
            if key in KNOWN_ISSUES_BY_ID:
                overrides.append(issue.id)
            issues.append(issue)
        for name, table in _build_mappings(document.get("patch_deployment_results"), path.name, problems).items():
            mappings.setdefault(name, {}).update(table)
    return CustomKnowledge(
        issues=tuple(issues),
        deployment_results=mappings,
        files=files,
        problems=problems,
        overrides=overrides,
        loaded_at=datetime.now(timezone.utc).isoformat(timespec="seconds") if files or problems else None,
        version=_next_version(),
    )


_versions = 0


def _next_version() -> int:
    global _versions
    _versions += 1
    return _versions


# --------------------------------------------------------------------------- #
# Cache
# --------------------------------------------------------------------------- #

#: config key -> (last check, file fingerprint, knowledge). One entry per distinct config.
_STATE: dict[tuple[str, str], tuple[float, Any, CustomKnowledge]] = {}


def _config_key(env: Mapping[str, str]) -> tuple[str, str]:
    return ((env.get(ENV_FILE) or "").strip(), (env.get("TPM_MCP_DATA_DIR") or "").strip())


def _fingerprint(env: Mapping[str, str]) -> Any:
    """Cheap signature of the files the configuration points at."""
    stamps = []
    for path in candidate_files(env):
        try:
            stat = path.stat()
            stamps.append((str(path), stat.st_size, stat.st_mtime_ns))
        except OSError:
            stamps.append((str(path), -1, 0))
    return tuple(stamps)


def active(env: Mapping[str, str] | None = None) -> CustomKnowledge:
    """The loaded knowledge, re-reading the files when they change on disk."""
    env = os.environ if env is None else env
    key = _config_key(env)
    now = time.monotonic()
    entry = _STATE.get(key)
    if entry is not None and now - entry[0] < RELOAD_INTERVAL_SECONDS:
        return entry[2]
    fingerprint = _fingerprint(env)
    if entry is not None and fingerprint == entry[1]:
        _STATE[key] = (now, fingerprint, entry[2])
        return entry[2]
    knowledge = load(env)
    _STATE[key] = (now, fingerprint, knowledge)
    return knowledge


def reload(env: Mapping[str, str] | None = None) -> CustomKnowledge:
    """Force a re-read; used after a file is edited and by the tests."""
    env = os.environ if env is None else env
    knowledge = load(env)
    _STATE[_config_key(env)] = (time.monotonic(), _fingerprint(env), knowledge)
    return knowledge


def reset() -> None:
    """Forget everything loaded; the next call reads the files again."""
    _STATE.clear()
