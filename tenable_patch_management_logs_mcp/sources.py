"""Log sources: where logs come from, and what each file is.

A source is a folder (local or UNC), a single log file, or a .zip / .tar.gz bundle -
for example the SaaS "Download All Server Logs" zip or a collector bundle. Bundles are
extracted once into ``<data dir>/bundles`` with path-traversal and size guards; the
original file is never modified.

Sources come from three places, in order of precedence:

1. ``TPM_LOG_SOURCES`` - ``name=path;name2=path2``
2. sources added at runtime with ``add_log_source`` (persisted to ``sources.json``)
3. TPM installed on this machine (``TPM_AUTO_DISCOVER``, default on)

For each file this module works out the device it came from, whether it is a server,
client or setup log, and its logical name (``adaptiva.2.log`` -> ``adaptiva.log``).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import tarfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .errors import InputError, NoSourcesError, SourceError
from .knowledge import CLIENT_ONLY_LOGS, LOG_CATALOG, LOG_ACQUISITION, SERVER_ONLY_LOGS, SETUP_LOGS

# --------------------------------------------------------------------------- #
# Tunable constants
# --------------------------------------------------------------------------- #

SOURCES_FILENAME = "sources.json"
BUNDLES_DIRNAME = "bundles"
#: Refuse to extract more than this from one bundle (zip-bomb guard).
MAX_BUNDLE_BYTES = 8 * 1024**3
MAX_BUNDLE_FILES = 100_000
#: Archives inside archives are unpacked this many levels deep.
MAX_NESTED_ARCHIVE_DEPTH = 2
#: Files listed per source before the listing is reported as truncated.
MAX_FILES_PER_SOURCE = 20_000
#: Bytes read per chunk when scanning a file for deployment markers and versions.
FACT_SCAN_CHUNK_BYTES = 4 * 1024 * 1024
#: Largest number of adaptiva.log / adaptiva.err files scanned for facts per source.
FACT_SCAN_MAX_FILES = 24

ROLE_SERVER = "server"
ROLE_CLIENT = "client"
ROLE_SETUP = "setup"
ROLE_UNKNOWN = "unknown"
ROLES = (ROLE_SERVER, ROLE_CLIENT, ROLE_SETUP, ROLE_UNKNOWN)

DEPLOYMENT_SAAS = "saas"
DEPLOYMENT_ONPREM = "onprem"
DEPLOYMENT_AUTO = "auto"
DEPLOYMENT_HINTS = (DEPLOYMENT_SAAS, DEPLOYMENT_ONPREM, DEPLOYMENT_AUTO)

KIND_FOLDER = "folder"
KIND_FILE = "file"
KIND_BUNDLE = "bundle"

_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_LOG_SUFFIXES = (".log", ".err", ".txt", ".properties")
_ROTATED_SUFFIX_NAME = re.compile(r"\.(?:log|err|txt)\.\d{1,3}$", re.IGNORECASE)
_ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz")

_SERVER_DIRS = frozenset({"adaptiva-server", "adaptivaserver", "adaptiva server", "patchserver"})
_CLIENT_DIRS = frozenset({"adaptiva-client", "adaptivaclient", "adaptiva client", "patchclient"})
_LAYOUT_DIRS = _SERVER_DIRS | _CLIENT_DIRS | frozenset(
    {"logs", "componentlogs", "workflowlogs", "msilogs", "adaptivasetuplogs", "client", "server", "tenable",
     "adaptiva"}
)

_ROTATED_MIDDLE = re.compile(r"^(?P<stem>.+?)\.(?P<n>\d{1,3})\.(?P<ext>log|err|txt)$", re.IGNORECASE)
_ROTATED_SUFFIX = re.compile(r"^(?P<stem>.+?)\.(?P<ext>log|err|txt)\.(?P<n>\d{1,3})$", re.IGNORECASE)
_CLIENT_PREFIX = re.compile(r"^(?P<client>\d{1,9})_(?P<rest>.+)$")
_HS_ERR = re.compile(r"^hs_err_pid\d+\.log$", re.IGNORECASE)
_WORKFLOW_FILE = re.compile(r"^(?P<workflow>.+)_(?P<id>\d+)_(?P<seq>\d+)\.log$", re.IGNORECASE)

_SAAS_BINDING = re.compile(rb"https://[0-9a-fA-F-]{36}\.adaptiva\.cloud/http2")
_VERSION_LINE = re.compile(
    rb"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[,.]\d{3}) - INFO - Current Version: (\d+(?:\.\d+){2,3})"
)
_BYTE_MARKERS: dict[bytes, tuple[str, str]] = {
    b"jdbc:postgresql": (DEPLOYMENT_SAAS, "server database is PostgreSQL (TPM SaaS; on-prem uses SQL Server)"),
    b"/opt/adaptiva/adaptiva-server": (DEPLOYMENT_SAAS, "server runs from /opt/adaptiva/adaptiva-server (SaaS)"),
    b"jdbc:sqlserver": (DEPLOYMENT_ONPREM, "server database is SQL Server (on-prem)"),
}


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class Source:
    name: str
    path: str
    origin: str  # env | runtime | auto
    deployment_hint: str = DEPLOYMENT_AUTO
    added_at: str | None = None
    kind: str = KIND_FOLDER
    root: Path | None = None
    single_file: Path | None = None
    error: str | None = None

    @property
    def available(self) -> bool:
        return self.error is None and self.root is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "kind": self.kind,
            "origin": self.origin,
            "deployment_hint": self.deployment_hint,
            "added_at": self.added_at,
            "available": self.available,
            "error": self.error,
        }


@dataclass
class LogFile:
    source: str
    path: Path
    rel: str
    device: str
    role: str
    log_key: str
    display_name: str
    rotation: int
    size: int
    mtime: float
    client_id: str | None = None

    @property
    def compressed(self) -> bool:
        return self.path.name.lower().endswith(".gz")

    def to_dict(self) -> dict[str, Any]:
        info = LOG_CATALOG.get(self.log_key)
        return {
            "source": self.source,
            "file": self.rel,
            "device": self.device,
            "role": self.role,
            "log": self.display_name,
            "rotation": self.rotation,
            "size_kb": round(self.size / 1024, 1),
            "modified": datetime.fromtimestamp(self.mtime).isoformat(sep=" ", timespec="seconds"),
            "purpose": info.purpose(self.role) if info else None,
        }


@dataclass
class FileFacts:
    markers: dict[str, list[str]] = field(default_factory=dict)  # deployment -> evidence
    versions: dict[str, list[str]] = field(default_factory=dict)  # version -> [first ts, last ts]


# --------------------------------------------------------------------------- #
# Name, role and device detection
# --------------------------------------------------------------------------- #


#: Files written by our own collector scripts that are not logs.
_IGNORED_FILENAMES = frozenset({"collection-notes.txt"})


def is_log_filename(name: str) -> bool:
    lower = name.lower()
    if lower in _IGNORED_FILENAMES:
        return False
    if lower.endswith(".gz"):
        lower = lower[:-3]
    return lower.endswith(_LOG_SUFFIXES) or bool(_ROTATED_SUFFIX_NAME.search(lower))


def logical_name(filename: str, parent_dirs: Iterable[str] = ()) -> tuple[str, str, int, str | None]:
    """``(log_key, display_name, rotation, client_id)`` for a file name.

    ``adaptiva.2.log`` -> ``adaptiva.log`` (rotation 2); ``13_adaptiva.log`` -> client 13;
    workflow and MSI logs are grouped under their folder.
    """
    name = filename[:-3] if filename.lower().endswith(".gz") else filename
    parents = [part.lower() for part in parent_dirs]
    if parents and parents[-1] == "workflowlogs":
        match = _WORKFLOW_FILE.match(name)
        return "workflowlogs", match.group("workflow") if match else name, 0, None
    if parents and parents[-1] == "msilogs":
        return "msilogs", name, 0, None

    client_id = None
    prefixed = _CLIENT_PREFIX.match(name)
    if prefixed:
        rest_key = _strip_rotation(prefixed.group("rest"))[0].lower()
        if rest_key in LOG_CATALOG:
            client_id, name = prefixed.group("client"), prefixed.group("rest")

    if _HS_ERR.match(name):
        return "hs_err_pid.log", name, 0, client_id
    base, rotation = _strip_rotation(name)
    return base.lower(), base, rotation, client_id


def _strip_rotation(name: str) -> tuple[str, int]:
    for pattern in (_ROTATED_MIDDLE, _ROTATED_SUFFIX):
        match = pattern.match(name)
        if match and not match.group("stem")[-1].isdigit():
            return f"{match.group('stem')}.{match.group('ext')}", int(match.group("n"))
    return name, 0


def detect_role(context_parts: Iterable[str], log_key: str, client_id: str | None) -> str:
    parts = {part.lower() for part in context_parts}
    if parts & _SERVER_DIRS:
        return ROLE_SERVER
    if parts & _CLIENT_DIRS or client_id or "msilogs" in parts:
        return ROLE_CLIENT
    if "adaptivasetuplogs" in parts or log_key in SETUP_LOGS:
        return ROLE_SETUP
    if log_key in SERVER_ONLY_LOGS:
        return ROLE_SERVER
    if log_key in CLIENT_ONLY_LOGS:
        return ROLE_CLIENT
    return ROLE_UNKNOWN


def detect_device(parts: list[str], fallback: str, client_id: str | None = None) -> str:
    """The folder that sits directly above a TPM layout folder, e.g. ``WS-BAD07/PatchClient/logs``."""
    if client_id:
        return f"client-{client_id}"
    for index in range(len(parts) - 1):
        if parts[index].lower() not in _LAYOUT_DIRS and parts[index + 1].lower() in _LAYOUT_DIRS:
            return parts[index]
    return fallback


def _descend_wrappers(root: Path) -> tuple[Path, list[str]]:
    """Step through folders that only wrap a single sub-folder (typical zip packaging)."""
    wrappers: list[str] = []
    current = root
    for _ in range(4):
        try:
            entries = [entry for entry in os.scandir(current) if not entry.name.startswith(".")]
        except OSError:
            break
        folders = [entry for entry in entries if entry.is_dir()]
        if len(folders) == 1 and len(folders) == len(entries):
            wrappers.append(folders[0].name)
            current = Path(folders[0].path)
        else:
            break
    return current, wrappers


def _unc_host(path: str) -> str | None:
    match = re.match(r"^\\\\([^\\]+)\\", path)
    return match.group(1) if match else None


# --------------------------------------------------------------------------- #
# Bundle extraction
# --------------------------------------------------------------------------- #


class _Budget:
    def __init__(self) -> None:
        self.files = 0
        self.bytes = 0

    def add(self, size: int) -> None:
        self.bytes += size
        if self.bytes > MAX_BUNDLE_BYTES:
            raise SourceError(
                f"Bundle expands to more than {MAX_BUNDLE_BYTES // 1024**3} GB; refusing to extract it.",
                remediation="Extract the logs you need manually and register that folder instead.",
            )

    def count_file(self) -> None:
        self.files += 1
        if self.files > MAX_BUNDLE_FILES:
            raise SourceError(
                f"Bundle contains more than {MAX_BUNDLE_FILES} files; refusing to extract it.",
                remediation="Extract the logs you need manually and register that folder instead.",
            )


_UNSAFE_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')


def _safe_member_path(dest: Path, member_name: str) -> Path | None:
    normalized = member_name.replace("\\", "/")
    if normalized.startswith("/"):
        return None  # absolute paths have no place in a log bundle
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts) or re.match(r"^[A-Za-z]:$", parts[0]):
        return None
    target = dest.joinpath(*(_UNSAFE_CHARS.sub("_", part) for part in parts))
    try:
        target.resolve().relative_to(dest.resolve())
    except ValueError:
        return None
    return target


def _is_archive_name(name: str) -> bool:
    return name.lower().endswith(_ARCHIVE_SUFFIXES)


def _copy_stream(source: Any, target: Path, budget: _Budget) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "wb") as out:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            budget.add(len(chunk))
            out.write(chunk)


def _extract_archive(archive: Path, dest: Path, budget: _Budget, depth: int = 0) -> None:
    nested: list[Path] = []
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                target = _safe_member_path(dest, info.filename)
                if target is None:
                    continue
                budget.count_file()
                with zf.open(info) as member:
                    _copy_stream(member, target, budget)
                try:
                    stamp = datetime(*info.date_time).timestamp()
                    os.utime(target, (stamp, stamp))
                except (ValueError, OSError, OverflowError):
                    pass
                if _is_archive_name(target.name):
                    nested.append(target)
    elif tarfile.is_tarfile(archive):
        with tarfile.open(archive, "r:*") as tf:
            for member in tf:
                if not member.isfile():
                    continue
                target = _safe_member_path(dest, member.name)
                if target is None:
                    continue
                budget.count_file()
                handle = tf.extractfile(member)
                if handle is None:
                    continue
                with handle:
                    _copy_stream(handle, target, budget)
                try:
                    os.utime(target, (member.mtime, member.mtime))
                except (OSError, OverflowError):
                    pass
                if _is_archive_name(target.name):
                    nested.append(target)
    else:
        raise SourceError(f"'{archive}' is not a readable .zip or .tar(.gz) archive.")

    if depth < MAX_NESTED_ARCHIVE_DEPTH:
        for inner in nested:
            folder = inner.with_name(inner.name + ".d")
            try:
                _extract_archive(inner, folder, budget, depth + 1)
            except SourceError:
                continue
            inner.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #


def default_data_dir(env: Mapping[str, str] | None = None) -> Path:
    source = os.environ if env is None else env
    configured = (source.get("TPM_MCP_DATA_DIR") or "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path(__file__).resolve().parent.parent / "data"


class SourceRegistry:
    """Resolves configured sources and lists the log files inside them."""

    def __init__(self, data_dir: Path | None = None, env: Mapping[str, str] | None = None) -> None:
        self.env = os.environ if env is None else env
        self.data_dir = data_dir or default_data_dir(self.env)
        self._facts_cache: dict[tuple[str, int, int], FileFacts] = {}

    # -- configuration --------------------------------------------------------- #

    @property
    def sources_file(self) -> Path:
        return self.data_dir / SOURCES_FILENAME

    @property
    def bundles_dir(self) -> Path:
        return self.data_dir / BUNDLES_DIRNAME

    def global_deployment_hint(self) -> str:
        value = (self.env.get("TPM_DEPLOYMENT") or DEPLOYMENT_AUTO).strip().lower()
        return value if value in DEPLOYMENT_HINTS else DEPLOYMENT_AUTO

    def auto_discover_enabled(self) -> bool:
        return (self.env.get("TPM_AUTO_DISCOVER") or "true").strip().lower() not in ("0", "false", "no", "off")

    def _env_sources(self) -> list[Source]:
        raw = self.env.get("TPM_LOG_SOURCES") or ""
        sources = []
        for item in raw.split(";"):
            item = item.strip()
            if not item:
                continue
            if "=" not in item:
                sources.append(Source(name=item, path="", origin="env",
                                      error="Expected name=path in TPM_LOG_SOURCES"))
                continue
            name, path = (part.strip().strip('"') for part in item.split("=", 1))
            sources.append(Source(name=name, path=path, origin="env", deployment_hint=self.global_deployment_hint()))
        return sources

    def _runtime_sources(self) -> list[Source]:
        try:
            records = json.loads(self.sources_file.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return []
        except (OSError, ValueError):
            return []
        sources = []
        for record in records if isinstance(records, list) else []:
            if isinstance(record, dict) and record.get("name") and record.get("path"):
                sources.append(
                    Source(
                        name=str(record["name"]),
                        path=str(record["path"]),
                        origin="runtime",
                        deployment_hint=str(record.get("deployment") or DEPLOYMENT_AUTO),
                        added_at=record.get("added_at"),
                    )
                )
        return sources

    def _auto_sources(self) -> list[Source]:
        if not self.auto_discover_enabled():
            return []
        windir = self.env.get("WINDIR") or self.env.get("windir") or r"C:\Windows"
        candidates = [
            ("local-server", [self.env.get("ADAPTIVASERVER"), r"C:\Program Files\Tenable\PatchServer",
                              r"C:\Program Files\Adaptiva\AdaptivaServer"], "logs"),
            ("local-client", [self.env.get("ADAPTIVACLIENT"), r"C:\Program Files\Tenable\PatchClient",
                              r"C:\Program Files\Adaptiva\AdaptivaClient", "/opt/tenable/patchclient"], "logs"),
            ("local-setup", [os.path.join(windir, "AdaptivaSetupLogs")], ""),
        ]
        sources = []
        for name, roots, sub in candidates:
            for root in roots:
                if not root:
                    continue
                folder = Path(root) / sub if sub else Path(root)
                if folder.is_dir():
                    sources.append(Source(name=name, path=str(folder), origin="auto",
                                          deployment_hint=DEPLOYMENT_ONPREM if name == "local-server"
                                          else self.global_deployment_hint()))
                    break
        return sources

    def sources(self) -> list[Source]:
        """All configured sources, resolved (bundles extracted) and de-duplicated by name."""
        seen: set[str] = set()
        resolved: list[Source] = []
        for source in self._env_sources() + self._runtime_sources() + self._auto_sources():
            key = source.name.lower()
            if key in seen:
                continue
            seen.add(key)
            resolved.append(self._resolve(source))
        return resolved

    def _resolve(self, source: Source) -> Source:
        if source.error:
            return source
        if not _NAME_PATTERN.match(source.name):
            source.error = "Invalid source name (letters, digits, '.', '_' and '-' only)."
            return source
        path = Path(source.path).expanduser()
        try:
            if path.is_dir():
                source.kind, source.root = KIND_FOLDER, path
            elif path.is_file() and _is_archive_name(path.name):
                source.kind = KIND_BUNDLE
                source.root = self._ensure_extracted(path)
            elif path.is_file() and is_log_filename(path.name):
                source.kind, source.root, source.single_file = KIND_FILE, path.parent, path
            elif path.is_file():
                source.error = "Unsupported file type (expected a log file, .zip, .tar or .tar.gz)."
            else:
                source.error = f"Path not found or not accessible: {path}"
        except SourceError as exc:
            source.error = exc.message
        except OSError as exc:
            source.error = f"{type(exc).__name__}: {exc}"
        return source

    def _ensure_extracted(self, archive: Path) -> Path:
        stat = archive.stat()
        key = hashlib.sha1(f"{archive.resolve()}|{stat.st_size}|{stat.st_mtime_ns}".encode()).hexdigest()[:16]
        dest = self.bundles_dir / key
        marker = dest / ".complete"
        if marker.exists():
            return dest
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True, exist_ok=True)
        try:
            _extract_archive(archive, dest, _Budget())
        except Exception:
            shutil.rmtree(dest, ignore_errors=True)
            raise
        marker.write_text(
            json.dumps({"archive": str(archive), "extracted_at": _utc_now_iso()}), encoding="utf-8"
        )
        return dest

    # -- selection ----------------------------------------------------------------- #

    def select(self, name: str | None) -> list[Source]:
        """``None``/``"all"`` -> every available source; otherwise the named one."""
        sources = self.sources()
        if not sources:
            raise NoSourcesError(
                "No log sources are configured.",
                remediation=(
                    "Add logs with add_log_source(name, path) - a folder, UNC path, single log file, or a "
                    ".zip/.tar.gz bundle - or set TPM_LOG_SOURCES. " + LOG_ACQUISITION["saas_server"]
                ),
            )
        if name and name.strip().lower() not in ("all", "*"):
            wanted = name.strip().lower()
            for source in sources:
                if source.name.lower() == wanted:
                    if not source.available:
                        raise SourceError(f"Source '{source.name}' is unavailable: {source.error}")
                    return [source]
            raise InputError(
                f"Unknown source '{name}'. Configured: {', '.join(s.name for s in sources)}.",
                remediation="Pass one of the configured names, or omit source to use all of them.",
            )
        available = [source for source in sources if source.available]
        if not available:
            raise SourceError(
                "None of the configured sources can be read: "
                + "; ".join(f"{s.name}: {s.error}" for s in sources)
            )
        return available

    # -- runtime management ---------------------------------------------------------- #

    def add(self, name: str, path: str, deployment: str = DEPLOYMENT_AUTO) -> Source:
        name = (name or "").strip()
        path = (path or "").strip().strip('"')
        deployment = (deployment or DEPLOYMENT_AUTO).strip().lower()
        if not _NAME_PATTERN.match(name):
            raise InputError(
                f"Invalid source name '{name}'.",
                remediation="Use 1-64 letters, digits, '.', '_' or '-', starting with a letter or digit.",
            )
        if deployment not in DEPLOYMENT_HINTS:
            raise InputError(f"deployment must be one of {', '.join(DEPLOYMENT_HINTS)} (got '{deployment}').")
        if not path:
            raise InputError("path is required.")
        existing = {source.name.lower(): source for source in self.sources()}
        clash = existing.get(name.lower())
        if clash is not None and clash.origin != "runtime":
            raise InputError(
                f"A source named '{name}' already comes from {clash.origin} configuration.",
                remediation="Choose a different name.",
            )
        source = self._resolve(Source(name=name, path=path, origin="runtime", deployment_hint=deployment,
                                      added_at=_utc_now_iso()))
        if not source.available:
            raise SourceError(f"Cannot use '{path}': {source.error}")
        records = [r for r in self._read_records() if str(r.get("name", "")).lower() != name.lower()]
        records.append({"name": name, "path": path, "deployment": deployment, "added_at": source.added_at})
        self._write_records(records)
        return source

    def remove(self, name: str) -> dict[str, Any]:
        wanted = (name or "").strip().lower()
        records = self._read_records()
        match = next((r for r in records if str(r.get("name", "")).lower() == wanted), None)
        if match is None:
            origin = next((s.origin for s in self.sources() if s.name.lower() == wanted), None)
            if origin:
                raise InputError(
                    f"Source '{name}' comes from {origin} configuration and cannot be removed here.",
                    remediation="Edit TPM_LOG_SOURCES, or set TPM_AUTO_DISCOVER=false for auto-discovered sources.",
                )
            raise InputError(f"No runtime source named '{name}'.")
        remaining = [r for r in records if r is not match]
        self._write_records(remaining)
        cache_removed = False
        path = Path(str(match["path"]))
        if path.is_file() and _is_archive_name(path.name):
            still_used = any(Path(str(r.get("path"))) == path for r in remaining)
            if not still_used:
                stat = path.stat()
                key = hashlib.sha1(f"{path.resolve()}|{stat.st_size}|{stat.st_mtime_ns}".encode()).hexdigest()[:16]
                cache = self.bundles_dir / key
                if cache.exists():
                    shutil.rmtree(cache, ignore_errors=True)
                    cache_removed = True
        return {"removed": match["name"], "path": match["path"], "extracted_copy_deleted": cache_removed}

    def _read_records(self) -> list[dict[str, Any]]:
        try:
            data = json.loads(self.sources_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        return [record for record in data if isinstance(record, dict)] if isinstance(data, list) else []

    def _write_records(self, records: list[dict[str, Any]]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.sources_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(records, indent=2), encoding="utf-8")
        tmp.replace(self.sources_file)

    # -- files ---------------------------------------------------------------------- #

    def files(self, source: Source) -> list[LogFile]:
        """Every log file in a source, with device, role and logical name."""
        if not source.available or source.root is None:
            return []
        if source.kind == KIND_FILE and source.single_file is not None:
            path = source.single_file
            return [
                self._log_file(source, path, parts=[], context=list(path.parent.parts),
                               fallback=self._fallback_device(source, []), rel=path.name)
            ]

        if source.kind == KIND_BUNDLE:
            root, wrappers = _descend_wrappers(source.root)
            prefix, context_prefix, display_root = wrappers, wrappers, source.root
        else:
            root, wrappers = source.root, []
            prefix, context_prefix, display_root = [], list(root.parts), root
        fallback = self._fallback_device(source, wrappers)
        results: list[LogFile] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
            rel_parts = list(Path(dirpath).relative_to(root).parts)
            for filename in sorted(filenames):
                if not is_log_filename(filename):
                    continue
                path = Path(dirpath) / filename
                results.append(
                    self._log_file(source, path, parts=prefix + rel_parts, context=context_prefix + rel_parts,
                                   fallback=fallback, rel=str(path.relative_to(display_root)))
                )
                if len(results) >= MAX_FILES_PER_SOURCE:
                    break
            if len(results) >= MAX_FILES_PER_SOURCE:
                break
        _propagate_devices(results, fallback)
        _propagate_roles(results)
        results.sort(key=lambda f: (f.device.lower(), f.role, f.log_key, f.rotation, f.rel.lower()))
        return results

    def _fallback_device(self, source: Source, wrappers: list[str]) -> str:
        if source.kind == KIND_BUNDLE:
            lowered = [w.lower() for w in wrappers]
            if any(w in _SERVER_DIRS for w in lowered):
                return "server"
            return source.name
        if source.origin == "auto":
            return socket.gethostname() or source.name
        return _unc_host(source.path) or source.name

    def _log_file(self, source: Source, path: Path, *, parts: list[str], context: list[str], fallback: str,
                  rel: str) -> LogFile:
        log_key, display, rotation, client_id = logical_name(path.name, parts)
        try:
            stat = path.stat()
            size, mtime = stat.st_size, stat.st_mtime
        except OSError:
            size, mtime = 0, 0.0
        return LogFile(
            source=source.name,
            path=path,
            rel=rel,
            device=detect_device(parts, fallback, client_id),
            role=detect_role(context, log_key, client_id),
            log_key=log_key,
            display_name=display,
            rotation=rotation,
            size=size,
            mtime=mtime,
            client_id=client_id,
        )

    # -- facts -------------------------------------------------------------------------- #

    def file_facts(self, log_file: LogFile) -> FileFacts:
        """Deployment markers and service versions found in one adaptiva log (cached)."""
        key = (str(log_file.path), log_file.size, int(log_file.mtime * 1e9))
        cached = self._facts_cache.get(key)
        if cached is not None:
            return cached
        facts = FileFacts()
        tail = b""
        try:
            with open(log_file.path, "rb") as fh:
                while True:
                    chunk = fh.read(FACT_SCAN_CHUNK_BYTES)
                    if not chunk:
                        break
                    window = tail + chunk
                    for marker, (deployment, evidence) in _BYTE_MARKERS.items():
                        if marker in window:
                            facts.markers.setdefault(deployment, [])
                            if evidence not in facts.markers[deployment]:
                                facts.markers[deployment].append(evidence)
                    if _SAAS_BINDING.search(window):
                        evidence = "client binds to a <tenant>.adaptiva.cloud URL (SaaS)"
                        facts.markers.setdefault(DEPLOYMENT_SAAS, [])
                        if evidence not in facts.markers[DEPLOYMENT_SAAS]:
                            facts.markers[DEPLOYMENT_SAAS].append(evidence)
                    for match in _VERSION_LINE.finditer(window):
                        stamp = match.group(1).decode("ascii")
                        version = match.group(2).decode("ascii")
                        span = facts.versions.setdefault(version, [stamp, stamp])
                        span[0] = min(span[0], stamp)
                        span[1] = max(span[1], stamp)
                    tail = chunk[-512:]
        except OSError:
            pass
        self._facts_cache[key] = facts
        return facts

    def source_facts(self, files: list[LogFile]) -> dict[str, Any]:
        """Deployment evidence and versions across a set of files."""
        evidence: dict[str, list[str]] = {DEPLOYMENT_SAAS: [], DEPLOYMENT_ONPREM: []}
        keys = {f.log_key for f in files}
        if "cloudinstancemanagement.log" in keys:
            evidence[DEPLOYMENT_SAAS].append("CloudInstanceManagement.log present (seen in SaaS server bundles)")
        if "ntlmauth.log" in keys:
            evidence[DEPLOYMENT_ONPREM].append("ntlmauth.log present (SQL Server authentication, on-prem only)")
        versions: dict[str, dict[str, Any]] = {}
        candidates = [f for f in files if f.log_key in ("adaptiva.log", "adaptiva.err") and not f.compressed]
        candidates.sort(key=lambda f: f.mtime, reverse=True)
        for log_file in candidates[:FACT_SCAN_MAX_FILES]:
            facts = self.file_facts(log_file)
            for deployment, items in facts.markers.items():
                for item in items:
                    if item not in evidence[deployment]:
                        evidence[deployment].append(item)
            for version, (first, last) in facts.versions.items():
                entry = versions.setdefault(version, {"version": version, "first_seen": first, "last_seen": last,
                                                      "devices": set(), "roles": set()})
                entry["first_seen"] = min(entry["first_seen"], first)
                entry["last_seen"] = max(entry["last_seen"], last)
                entry["devices"].add(log_file.device)
                entry["roles"].add(log_file.role)
        return {
            "evidence": evidence,
            "versions": sorted(
                ({**v, "devices": sorted(v["devices"]), "roles": sorted(v["roles"])} for v in versions.values()),
                key=lambda v: v["last_seen"],
            ),
        }

    def deployment(self, source: Source, files: list[LogFile]) -> dict[str, Any]:
        facts = self.source_facts(files)
        evidence = facts["evidence"]
        if evidence[DEPLOYMENT_SAAS] and not evidence[DEPLOYMENT_ONPREM]:
            inferred = DEPLOYMENT_SAAS
        elif evidence[DEPLOYMENT_ONPREM] and not evidence[DEPLOYMENT_SAAS]:
            inferred = DEPLOYMENT_ONPREM
        elif evidence[DEPLOYMENT_SAAS] and evidence[DEPLOYMENT_ONPREM]:
            inferred = "mixed"
        else:
            inferred = "unknown"
        hint = source.deployment_hint
        return {
            "value": hint if hint in (DEPLOYMENT_SAAS, DEPLOYMENT_ONPREM) else inferred,
            "configured": hint in (DEPLOYMENT_SAAS, DEPLOYMENT_ONPREM),
            "inferred": inferred,
            "evidence": {k: v for k, v in evidence.items() if v},
            "versions": facts["versions"],
        }


def _propagate_devices(files: list[LogFile], fallback: str) -> None:
    """Files sitting directly in a device folder (no layout folder below) inherit that device."""
    known = {f.device for f in files if f.device != fallback and not f.client_id}
    if not known:
        return
    for log_file in files:
        if log_file.device == fallback and not log_file.client_id:
            parts = re.split(r"[\\/]", log_file.rel)[:-1]
            matches = [part for part in parts if part in known]
            if matches:
                log_file.device = matches[-1]


def _propagate_roles(files: list[LogFile]) -> None:
    """Give unknown-role files the single definite role seen for the same device."""
    by_device: dict[tuple[str, str], set[str]] = {}
    for log_file in files:
        if log_file.role in (ROLE_SERVER, ROLE_CLIENT):
            by_device.setdefault((log_file.source, log_file.device), set()).add(log_file.role)
    for log_file in files:
        if log_file.role == ROLE_UNKNOWN:
            roles = by_device.get((log_file.source, log_file.device), set())
            if len(roles) == 1:
                log_file.role = next(iter(roles))


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
