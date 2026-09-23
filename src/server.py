"""tenable-patch-mcp - MCP server over Tenable Patch Management server and client logs.

Entrypoint and tool registration only. Parsing lives in ``logformat``, file discovery
in ``sources``, enrichment in ``classifier``, rollups in ``analysis`` and baseline
comparison in ``anomaly``. Tools return finished, pre-computed structures: no tool
hands back a pile of raw lines expecting the caller to do the counting.

Run with stdio transport::

    uv run python -m src.server
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Callable

from dotenv import find_dotenv, load_dotenv

try:  # mcp >= 2.0 renamed FastMCP to MCPServer; the decorator API is unchanged
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:  # pragma: no cover - mcp 1.x
    from mcp.server.fastmcp import FastMCP  # type: ignore[no-redef]

try:
    from mcp.types import ToolAnnotations
except ImportError:  # pragma: no cover - very old SDKs
    ToolAnnotations = None  # type: ignore[assignment,misc]

from . import __version__, analysis, anomaly
from .errors import TpmLogError
from .sources import SourceRegistry

SERVER_NAME = "tenable-patch-mcp"
SERVER_VERSION = __version__

logging.basicConfig(
    stream=sys.stderr,  # stdout is the MCP transport - never log to it
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(SERVER_NAME)

INSTRUCTIONS = (
    "Read-only analysis of Tenable Patch Management (TPM) logs for SaaS and on-prem deployments: server logs "
    "(an Admin Portal 'Download All Server Logs' zip, or the on-prem logs folder) and client logs. "
    "Start with check_log_sources. For 'what is wrong', call summarize_errors; for a specific symptom call "
    "diagnose; use search_logs and build_timeline to confirm details. Counts, grouping across duplicate log "
    "files, error-code decoding and known-issue matching are done server-side - use the numbers as given. "
    "Quote the file and line ('log', 'line' or 'at') so findings can be verified. Relative times such as 24h "
    "count back from the newest log entry, not from now. Known platform noise is set aside by default and "
    "reported separately."
)

mcp = FastMCP(SERVER_NAME, version=SERVER_VERSION, instructions=INSTRUCTIONS)

_registry: SourceRegistry | None = None


def get_registry() -> SourceRegistry:
    """Lazily build the registry so importing the module needs no configuration."""
    global _registry
    if _registry is None:
        _registry = SourceRegistry()
    return _registry


def _tool(*, read_only: bool = True) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    kwargs: dict[str, Any] = {}
    if ToolAnnotations is not None:
        kwargs["annotations"] = ToolAnnotations(
            readOnlyHint=read_only, destructiveHint=False, idempotentHint=read_only, openWorldHint=False
        )
    try:
        return mcp.tool(**kwargs)
    except TypeError:  # pragma: no cover - SDKs without annotation support
        return mcp.tool()


def _fail(exc: Exception) -> dict[str, Any]:
    """Turn any exception into a structured, human-readable tool result."""
    if isinstance(exc, TpmLogError):
        logger.warning("%s: %s", exc.kind, exc.message)
        return exc.to_dict()
    logger.exception("Unexpected error in tool call")
    return {
        "ok": False,
        "error": "unexpected_error",
        "message": f"{type(exc).__name__}: {exc}",
        "remediation": "Check the server logs (stderr) for the full traceback.",
    }


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #


@_tool()
def check_log_sources() -> dict[str, Any]:
    """Show which TPM logs are available, and whether they can be read and parsed.

    Run this first. For every source it reports the devices found (server / client /
    setup logs), the time span each device's logs cover, whether the deployment looks
    like SaaS or on-prem (with the evidence), TPM versions seen in service start lines,
    version advisories, and any files whose line format was not recognised. It also
    says where to get missing logs (for example the Admin Portal zip for SaaS server
    logs).

    Returns:
        A dict with ``ok``, a ``message``, per-source details, ``guidance`` for missing
        logs, and the active ``configuration``.
    """
    try:
        return analysis.check_sources(get_registry())
    except Exception as exc:  # noqa: BLE001 - tools must not raise at the transport
        return _fail(exc)


@_tool(read_only=False)
def add_log_source(name: str, path: str, deployment: str = "auto") -> dict[str, Any]:
    """Register TPM logs to analyse; remembered between sessions.

    Nothing at ``path`` is modified. Bundles are extracted once into the server's data
    folder.

    Args:
        name: Short label, e.g. "acme-saas-server" or "clients-0917" (letters, digits,
            '.', '_', '-').
        path: A folder (local or UNC, e.g. \\\\tpm01\\c$\\Program Files\\Tenable\\PatchServer\\logs),
            a single log file (e.g. 13_adaptiva.log requested from a client), or a .zip /
            .tar.gz bundle such as the Admin Portal "Download All Server Logs" zip.
        deployment: "saas", "onprem" or "auto" (infer from the logs).

    Returns:
        The registered source, the devices and log counts found, and the next step.
    """
    try:
        registry = get_registry()
        source = registry.add(name, path, deployment)
        files = registry.files(source)
        return {
            "ok": True,
            "source": source.to_dict(),
            "files": len(files),
            "devices": sorted({f.device for f in files}),
            "roles": sorted({f.role for f in files}),
            "next_step": "Call check_log_sources for coverage and deployment details, or summarize_errors.",
        }
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


@_tool(read_only=False)
def remove_log_source(name: str) -> dict[str, Any]:
    """Unregister a source added with add_log_source.

    The original folder or bundle is never touched; only the extracted copy of a bundle
    kept by this server is deleted. Sources from TPM_LOG_SOURCES or auto-discovery are
    configured outside the server and cannot be removed here.

    Args:
        name: The source name.

    Returns:
        What was removed.
    """
    try:
        return {"ok": True, **get_registry().remove(name)}
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


@_tool()
def list_log_files(
    source: str | None = None,
    device: str | None = None,
    role: str | None = None,
    name: str | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    """List log files with device, role, purpose, size and the time span they cover.

    Args:
        source: Source name; omit for all sources.
        device: Device name (e.g. "server", "client-13", "WS-BAD07").
        role: "server", "client", "setup" or "unknown".
        name: Log name or glob, e.g. "adaptiva.log", "_SDMErrors.log", "content*.log".
            Rotated files (adaptiva.2.log) match their base name.
        limit: Maximum rows (1-1000).

    Returns:
        ``files`` (one row per file) plus counts by device, role and log name.
    """
    try:
        return analysis.list_log_files(get_registry(), source=source, device=device, role=role, name=name, limit=limit)
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


@_tool()
def summarize_errors(
    since: str | None = "7d",
    until: str | None = None,
    source: str | None = None,
    device: str | None = None,
    role: str | None = None,
    files: list[str] | None = None,
    min_severity: str = "WARN",
    include_noise: bool = False,
    top: int = 25,
) -> dict[str, Any]:
    """Group every warning and error into distinct issues, ranked, with known fixes.

    The best first call for "what is wrong?". Repeats are collapsed into signatures
    (IDs, GUIDs, IPs, numbers and paths normalised); the same event written to several
    logs is counted once. Each issue has counts, first/last seen, devices, decoded error
    codes, root causes from stack traces, the latest example with file and line, and -
    when recognised - a known-issue explanation and remediation. INFO lines that carry
    stack traces are raised to ERROR (flagged). Known platform noise is counted under
    ``noise`` instead of cluttering ``issues``.

    Args:
        since: Window start: ISO time (2026-09-17T08:00) or relative (90m, 24h, 7d, 2w)
            counted back from the newest log entry. Default 7d.
        until: Window end (same formats). Default: newest entry.
        source: Source name; omit for all sources.
        device: Only this device.
        role: "server", "client" or "setup".
        files: Log names or globs, e.g. ["VulnerabilityManagement.log"].
        min_severity: WARN (default), ERROR or FATAL.
        include_noise: Include known platform noise in ``issues``.
        top: Issues to return (1-100).

    Returns:
        ``totals``, ranked ``issues``, ``noise``, top components/logs and ``coverage``.
    """
    try:
        return analysis.summarize_errors(
            get_registry(), source=source, since=since, until=until, min_severity=min_severity, device=device,
            role=role, files=files, include_noise=include_noise, top=top,
        )
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


@_tool()
def search_logs(
    pattern: str,
    regex: bool = False,
    case_sensitive: bool = False,
    since: str | None = None,
    until: str | None = None,
    source: str | None = None,
    device: str | None = None,
    role: str | None = None,
    files: list[str] | None = None,
    component: str | None = None,
    min_severity: str | None = None,
    context: int = 0,
    limit: int = 50,
    offset: int = 0,
    order: str = "newest",
) -> dict[str, Any]:
    """Search every log, including multi-line messages and stack traces.

    Matches are whole entries (not single lines), de-duplicated across logs that repeat
    the same event, sorted by time, and redacted.

    Args:
        pattern: Text to find (literal unless regex=true), e.g. a KB number, patch ID,
            client ID, content ID ("Policy_104117") or error text.
        regex: Treat pattern as a regular expression.
        case_sensitive: Default false.
        since: Window start (ISO or relative like 24h); default all history.
        until: Window end.
        source: Source name; omit for all sources.
        device: Only this device.
        role: "server", "client" or "setup".
        files: Log names or globs to search.
        component: Exact component name, e.g. "TenableClient".
        min_severity: Only entries at or above INFO/WARN/ERROR.
        context: Entries of context before and after each match from the same file (0-5).
        limit: Matches to return (1-200).
        offset: Skip this many matches (paging; see next_offset).
        order: "newest" (default) or "oldest" first.

    Returns:
        ``total_matches``, ``matches`` (with file, line, component, thread, codes) and paging.
    """
    try:
        return analysis.search_logs(
            get_registry(), pattern, regex=regex, case_sensitive=case_sensitive, source=source, since=since,
            until=until, min_severity=min_severity, device=device, role=role, files=files, component=component,
            context=context, limit=limit, offset=offset, order=order,
        )
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


@_tool()
def build_timeline(
    around: str | None = None,
    minutes_before: int = 15,
    minutes_after: int = 15,
    since: str | None = None,
    until: str | None = None,
    source: str | None = None,
    device: str | None = None,
    role: str | None = None,
    files: list[str] | None = None,
    min_severity: str = "INFO",
    keyword: str | None = None,
    include_noise: bool = False,
    collapse_repeats: bool = True,
    limit: int = 200,
) -> dict[str, Any]:
    """Merge all logs into one chronological sequence - what happened before and after.

    Useful for "what led up to this failure": server and client logs are interleaved
    by timestamp, duplicates across logs removed, and consecutive repeats collapsed
    (``repeats``). When there are more rows than ``limit``, WARN and above are always
    kept and the rest are sampled evenly (``sampled``).

    Args:
        around: Centre the window on this time (ISO, or relative like 2h).
        minutes_before: Minutes before ``around`` (default 15).
        minutes_after: Minutes after ``around`` (default 15).
        since: Window start when not using ``around``. Default: the last 60 minutes of logs.
        until: Window end when not using ``around``.
        source: Source name; omit for all sources.
        device: Only this device.
        role: "server", "client" or "setup".
        files: Log names or globs.
        min_severity: INFO (default), WARN, ERROR; DEBUG to include debug lines.
        keyword: Only entries containing this text.
        include_noise: Include known platform noise.
        collapse_repeats: Merge consecutive identical rows (default true).
        limit: Rows to return (10-1000).

    Returns:
        ``rows`` in time order, each with time, device, severity, log, component, message
        and ``at`` (file:line).
    """
    try:
        return analysis.build_timeline(
            get_registry(), source=source, since=since, until=until, around=around, minutes_before=minutes_before,
            minutes_after=minutes_after, device=device, role=role, files=files, min_severity=min_severity,
            keyword=keyword, include_noise=include_noise, collapse_repeats=collapse_repeats, limit=limit,
        )
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


@_tool()
def diagnose(
    symptom: str,
    since: str | None = "7d",
    until: str | None = None,
    source: str | None = None,
    device: str | None = None,
) -> dict[str, Any]:
    """Run a symptom playbook: read the right logs and return a verdict with evidence.

    Symptoms:
      * patch_install_failed - deployment results, installer exit codes (decoded), MSI failures
      * content_download - content / peer-to-peer / CDN download problems on clients
      * client_connectivity - client transport errors, server retries per client ID,
        registrations rejected for missing install authentication
      * vm_integration - Tenable VM / Security Center access settings, API key failures,
        vulnerability import runs
      * feeds - periodic feed checks, last success, failure root causes
      * content_publication - content uploads to the CDN that failed
      * service_health - service starts with versions, restart loops, crashes, out-of-memory
      * database - SQL errors, SQL Server authentication, deadlocks
      * client_upgrade - upgrade problems and versions seen over time
      * feature_update_readiness - free disk space vs the 50 GB requirement, NOT INSTALLED scans

    Args:
        symptom: One of the symptom ids above.
        since: Window start (ISO or relative like 24h). Default 7d.
        until: Window end.
        source: Source name; omit for all sources.
        device: Only this device.

    Returns:
        ``verdict``, ``findings`` (known issues with remediation), other related errors,
        playbook-specific ``details``, ``missing_logs`` with how to get them, and ``advice``.
    """
    try:
        return analysis.diagnose(get_registry(), symptom, source=source, since=since, until=until, device=device)
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


@_tool()
def compare_devices(
    healthy_device: str,
    problem_device: str,
    since: str | None = "7d",
    until: str | None = None,
    source: str | None = None,
    min_severity: str = "WARN",
    include_noise: bool = False,
    top: int = 25,
) -> dict[str, Any]:
    """Show warnings and errors on a problem device that a healthy device does not have.

    Args:
        healthy_device: A device that patches correctly.
        problem_device: The device with the problem.
        since: Window start (ISO or relative). Default 7d.
        until: Window end.
        source: Source name; omit for all sources.
        min_severity: WARN (default) or ERROR.
        include_noise: Include known platform noise.
        top: Issues per list (1-100).

    Returns:
        ``only_on_problem_device`` and ``more_frequent_on_problem_device``, with counts.
    """
    try:
        return analysis.compare_devices(
            get_registry(), healthy_device, problem_device, source=source, since=since, until=until,
            min_severity=min_severity, include_noise=include_noise, top=top,
        )
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


@_tool()
def detect_log_anomalies(
    since: str | None = "24h",
    until: str | None = None,
    baseline_days: int = 7,
    source: str | None = None,
    device: str | None = None,
    role: str | None = None,
) -> dict[str, Any]:
    """Compare a recent window with the days before it, in the same logs.

    Flags error signatures never seen in the baseline, errors whose rate jumped above
    the spike threshold, services that started repeatedly, and logs that stopped
    writing. Each finding has evidence, the threshold crossed and a reasoning sentence.
    Findings are marked low confidence when the logs do not reach far enough back.

    Args:
        since: Window start (ISO or relative like 24h, counted back from the newest entry).
        until: Window end. Default: newest entry.
        baseline_days: Days before the window to compare against (1-90, default 7).
        source: Source name; omit for all sources.
        device: Only this device.
        role: "server", "client" or "setup".

    Returns:
        Severity-ordered ``findings``, counts by type and severity, baseline coverage and
        the active ``thresholds``.
    """
    try:
        return anomaly.detect_log_anomalies(
            get_registry(), source=source, since=since, until=until, baseline_days=baseline_days, device=device,
            role=role,
        )
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


@_tool()
def explain(topic: str | None = None) -> dict[str, Any]:
    """Explain a TPM log file, an error code, a symptom or a known issue.

    Args:
        topic: A log name ("_SDMErrors.log", "13_adaptiva.log"), an error code
            ("0x80070643", "-2147467259", "1603", "http 407"), a symptom id
            ("patch_install_failed") or a known issue id. Omit for the index.

    Returns:
        What the topic is, where it comes from, and related symptoms or fixes.
    """
    try:
        return analysis.explain(topic)
    except Exception as exc:  # noqa: BLE001
        return _fail(exc)


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #


def main() -> None:
    """Load ``.env`` (if present) and serve over stdio."""
    dotenv_path = find_dotenv(usecwd=True)
    if dotenv_path:
        load_dotenv(dotenv_path)
        logger.info("Loaded environment from %s", dotenv_path)
    else:
        load_dotenv()
    logger.info("Starting %s v%s (stdio)", SERVER_NAME, SERVER_VERSION)
    mcp.run("stdio")


if __name__ == "__main__":
    main()
