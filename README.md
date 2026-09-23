# tenable-patch-management-logs-mcp

[![Tests](https://github.com/brendanong95/tenable-patch-management-logs-mcp/actions/workflows/tests.yml/badge.svg)](https://github.com/brendanong95/tenable-patch-management-logs-mcp/actions/workflows/tests.yml)

An MCP server that does the log digging for **Tenable Patch Management (TPM)**, for both
**SaaS and on-prem** deployments. Point it at server logs (the Admin Portal zip, or the
on-prem logs folder) and client logs (device folders, collector bundles, or a log requested
from a client), then ask questions like *"why are my Tenable VM vulnerabilities not showing up
in TPM?"* or *"what changed on the server in the last 24 hours?"*.

The server does the analysis. Parsing, de-duplication across logs, error-code decoding,
known-issue matching and threshold comparisons all happen in Python; tools return finished,
structured results (`verdict`, ranked `issues` with counts and fixes, `findings` with
reasoning) instead of piles of raw lines for the model to add up.

## What it gives you

| Tool | Purpose |
| --- | --- |
| `check_log_sources` | **Start here.** Sources, devices, server/client/setup logs, time span, SaaS vs on-prem (with evidence), TPM versions, version advisories, and where to get missing logs. |
| `summarize_errors` | Every warning and error grouped into distinct issues, ranked, de-duplicated across logs, with decoded error codes, root causes, the latest example (file and line) and known-issue fixes. Platform noise is counted separately. |
| `diagnose` | Symptom playbooks with a verdict: `patch_install_failed`, `content_download`, `client_connectivity`, `vm_integration`, `feeds`, `content_publication`, `service_health`, `database`, `client_upgrade`, `feature_update_readiness`. |
| `search_logs` | Literal or regex search across all logs, including multi-line messages and stack traces, with context and paging. |
| `build_timeline` | Server and client logs merged into one time-ordered sequence, around a moment or over a window. |
| `compare_devices` | Warnings and errors a problem device has that a healthy device does not. |
| `detect_log_anomalies` | A recent window compared with the days before it: new error signatures, error spikes, restart loops, logs that went quiet. |
| `list_log_files` | Files with device, role, purpose, size and time span. |
| `explain` | What a log file records, what an error code means (`0x80070643`, `1603`, `http 407`), or what a symptom / known issue covers. |
| `add_log_source` / `remove_log_source` | Register a folder, UNC path, single log file, `.zip` or `.tar.gz`; remembered between sessions. |

Safety properties worth knowing:

- **Read-only.** Sources are never modified. The only writes are `data/sources.json` (sources added
  with `add_log_source`) and an extracted copy of each bundle under `data/bundles`.
- **Nothing that looks like a credential is returned.** TPM writes the Tenable VM access key into
  `VulnerabilityManagement.log` and `adaptiva.err` in plain text; 64-hex key material, `token:` /
  `password=` / `secretKey=` values, bearer tokens and URL passwords are masked to their last 4
  characters. Host names, IPs, e-mail addresses, GUIDs and client IDs are kept because
  troubleshooting needs them.
- **No silent truncation.** Each call reads at most 1 GB / 5,000 files (newest first); anything not
  read is listed in `coverage` with how to narrow the call. Lines in an unrecognised format are
  never merged into one entry.
- **Bundles are extracted defensively**: path-traversal entries are skipped, and extraction stops at
  8 GB or 100,000 files.
- **No network access and no Tenable API keys.** TPM has no documented public API; everything comes
  from its logs.

## How it covers SaaS and on-prem

| | Server logs | Client logs |
| --- | --- | --- |
| **SaaS** | Admin Portal → gear icon → **Logs** → **Download All Server Logs**, then `add_log_source` with the zip. This is the only way to get SaaS server logs. | Same for both: copy `%ADAPTIVACLIENT%\logs` (default `C:\Program Files\Tenable\PatchClient\logs`; `/opt/tenable/patchclient/logs` on Linux/macOS), run `collect/Collect-TPMLogs.ps1`, or request a log from the server (10.2.973.9+), which downloads as e.g. `13_adaptiva.log` (client ID 13). |
| **On-prem** | Register `%ADAPTIVASERVER%\logs` directly (default `C:\Program Files\Tenable\PatchServer\logs`), locally or as a UNC path; or download from Admin Portal → Logs. | |

Client logs look the same in both deployments, so every tool works the same way. The deployment
is inferred per source from the logs themselves and shown with its evidence by `check_log_sources`,
for example a PostgreSQL database and `/opt/adaptiva/adaptiva-server` paths (SaaS) or
`ntlmauth.log` and SQL Server (on-prem). Set `TPM_DEPLOYMENT` or pass `deployment` to
`add_log_source` to override.

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/)
- TPM logs (see above). No Tenable credentials are needed.

## Setup

```bash
uv sync --extra dev
```

Optionally copy `.env.example` to `.env` to preconfigure sources:

```bash
cp .env.example .env
```

| Variable | Meaning |
| --- | --- |
| `TPM_LOG_SOURCES` | `name=path;name2=path2` - folders, UNC paths, log files, `.zip` / `.tar.gz` bundles. |
| `TPM_DEPLOYMENT` | `saas`, `onprem` or `auto` (default: inferred per source). |
| `TPM_AUTO_DISCOVER` | Also use TPM installed on this machine (`%ADAPTIVASERVER%`, `%ADAPTIVACLIENT%`, `%windir%\AdaptivaSetupLogs`, `/opt/tenable/patchclient/logs`). Default `true`. |
| `TPM_MCP_DATA_DIR` | Where runtime sources and extracted bundles live. Default `./data`. |

Sources can also be added in conversation with `add_log_source`, which is usually easier for
support bundles.

Run the server directly (it speaks MCP over stdio, so it will just sit there waiting for a
client - that is the correct behaviour):

```bash
uv run python -m src.server
```

## Connecting a client

Use the **absolute path** to this folder in the config below.

### Claude Desktop

Edit `claude_desktop_config.json` (`%APPDATA%\Claude\claude_desktop_config.json` on Windows,
`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "tenable-patch-logs": {
      "command": "uv",
      "args": [
        "--directory",
        "C:\\path\\to\\tenable-patch-management-logs-mcp",
        "run",
        "python",
        "-m",
        "src.server"
      ],
      "env": {
        "TPM_LOG_SOURCES": "saas-server=C:\\cases\\acme\\logs.zip;clients=C:\\cases\\acme\\TPM-Logs-20260917"
      }
    }
  }
}
```

Restart Claude Desktop afterwards. If `uv` is not on the launcher's `PATH`, use its absolute
path (`(Get-Command uv).Source` / `which uv`) as `command`. The `env` block is optional.

### Claude Code

```bash
claude mcp add tenable-patch-logs -- uv --directory /absolute/path/to/tenable-patch-management-logs-mcp run python -m src.server
```

Add `--env TPM_LOG_SOURCES=...` to preconfigure sources, or add the same block as above to a
project-level `.mcp.json`.

## Getting the logs

- **SaaS server:** Admin Portal → gear icon → Logs → **Download All Server Logs**. The zip contains
  `adaptiva-server/` with `adaptiva*.log`, `adaptiva.err`, `componentlogs/` and `workflowlogs/`.
  Downloading it twice gives two slightly different snapshots; use the newer one.
- **On-prem server:** the logs folder itself, or a UNC path such as
  `\\tpm01\c$\Program Files\Tenable\PatchServer\logs`.
- **Clients, several at once (Windows):**

  ```powershell
  .\collect\Collect-TPMLogs.ps1 -ComputerName WS-BAD07, WS-GOOD01 -Days 3
  .\collect\Collect-TPMLogs.ps1 -ComputerName TPM01 -IncludeServer     # on-prem server box
  ```

  One folder per device, zipped, plus the Client Validator results from the registry. Include a
  healthy device so `compare_devices` has something to compare against.
- **Linux / macOS clients:** `sudo ./collect/collect-tpm-logs.sh 3 /tmp` (tar.gz, includes the
  `adaptivaclientd` journal).
- **One client from the console:** 10.2.973.9 and later can request a log file from a client; the
  download (`<clientId>_adaptiva.log`) can be registered as is.

## Example questions to ask once connected

- *"Add C:\cases\acme\logs.zip as acme-saas and check the log sources."*
- *"Summarise what's wrong on the TPM server over the last 7 days, ignoring noise."*
- *"Why is Tenable VM data not showing up in Patch Management?"* (runs `diagnose vm_integration`)
- *"Why did patching fail on WS-BAD07 yesterday? Decode the exit codes."*
- *"Build a timeline for WS-BAD07 from 30 minutes before the first installer failure."*
- *"What does WS-BAD07 have that WS-GOOD01 doesn't?"*
- *"Anything new or spiking in the last 24 hours compared with the week before?"*
- *"Which clients is the server retrying messages to?"*

## How the analysis works

**Parsing.** Log layouts were taken from real TPM 10.2.973.9 logs (a SaaS server bundle and a
Windows client), plus the standard Windows Installer log:

| Layout | Where | Example |
| --- | --- | --- |
| `adaptiva` | `adaptiva.log`, `adaptiva.err`, every component log, server and client | `2026-09-12 18:00:25,141 - INFO - <message> - PolicyManager - TID=3340624, <thread>` |
| `workflow` | `workflowlogs/<name>_<id>_<seq>.log` | `09-17-2026 14:00:00:2 : Exec: Starting: Start1.Global_Approvals` |
| `blocks` | `SQLUploader.log` | `----- START(2026-09-02T01:44:27.942) -----` |
| `msi` | `msiLogs/*.log` (UTF-16 handled) | `MSI (s) (A4:B8) [10:01:02:300]: ... error status: 1603.` |
| `timestamped` | setup logs, exported journalctl | `2026-09-10T08:15:02+0800 host adaptivaclientd[812]: ...` |

Multi-line messages (the component suffix can sit on a later line) and stack traces stay attached
to their entry. Rotated files (`adaptiva.2.log`, `Feeds.1.log`, `.gz`) are read as one log.

**De-duplication.** TPM writes an error to `adaptiva.log` or a component log *and* to
`adaptiva.err`. Events are matched on device, timestamp, level, thread and message, and counted
once (`duplicate_lines_in_other_logs` reports how many repeats were removed).

**Severity.** TPM sometimes logs real failures at INFO. The documented Services-sensor issue, for
example, is an INFO line carrying an exception. Entries with a stack trace or a non-zero Adaptiva
`Error Code` are raised to ERROR and flagged with `raised_from_lower_level`.

**Known issues** (`src/knowledge.py`) each carry a `confidence`:

- `documented`: described by Tenable or Adaptiva, with a source link (for example the 9.2
  Services-sensor DLL issue, or the 9.1.965.x client upgrade failure).
- `observed`: seen in real TPM 10.2.973.9 logs, explained from the message and surrounding lines
  (for example Tenable VM keys rejected with "not related to any active containers", periodic feed
  check failures, CDN publication failures, clients rejected for missing install authentication).
- `generic`: standard Java, Windows, SQL or network errors.

Issues with `impact: none` are **platform noise** (for example the SQL Server monitoring query that
fails daily on the SaaS PostgreSQL database, or receipt-cleanup warnings). About two thirds of the
warning and error events in the real SaaS bundle were noise. They are counted under `noise`, not
listed as issues.

**Error codes** are decoded from context: MSI / Win32 exit codes (`1603`, `1618`, `3010`),
HRESULTs including `HRESULT_FROM_WIN32` values (`0x80070643`), Windows Update (`0x8024xxxx`),
component servicing (`0x800Fxxxx`), negative decimal HRESULTs and HTTP statuses. Adaptiva's own
`Error Code = N` values are shown but never decoded as Windows errors.

**Anomalies** compare a window with the period before it, read from the same logs, so no state
has to build up. Thresholds are constants at the top of `src/anomaly.py` and are echoed in every
result:

| Constant | Default | Meaning |
| --- | --- | --- |
| `SPIKE_MULTIPLIER` | `3.0` | Window rate per day must exceed this multiple of the baseline rate |
| `SPIKE_MIN_WINDOW_EVENTS` | `10` | Minimum window events before a spike is flagged |
| `NEW_SIGNATURE_HIGH_COUNT` | `10` | A new ERROR signature with this many events is rated high |
| `MIN_BASELINE_COVERAGE_PCT` | `50.0` | Below this share of the baseline covered by a log, "new" findings are low confidence |
| `RESTART_MIN_STARTS` | `3` | Service starts in the window that count as repeated restarts |
| `SILENT_LOG_MIN_BASELINE_EVENTS` | `50` | Baseline entries a log needs before going quiet is notable |

Each finding is judged against the log(s) it appears in. A log that only started recently is not
reported as a spike just because the device's other logs go back further.

**Time.** Relative windows (`90m`, `24h`, `7d`, `2w`) count back from the **newest entry in the
selected logs**, not from now, so an old support bundle still gives sensible results. Timestamps
are shown as written. TPM 10.2 SaaS server logs and Windows client logs were observed to be in UTC.

## Layout

```
src/
  server.py        MCP entrypoint and the eleven tool definitions
  sources.py       Source configuration, bundle extraction, device / role / rotation detection
  logformat.py     Line layouts, multi-line entries, encodings, time spans
  classifier.py    Redaction, signatures, severity, known-issue matching, extractions
  error_codes.py   Win32 / MSI / HRESULT / Windows Update / CBS / HTTP code decoding
  knowledge.py     Log catalog, known issues, playbooks, version advisories, where to get logs
  analysis.py      Scoped, bounded scanning; summaries, search, timelines, playbooks, comparisons
  anomaly.py       Window-versus-baseline findings and thresholds
collect/
  Collect-TPMLogs.ps1    Windows collector (local or WinRM), one folder per device
  collect-tpm-logs.sh    Linux / macOS collector
scripts/
  smoke_local.py   Offline end-to-end run of every tool
  live_check.py    Read-only run against your configured logs
tests/
  sample_logs.py   Synthetic, sanitised logs in the real layouts
  test_*.py
```

Dependency direction is one-way: `server → {analysis, anomaly} → {classifier, sources} → {logformat, error_codes, knowledge}`.

## Testing

### 1. Unit tests (no network)

```bash
uv run pytest -q
```

162 tests covering every layout, rotation and encoding, bundle extraction guards, device/role
detection, redaction, signatures, severity escalation, known issues, every playbook, anomaly
thresholds and the tool contracts. All fixtures are synthetic (`tests/sample_logs.py`); no real log
content is stored in the repository.

### 2. Offline end-to-end

```bash
uv run python scripts/smoke_local.py
```

Registers a synthetic SaaS server bundle, a two-device client bundle and a single requested
client log through the tools, calls every tool, and asserts the results: duplicates counted once,
noise set aside, planted secrets redacted, known issues found, bad input returned as a structured
error. Exits non-zero on any failure, so it works as a CI gate.

### 3. Against your logs (read-only)

```bash
uv run python scripts/live_check.py 7d
```

Uses the same configuration as the server and prints sources, the error summary, the playbooks
relevant to the logs you have, and anomalies. On the real 80 MB SaaS bundle every call finished in
under 5 seconds.

### 4. Through an MCP client

```bash
npx @modelcontextprotocol/inspector uv --directory . run python -m src.server
```

Or connect Claude Desktop / Claude Code (above) and ask one of the example questions.

## Known limitations

- **Formats validated on 10.2.973.9 SaaS server logs and a Windows client `adaptiva.log`.** On-prem
  server logs use the same Java logging and are expected to match, but have not been checked
  against a real on-prem bundle. The same applies to Linux and macOS client logs. `check_log_sources`
  lists any file whose format was not recognised.
- **Client component logs were not in the real samples.** The playbooks for `_SDMErrors.log`,
  `SoftwareInstaller.log` and `WindowsPatching.log` rely on exit codes, HRESULTs, exceptions and the
  documented `PatchDeploymentResult` line rather than exact message wording. Add real patterns to
  `KNOWN_ISSUES` as you meet them.
- **`PatchDeploymentResult` status and reason values are undocumented.** They are shown as logged;
  failure evidence comes from non-zero reason codes and exceptions.
- **Timestamps are not converted between time zones.** Mixing logs from machines that log in
  different zones shifts them relative to each other in timelines.
- **Relative windows follow the newest entry in the selected logs.** Filter to one source or device
  when their logs end at very different times.
- **Anomaly detection only sees what the logs still contain.** Heavily rotated logs give short
  baselines; findings then carry `low_confidence`.
- **The knowledge base is a starting point.** Known issues marked `observed` come from one tenant's
  logs; confirm fixes against current Tenable documentation.

## Disclaimer

Not affiliated with, endorsed by, or supported by Tenable, Inc. or Adaptiva. "Tenable", "Tenable Patch
Management", "Tenable Vulnerability Management" and "Adaptiva" are trademarks of their respective owners.
This project reads log files you already have; it is an independent troubleshooting aid, not a Tenable
product, and its findings should be confirmed against current vendor documentation before you act on them.

## Sources

- Tenable Patch Management docs: [client logs](https://docs.tenable.com/integrations/Tenable-Patch-Management/Content/ts-client-logs.htm),
  [server logs](https://docs.tenable.com/integrations/Tenable-Patch-Management/Content/ts-server-logs.htm),
  [client install logs](https://docs.tenable.com/integrations/Tenable-Patch-Management/Content/client-install-logs.htm),
  [Client Validator](https://docs.tenable.com/integrations/Tenable-Patch-Management/Content/client-validator.htm),
  [SaaS vs self-hosted](https://docs.tenable.com/integrations/Tenable-Patch-Management/Content/saas-vs-selfhosted.htm),
  [2025](https://docs.tenable.com/release-notes/Content/patch-management/2025.htm) and
  [2026](https://docs.tenable.com/release-notes/Content/patch-management/2026.htm) release notes.
- Adaptiva (the TPM platform): [logging configuration](https://support.adaptiva.com/hc/en-us/articles/38137478589709-Modifying-the-Adaptiva-Logging-Configuration),
  [Services sensor issue (9.2)](https://support.adaptiva.com/hc/en-us/articles/37731460124429-Patches-show-as-Failed-due-to-Services-sensor-error-in-OneSite-Patch-9-2),
  [client upgrade issue (9.1.965)](https://support.adaptiva.com/hc/en-us/articles/31519727703949-Adaptiva-Client-upgrade-completes-successfully-but-ClientService-fails-to-start),
  [10.0.971 known issues](https://support.adaptiva.com/hc/en-us/articles/43750967019149-Known-Issues-10-0-971-Issues),
  [feature updates](https://docs.adaptiva.com/patch/scenarios/feature-updates).
