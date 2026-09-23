"""Offline end-to-end exercise of every tool. No credentials, no network.

Builds the synthetic TPM log set (a SaaS server bundle zip, a two-device client
collector bundle and a single requested client log), registers it through the tools,
calls every tool, and asserts the invariants that matter: secrets redacted, duplicates
counted once, noise set aside, known issues recognised, and bad input returned as a
structured error instead of an exception.

    uv run python scripts/smoke_local.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

WORK = Path(tempfile.mkdtemp(prefix="tpm-smoke-"))
os.environ["TPM_MCP_DATA_DIR"] = str(WORK / "data")
os.environ["TPM_AUTO_DISCOVER"] = "false"
os.environ.pop("TPM_LOG_SOURCES", None)

from src import server  # noqa: E402
from tests.sample_logs import PLANTED_KEY, PLANTED_TOKEN, build_sample_tree  # noqa: E402

failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if condition else 'FAIL'}] {label}{f' - {detail}' if detail else ''}")
    if not condition:
        failures.append(label)


def clean(result: dict) -> bool:
    text = json.dumps(result, default=str)
    return PLANTED_KEY not in text and PLANTED_TOKEN not in text and "Hunter2Hunter2" not in text


samples = build_sample_tree(WORK / "samples")

print("\n1. add_log_source / check_log_sources")
check("server zip registered", server.add_log_source("saas-server", str(samples["server_zip"]))["ok"] is True)
check("client bundle registered", server.add_log_source("clients", str(samples["clients_tar"]))["ok"] is True)
check("single client log registered", server.add_log_source("client13", str(samples["client13_file"]))["ok"] is True)
sources = server.check_log_sources()
by_name = {s["name"]: s for s in sources["sources"]}
check("sources readable", sources["ok"] is True, sources["message"])
check("SaaS inferred from the logs", by_name["saas-server"]["deployment"]["value"] == "saas",
      "; ".join(by_name["saas-server"]["deployment"]["evidence"]["saas"]))
check("version found", by_name["saas-server"]["deployment"]["versions"][0]["version"] == "10.2.973.9")
check("client devices found", {d["device"] for d in by_name["clients"]["devices"]} == {"WS-BAD07", "WS-GOOD01"})

print("\n2. summarize_errors")
summary = server.summarize_errors(since="24h")
issues = {i["known_issue"]["id"]: i for i in summary["issues"] if i["known_issue"]}
for issue in summary["issues"][:6]:
    title = issue["known_issue"]["title"] if issue["known_issue"] else issue["signature"]
    print(f"      #{issue['rank']} [{issue['severity']}] x{issue['count']} {title[:110]}")
check("feed failures counted once across logs", issues["feed_check_failed"]["count"] == 12)
check("noise set aside", summary["totals"]["noise_events"] > 0 and summary["noise"] != [])
check("INFO-level sensor failure raised", issues["services_sensor_missing_dll"].get("raised_from_lower_level") == 1)
check("no secrets in output", clean(summary))

print("\n3. diagnose")
verdicts = {}
for symptom in ("vm_integration", "feeds", "client_connectivity", "patch_install_failed", "service_health",
                "database", "feature_update_readiness", "content_publication", "client_upgrade", "content_download"):
    result = server.diagnose(symptom, since="30d")
    verdicts[symptom] = result
    print(f"      {symptom}: {result.get('verdict', result.get('message'))[:160]}")
    check(f"{symptom} ok and clean", result["ok"] is True and clean(result))
check("integration not configured detected", "not configured" in verdicts["vm_integration"]["verdict"])
check("MSI 1603 decoded", any(r["code"]["name"] == "ERROR_INSTALL_FAILURE"
                              for r in verdicts["patch_install_failed"]["details"]["error_codes"]))
check("restart loop detected", bool(verdicts["service_health"]["details"]["restart_loops"]))

print("\n4. search_logs / build_timeline / compare_devices")
search = server.search_logs("does not appear to be related", context=1)
check("search deduplicates repeated events", search["total_matches"] == 3)
check("search output redacted", clean(search))
timeline = server.build_timeline(around="2026-09-10 09:15", minutes_before=2, minutes_after=2)
check("timeline around the dropped connection", any(r.get("known_issue") == "client_server_channel_closed"
                                                   for r in timeline["rows"]))
compare = server.compare_devices("WS-GOOD01", "WS-BAD07")
only = {i["known_issue"]["id"] for i in compare["only_on_problem_device"] if i["known_issue"]}
check("problem-only issues found", "services_sensor_missing_dll" in only, ", ".join(sorted(only)))

print("\n5. detect_log_anomalies")
anomalies = server.detect_log_anomalies(since="24h", baseline_days=7)
for finding in anomalies["findings"][:5]:
    print(f"      [{finding['severity']}] {finding['type']}: {finding['reasoning'][:140]}")
check("feed failure spike flagged", any(f["type"] == "error_spike" and f["known_issue"] == "feed_check_failed"
                                        for f in anomalies["findings"]))
check("restart loop flagged", anomalies["findings_by_type"].get("service_restarts") == 1)

print("\n6. explain and error handling")
check("error code explained", server.explain("0x80070643")["name"] == "HRESULT_FROM_WIN32(ERROR_INSTALL_FAILURE)")
bad = server.summarize_errors(since="last tuesday")
check("bad time returns a structured error", bad["ok"] is False and bad["error"] == "invalid_input")
missing = server.add_log_source("nope", str(WORK / "missing.zip"))
check("missing path explained", missing["ok"] is False and "Cannot use" in missing["message"])
check("source removed", server.remove_log_source("client13")["ok"] is True)

print(f"\n{'FAILED: ' + ', '.join(failures) if failures else 'All local smoke checks passed.'}")
sys.exit(1 if failures else 0)
