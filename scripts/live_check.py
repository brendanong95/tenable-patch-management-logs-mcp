"""Run the tools against your real TPM logs (read-only) and print what they find.

Uses TPM_LOG_SOURCES / sources added with add_log_source / auto-discovered local logs,
exactly as the MCP server does. Nothing is written except the extracted copy of any
bundle in the data folder.

    uv run python scripts/live_check.py [window]

``window`` defaults to 7d (relative to the newest log entry).

It also prints the zone, site-knowledge and recorded-baseline configuration in force,
so a misconfigured zone or knowledge file shows up before you trust the numbers.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import find_dotenv, load_dotenv  # noqa: E402

load_dotenv(find_dotenv(usecwd=True))

from tenable_patch_management_logs_mcp import server  # noqa: E402

WINDOW = sys.argv[1] if len(sys.argv) > 1 else "7d"


def timed(label: str, call):
    started = time.perf_counter()
    result = call()
    print(f"\n=== {label} ({time.perf_counter() - started:.1f}s, ok={result.get('ok')}) ===")
    if not result.get("ok"):
        print("  error:", result.get("error"), "-", result.get("message"))
        print("  remediation:", result.get("remediation"))
    return result


sources = timed("check_log_sources", server.check_log_sources)
if not sources.get("ok"):
    print("\nStopping: configure log sources first (see README).")
    sys.exit(1)
roles: set[str] = set()
for source in sources["sources"]:
    deployment = source.get("deployment", {})
    print(f"  {source['name']}: {source.get('files', 0)} file(s), deployment={deployment.get('value')}, "
          f"versions={[v['version'] for v in deployment.get('versions', [])]}")
    for device in source.get("devices", []):
        roles |= set(device["roles"])
        print(f"    - {device['device']} {device['roles']} {device['first_entry']} -> {device['last_entry']}")
for item in sources.get("guidance", []):
    print("  guidance:", item)
config = sources.get("configuration", {})
zones = config.get("time_zones", {})
print(f"  time zones: display={zones.get('display_timezone') or 'as written'} {zones.get('log_timezones') or ''}")
for problem in zones.get("problems", []):
    print("    problem:", problem)
site = config.get("site_knowledge", {})
print(f"  site knowledge: {site.get('known_issues_loaded', 0)} issue(s) from {len(site.get('files', []))} file(s)")
for problem in site.get("problems", []):
    print("    problem:", problem)
store = config.get("baseline_history", {})
print("  recorded baselines:", f"{store.get('days_recorded')} day(s) {store.get('first_day')} -> {store.get('last_day')}"
      if store.get("recorded") else "none (record_baseline_snapshot keeps one after the logs rotate)")

summary = timed(f"summarize_errors (since {WINDOW})", lambda: server.summarize_errors(since=WINDOW, top=15))
if summary.get("ok"):
    print("  totals:", json.dumps(summary["totals"]))
    for issue in summary["issues"]:
        title = issue["known_issue"]["title"] if issue["known_issue"] else issue["signature"]
        print(f"  #{issue['rank']:>2} [{issue['severity']}] x{issue['count']:<5} {title[:120]}")
    for row in summary["noise"]:
        print(f"  noise x{row['count']:<5} {row['title']}")

symptoms = []
if "server" in roles:
    symptoms += ["vm_integration", "feeds", "content_publication", "service_health", "database"]
if "client" in roles:
    symptoms += ["patch_install_failed", "client_connectivity", "feature_update_readiness"]
for symptom in symptoms:
    result = timed(f"diagnose {symptom}", lambda s=symptom: server.diagnose(s, since=WINDOW))
    if result.get("ok"):
        print("  verdict:", result["verdict"])

anomalies = timed("detect_log_anomalies (last 24h vs 7 days)", lambda: server.detect_log_anomalies(since="24h"))
for finding in anomalies.get("findings", [])[:10]:
    print(f"  [{finding['severity']}] {finding['type']}: {finding['reasoning'][:200]}")
if anomalies.get("ok"):
    print("  baseline history:", anomalies["baseline_history"]["note"])

print("\nLive check complete.")
