"""Summaries, search, timelines, playbooks, comparisons and source checks over the sample logs."""

from __future__ import annotations

import json

import pytest

from tenable_patch_management_logs_mcp import analysis
from tenable_patch_management_logs_mcp.errors import InputError
from tests.conftest import make_registry
from tests.sample_logs import PLANTED_KEY, PLANTED_TOKEN, REJECTED_IP


def assert_no_secrets(result: dict) -> None:
    text = json.dumps(result, default=str)
    assert PLANTED_KEY not in text
    assert PLANTED_TOKEN not in text
    assert "Hunter2Hunter2" not in text


# --------------------------------------------------------------------------- #
# summarize_errors
# --------------------------------------------------------------------------- #


def test_summary_groups_dedupes_and_sets_noise_aside(registry):
    result = analysis.summarize_errors(registry, since="24h", top=50)
    assert result["ok"] is True
    assert result["window"]["to_is_newest_entry"] is True
    assert result["window"]["to"].startswith("2026-09-10 12:00")
    issues = {issue["known_issue"]["id"]: issue for issue in result["issues"] if issue["known_issue"]}

    feed = issues["feed_check_failed"]
    assert feed["count"] == 12  # written to Feeds.log and adaptiva.err, counted once
    assert set(feed["logs"]) == {"Feeds.log", "adaptiva.err"}
    assert feed["root_causes"][0]["cause"].startswith("org.apache.hc.core5.util.TimeoutValueException")
    assert result["totals"]["duplicate_lines_in_other_logs"] >= 12

    assert issues["tvm_keys_not_linked_to_container"]["count"] == 3
    assert "tvm_keys_not_linked_to_container" in result["known_issues"]
    assert issues["services_sensor_missing_dll"]["raised_from_lower_level"] == 1

    noise_ids = {row["known_issue"] for row in result["noise"]}
    assert {"content_receipt_cleanup_noise", "http_client_lazy_init_noise"} <= noise_ids
    assert not any(issue["known_issue"] and issue["known_issue"]["noise"] for issue in result["issues"])
    assert_no_secrets(result)


def test_errors_rank_above_warnings(registry):
    issues = analysis.summarize_errors(registry, since="24h", top=50)["issues"]
    severities = [issue["severity"] for issue in issues]
    assert severities == sorted(severities, key=lambda s: {"FATAL": 0, "ERROR": 1, "WARN": 2}[s])


def test_include_noise_puts_noise_back_in_issues(registry):
    result = analysis.summarize_errors(registry, since="24h", include_noise=True, top=100)
    assert any(issue["known_issue"] and issue["known_issue"]["noise"] for issue in result["issues"])


def test_filters_narrow_the_scope(registry):
    result = analysis.summarize_errors(registry, since="7d", device="WS-BAD07", min_severity="ERROR")
    assert result["scope"]["devices"] == ["WS-BAD07"]
    assert all(issue["severity"] in ("ERROR", "FATAL") for issue in result["issues"])


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"since": "yesterday-ish"}, "not a valid time"),
        ({"since": "2026-09-10", "until": "2026-09-01"}, "earlier"),
        ({"min_severity": "LOUD"}, "min_severity"),
        ({"device": "no-such-device"}, "No log files match"),
        ({"role": "printer"}, "role must be"),
    ],
)
def test_bad_arguments_raise_input_errors(registry, kwargs, message):
    with pytest.raises(InputError) as excinfo:
        analysis.summarize_errors(registry, **kwargs)
    assert message in excinfo.value.message


def test_read_budget_truncation_is_reported(registry, monkeypatch):
    monkeypatch.setattr(analysis, "MAX_BYTES_PER_CALL", 1)
    coverage = analysis.summarize_errors(registry, since=None)["coverage"]
    assert coverage["truncated"] is True
    assert coverage["files_read"] == 1
    assert "not read" in coverage["truncation_note"]


# --------------------------------------------------------------------------- #
# search_logs
# --------------------------------------------------------------------------- #


def test_search_is_deduplicated_across_logs_and_redacted(registry):
    result = analysis.search_logs(registry, "does not appear to be related", limit=10)
    assert result["total_matches"] == 3
    assert all(match["also_in"] for match in result["matches"])
    assert result["matches"][0]["timestamp"] > result["matches"][-1]["timestamp"]  # newest first
    assert_no_secrets(result)


def test_search_can_find_secrets_but_never_returns_them(registry):
    result = analysis.search_logs(registry, PLANTED_TOKEN)
    assert result["total_matches"] == 1
    assert_no_secrets(result)


def test_search_matches_inside_stack_traces_with_context(registry):
    result = analysis.search_logs(registry, r"UnsatisfiedLinkError", regex=True, context=1, device="WS-BAD07")
    assert result["total_matches"] == 1
    match = result["matches"][0]
    assert match["component"] == "PatchingAdmin"
    assert "context_before" in match and "context_after" in match


def test_search_paging(registry):
    def keys(result: dict) -> set[tuple[str, str]]:
        return {(m["log"], m["line"]) for m in result["matches"]}

    first = analysis.search_logs(registry, "HTTP connection disconnected", limit=5)
    assert first["has_more"] is True and first["next_offset"] == 5
    second = analysis.search_logs(registry, "HTTP connection disconnected", limit=5, offset=5)
    assert len(keys(first)) == len(keys(second)) == 5
    assert keys(first).isdisjoint(keys(second))
    assert first["matches"][-1]["timestamp"] >= second["matches"][0]["timestamp"]


def test_search_component_filter_and_bad_regex(registry):
    result = analysis.search_logs(registry, "Periodic Feed Check", component="FeedServer", since="24h", limit=1)
    assert result["total_matches"] > 0
    with pytest.raises(InputError):
        analysis.search_logs(registry, "(unclosed", regex=True)


# --------------------------------------------------------------------------- #
# build_timeline
# --------------------------------------------------------------------------- #


def test_timeline_interleaves_devices_and_collapses_repeats(registry):
    result = analysis.build_timeline(registry, since="2026-09-10 08:00", until="2026-09-10 10:05", limit=500)
    rows = result["rows"]
    assert [row["time"] for row in rows] == sorted(row["time"] for row in rows)
    assert {"server", "WS-BAD07"} <= {row["device"] for row in rows}
    assert any(row.get("known_issue") == "services_sensor_missing_dll" for row in rows)
    assert result["sampled"] is False


def test_timeline_around_a_moment(registry):
    result = analysis.build_timeline(registry, around="2026-09-10 09:15", minutes_before=1, minutes_after=1)
    assert result["window"]["from"] == "2026-09-10 09:14:00.000"
    assert any(row.get("known_issue") == "client_server_channel_closed" for row in result["rows"])


def test_timeline_sampling_keeps_warnings(registry):
    result = analysis.build_timeline(registry, since="36h", limit=10, collapse_repeats=False)
    assert result["sampled"] is True
    assert len(result["rows"]) == 10
    assert all(row["severity"] in ("WARN", "ERROR", "FATAL") for row in result["rows"])


# --------------------------------------------------------------------------- #
# diagnose
# --------------------------------------------------------------------------- #


def test_vm_integration_playbook(registry):
    result = analysis.diagnose(registry, "vm_integration", since="7d")
    assert "not configured" in result["verdict"]
    assert "API key validation failed 4 time(s)" in result["verdict"]
    assert result["details"]["counts"]["key_validation_attempts"] == 3
    assert {f["id"] for f in result["findings"]} >= {"tvm_keys_not_linked_to_container", "tvm_invalid_credentials"}
    assert_no_secrets(result)


def test_feeds_playbook_reports_last_success_and_recovery(registry):
    result = analysis.diagnose(registry, "feeds", since="30d")
    details = result["details"]
    assert details["last_successful_check"] == "2026-09-10 11:30:00.300"
    assert details["counts"]["checks_failed"] == 12 + 8  # current day plus one a day in the baseline
    assert "Checks have succeeded since the last failure" in result["verdict"]
    assert details["failure_root_causes"][0]["cause"].startswith("org.apache.hc.core5.util.TimeoutValueException")


def test_client_connectivity_playbook(registry):
    result = analysis.diagnose(registry, "client_connectivity", since="7d")
    details = result["details"]
    assert details["unacknowledged_messages_by_client"][0]["client_id"] == "42"
    assert details["unacknowledged_messages_by_client"][0]["max_retry_count"] == 34
    assert details["install_auth_rejections"][0]["ip"] == REJECTED_IP
    assert "WS-BAD07" in details["client_server_bindings"]
    assert "client IDs 42" in result["verdict"]


def test_patch_install_failed_playbook(registry):
    result = analysis.diagnose(registry, "patch_install_failed", since="7d", device="WS-BAD07")
    details = result["details"]
    [failed] = details["deployment_results_with_failure_evidence"]
    assert failed["patch_id"] == "1021126111"
    codes = {row["code"]["code"] for row in details["error_codes"]}
    assert {"1603", "0x800F0922"} <= codes
    [msi] = details["installer_failures"]
    assert msi["product"] == "Contoso App"
    assert msi["failed_action"] == "InstallFinalize"
    assert msi["exit_code"]["name"] == "ERROR_INSTALL_FAILURE"
    assert result["findings"][0]["id"] == "services_sensor_missing_dll"


def test_healthy_device_has_no_patch_failures(registry):
    result = analysis.diagnose(registry, "patch_install_failed", since="7d", device="WS-GOOD01")
    assert result["details"]["deployment_results_seen"] == 1
    assert result["details"]["deployment_results_with_failure_evidence"] == []


def test_service_health_detects_a_restart_loop(registry):
    result = analysis.diagnose(registry, "service_health", since="7d")
    assert result["details"]["restart_loops"][0]["device"] == "server"
    assert "Restart loop on server" in result["verdict"]


def test_database_playbook_sets_noise_aside(registry):
    result = analysis.diagnose(registry, "database", since="30d")
    assert "known-noise event(s) set aside" in result["verdict"]
    assert result["findings"][0]["id"] == "duplicate_key_violation"
    assert result["findings"][-1]["id"] == "sqlserver_proc_on_postgres"


def test_feature_update_readiness_playbook(registry):
    result = analysis.diagnose(registry, "feature_update_readiness", since="7d")
    [reading] = result["details"]["latest_free_space"]
    assert reading["free_gb"] == 20.0 and reading["meets_50gb_requirement"] is False
    assert result["details"]["not_installed_scan_results"] == {"WS-BAD07": 1}


def test_content_publication_playbook(registry):
    result = analysis.diagnose(registry, "content_publication", since="7d")
    assert result["details"]["failed_content"][0]["content_id"] == "Policy_104117"


def test_client_upgrade_playbook_reads_setup_logs(registry):
    result = analysis.diagnose(registry, "client_upgrade", since="7d")
    assert result["findings"][0]["id"] == "client_upgrade_virtual_mode_failed"


def test_playbook_reports_missing_logs(tmp_path, sample_tree):
    only_server = make_registry(tmp_path / "data", server=sample_tree["server_zip"])
    result = analysis.diagnose(only_server, "patch_install_failed")
    assert result["missing_logs"][0]["what"] == "client logs"


def test_unknown_symptom(registry):
    with pytest.raises(InputError) as excinfo:
        analysis.diagnose(registry, "printer_on_fire")
    assert "patch_install_failed" in excinfo.value.remediation


# --------------------------------------------------------------------------- #
# compare_devices, check_sources, list_log_files, explain
# --------------------------------------------------------------------------- #


def test_compare_devices(registry):
    result = analysis.compare_devices(registry, "WS-GOOD01", "WS-BAD07")
    only = {issue["known_issue"]["id"] for issue in result["only_on_problem_device"] if issue["known_issue"]}
    assert {"services_sensor_missing_dll", "client_server_channel_closed"} <= only
    assert "sensor_expression_warnings" not in only  # both devices have it
    assert result["shared_issues"] >= 1
    with pytest.raises(InputError):
        analysis.compare_devices(registry, "WS-GOOD01", "WS-GOOD01")


def test_check_sources_reports_devices_deployment_and_versions(registry):
    result = analysis.check_sources(registry)
    assert result["ok"] is True
    sources = {source["name"]: source for source in result["sources"]}
    assert sources["saas-server"]["deployment"]["value"] == "saas"
    assert sources["saas-server"]["deployment"]["versions"][0]["version"] == "10.2.973.9"
    assert {d["device"] for d in sources["clients"]["devices"]} == {"WS-BAD07", "WS-GOOD01"}
    assert result["guidance"] == []


def test_check_sources_guides_towards_missing_client_logs(tmp_path, sample_tree):
    only_server = make_registry(tmp_path / "data", server=sample_tree["server_zip"])
    result = analysis.check_sources(only_server)
    assert any("No client logs" in item for item in result["guidance"])


def test_check_sources_without_anything_configured(tmp_path):
    from tenable_patch_management_logs_mcp.sources import SourceRegistry

    result = analysis.check_sources(SourceRegistry(data_dir=tmp_path / "d", env={"TPM_AUTO_DISCOVER": "false"}))
    assert result["ok"] is False and result["error"] == "no_sources"


def test_list_log_files_filters_by_name_glob(registry):
    result = analysis.list_log_files(registry, name="adaptiva.log", device="server")
    names = {row["file"].split("\\")[-1].split("/")[-1] for row in result["files"]}
    assert names == {"adaptiva.log", "adaptiva.1.log", "adaptiva.2.log.gz"}
    assert all(row["layout"] == "adaptiva" for row in result["files"])


@pytest.mark.parametrize(
    ("topic", "kind"),
    [
        (None, "index"),
        ("_SDMErrors.log", "log"),
        ("13_adaptiva.log", "log"),
        ("0x80070643", "error_code"),
        ("patch_install_failed", "symptom"),
        ("feed_check_failed", "known_issue"),
        ("feature update", "search"),
    ],
)
def test_explain(topic, kind):
    assert analysis.explain(topic)["type"] == kind


def test_explain_unknown_topic():
    with pytest.raises(InputError):
        analysis.explain("zzzz-nothing-matches-this")
