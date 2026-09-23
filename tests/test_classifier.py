"""Redaction, signatures, severity escalation, known issues and structured extraction."""

from __future__ import annotations

from datetime import datetime

import pytest

from tenable_patch_management_logs_mcp.classifier import (
    classify,
    effective_severity,
    extract_detections,
    extract_free_space,
    extract_install_auth_ip,
    extract_message_retry,
    extract_patch_result,
    extract_version,
    match_known_issue,
    normalize_signature,
    redact,
)
from tenable_patch_management_logs_mcp.logformat import LogEntry
from tests.sample_logs import PLANTED_KEY, PLANTED_TOKEN, SERVICES_SENSOR_ENTRY


def entry(message: str, level: str | None = "ERROR", detail: list[str] | None = None, component: str = "Comp") -> LogEntry:
    return LogEntry(
        line=1,
        timestamp=datetime(2026, 9, 10, 10),
        level=level,
        message=message,
        raw=message,
        layout="adaptiva",
        component=component,
        detail=detail or [],
    )


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "text",
    [
        f"Failed to validate settings with access key {PLANTED_KEY}, status code 401",
        f"Testing validity of access settings with API key ID [{PLANTED_KEY}]",
        f"Using old client token: {PLANTED_TOKEN}, for new client handshake",
        "X-ApiKeys: accessKey=abcdef0123456789;secretKey=0123456789abcdef",  # gitleaks:allow - fabricated
        "jdbc:postgresql://db:5432/tpm?password=Hunter2Hunter2",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
        "https://svc_user:SuperSecret99@proxy.example.com:8080/path",
    ],
)
def test_credentials_are_masked(text):
    redacted = redact(text)
    for secret in (PLANTED_KEY, PLANTED_TOKEN, "abcdef0123456789", "0123456789abcdef",  # gitleaks:allow - fabricated
                   "Hunter2Hunter2", "payload.signature", "SuperSecret99"):
        assert secret not in redacted


def test_masking_keeps_the_last_four_characters():
    assert redact(f"access key {PLANTED_KEY}") == "access key ****" + PLANTED_KEY[-4:]


def test_troubleshooting_identifiers_are_kept():
    text = ("hostId: [c9f6fb18-36ab-4602-ac49-dcfa48c6873c] from /10.20.30.40 by admin@example.com: "
            "Tenable returned 401 UNAUTHORIZED for access key, it is invalid.")
    assert redact(text) == text


# --------------------------------------------------------------------------- #
# Signatures
# --------------------------------------------------------------------------- #


def test_repeats_with_different_ids_share_a_signature():
    first = normalize_signature("MAC address not known for client: 11 at /10.0.0.4 id c9f6fb18-36ab-4602-ac49-dcfa48c6873c")
    second = normalize_signature("MAC address not known for client: 7 at /10.9.9.9 id 00000000-36ab-4602-ac49-dcfa48c6873c")
    assert first == second == "MAC address not known for client: <n> at <ip> id <guid>"


def test_hresults_survive_normalisation_so_different_codes_stay_apart():
    assert "0x800F0922" in normalize_signature("result code 0x800F0922 after 3 tries")
    assert normalize_signature("code 0x80070643") != normalize_signature("code 0x80240017")


def test_paths_urls_request_ids_and_secrets_collapse():
    signature = normalize_signature(
        f"Upload C:\\Program Files\\Tenable\\x.log to https://abc.adaptivacdn.cloud/Adaptiva/Policy_1/f.content "
        f"request [zpvzWCccTZKDdTfMrwrQsw] key {PLANTED_KEY}"
    )
    assert signature == "Upload <path> to https://abc.adaptivacdn.cloud/<path> request [<id>] key <secret>"


# --------------------------------------------------------------------------- #
# Severity
# --------------------------------------------------------------------------- #


def test_info_entry_with_a_stack_trace_is_raised_to_error():
    severity, reason = effective_severity(entry(SERVICES_SENSOR_ENTRY[0], level="INFO", detail=SERVICES_SENSOR_ENTRY[1:]))
    assert severity == "ERROR"
    assert "stack trace" in reason


def test_info_entry_reporting_a_nonzero_error_code_is_raised():
    severity, reason = effective_severity(entry("Result: Error Code = 5 (0x5), Source Object = null", level="INFO"))
    assert severity == "ERROR" and "Error Code = 5" in reason


def test_info_entry_with_error_code_zero_is_left_alone():
    assert effective_severity(entry("Done, Error Code = 0 (0x0)", level="INFO")) == ("INFO", None)


def test_written_warn_and_error_levels_are_kept():
    assert effective_severity(entry("x", level="WARN")) == ("WARN", None)
    assert effective_severity(entry("x", level="ERROR")) == ("ERROR", None)


def test_untagged_lines_use_failure_keywords():
    assert effective_severity(entry("CustomAction failed", level=None))[0] == "WARN"
    assert effective_severity(entry("Action ended 1:02:03: X. Return value 3.", level=None))[0] == "ERROR"
    assert effective_severity(entry("Resetting cached policy values", level=None)) == ("INFO", None)


# --------------------------------------------------------------------------- #
# Known issues
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("message", "detail", "expected"),
    [
        ('Failed to validate settings with access key x, status code 401, body: {"error": "This scanner, agent, or '
         'API key token does not appear to be related to any active containers on any sites."}', [],
         "tvm_keys_not_linked_to_container"),
        ("Tenable returned 401 UNAUTHORIZED for access key, it is invalid.", [], "tvm_invalid_credentials"),
        ("Exception occurred in executing SQL Query:EXEC [dbo].[prc_get_database_statistics]", [],
         "sqlserver_proc_on_postgres"),
        ("[Periodic Feed Check] An exception arose trying to retrieve new Feed instructions from the Operations Manager!",
         ["Caused by: java.net.SocketTimeoutException: Read timed out"], "feed_check_failed"),
        ("Could not reach", ["Caused by: java.net.UnknownHostException: services.adaptiva.cloud: Temporary failure"],
         "adaptiva_cloud_dns_failure"),
        ("Could not reach", ["Caused by: java.net.UnknownHostException: intranet.example.com"], "dns_failure"),
        (SERVICES_SENSOR_ENTRY[0], SERVICES_SENSOR_ENTRY[1:], "services_sensor_missing_dll"),
        ("Something nobody has seen before", [], None),
    ],
)
def test_known_issue_matching_prefers_specific_signatures(message, detail, expected):
    issue = match_known_issue(entry(message, detail=detail))
    assert (issue.id if issue else None) == expected


def test_classify_builds_a_complete_event():
    event = classify(
        entry("Installation of patch [1021126111] failed with exit code [1603]", component="SoftwareInstaller"),
        source="s", device="WS-BAD07", role="client", file="componentlogs/_SDMErrors.log", log_name="_SDMErrors.log",
    )
    assert event.signature == "Installation of patch [<n>] failed with exit code [<n>]"
    assert [c.value for c in event.codes] == [1603]
    assert event.dedupe_key()[0] == "WS-BAD07"


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #


def test_patch_deployment_result_fields_and_failure_evidence():
    result = extract_patch_result(entry(SERVICES_SENSOR_ENTRY[0], level="INFO", detail=SERVICES_SENSOR_ENTRY[1:]))
    assert result["patch_id"] == "1021126111"
    assert result["request_id"] == "zpvzWCccTZKDdTfMrwrQsw"
    assert result["operation_status"] == "2"
    assert result["reason_code"] == "1"
    assert result["reboot_required"] == "false"
    assert "reasonCode=1" in result["failure_evidence"]
    assert any("EvaluatorException" in item for item in result["failure_evidence"])


def test_successful_patch_result_has_no_failure_evidence():
    result = extract_patch_result(entry(
        "Completion status for patch [1], request [abc] is [PatchDeploymentResult : patchID=[1],, operation=1, "
        "softwareDeploymentOperationStatus=1, reasonCode=0, reasonMessage='', wuaRebootRequired=false]", level="INFO"))
    assert result["failure_evidence"] == []


def test_other_extractions():
    assert extract_message_retry(entry(
        "The message has been retried 33 times . Message is :Name of the message: ContentDeletion, Sender ID: 0, "
        "Receiver ID: 1, Queue ID: 1")) == {"receiver_client_id": "1", "message": "ContentDeletion", "retry_count": 33}
    assert extract_install_auth_ip(entry(
        "All Client install authentication enabled, install attempted without auth information: /192.0.2.7")) == "192.0.2.7"
    assert extract_free_space(entry("Drive [C] is having actualFreeSpace Including Progress [21474836480]")) == ("C", 21474836480)
    assert extract_detections(entry("Processing 12 vulnerability detections that were marked as NEW")) == ("NEW", 12)
    assert extract_version(entry("Current Version: 10.2.973.9")) == "10.2.973.9"
