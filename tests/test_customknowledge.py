"""Site knowledge files: what loads, what is rejected, and how it changes the results."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from tenable_patch_management_logs_mcp import analysis, classifier, customknowledge
from tenable_patch_management_logs_mcp.logformat import LogEntry
from tests.conftest import make_registry

PROXY_ISSUE = {
    "id": "acme_proxy_407",
    "title": "ACME: proxy rejects client downloads",
    "pattern": r"407 Proxy Authentication Required",
    "impact": "high",
    "category": "connectivity",
    "explanation": "Our proxy asks TPM clients to authenticate, which they cannot do.",
    "remediation": "Allow *.adaptiva.cloud through the proxy without authentication.",
    "applies_to": "client",
    "source": "https://acme.example/runbooks/407",
}


def write_knowledge(path: Path, document: dict) -> Path:
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return path


def entry(message: str) -> LogEntry:
    return LogEntry(line=1, timestamp=datetime(2026, 9, 10, 11, 0), level="ERROR", message=message,
                    raw=message, layout="adaptiva", component="HttpTransport")


def load(tmp_path: Path, document: dict, monkeypatch: pytest.MonkeyPatch) -> customknowledge.CustomKnowledge:
    path = write_knowledge(tmp_path / "known_issues.json", document)
    monkeypatch.setenv(customknowledge.ENV_FILE, str(path))
    return customknowledge.reload()


# --------------------------------------------------------------------------- #
# Loading and validation
# --------------------------------------------------------------------------- #


def test_no_file_means_no_site_knowledge(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TPM_MCP_DATA_DIR", str(tmp_path))
    monkeypatch.delenv(customknowledge.ENV_FILE, raising=False)
    knowledge = customknowledge.reload()
    assert knowledge.issues == () and knowledge.configured is False
    assert "known_issues.json" in knowledge.to_dict()["note"]


def test_a_valid_entry_becomes_a_known_issue(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    knowledge = load(tmp_path, {"known_issues": [PROXY_ISSUE]}, monkeypatch)
    [issue] = knowledge.issues
    assert issue.id == "acme_proxy_407"
    assert issue.impact == "high" and issue.applies_to == "client" and issue.confidence == "site"
    assert issue.to_dict()["source"] == "https://acme.example/runbooks/407"
    assert knowledge.to_dict()["known_issues_loaded"] == 1
    assert "problems" not in knowledge.to_dict()


def test_only_id_title_and_pattern_are_required(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    knowledge = load(tmp_path, {"known_issues": [
        {"id": "acme_noise", "title": "ACME: chatter we ignore", "pattern": "Reticulating splines", "impact": "none"},
    ]}, monkeypatch)
    [issue] = knowledge.issues
    assert issue.is_noise is True
    assert issue.explanation == customknowledge.DEFAULT_EXPLANATION
    assert issue.remediation == customknowledge.DEFAULT_REMEDIATION


def test_bad_entries_are_named_and_the_good_ones_still_load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    knowledge = load(tmp_path, {"known_issues": [
        PROXY_ISSUE,
        {"id": "no spaces allowed", "title": "x", "pattern": "y"},
        {"id": "acme_no_title", "pattern": "y"},
        {"id": "acme_no_pattern", "title": "x"},
        {"id": "acme_bad_regex", "title": "x", "pattern": "([unclosed"},
        {"id": "acme_bad_impact", "title": "x", "pattern": "y", "impact": "catastrophic"},
        {"id": "acme_proxy_407", "title": "duplicate", "pattern": "z"},
        "not an object",
    ]}, monkeypatch)
    assert [issue.id for issue in knowledge.issues] == ["acme_proxy_407"]
    problems = " | ".join(knowledge.problems)
    assert "no spaces allowed" in problems
    assert "has no title" in problems and "has no pattern" in problems
    assert "not a valid regular expression" in problems
    assert "impact must be one of" in problems
    assert "already defined" in problems
    assert knowledge.to_dict()["remediation"].startswith("Fix the entries")


def test_a_broken_file_is_reported_not_raised(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "known_issues.json"
    path.write_text("{ this is not json", encoding="utf-8")
    monkeypatch.setenv(customknowledge.ENV_FILE, str(path))
    knowledge = customknowledge.reload()
    assert knowledge.issues == ()
    assert "invalid JSON" in knowledge.problems[0]

    monkeypatch.setenv(customknowledge.ENV_FILE, str(tmp_path / "gone.json"))
    assert "not found" in customknowledge.reload().problems[0]


def test_the_data_dir_file_is_picked_up_without_configuration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(customknowledge.ENV_FILE, raising=False)
    monkeypatch.setenv("TPM_MCP_DATA_DIR", str(tmp_path))
    write_knowledge(tmp_path / "known_issues.json", {"known_issues": [PROXY_ISSUE]})
    assert [issue.id for issue in customknowledge.reload().issues] == ["acme_proxy_407"]


def test_an_edited_file_is_picked_up(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = write_knowledge(tmp_path / "known_issues.json", {"known_issues": [PROXY_ISSUE]})
    monkeypatch.setenv(customknowledge.ENV_FILE, str(path))
    assert customknowledge.active().issues[0].title.startswith("ACME:")
    write_knowledge(path, {"known_issues": [{**PROXY_ISSUE, "title": "ACME: renamed"}]})
    customknowledge.reset()
    assert customknowledge.active().issues[0].title == "ACME: renamed"


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #


def test_site_issues_are_matched_before_the_built_in_ones(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    load(tmp_path, {"known_issues": [PROXY_ISSUE]}, monkeypatch)
    matched = classifier.match_known_issue(entry("Download failed: HTTP/1.1 407 Proxy Authentication Required"))
    assert matched is not None and matched.id == "acme_proxy_407"
    _, catalog = classifier.known_issue_catalog()
    assert catalog[0].id == "acme_proxy_407"
    assert classifier.known_issue_by_id("acme_proxy_407") is not None
    # The built-in catalog still works.
    assert classifier.match_known_issue(entry("java.lang.OutOfMemoryError: Java heap space")) is not None


def test_a_site_entry_can_replace_a_built_in_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    knowledge = load(tmp_path, {"known_issues": [{
        "id": "jvm_out_of_memory",
        "title": "ACME: out of memory - page the platform team",
        "pattern": "OutOfMemoryError",
        "impact": "high",
    }]}, monkeypatch)
    assert knowledge.overrides == ["jvm_out_of_memory"]
    assert knowledge.to_dict()["built_in_issues_replaced"] == ["jvm_out_of_memory"]
    matched = classifier.match_known_issue(entry("java.lang.OutOfMemoryError: Java heap space"))
    assert matched is not None and matched.title.startswith("ACME:")
    ids = [issue.id for issue in classifier.known_issue_catalog()[1]]
    assert ids.count("jvm_out_of_memory") == 1


def test_a_pattern_the_prefilter_cannot_hold_still_matches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Two named groups with the same name cannot be combined into one union pattern.
    load(tmp_path, {"known_issues": [
        {"id": "acme_one", "title": "one", "pattern": r"(?P<code>\d+) failed"},
        {"id": "acme_two", "title": "two", "pattern": r"(?P<code>\d+) refused"},
    ]}, monkeypatch)
    union, catalog = classifier.known_issue_catalog()
    assert union is None
    assert [issue.id for issue in catalog[:2]] == ["acme_one", "acme_two"]
    matched = classifier.match_known_issue(entry("Request 42 refused by the server"))
    assert matched is not None and matched.id == "acme_two"


def test_site_noise_is_set_aside_like_built_in_noise(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                    registry, sample_tree) -> None:
    load(tmp_path, {"known_issues": [{
        "id": "acme_feed_chatter",
        "title": "ACME: feed timeouts we already have a ticket for",
        "pattern": "An exception arose trying to retrieve new Feed instructions",
        "impact": "none",
    }]}, monkeypatch)
    result = analysis.summarize_errors(registry, since="24h", top=50)
    noise = {row["known_issue"]: row for row in result["noise"]}
    assert "acme_feed_chatter" in noise
    assert noise["acme_feed_chatter"]["title"].startswith("ACME:")
    assert all(issue["known_issue"]["id"] != "acme_feed_chatter" for issue in result["issues"] if issue["known_issue"])


# --------------------------------------------------------------------------- #
# PatchDeploymentResult mappings
# --------------------------------------------------------------------------- #


def test_deployment_result_values_are_decoded_when_mapped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    load(tmp_path, {"patch_deployment_results": {
        "operation_status": {"3": "Failed"},
        "reason_code": {"3010": "Success, reboot required"},
        "made_up_field": {"1": "x"},
    }}, monkeypatch)
    knowledge = customknowledge.active()
    assert knowledge.decode_result("operation_status", "3") == "Failed"
    assert knowledge.decode_result("reason_code", "3010") == "Success, reboot required"
    assert knowledge.decode_result("reason_code", "9999") is None
    assert "made_up_field" in " ".join(knowledge.problems)

    message = ("Completion status for patch [KB5001234], request [77] is [PatchDeploymentResult "
               "operation=[1], softwareDeploymentOperationStatus=[3], reasonCode=[3010], wuaRebootRequired=[true], "
               "reasonMessage='Installer returned 3010']")
    result = classifier.extract_patch_result(entry(message))
    assert result is not None
    assert result["operation_status_meaning"] == "Failed"
    assert result["reason_code_meaning"] == "Success, reboot required"


def test_without_mappings_the_playbook_says_how_to_add_them(registry) -> None:
    result = analysis.diagnose(registry, "patch_install_failed", since="24h")
    assert "site knowledge file" in result["details"]["note"]


def test_with_mappings_the_playbook_says_they_were_used(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                        registry) -> None:
    load(tmp_path, {"patch_deployment_results": {"reason_code": {"3010": "Reboot required"}}}, monkeypatch)
    result = analysis.diagnose(registry, "patch_install_failed", since="24h")
    assert "reason_code: 1" in result["details"]["note"]


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


def test_check_log_sources_and_explain_report_the_site_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                            sample_tree) -> None:
    path = write_knowledge(tmp_path / "known_issues.json", {"known_issues": [PROXY_ISSUE]})
    monkeypatch.setenv(customknowledge.ENV_FILE, str(path))
    customknowledge.reset()
    registry = make_registry(tmp_path / "data", env={customknowledge.ENV_FILE: str(path)},
                             **{"saas-server": sample_tree["server_zip"]})
    site = analysis.check_sources(registry)["configuration"]["site_knowledge"]
    assert site["configured"] is True and site["known_issues_loaded"] == 1
    assert site["files"] == [str(path)]

    index = analysis.explain()
    assert index["site_known_issues"] == ["acme_proxy_407"]
    assert index["known_issues"]["acme_proxy_407"].startswith("ACME:")
    explained = analysis.explain("acme_proxy_407")
    assert explained["from_site_knowledge_file"] is True
    assert explained["remediation"].startswith("Allow")
    assert any(hit["id"] == "acme_proxy_407" for hit in analysis.explain("proxy")["known_issues"])
