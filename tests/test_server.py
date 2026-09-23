"""Tool registration and the structured-result contract of every tool."""

from __future__ import annotations

import asyncio
import json

import pytest

from tenable_patch_management_logs_mcp import server
from tenable_patch_management_logs_mcp.sources import SourceRegistry
from tests.sample_logs import PLANTED_KEY, PLANTED_TOKEN

READ_ONLY_TOOLS = {
    "check_log_sources", "list_log_files", "summarize_errors", "search_logs", "build_timeline", "diagnose",
    "compare_devices", "detect_log_anomalies", "explain",
}


@pytest.fixture()
def wired(registry, monkeypatch):
    monkeypatch.setattr(server, "_registry", registry)
    return registry


def test_all_tools_are_registered_with_annotations():
    tools = {tool.name: tool for tool in asyncio.run(server.mcp.list_tools())}
    assert set(tools) == READ_ONLY_TOOLS | {"add_log_source", "remove_log_source"}
    for name, tool in tools.items():
        hints = tool.model_dump(exclude_none=True).get("annotations") or {}
        read_only = hints.get("read_only_hint", hints.get("readOnlyHint"))
        assert read_only is (name in READ_ONLY_TOOLS), name


def test_every_read_tool_returns_ok_without_leaking_secrets(wired):
    calls = [
        server.check_log_sources(),
        server.list_log_files(),
        server.summarize_errors(),
        server.search_logs("token"),
        server.build_timeline(since="24h"),
        server.compare_devices("WS-GOOD01", "WS-BAD07"),
        server.detect_log_anomalies(),
        server.explain("1603"),
        *[server.diagnose(symptom) for symptom in (
            "patch_install_failed", "content_download", "client_connectivity", "vm_integration", "feeds",
            "content_publication", "service_health", "database", "client_upgrade", "feature_update_readiness",
        )],
    ]
    for result in calls:
        assert result["ok"] is True, result
        text = json.dumps(result, default=str)
        assert PLANTED_KEY not in text and PLANTED_TOKEN not in text


def test_bad_input_comes_back_as_a_structured_error(wired):
    result = server.summarize_errors(since="the other day")
    assert result == {
        "ok": False,
        "error": "invalid_input",
        "message": "since='the other day' is not a valid time.",
        "remediation": result["remediation"],
    }
    assert "relative span" in result["remediation"]


def test_no_sources_is_explained(tmp_path, monkeypatch):
    monkeypatch.setattr(
        server, "_registry", SourceRegistry(data_dir=tmp_path / "d", env={"TPM_AUTO_DISCOVER": "false"})
    )
    result = server.summarize_errors()
    assert result["ok"] is False and result["error"] == "no_sources"
    assert "add_log_source" in result["remediation"]


def test_add_and_remove_source_through_the_tools(tmp_path, sample_tree, monkeypatch):
    monkeypatch.setattr(
        server, "_registry", SourceRegistry(data_dir=tmp_path / "d", env={"TPM_AUTO_DISCOVER": "false"})
    )
    added = server.add_log_source("case", str(sample_tree["server_zip"]))
    assert added["ok"] is True and added["devices"] == ["server"] and added["roles"] == ["server"]
    missing = server.add_log_source("other", str(tmp_path / "missing.zip"))
    assert missing["ok"] is False and missing["error"] == "source_error"
    assert server.remove_log_source("case")["ok"] is True
    assert server.remove_log_source("case")["ok"] is False


def test_unexpected_exceptions_do_not_escape(wired, monkeypatch):
    def explode(*args, **kwargs):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(server.analysis, "summarize_errors", explode)
    result = server.summarize_errors()
    assert result["ok"] is False and result["error"] == "unexpected_error"
    assert "kaboom" in result["message"]
