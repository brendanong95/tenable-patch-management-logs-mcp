"""Source registration, bundle extraction, and file / device / role detection."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from tenable_patch_management_logs_mcp.errors import InputError, NoSourcesError, SourceError
from tenable_patch_management_logs_mcp.sources import SourceRegistry, detect_device, detect_role, logical_name
from tests.conftest import make_registry
from tests.sample_logs import build_single_client_log, malicious_zip, zip_folder


@pytest.mark.parametrize(
    ("filename", "parents", "expected"),
    [
        ("adaptiva.log", [], ("adaptiva.log", "adaptiva.log", 0, None)),
        ("adaptiva.2.log", [], ("adaptiva.log", "adaptiva.log", 2, None)),
        ("Feeds.1.log", ["componentlogs"], ("feeds.log", "Feeds.log", 1, None)),
        ("adaptiva.log.3", [], ("adaptiva.log", "adaptiva.log", 3, None)),
        ("adaptiva.2.log.gz", [], ("adaptiva.log", "adaptiva.log", 2, None)),
        ("13_adaptiva.log", [], ("adaptiva.log", "adaptiva.log", 0, "13")),
        ("hs_err_pid4242.log", [], ("hs_err_pid.log", "hs_err_pid4242.log", 0, None)),
        ("Policy Updated Workflow_10798_2306.log", ["workflowlogs"], ("workflowlogs", "Policy Updated Workflow", 0, None)),
        ("1021126111_ab12cd34.log", ["msiLogs"], ("msilogs", "1021126111_ab12cd34.log", 0, None)),
        ("tenable-patch-client-10.2.973.9.log", [], ("tenable-patch-client-10.2.973.9.log",
                                                     "tenable-patch-client-10.2.973.9.log", 0, None)),
        ("2026_notes.txt", [], ("2026_notes.txt", "2026_notes.txt", 0, None)),
    ],
)
def test_logical_names(filename, parents, expected):
    assert logical_name(filename, parents) == expected


def test_device_detection():
    assert detect_device(["TPM-Logs-20260910", "WS-BAD07", "PatchClient", "logs", "componentlogs"], "fallback") == "WS-BAD07"
    assert detect_device(["adaptiva-server", "componentlogs"], "server") == "server"
    assert detect_device([], "fallback", client_id="13") == "client-13"


def test_role_detection():
    assert detect_role(["adaptiva-server", "componentlogs"], "feeds.log", None) == "server"
    assert detect_role(["WS-BAD07", "PatchClient", "logs"], "adaptiva.log", None) == "client"
    assert detect_role(["WS-BAD07", "AdaptivaSetupLogs", "Client"], "adaptivaclientsetup.log", None) == "setup"
    assert detect_role([], "vulnerabilitymanagement.log", None) == "server"
    assert detect_role([], "_sdmerrors.log", None) == "client"
    assert detect_role([], "adaptiva.log", "13") == "client"
    assert detect_role([], "adaptiva.log", None) == "unknown"


def test_env_sources_resolve_bundle_folder_and_single_file(registry):
    sources = {source.name: source for source in registry.sources()}
    assert sources["saas-server"].kind == "bundle"
    assert sources["clients"].kind == "folder"
    assert sources["client13"].kind == "file"
    assert all(source.available for source in sources.values())


def test_server_bundle_files_are_classified(registry):
    [server] = [s for s in registry.sources() if s.name == "saas-server"]
    files = registry.files(server)
    assert {f.device for f in files} == {"server"}
    assert {f.role for f in files} == {"server"}
    by_name = {f.path.name: f for f in files}
    assert by_name["adaptiva.2.log.gz"].rotation == 2
    assert by_name["Policy Updated Workflow_10798_2306.log"].log_key == "workflowlogs"
    assert by_name["Feeds.1.log"].log_key == "feeds.log"


def test_collector_folder_files_are_classified(registry):
    [clients] = [s for s in registry.sources() if s.name == "clients"]
    files = registry.files(clients)
    assert {f.device for f in files} == {"WS-BAD07", "WS-GOOD01"}
    setup = [f for f in files if f.log_key == "adaptivaclientsetup.log"]
    assert setup and setup[0].role == "setup" and setup[0].device == "WS-BAD07"
    msi = [f for f in files if f.log_key == "msilogs"]
    assert msi and msi[0].role == "client"


def test_requested_client_log_is_its_own_device(registry):
    [single] = [s for s in registry.sources() if s.name == "client13"]
    [log_file] = registry.files(single)
    assert (log_file.device, log_file.role, log_file.client_id) == ("client-13", "client", "13")


def test_tar_bundles_work_like_folders(tmp_path, sample_tree):
    registry = make_registry(tmp_path / "data", clients=sample_tree["clients_tar"])
    [source] = registry.sources()
    assert source.kind == "bundle"
    assert {f.device for f in registry.files(source)} == {"WS-BAD07", "WS-GOOD01"}


def test_bundles_are_extracted_once(tmp_path, sample_tree):
    registry = make_registry(tmp_path / "data", server=sample_tree["server_zip"])
    [first] = registry.sources()
    marker = first.root / ".complete"
    stamp = marker.stat().st_mtime_ns
    [second] = registry.sources()
    assert second.root == first.root
    assert marker.stat().st_mtime_ns == stamp


def test_zip_slip_entries_are_never_written(tmp_path):
    archive = malicious_zip(tmp_path / "evil.zip")
    registry = make_registry(tmp_path / "data", evil=archive)
    [source] = registry.sources()
    assert source.available
    written = {p.name for p in (tmp_path / "data").rglob("*.log")}
    assert written == {"adaptiva.log"}
    assert not (tmp_path / "escaped.log").exists()


def test_nested_zips_are_unpacked(tmp_path):
    single = build_single_client_log(tmp_path / "inner")
    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w") as zf:
        zf.write(single, "logs/13_adaptiva.log")
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as zf:
        zf.write(inner, "case/inner.zip")
    registry = make_registry(tmp_path / "data", case=outer)
    [source] = registry.sources()
    assert [f.device for f in registry.files(source)] == ["client-13"]


def test_runtime_sources_persist_and_can_be_removed(tmp_path, sample_tree):
    registry = SourceRegistry(data_dir=tmp_path / "data", env={"TPM_AUTO_DISCOVER": "false"})
    added = registry.add("case-0917", str(sample_tree["server_zip"]), "saas")
    assert added.available and added.origin == "runtime"
    reloaded = SourceRegistry(data_dir=tmp_path / "data", env={"TPM_AUTO_DISCOVER": "false"})
    assert [s.name for s in reloaded.sources()] == ["case-0917"]
    result = reloaded.remove("case-0917")
    assert result["removed"] == "case-0917" and result["extracted_copy_deleted"] is True
    assert reloaded.sources() == []


@pytest.mark.parametrize(
    ("name", "path", "deployment", "error"),
    [
        ("bad name!", "x", "auto", InputError),
        ("ok", "", "auto", InputError),
        ("ok", "C:/definitely/not/here", "auto", SourceError),
        ("ok", ".", "cloudy", InputError),
    ],
)
def test_add_validates_input(tmp_path, name, path, deployment, error):
    registry = SourceRegistry(data_dir=tmp_path / "data", env={"TPM_AUTO_DISCOVER": "false"})
    with pytest.raises(error):
        registry.add(name, path, deployment)


def test_env_sources_cannot_be_shadowed_or_removed(registry, sample_tree):
    with pytest.raises(InputError):
        registry.add("clients", str(sample_tree["clients_dir"]))
    with pytest.raises(InputError):
        registry.remove("clients")


def test_selecting_without_sources_explains_how_to_add_them(tmp_path):
    registry = SourceRegistry(data_dir=tmp_path / "data", env={"TPM_AUTO_DISCOVER": "false"})
    with pytest.raises(NoSourcesError) as excinfo:
        registry.select(None)
    assert "Download All Server Logs" in excinfo.value.remediation


def test_unknown_source_name_lists_the_configured_ones(registry):
    with pytest.raises(InputError) as excinfo:
        registry.select("nope")
    assert "saas-server" in excinfo.value.message


def test_deployment_and_version_inference(registry):
    [server] = [s for s in registry.sources() if s.name == "saas-server"]
    deployment = registry.deployment(server, registry.files(server))
    assert deployment["value"] == "saas" and deployment["configured"] is False
    assert any("PostgreSQL" in item for item in deployment["evidence"]["saas"])
    assert [v["version"] for v in deployment["versions"]] == ["10.2.973.9"]

    [clients] = [s for s in registry.sources() if s.name == "clients"]
    assert registry.deployment(clients, registry.files(clients))["inferred"] == "saas"


def test_onprem_evidence(tmp_path):
    root = tmp_path / "PatchServer" / "logs"
    root.mkdir(parents=True)
    (root / "ntlmauth.log").write_text("2026-09-10 10:00:00,000 - INFO - auth ok - NtlmAuth - TID=1, t\n")
    (root / "adaptiva.log").write_text(
        "2026-09-10 10:00:00,000 - INFO - Using SQL URL: jdbc:sqlserver://sql01:1433 - SQLDataAccessManager - TID=1, t\n"
    )
    registry = make_registry(tmp_path / "data", onprem=root)
    [source] = registry.sources()
    files = registry.files(source)
    assert {f.role for f in files} == {"server"}
    assert registry.deployment(source, files)["value"] == "onprem"


def test_auto_discovery_finds_a_local_client(tmp_path):
    client = tmp_path / "PatchClient"
    (client / "logs").mkdir(parents=True)
    (client / "logs" / "adaptiva.log").write_text("2026-09-10 10:00:00,000 - INFO - hi - Comp - TID=1, t\n")
    registry = SourceRegistry(
        data_dir=tmp_path / "data",
        env={"ADAPTIVACLIENT": str(client), "WINDIR": str(tmp_path / "nowindows")},
    )
    names = [s.name for s in registry.sources()]
    assert "local-client" in names
    [local] = [s for s in registry.sources() if s.name == "local-client"]
    assert [f.role for f in registry.files(local)] == ["client"]
