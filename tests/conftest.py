"""Shared fixtures: a synthetic TPM log set and a registry pointed at it. No network."""

from __future__ import annotations

from pathlib import Path

import pytest

from tenable_patch_management_logs_mcp.sources import SourceRegistry
from tests.sample_logs import build_sample_tree


@pytest.fixture(scope="session")
def sample_tree(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    return build_sample_tree(tmp_path_factory.mktemp("samples"))


def make_registry(data_dir: Path, **sources: Path) -> SourceRegistry:
    env = {
        "TPM_LOG_SOURCES": ";".join(f"{name}={path}" for name, path in sources.items()),
        "TPM_AUTO_DISCOVER": "false",
    }
    return SourceRegistry(data_dir=data_dir, env=env)


@pytest.fixture()
def registry(tmp_path: Path, sample_tree: dict[str, Path]) -> SourceRegistry:
    """Server bundle as a zip, clients as a collector folder, and one requested client log."""
    return make_registry(
        tmp_path / "data",
        **{
            "saas-server": sample_tree["server_zip"],
            "clients": sample_tree["clients_dir"],
            "client13": sample_tree["client13_file"],
        },
    )
