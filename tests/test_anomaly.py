"""Window-versus-baseline anomaly findings."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from tenable_patch_management_logs_mcp import anomaly
from tests.conftest import make_registry


def by_type(result: dict, finding_type: str) -> list[dict]:
    return [f for f in result["findings"] if f["type"] == finding_type]


def test_feed_failure_spike_is_flagged(registry):
    result = anomaly.detect_log_anomalies(registry, since="24h", baseline_days=7)
    spikes = [f for f in by_type(result, anomaly.FINDING_SPIKE) if f["known_issue"] == "feed_check_failed"]
    assert len(spikes) == 1
    spike = spikes[0]
    assert spike["evidence"]["window_count"] == 12
    assert spike["evidence"]["ratio"] >= anomaly.SPIKE_MULTIPLIER
    assert "above the 3.0x threshold" in spike["reasoning"]
    assert "feed_check_failed" in result["known_issues"]


def test_a_log_that_only_recently_started_is_not_a_spike(registry):
    # VulnerabilityManagement.log only reaches back ~12h before the window, although the server's other
    # logs go back weeks; its warnings must be judged against its own short history.
    result = anomaly.detect_log_anomalies(registry, since="24h")
    assert not [f for f in by_type(result, anomaly.FINDING_SPIKE) if f["known_issue"] == "tvm_access_settings_missing"]


def test_new_signatures_are_flagged_with_reasoning(registry):
    result = anomaly.detect_log_anomalies(registry, since="24h")
    new = {f["known_issue"]: f for f in by_type(result, anomaly.FINDING_NEW_SIGNATURE) if f["known_issue"]}
    assert "tvm_keys_not_linked_to_container" in new
    assert new["tvm_keys_not_linked_to_container"]["severity"] == anomaly.SEVERITY_HIGH
    assert "not once in the preceding 7 day(s)" in new["tvm_keys_not_linked_to_container"]["reasoning"]
    # The 401 'invalid credentials' error happened during the baseline, so it is not new.
    assert "tvm_invalid_credentials" not in new


def test_restart_loop_is_flagged(registry):
    result = anomaly.detect_log_anomalies(registry, since="24h")
    [restarts] = by_type(result, anomaly.FINDING_RESTARTS)
    assert restarts["device"] == "server"
    assert len(restarts["evidence"]["starts"]) == 3


def test_short_history_makes_new_findings_low_confidence(registry):
    result = anomaly.detect_log_anomalies(registry, since="24h", device="client-13")
    assert result["baseline_coverage_pct_by_device"]["client-13"] == 0.0
    [finding] = by_type(result, anomaly.FINDING_NEW_SIGNATURE)
    assert finding["evidence"]["low_confidence"] is True
    assert "may simply predate them" in finding["reasoning"]


def test_noise_is_never_an_anomaly_and_thresholds_are_echoed(registry):
    result = anomaly.detect_log_anomalies(registry, since="24h")
    assert all(f.get("known_issue") not in ("content_receipt_cleanup_noise", "sqlserver_proc_on_postgres")
               for f in result["findings"])
    assert result["thresholds"]["spike_multiplier"] == anomaly.SPIKE_MULTIPLIER
    assert result["findings"] == sorted(
        result["findings"], key=lambda f: ({"high": 0, "medium": 1, "low": 2}[f["severity"]], f["type"], f["device"])
    )


# --------------------------------------------------------------------------- #
# Recorded baselines
# --------------------------------------------------------------------------- #


def rotating_logs(root: Path) -> Path:
    """A rotated log with a week of one recurring error, and a current log with a new one."""
    logs = root / "logs"
    logs.mkdir(parents=True)
    start = datetime(2026, 9, 1, 8, 0, 0)

    def line(when: datetime, message: str, component: str) -> str:
        return f"{when:%Y-%m-%d %H:%M:%S},000 - ERROR - {message} - {component} - TID=42, main\n"

    old = [line(start + timedelta(days=day, minutes=n * 7),
                f"Upload of content {1000 + n} failed: connection reset", "ContentPublisher")
           for day in range(7) for n in range(5)]
    (logs / "adaptiva.1.log").write_text("".join(old), encoding="utf-8")
    window_day = start + timedelta(days=7)
    current = [line(window_day + timedelta(minutes=n * 5),
                    f"Upload of content {1000 + n} failed: connection reset", "ContentPublisher")
               for n in range(5)]
    current += [line(window_day + timedelta(minutes=30 + n),
                     f"Database deadlock while writing patch state {n}", "SqlWriter") for n in range(3)]
    (logs / "adaptiva.log").write_text("".join(current), encoding="utf-8")
    return logs


def new_signature_titles(result: dict) -> set[str]:
    return {f["title"] for f in by_type(result, anomaly.FINDING_NEW_SIGNATURE)}


def test_a_recorded_baseline_survives_rotation(tmp_path):
    logs = rotating_logs(tmp_path)
    data = tmp_path / "data"
    registry = make_registry(data, srv=logs)
    snapshot = anomaly.record_baseline_snapshot(registry, since="30d")
    assert snapshot["ok"] is True
    assert snapshot["days"]["count"] == 8
    assert snapshot["store_state"]["signature_days"] == snapshot["signature_days_written"]

    (logs / "adaptiva.1.log").unlink()  # the baseline period rotates away
    registry = make_registry(data, srv=logs)

    without = anomaly.detect_log_anomalies(registry, since="24h", baseline_days=7, use_history=False)
    assert len(new_signature_titles(without)) == 2  # the recurring error looks new
    assert without["baseline_history"]["used"] is False
    assert "were not used" in without["baseline_history"]["note"]

    with_history = anomaly.detect_log_anomalies(registry, since="24h", baseline_days=7)
    titles = new_signature_titles(with_history)
    assert len(titles) == 1 and any("eadlock" in title for title in titles)
    assert with_history["baseline_history"]["used"] is True
    assert with_history["baseline_history"]["days_supplied_by_history"] == 6
    assert with_history["baseline_history"]["coverage_pct_by_device"]["srv"] > 80
    assert "came from earlier snapshots" in with_history["baseline_history"]["note"]
    [finding] = [f for f in by_type(with_history, anomaly.FINDING_NEW_SIGNATURE)]
    assert "logs or recorded history" in finding["reasoning"]
    assert finding["evidence"]["low_confidence"] is False


def test_recording_twice_does_not_inflate_the_baseline(tmp_path):
    logs = rotating_logs(tmp_path)
    data = tmp_path / "data"
    registry = make_registry(data, srv=logs)
    first = anomaly.record_baseline_snapshot(registry, since="30d")
    second = anomaly.record_baseline_snapshot(registry, since="30d")
    assert second["store_state"]["signature_days"] == first["store_state"]["signature_days"]
    assert second["store_state"]["snapshots_taken"] == 2

    (logs / "adaptiva.1.log").unlink()
    registry = make_registry(data, srv=logs)
    result = anomaly.detect_log_anomalies(registry, since="24h", baseline_days=7)
    spikes = by_type(result, anomaly.FINDING_SPIKE)
    assert all(f["evidence"]["baseline_count"] == 35 for f in spikes)  # 7 days x 5, counted once


def test_without_a_snapshot_the_gap_is_stated(registry):
    result = anomaly.detect_log_anomalies(registry, since="24h", device="client-13")
    history_block = result["baseline_history"]
    assert history_block["used"] is False
    assert history_block["recorded"] is False
    assert "record_baseline_snapshot" in history_block["note"]
