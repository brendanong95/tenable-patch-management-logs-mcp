"""Window-versus-baseline anomaly findings."""

from __future__ import annotations

from src import anomaly


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
