"""Unit tests for host/can-flow/md_can_flow.py (SIMULATED optical flow vs CAN speed)."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "host" / "can-flow"))

import md_can_flow  # noqa: E402


def test_matched_acceleration_passes_even_with_gain_modulation() -> None:
    speeds = np.linspace(4.0, 26.0, 20)
    gains = [0.70 if (i % 2 == 0) else 1.30 for i in range(20)]
    frames = md_can_flow.synthesize_driving_sequence(
        speeds,
        per_frame_gains=gains,
        seed=42,
    )
    report = md_can_flow.verify_flow_vs_can_speed(frames, speeds)
    assert report.allow is True
    assert report.verdict == "VERIFIED_FLOW_CAN_MATCH"
    assert report.nrmse < 0.10
    assert report.pearson_r is not None and report.pearson_r > 0.95


def test_replay_with_mismatched_can_speed_is_flagged() -> None:
    recorded_speeds = np.linspace(4.0, 26.0, 20)
    recorded_frames = md_can_flow.synthesize_driving_sequence(recorded_speeds, seed=7)

    # Vehicle CAN says stopped / decelerating while recorded clip is replayed
    actual_can_speeds = np.linspace(26.0, 0.0, 20)
    report = md_can_flow.verify_flow_vs_can_speed(recorded_frames, actual_can_speeds)
    assert report.allow is False
    assert report.verdict == "FLAG_REPLAY_CAN_SPEED_MISMATCH"
    assert report.nrmse > 0.25


def test_static_video_against_moving_can_is_flagged() -> None:
    zero_motion = np.zeros(16)
    static_frames = md_can_flow.synthesize_driving_sequence(zero_motion, seed=11)
    moving_can = np.full(16, 18.0)

    report = md_can_flow.verify_flow_vs_can_speed(static_frames, moving_can)
    assert report.allow is False
    assert report.verdict == "FLAG_REPLAY_CAN_SPEED_MISMATCH"
    assert report.mean_flow_px_per_frame < 0.1
    assert report.nrmse > 0.25


def test_cli_demo_writes_json_report() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = Path(tmpdir) / "can_flow_report.json"
        rc = md_can_flow.main(["--demo", "--out", str(out_path)])
        assert rc == 0
        data = json.loads(out_path.read_text(encoding="utf-8"))
        assert data["status"] == "SIMULATED"
        assert data["matched_authentic"]["allow"] is True
        assert data["replay_mismatched_can"]["allow"] is False
