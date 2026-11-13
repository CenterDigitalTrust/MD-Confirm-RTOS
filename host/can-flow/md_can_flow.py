#!/usr/bin/env python3
"""Host-only SIMULATED optical-flow vs. synthetic CAN speed consistency check.

STATUS: SIMULATED / HOST-ONLY PYTHON. Real vehicle CAN bus + automotive camera
calibration is NOT YET MEASURED. Demonstrates the verification concept behind
cross-checking visual ego-motion against chassis odometry to flag replayed video.
"""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import numpy as np


DEFAULT_SCALE_PX_PER_FRAME_PER_MPS = 0.05  # 20 m/s -> 1.0 px/frame at 30 FPS (SIMULATED)


@dataclass
class CanFlowReport:
    """Result of comparing consecutive-frame optical flow magnitude against CAN speed."""

    status_label: str
    verdict: str
    allow: bool
    num_frames: int
    num_pairs: int
    scale_px_per_frame_per_mps: float
    mean_flow_px_per_frame: float
    mean_expected_flow_px_per_frame: float
    nrmse: float
    pearson_r: float | None
    reason: str
    pair_details: List[Dict[str, float]]


def _sample_road_field(x_grid: np.ndarray, y_grid: np.ndarray) -> np.ndarray:
    """Deterministic continuous 2D multi-frequency road/lane texture (SIMULATED).

    Analytic evaluation on continuous coordinates avoids boundary wrapping artifacts
    and supports subpixel ground-truth shifts without external datasets.
    """
    texture = (
        40.0 * np.sin(0.19 * x_grid + 0.07 * y_grid)
        + 30.0 * np.cos(0.31 * x_grid - 0.23 * y_grid + 0.6)
        + 22.0 * np.sin(0.47 * x_grid + 0.41 * y_grid + 1.3)
        + 16.0 * np.cos(0.63 * x_grid - 0.53 * y_grid + 2.1)
    )
    return 128.0 + texture


def synthesize_driving_sequence(
    can_speeds_mps: Sequence[float],
    *,
    width: int = 96,
    height: int = 64,
    scale_px_per_frame_per_mps: float = DEFAULT_SCALE_PX_PER_FRAME_PER_MPS,
    noise_std: float = 0.4,
    seed: int = 20261113,
    per_frame_gains: Sequence[float] | None = None,
) -> List[np.ndarray]:
    """Generate SIMULATED grayscale frames whose texture shift matches `can_speeds_mps`."""
    if len(can_speeds_mps) < 2:
        raise ValueError("can_speeds_mps must contain at least 2 samples")
    if per_frame_gains is not None and len(per_frame_gains) != len(can_speeds_mps):
        raise ValueError("per_frame_gains must match len(can_speeds_mps)")

    rng = np.random.default_rng(seed)
    xs = np.arange(width, dtype=np.float64)[None, :]
    ys = np.arange(height, dtype=np.float64)[:, None]

    frames: List[np.ndarray] = []
    cum_shift_x = 0.0
    for idx, speed in enumerate(can_speeds_mps):
        if idx > 0:
            interval_speed = 0.5 * (float(can_speeds_mps[idx - 1]) + float(speed))
            cum_shift_x += interval_speed * scale_px_per_frame_per_mps

        img = _sample_road_field(xs - cum_shift_x, ys)
        if noise_std > 0.0:
            img = img + rng.normal(0.0, noise_std, size=img.shape)
        if per_frame_gains is not None:
            img = img * float(per_frame_gains[idx])
        frames.append(img.astype(np.float64, copy=False))

    return frames


def _bilinear_sample(img: np.ndarray, x_coords: np.ndarray, y_coords: np.ndarray) -> np.ndarray:
    """Bilinearly interpolate `img` at floating-point `(x_coords, y_coords)`."""
    h, w = img.shape
    xc = np.clip(x_coords, 0.0, float(w - 1) - 1e-6)
    yc = np.clip(y_coords, 0.0, float(h - 1) - 1e-6)
    x0 = np.floor(xc).astype(np.int64)
    y0 = np.floor(yc).astype(np.int64)
    x1 = np.minimum(x0 + 1, w - 1)
    y1 = np.minimum(y0 + 1, h - 1)
    fx = xc - x0
    fy = yc - y0

    return (
        (1.0 - fx) * (1.0 - fy) * img[y0, x0]
        + fx * (1.0 - fy) * img[y0, x1]
        + (1.0 - fx) * fy * img[y1, x0]
        + fx * fy * img[y1, x1]
    )


def _normalize_intensity(frame: np.ndarray) -> np.ndarray:
    """Normalize per-frame gain/offset so challenge-response exposure changes do not bias flow."""
    arr = np.asarray(frame, dtype=np.float64)
    mean = float(np.mean(arr))
    std = float(np.std(arr))
    if std < 1e-6:
        return arr - mean
    return (arr - mean) / std


def estimate_frame_flow_magnitude(
    prev_frame: np.ndarray,
    next_frame: np.ndarray,
    *,
    iterations: int = 5,
    margin: int = 4,
) -> Tuple[float, float, float]:
    """Estimate global 2D translational optical flow `(u, v, hypot(u, v))` via iterative LK.

    Returns `(dx, dy, magnitude_px_per_frame)` between `prev_frame` and `next_frame`.
    """
    if prev_frame.shape != next_frame.shape:
        raise ValueError("Consecutive frames must have matching shape")
    h, w = prev_frame.shape
    if h <= 2 * margin + 4 or w <= 2 * margin + 4:
        raise ValueError("Frame dimensions too small for optical flow margin")

    p_norm = _normalize_intensity(prev_frame)
    n_norm = _normalize_intensity(next_frame)

    ix = 0.5 * (p_norm[1:-1, 2:] - p_norm[1:-1, :-2])
    iy = 0.5 * (p_norm[2:, 1:-1] - p_norm[:-2, 1:-1])

    pad = margin - 1
    ix_crop = ix[pad : h - 2 - pad, pad : w - 2 - pad]
    iy_crop = iy[pad : h - 2 - pad, pad : w - 2 - pad]
    p_crop = p_norm[margin : h - margin, margin : w - margin]

    h_xx = float(np.sum(ix_crop * ix_crop))
    h_xy = float(np.sum(ix_crop * iy_crop))
    h_yy = float(np.sum(iy_crop * iy_crop))
    det = h_xx * h_yy - h_xy * h_xy
    if det < 1e-6:
        return 0.0, 0.0, 0.0

    yy, xx = np.mgrid[margin : h - margin, margin : w - margin].astype(np.float64)
    u = 0.0
    v = 0.0
    for _ in range(iterations):
        warped_next = _bilinear_sample(n_norm, xx + u, yy + v)
        it = warped_next - p_crop
        b_x = -float(np.sum(ix_crop * it))
        b_y = -float(np.sum(iy_crop * it))
        du = (h_yy * b_x - h_xy * b_y) / det
        dv = (h_xx * b_y - h_xy * b_x) / det
        u += du
        v += dv
        if abs(du) < 1e-4 and abs(dv) < 1e-4:
            break

    return float(u), float(v), float(math.hypot(u, v))


def verify_flow_vs_can_speed(
    frames: Sequence[np.ndarray],
    can_speeds_mps: Sequence[float],
    *,
    scale_px_per_frame_per_mps: float = DEFAULT_SCALE_PX_PER_FRAME_PER_MPS,
    min_corr: float = 0.75,
    max_nrmse: float = 0.25,
) -> CanFlowReport:
    """Compare measured visual optical flow magnitude against logged CAN wheel speeds."""
    if len(frames) < 4:
        raise ValueError("Need at least 4 frames for CAN speed consistency analysis")
    n_pairs = len(frames) - 1
    if len(can_speeds_mps) == len(frames):
        pair_speeds = np.array(
            [
                0.5 * (float(can_speeds_mps[i]) + float(can_speeds_mps[i + 1]))
                for i in range(n_pairs)
            ],
            dtype=np.float64,
        )
    elif len(can_speeds_mps) == n_pairs:
        pair_speeds = np.asarray(can_speeds_mps, dtype=np.float64)
    else:
        raise ValueError("can_speeds_mps length must be len(frames) or len(frames) - 1")

    expected = np.abs(pair_speeds) * float(scale_px_per_frame_per_mps)
    measured = np.zeros(n_pairs, dtype=np.float64)
    details: List[Dict[str, float]] = []

    for i in range(n_pairs):
        dx, dy, mag = estimate_frame_flow_magnitude(frames[i], frames[i + 1])
        measured[i] = mag
        details.append(
            {
                "pair_index": float(i),
                "can_speed_mps": float(pair_speeds[i]),
                "expected_flow_px": float(expected[i]),
                "measured_flow_px": float(mag),
                "dx_px": float(dx),
                "dy_px": float(dy),
            }
        )

    rmse = float(np.sqrt(np.mean((measured - expected) ** 2)))
    denom = max(float(np.mean(expected)), float(np.mean(measured)), 0.05)
    nrmse = rmse / denom

    pearson_r: float | None = None
    std_exp = float(np.std(expected))
    std_meas = float(np.std(measured))
    if std_exp > 1e-4 and std_meas > 1e-4:
        pearson_r = float(np.corrcoef(expected, measured)[0, 1])

    allow = True
    reasons: List[str] = []
    if nrmse > max_nrmse:
        allow = False
        reasons.append(f"nrmse={nrmse:.3f} > max_nrmse={max_nrmse:.3f}")
    if std_exp > 0.08:
        if pearson_r is None or pearson_r < min_corr:
            allow = False
            r_str = "None" if pearson_r is None else f"{pearson_r:.3f}"
            reasons.append(f"pearson_r={r_str} < min_corr={min_corr:.3f}")

    verdict = "VERIFIED_FLOW_CAN_MATCH" if allow else "FLAG_REPLAY_CAN_SPEED_MISMATCH"
    reason = "Optical flow magnitude consistent with CAN speed log" if allow else "; ".join(reasons)

    return CanFlowReport(
        status_label="SIMULATED (host-only synthetic optical flow vs synthetic CAN log)",
        verdict=verdict,
        allow=allow,
        num_frames=len(frames),
        num_pairs=n_pairs,
        scale_px_per_frame_per_mps=float(scale_px_per_frame_per_mps),
        mean_flow_px_per_frame=float(np.mean(measured)),
        mean_expected_flow_px_per_frame=float(np.mean(expected)),
        nrmse=float(nrmse),
        pearson_r=pearson_r,
        reason=reason,
        pair_details=details,
    )


def run_demo() -> Dict[str, Any]:
    """Run SIMULATED matched vs. replay-mismatched CAN speed demonstrations."""
    n_frames = 24
    # Smooth acceleration 4 m/s -> 26 m/s (per-frame shift 0.2..1.3 px/frame)
    true_speeds = np.linspace(4.0, 26.0, n_frames)
    # Apply synthetic gain variation to prove flow normalization ignores Task 7 exposure modulation
    gains = [0.75 if (i % 2 == 0) else 1.25 for i in range(n_frames)]
    authentic_frames = synthesize_driving_sequence(
        true_speeds,
        per_frame_gains=gains,
        seed=20261113,
    )

    matched_report = verify_flow_vs_can_speed(authentic_frames, true_speeds)

    # Replay scenario: attacker injects the authentic recorded highway clip while CAN reports deceleration/stop
    replay_can_speeds = np.linspace(24.0, 0.0, n_frames)
    replay_report = verify_flow_vs_can_speed(authentic_frames, replay_can_speeds)

    return {
        "status": "SIMULATED",
        "disclaimer": (
            "Synthetic optical flow vs synthetic CAN speed log only. "
            "Real camera ego-motion / CAN timing alignment is NOT YET MEASURED."
        ),
        "matched_authentic": asdict(matched_report),
        "replay_mismatched_can": asdict(replay_report),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="SIMULATED host-only check: visual optical-flow magnitude vs synthetic CAN speed log"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run built-in SIMULATED matched vs replay-mismatched scenarios",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Optional path to write JSON report",
    )
    args = parser.parse_args(argv)

    payload = run_demo()
    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    m = payload["matched_authentic"]
    r = payload["replay_mismatched_can"]
    print("[md_can_flow] STATUS: SIMULATED (host-only; real vehicle CAN/camera NOT YET MEASURED)")
    print(
        f"  1) Matched stream      : verdict={m['verdict']} allow={m['allow']} "
        f"nrmse={m['nrmse']:.4f} pearson_r={m['pearson_r']:.4f}"
    )
    print(
        f"  2) Replay vs CAN brake : verdict={r['verdict']} allow={r['allow']} "
        f"nrmse={r['nrmse']:.4f} pearson_r={r['pearson_r']:.4f} ({r['reason']})"
    )

    return 0 if (m["allow"] and not r["allow"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
