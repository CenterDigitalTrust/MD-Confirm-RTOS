"""Markdown report generator for PRNU real-dataset evaluation results."""

from __future__ import annotations

import os
from typing import Any


def _fmt(val: Any, digits: int = 4) -> str:
    if val is None:
        return "N/A"
    if isinstance(val, int):
        return str(val)
    if isinstance(val, float):
        return f"{val:.{digits}f}"
    return str(val)


def render_results_markdown(summary: dict[str, Any], command_line: str) -> str:
    """Format measured PRNU evaluation tables into Markdown without inventing values."""
    params = summary.get("pipeline_params", {})
    lines: list[str] = [
        "# PRNU Evaluation Results on Real Camera Images",
        "",
        f"**Status:** MEASURED on `{summary.get('dataset_kind', 'Unknown')}` dataset (`seed={summary.get('seed')}`)",
        "",
        "## 1. Dataset, License & Exact Command",
        "",
        f"- **Dataset Kind:** `{summary.get('dataset_kind')}`",
        f"- **License Scope:** {summary.get('dataset_license', 'See dataset provider license.')}",
        f"- **Devices Discovered:** `{summary.get('n_devices_discovered')}`",
        f"- **Total Images Loaded:** `{summary.get('total_images_loaded')}` (`max_images={summary.get('max_images')}`)",
        f"- **Exact Command:** `{command_line}`",
        "",
        "## 2. Documented Pipeline Parameters",
        "",
        f"- **Wavelet Denoising:** `pywt.wavedec2` (`wavelet={params.get('wavelet')}`, `level={params.get('levels')}`, `mode=symmetric`, Mihcak `[3,5,7,9]` local Wiener filter, `sigma_0^2={params.get('noise_var_sigma_sq')}`)",
        "- **Normalization:** weighted MLE averaging + column/row zero-mean subtraction",
        f"- **PCE:** signed 2D FFT cross-correlation with `(2*{params.get('pce_exclude_radius')}+1)^2` (`11x11`) peak neighborhood exclusion",
        f"- **Operating Thresholds Evaluated:** `PCE >= {params.get('pce_threshold')}` and `NCC >= {params.get('ncc_threshold')}`",
        f"- **Center Crops:** `{summary.get('crops')}`",
        "",
        "## 3. Experiment (a): Same-Camera vs Different-Camera ROC / FAR / FRR",
        "",
        "| Crop | Devices | Pos Pairs | Neg Pairs | PCE AUC | PCE Median (Same / Diff) | FAR @ PCE=60 | FRR @ PCE=60 | NCC AUC | FAR @ NCC=0.75 | FRR @ NCC=0.75 |",
        "|------|---------|-----------|-----------|---------|--------------------------|--------------|--------------|---------|----------------|----------------|",
    ]

    for row in summary.get("same_vs_diff_summary", []):
        lines.append(
            f"| {row['crop_size']}x{row['crop_size']} | {row['n_devices']} | {row['n_pos']} | {row['n_neg']} | "
            f"{_fmt(row.get('pce_auc'))} | {_fmt(row.get('pce_pos_median'), 2)} / {_fmt(row.get('pce_neg_median'), 2)} | "
            f"{_fmt(row.get('pce_far_at_60'))} | {_fmt(row.get('pce_frr_at_60'))} | "
            f"{_fmt(row.get('ncc_auc'))} | {_fmt(row.get('ncc_far_at_075'))} | {_fmt(row.get('ncc_frr_at_075'))} |"
        )

    lines.extend(
        [
            "",
            "## 4. Experiment (b): Reference Pool Size Sweep (`N_ref`)",
            "",
            "| Crop | `N_ref` | Devices | Same PCE Median | Same NCC Mean | PCE AUC | FAR @ PCE=60 | FRR @ PCE=60 |",
            "|------|---------|---------|-----------------|---------------|---------|--------------|--------------|",
        ]
    )
    for row in summary.get("ref_size_sweep", []):
        lines.append(
            f"| {row['crop_size']}x{row['crop_size']} | {row['n_ref']} | {row['n_devices']} | "
            f"{_fmt(row.get('pce_pos_median'), 2)} | {_fmt(row.get('ncc_pos_mean'))} | "
            f"{_fmt(row.get('pce_auc'))} | {_fmt(row.get('pce_far'))} | {_fmt(row.get('pce_frr'))} |"
        )

    lines.extend(
        [
            "",
            "## 5. Experiment (c): Degradation Robustness",
            "",
            "| Crop | Transform | Same PCE Median | Same NCC Mean | PCE AUC | FAR @ PCE=60 | FRR @ PCE=60 | FRR @ NCC=0.75 |",
            "|------|-----------|-----------------|---------------|---------|--------------|--------------|----------------|",
        ]
    )
    for row in summary.get("robustness", []):
        lines.append(
            f"| {row['crop_size']}x{row['crop_size']} | `{row['transform']}` | "
            f"{_fmt(row.get('pce_pos_median'), 2)} | {_fmt(row.get('ncc_pos_mean'))} | "
            f"{_fmt(row.get('pce_auc'))} | {_fmt(row.get('pce_far_at_60'))} | "
            f"{_fmt(row.get('pce_frr_at_60'))} | {_fmt(row.get('ncc_frr_at_075'))} |"
        )

    lines.extend(
        [
            "",
            "## 6. Experiment (d): Fingerprint-Copy Attack (`K_attack` from Disjoint Images)",
            "",
            "| Crop | `N_attack` | Target | Trials | Forged PCE Median | Pass Rate (`PCE >= 60`) |",
            "|------|------------|--------|--------|-------------------|-------------------------|",
        ]
    )
    for row in summary.get("fingerprint_copy_attack", []):
        lines.append(
            f"| {row['crop_size']}x{row['crop_size']} | {row['n_attack']} | `{row['target_type']}` | "
            f"{row['n_trials']} | {_fmt(row.get('pce_median'), 2)} | {_fmt(row.get('pass_rate_ge_60'))} |"
        )

    lines.extend(["", "Minimum `N_attack` reaching `>= 95%` attack pass rate at `PCE >= 60`:"])
    for crop_str, targets in summary.get("min_n_attack_for_95pct", {}).items():
        lines.append(
            f"- **{crop_str}x{crop_str}**: `foreign_camera` = `{targets.get('foreign_camera')}`, "
            f"`synthetic_noise_free` = `{targets.get('synthetic_noise_free')}`"
        )

    lines.extend(
        [
            "",
            "## 7. Known Methodological Limitations",
            "",
            "1. **JPEG vs RAW Sensor Input:** Dresden and VISION consumer datasets primarily provide in-camera processed JPEG images rather than uncompressed 12/16-bit Bayer RAW streams.",
            "2. **No Thermal Variation:** Benchmarks on standard ambient indoor/outdoor camera collections do not capture automotive thermal drift (`-40°C` to `+85°C`) affecting dark-current/PRNU SNR.",
            "3. **No Automotive CMOS Sensors:** Public datasets contain consumer DSLR/compact/smartphone sensors rather than automotive HDR/RCCB sensors (e.g., Sony IMX390 / ON Semi AR0820).",
        ]
    )
    return "\n".join(lines) + "\n"


def write_results_markdown(summary: dict[str, Any], command_line: str, out_path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    text = render_results_markdown(summary, command_line)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(text)
