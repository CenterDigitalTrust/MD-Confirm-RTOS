"""Matplotlib plots for PRNU evaluation results (ROC & PCE-vs-N)."""

from __future__ import annotations

import os
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


def save_roc_plot(summary: dict[str, Any], out_png: str) -> None:
    """Plot ROC curves for PCE and NCC across crop sizes (512x512, 1024x1024)."""
    roc_curves = summary.get("roc_curves", {})
    summary_rows = {str(r["crop_size"]): r for r in summary.get("same_vs_diff_summary", [])}

    fig, ax = plt.subplots(figsize=(7.5, 6.0), dpi=150)
    plotted = False
    colors = {"512": "#1f77b4", "1024": "#d62728"}

    for crop_str, curves in sorted(roc_curves.items(), key=lambda kv: int(kv[0])):
        col = colors.get(crop_str, "#2ca02c")
        row = summary_rows.get(crop_str, {})
        pce_pts = curves.get("pce", [])
        ncc_pts = curves.get("ncc", [])

        if pce_pts:
            auc_val = row.get("pce_auc")
            auc_txt = f"{auc_val:.4f}" if auc_val is not None else "N/A"
            ax.plot(
                [pt[0] for pt in pce_pts],
                [pt[1] for pt in pce_pts],
                color=col,
                linewidth=2.0,
                label=f"{crop_str}x{crop_str} PCE (AUC={auc_txt})",
            )
            far = row.get("pce_far_at_60")
            frr = row.get("pce_frr_at_60")
            if far is not None and frr is not None:
                ax.scatter(
                    [far],
                    [1.0 - frr],
                    color=col,
                    marker="o",
                    s=55,
                    zorder=5,
                    label=f"  @PCE=60 (FAR={far:.3f}, FRR={frr:.3f})",
                )
            plotted = True

        if ncc_pts:
            auc_n = row.get("ncc_auc")
            auc_ntxt = f"{auc_n:.4f}" if auc_n is not None else "N/A"
            ax.plot(
                [pt[0] for pt in ncc_pts],
                [pt[1] for pt in ncc_pts],
                color=col,
                linestyle="--",
                linewidth=1.5,
                alpha=0.85,
                label=f"{crop_str}x{crop_str} NCC (AUC={auc_ntxt})",
            )
            plotted = True

    ax.plot([0.0, 1.0], [0.0, 1.0], color="#888888", linestyle=":", linewidth=1.0)
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(-0.02, 1.02)
    ax.set_xlabel("False Acceptance Rate (FAR / FPR)")
    ax.set_ylabel("True Positive Rate (1 - FRR)")
    ax.set_title(f"PRNU Same-Camera vs Different-Camera ROC ({summary.get('dataset_kind', 'Dataset')})")
    ax.grid(True, linestyle="--", alpha=0.35)
    if plotted:
        ax.legend(loc="lower right", fontsize=8.5)
    else:
        ax.text(0.5, 0.5, "Insufficient positive/negative pairs for ROC", ha="center", va="center")

    os.makedirs(os.path.dirname(os.path.abspath(out_png)), exist_ok=True)
    fig.tight_layout()
    fig.savefig(out_png)
    plt.close(fig)


def save_pce_vs_n_plot(summary: dict[str, Any], out_png: str) -> None:
    """Plot PCE vs N_ref (left) and Fingerprint-Copy Attack PCE vs N_attack (right)."""
    ref_rows = summary.get("ref_size_sweep", [])
    att_rows = summary.get("fingerprint_copy_attack", [])
    min_n = summary.get("min_n_attack_for_95pct", {})
    pce_thr = float(summary.get("pipeline_params", {}).get("pce_threshold", 60.0))

    fig, (ax_ref, ax_att) = plt.subplots(1, 2, figsize=(13.0, 5.2), dpi=150)

    # Panel 1: Reference size N_ref sweep
    crops_ref = sorted({r["crop_size"] for r in ref_rows})
    for crop in crops_ref:
        sub = sorted(
            [r for r in ref_rows if r["crop_size"] == crop and r.get("pce_pos_median") is not None],
            key=lambda r: r["n_ref"],
        )
        if not sub:
            continue
        ax_ref.plot(
            [r["n_ref"] for r in sub],
            [r["pce_pos_median"] for r in sub],
            marker="o",
            linewidth=2.0,
            label=f"Same-camera {crop}x{crop} (median)",
        )
    ax_ref.axhline(pce_thr, color="#333333", linestyle="--", linewidth=1.2, label=f"Threshold PCE={pce_thr:g}")
    ax_ref.set_xlabel("Reference Pool Size N_ref")
    ax_ref.set_ylabel("Median PCE (linear)")
    ax_ref.set_title("(b) Reference Size N_ref vs Same-Camera PCE")
    ax_ref.grid(True, linestyle="--", alpha=0.35)
    ax_ref.legend(loc="best", fontsize=8.5)

    # Panel 2: Fingerprint-copy attack N_attack sweep
    combos = sorted({(r["crop_size"], r["target_type"]) for r in att_rows})
    for crop, target_kind in combos:
        sub = sorted(
            [
                r
                for r in att_rows
                if r["crop_size"] == crop and r["target_type"] == target_kind
            ],
            key=lambda r: r["n_attack"],
        )
        if not sub:
            continue
        min_val = min_n.get(str(crop), {}).get(target_kind)
        min_txt = f"min>=95%: {min_val}" if min_val is not None else "min>=95%: N/A"
        ax_att.plot(
            [r["n_attack"] for r in sub],
            [r["pce_median"] for r in sub],
            marker="s" if target_kind == "foreign_camera" else "^",
            linestyle="-" if target_kind == "foreign_camera" else "-.",
            linewidth=1.8,
            label=f"{crop}x{crop} -> {target_kind} ({min_txt})",
        )
    ax_att.axhline(pce_thr, color="#333333", linestyle="--", linewidth=1.2, label=f"Threshold PCE={pce_thr:g}")
    ax_att.set_xlabel("Attacker Estimation Images N_attack")
    ax_att.set_ylabel("Median Forged PCE (linear)")
    ax_att.set_title("(d) Fingerprint-Copy Attack PCE vs N_attack")
    ax_att.grid(True, linestyle="--", alpha=0.35)
    ax_att.legend(loc="best", fontsize=8.0)

    os.makedirs(os.path.dirname(os.path.abspath(out_png)), exist_ok=True)
    fig.tight_layout()
    fig.savefig(out_png)
    plt.close(fig)
