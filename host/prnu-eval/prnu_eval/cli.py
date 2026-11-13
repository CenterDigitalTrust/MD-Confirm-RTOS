"""Command-line interface for MD-Confirm PRNU evaluation."""

from __future__ import annotations

import argparse
import os
import shlex
import sys

from .experiments import (
    DEFAULT_ATTACK_SIZES,
    DEFAULT_CROPS,
    DEFAULT_REF_SIZES,
    run_all_experiments,
)
from .plots import save_pce_vs_n_plot, save_roc_plot
from .prnu import DEFAULT_NCC_THRESHOLD, DEFAULT_PCE_THRESHOLD
from .report import write_results_markdown


def _parse_int_list(raw: str) -> tuple[int, ...]:
    return tuple(int(part.strip()) for part in raw.split(",") if part.strip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m prnu_eval",
        description="Evaluate PRNU identification, robustness, and fingerprint-copy attacks",
    )
    parser.add_argument(
        "--dataset",
        required=True,
        help="Path to local Dresden Image Database or VISION dataset directory",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Output directory for CSV tables and ROC / PCE-vs-N PNG figures",
    )
    parser.add_argument(
        "--crops",
        default="512,1024",
        help="Comma-separated center crop sizes (default: 512,1024)",
    )
    parser.add_argument(
        "--ref-sizes",
        default=",".join(str(x) for x in DEFAULT_REF_SIZES),
        help="Comma-separated N_ref sizes (default: 5,10,20,50,100)",
    )
    parser.add_argument(
        "--attack-sizes",
        default=",".join(str(x) for x in DEFAULT_ATTACK_SIZES),
        help="Comma-separated N_attack sizes (default: 1,2,5,10,20,50)",
    )
    parser.add_argument(
        "--max-images",
        type=int,
        default=None,
        help="Optional cap on total images loaded (balanced across devices) for quick runs",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Fixed random seed for reproducible splits and sampling (default: 42)",
    )
    parser.add_argument(
        "--pce-threshold",
        type=float,
        default=DEFAULT_PCE_THRESHOLD,
        help=f"PCE detection threshold (default: {DEFAULT_PCE_THRESHOLD})",
    )
    parser.add_argument(
        "--ncc-threshold",
        type=float,
        default=DEFAULT_NCC_THRESHOLD,
        help=f"NCC detection threshold (default: {DEFAULT_NCC_THRESHOLD})",
    )
    parser.add_argument(
        "--attack-strength",
        type=float,
        default=1.0,
        help="Fingerprint-copy injection scale factor alpha (default: 1.0)",
    )
    parser.add_argument(
        "--report",
        default=None,
        help="Optional Markdown report path (also written inside --out/PRNU_RESULTS.md)",
    )
    args = parser.parse_args(argv)

    crops = _parse_int_list(args.crops) or DEFAULT_CROPS
    ref_sizes = _parse_int_list(args.ref_sizes) or DEFAULT_REF_SIZES
    attack_sizes = _parse_int_list(args.attack_sizes) or DEFAULT_ATTACK_SIZES

    summary = run_all_experiments(
        args.dataset,
        args.out,
        crops=crops,
        ref_sizes=ref_sizes,
        attack_sizes=attack_sizes,
        max_images=args.max_images,
        seed=args.seed,
        pce_threshold=args.pce_threshold,
        ncc_threshold=args.ncc_threshold,
        attack_strength=args.attack_strength,
    )

    save_roc_plot(summary, os.path.join(args.out, "roc_prnu.png"))
    save_pce_vs_n_plot(summary, os.path.join(args.out, "pce_vs_n.png"))

    argv_used = argv if argv is not None else sys.argv[1:]
    cmd_str = "python -m prnu_eval " + " ".join(shlex.quote(a) for a in argv_used)
    write_results_markdown(
        summary, cmd_str, os.path.join(args.out, "PRNU_RESULTS.md")
    )
    if args.report:
        write_results_markdown(summary, cmd_str, args.report)

    print(
        f"[PRNU EVAL DONE] dataset={summary['dataset_kind']} "
        f"devices={summary['n_devices_discovered']} images={summary['total_images_loaded']} "
        f"out={args.out}"
    )
    return 0
