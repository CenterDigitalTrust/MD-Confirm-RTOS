"""PRNU evaluation experiments (a) same-vs-diff, (b) N_ref sweep, (c) robustness, (d) copy attack."""

from __future__ import annotations

from collections import OrderedDict
import csv
from dataclasses import dataclass
import json
import os
import random
from typing import Any

import numpy as np

from .dataset import DATASET_LICENSES, ImageRecord, load_dataset
from .prnu import (
    DEFAULT_NCC_THRESHOLD,
    DEFAULT_PCE_THRESHOLD,
    PCE_EXCLUDE_RADIUS,
    WAVELET_LEVELS,
    WAVELET_NAME,
    WAVELET_NOISE_VAR,
    apply_transform,
    center_crop,
    estimate_reference_k,
    extract_noise_residual,
    inject_fingerprint,
    load_grayscale,
    ncc_score,
    pce_score,
)

DEFAULT_CROPS = (512, 1024)
DEFAULT_REF_SIZES = (5, 10, 20, 50, 100)
DEFAULT_ATTACK_SIZES = (1, 2, 5, 10, 20, 50)
DEFAULT_ROBUSTNESS_TRANSFORMS = (
    "baseline",
    "jpeg_95",
    "jpeg_90",
    "jpeg_75",
    "downscale_0.75",
    "brightness_shift",
)


class _CropCache:
    """Bounded LRU cache of grayscale crops & wavelet residuals for a fixed crop size."""

    def __init__(self, crop_size: int, max_items: int = 256) -> None:
        self.crop_size = crop_size
        self.max_items = max_items
        self._items: OrderedDict[str, tuple[np.ndarray, np.ndarray]] = OrderedDict()
        self._rejected: set[str] = set()

    def get(self, path: str) -> tuple[np.ndarray, np.ndarray] | None:
        if path in self._rejected:
            return None
        if path in self._items:
            self._items.move_to_end(path)
            return self._items[path]

        full = load_grayscale(path)
        crop = center_crop(full, self.crop_size)
        if crop is None:
            self._rejected.add(path)
            return None
        residual = extract_noise_residual(crop)
        self._items[path] = (crop, residual)
        if len(self._items) > self.max_items:
            self._items.popitem(last=False)
        return crop, residual


@dataclass
class DeviceSplit:
    device_id: str
    ref_paths: list[str]
    test_paths: list[str]
    attack_paths: list[str]


def build_disjoint_splits(
    grouped: dict[str, list[ImageRecord]],
    cache: _CropCache,
    seed: int,
) -> dict[str, DeviceSplit]:
    """Create strictly disjoint ref / test / attack path lists per camera device."""
    splits: dict[str, DeviceSplit] = {}
    rng = random.Random(seed)

    for dev_id in sorted(grouped.keys()):
        flat_paths: list[str] = []
        other_paths: list[str] = []
        for rec in grouped[dev_id]:
            if cache.get(rec.path) is None:
                continue
            if rec.subset_kind == "flat":
                flat_paths.append(rec.path)
            else:
                other_paths.append(rec.path)

        rng.shuffle(flat_paths)
        rng.shuffle(other_paths)

        # Prefer flat-field frames for K estimation and natural frames for test & attack.
        ordered = flat_paths + other_paths
        total = len(ordered)
        if total < 3:
            continue

        # Hold out test frames from the tail (natural images first).
        n_test = max(1, min(20, total // 5 if total >= 5 else 1))
        test_paths = ordered[total - n_test :]
        remainder = ordered[: total - n_test]

        if flat_paths and len(other_paths) > n_test:
            # Flat frames serve as reference pool; non-test natural frames serve attack pool.
            avail_nat = [p for p in other_paths if p not in set(test_paths)]
            ref_paths = list(flat_paths)
            attack_paths = avail_nat
        else:
            # Split remainder ~60% ref / ~40% attack cleanly.
            n_ref = max(1, (len(remainder) * 3) // 5)
            if len(remainder) >= 2 and n_ref == len(remainder):
                n_ref -= 1
            ref_paths = remainder[:n_ref]
            attack_paths = remainder[n_ref:]

        assert not (set(ref_paths) & set(test_paths))
        assert not (set(ref_paths) & set(attack_paths))
        assert not (set(test_paths) & set(attack_paths))

        splits[dev_id] = DeviceSplit(
            device_id=dev_id,
            ref_paths=ref_paths,
            test_paths=test_paths,
            attack_paths=attack_paths,
        )
    return splits


def _compute_ref_k(paths: list[str], cache: _CropCache) -> np.ndarray:
    res_list: list[np.ndarray] = []
    img_list: list[np.ndarray] = []
    for p in paths:
        entry = cache.get(p)
        if entry is not None:
            crop, residual = entry
            res_list.append(residual)
            img_list.append(crop)
    return estimate_reference_k(res_list, img_list)


def compute_roc_and_metrics(
    scores_pos: list[float],
    scores_neg: list[float],
    threshold: float,
) -> tuple[list[tuple[float, float, float]], dict[str, Any]]:
    """Compute ROC curve (fpr, tpr, thr), AUC, and FAR/FRR at threshold."""
    n_pos = len(scores_pos)
    n_neg = len(scores_neg)
    if n_pos == 0 or n_neg == 0:
        return [], {
            "n_pos": n_pos,
            "n_neg": n_neg,
            "auc": None,
            "far": None,
            "frr": None,
            "tpr": None,
            "threshold": threshold,
        }

    pos_arr = np.asarray(scores_pos, dtype=np.float64)
    neg_arr = np.asarray(scores_neg, dtype=np.float64)

    far = float(np.mean(neg_arr >= threshold))
    frr = float(np.mean(pos_arr < threshold))
    tpr_at_thr = float(1.0 - frr)

    unique_thrs = np.unique(np.concatenate([pos_arr, neg_arr]))
    if len(unique_thrs) > 400:
        unique_thrs = np.quantile(unique_thrs, np.linspace(0.0, 1.0, 400))
    thrs_desc = sorted([float("inf"), *unique_thrs.tolist(), float("-inf")], reverse=True)

    roc: list[tuple[float, float, float]] = []
    for thr in thrs_desc:
        fpr = float(np.mean(neg_arr >= thr))
        tpr = float(np.mean(pos_arr >= thr))
        roc.append((fpr, tpr, float(thr)))

    fprs = np.asarray([pt[0] for pt in roc], dtype=np.float64)
    tprs = np.asarray([pt[1] for pt in roc], dtype=np.float64)
    order = np.argsort(fprs)
    trap_fn = getattr(np, "trapezoid", None) or getattr(np, "trapz", None)
    if trap_fn is None:
        raise AttributeError("Neither numpy.trapezoid nor numpy.trapz is available")
    auc = float(trap_fn(tprs[order], fprs[order]))

    return roc, {
        "n_pos": n_pos,
        "n_neg": n_neg,
        "auc": auc,
        "far": far,
        "frr": frr,
        "tpr": tpr_at_thr,
        "threshold": threshold,
        "pos_mean": float(np.mean(pos_arr)),
        "pos_median": float(np.median(pos_arr)),
        "neg_mean": float(np.mean(neg_arr)),
        "neg_median": float(np.median(neg_arr)),
    }


def _evaluate_pairs(
    refs: dict[str, np.ndarray],
    splits: dict[str, DeviceSplit],
    cache: _CropCache,
    seed: int,
    *,
    transform_name: str | None = None,
    max_neg_per_device: int = 30,
) -> tuple[list[dict[str, Any]], list[float], list[float], list[float], list[float]]:
    rng = random.Random(seed)
    devices = sorted(refs.keys())
    rows: list[dict[str, Any]] = []
    pce_pos: list[float] = []
    pce_neg: list[float] = []
    ncc_pos: list[float] = []
    ncc_neg: list[float] = []

    transformed_cache: dict[str, tuple[np.ndarray, np.ndarray]] = {}

    def _get_query(path: str) -> tuple[np.ndarray, np.ndarray] | None:
        base = cache.get(path)
        if base is None:
            return None
        if transform_name is None or transform_name == "baseline":
            return base
        if path not in transformed_cache:
            t_img = apply_transform(base[0], transform_name)
            t_res = extract_noise_residual(t_img)
            transformed_cache[path] = (t_img, t_res)
        return transformed_cache[path]

    for dev in devices:
        k_ref = refs[dev]
        for q_path in splits[dev].test_paths:
            q_pair = _get_query(q_path)
            if q_pair is None:
                continue
            q_img, q_res = q_pair
            pce = pce_score(q_res, k_ref, q_img)
            ncc = ncc_score(q_res, k_ref, q_img)
            pce_pos.append(pce)
            ncc_pos.append(ncc)
            rows.append(
                {
                    "ref_device": dev,
                    "query_device": dev,
                    "same_camera": 1,
                    "pce": pce,
                    "ncc": ncc,
                }
            )

        other_devs = [d for d in devices if d != dev]
        if not other_devs:
            continue
        foreign_candidates = [
            (od, qp) for od in other_devs for qp in splits[od].test_paths
        ]
        rng.shuffle(foreign_candidates)
        for od, qp in foreign_candidates[:max_neg_per_device]:
            q_pair = _get_query(qp)
            if q_pair is None:
                continue
            q_img, q_res = q_pair
            pce = pce_score(q_res, k_ref, q_img)
            ncc = ncc_score(q_res, k_ref, q_img)
            pce_neg.append(pce)
            ncc_neg.append(ncc)
            rows.append(
                {
                    "ref_device": dev,
                    "query_device": od,
                    "same_camera": 0,
                    "pce": pce,
                    "ncc": ncc,
                }
            )

    return rows, pce_pos, pce_neg, ncc_pos, ncc_neg


def _synthetic_noise_free_image(crop_size: int, variant_idx: int) -> np.ndarray:
    """Deterministic smooth synthetic uint8 image completely free of camera PRNU."""
    yy, xx = np.mgrid[0:crop_size, 0:crop_size].astype(np.float64)
    nx = xx / max(1.0, float(crop_size - 1))
    ny = yy / max(1.0, float(crop_size - 1))
    phase = 0.7 * variant_idx
    base = (
        128.0
        + 40.0 * np.sin(2.0 * np.pi * nx + phase)
        + 35.0 * np.cos(2.0 * np.pi * ny + 0.5 * phase)
    )
    return np.clip(np.rint(base), 0.0, 255.0).astype(np.float64)


def _write_csv(path: str, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def run_all_experiments(
    dataset_path: str,
    out_dir: str,
    *,
    crops: tuple[int, ...] = DEFAULT_CROPS,
    ref_sizes: tuple[int, ...] = DEFAULT_REF_SIZES,
    attack_sizes: tuple[int, ...] = DEFAULT_ATTACK_SIZES,
    max_images: int | None = None,
    seed: int = 42,
    pce_threshold: float = DEFAULT_PCE_THRESHOLD,
    ncc_threshold: float = DEFAULT_NCC_THRESHOLD,
    attack_strength: float = 1.0,
) -> dict[str, Any]:
    """Run experiments (a)-(d) across configured crops and write CSVs + summary."""
    os.makedirs(out_dir, exist_ok=True)
    grouped, dataset_kind = load_dataset(
        dataset_path, max_images=max_images, seed=seed
    )

    same_vs_diff_summary: list[dict[str, Any]] = []
    roc_rows: list[dict[str, Any]] = []
    roc_curves: dict[str, dict[str, list[tuple[float, float, float]]]] = {}
    ref_sweep_rows: list[dict[str, Any]] = []
    robustness_rows: list[dict[str, Any]] = []
    attack_rows: list[dict[str, Any]] = []
    min_attack_summary: dict[str, dict[str, int | None]] = {}

    for crop_size in crops:
        cache = _CropCache(crop_size=crop_size, max_items=256)
        splits = build_disjoint_splits(grouped, cache, seed=seed)
        if not splits:
            continue

        # Default K_ref per device uses up to 50 disjoint reference images
        default_refs: dict[str, np.ndarray] = {}
        for dev_id, sp in splits.items():
            use_n = min(50, len(sp.ref_paths))
            default_refs[dev_id] = _compute_ref_k(sp.ref_paths[:use_n], cache)

        # (a) Same camera vs different camera
        pair_rows, pce_pos, pce_neg, ncc_pos, ncc_neg = _evaluate_pairs(
            default_refs, splits, cache, seed=seed + crop_size
        )
        _write_csv(
            os.path.join(out_dir, f"same_vs_diff_pairs_{crop_size}.csv"),
            ["ref_device", "query_device", "same_camera", "pce", "ncc"],
            pair_rows,
        )

        roc_pce, metrics_pce = compute_roc_and_metrics(
            pce_pos, pce_neg, pce_threshold
        )
        roc_ncc, metrics_ncc = compute_roc_and_metrics(
            ncc_pos, ncc_neg, ncc_threshold
        )
        roc_curves[str(crop_size)] = {"pce": roc_pce, "ncc": roc_ncc}
        for fpr, tpr, thr in roc_pce:
            roc_rows.append(
                {
                    "crop_size": crop_size,
                    "metric": "pce",
                    "fpr": fpr,
                    "tpr": tpr,
                    "threshold": thr,
                }
            )
        for fpr, tpr, thr in roc_ncc:
            roc_rows.append(
                {
                    "crop_size": crop_size,
                    "metric": "ncc",
                    "fpr": fpr,
                    "tpr": tpr,
                    "threshold": thr,
                }
            )

        same_vs_diff_summary.append(
            {
                "crop_size": crop_size,
                "n_devices": len(splits),
                "n_pos": metrics_pce["n_pos"],
                "n_neg": metrics_pce["n_neg"],
                "pce_auc": metrics_pce["auc"],
                "pce_far_at_60": metrics_pce["far"],
                "pce_frr_at_60": metrics_pce["frr"],
                "pce_pos_median": metrics_pce.get("pos_median"),
                "pce_neg_median": metrics_pce.get("neg_median"),
                "ncc_auc": metrics_ncc["auc"],
                "ncc_far_at_075": metrics_ncc["far"],
                "ncc_frr_at_075": metrics_ncc["frr"],
                "ncc_pos_median": metrics_ncc.get("pos_median"),
                "ncc_neg_median": metrics_ncc.get("neg_median"),
            }
        )

        # (b) Reference size sweep N_ref in {5, 10, 20, 50, 100}
        for n_ref in ref_sizes:
            eligible = {
                d: _compute_ref_k(sp.ref_paths[:n_ref], cache)
                for d, sp in splits.items()
                if len(sp.ref_paths) >= n_ref
            }
            eligible_splits = {d: splits[d] for d in eligible}
            if len(eligible) < 2:
                # If only 1 device meets n_ref, evaluate positive residuals if any, or skip
                if len(eligible) == 1:
                    _, p_pos, p_neg, n_pos, _ = _evaluate_pairs(
                        eligible, eligible_splits, cache, seed=seed + n_ref
                    )
                    ref_sweep_rows.append(
                        {
                            "crop_size": crop_size,
                            "n_ref": n_ref,
                            "n_devices": 1,
                            "n_pos": len(p_pos),
                            "n_neg": len(p_neg),
                            "pce_pos_mean": float(np.mean(p_pos)) if p_pos else None,
                            "pce_pos_median": float(np.median(p_pos)) if p_pos else None,
                            "ncc_pos_mean": float(np.mean(n_pos)) if n_pos else None,
                            "pce_auc": None,
                            "pce_far": None,
                            "pce_frr": float(np.mean(np.asarray(p_pos) < pce_threshold))
                            if p_pos
                            else None,
                            "ncc_far": None,
                            "ncc_frr": float(np.mean(np.asarray(n_pos) < ncc_threshold))
                            if n_pos
                            else None,
                        }
                    )
                continue

            _, p_pos, p_neg, n_pos, n_neg = _evaluate_pairs(
                eligible, eligible_splits, cache, seed=seed + crop_size + n_ref
            )
            _, m_pce = compute_roc_and_metrics(p_pos, p_neg, pce_threshold)
            _, m_ncc = compute_roc_and_metrics(n_pos, n_neg, ncc_threshold)
            ref_sweep_rows.append(
                {
                    "crop_size": crop_size,
                    "n_ref": n_ref,
                    "n_devices": len(eligible),
                    "n_pos": m_pce["n_pos"],
                    "n_neg": m_pce["n_neg"],
                    "pce_pos_mean": m_pce.get("pos_mean"),
                    "pce_pos_median": m_pce.get("pos_median"),
                    "ncc_pos_mean": m_ncc.get("pos_mean"),
                    "pce_auc": m_pce["auc"],
                    "pce_far": m_pce["far"],
                    "pce_frr": m_pce["frr"],
                    "ncc_far": m_ncc["far"],
                    "ncc_frr": m_ncc["frr"],
                }
            )

        # (c) Robustness transforms
        for tname in DEFAULT_ROBUSTNESS_TRANSFORMS:
            _, p_pos, p_neg, n_pos, n_neg = _evaluate_pairs(
                default_refs,
                splits,
                cache,
                seed=seed + crop_size,
                transform_name=tname,
            )
            _, m_pce = compute_roc_and_metrics(p_pos, p_neg, pce_threshold)
            _, m_ncc = compute_roc_and_metrics(n_pos, n_neg, ncc_threshold)
            robustness_rows.append(
                {
                    "crop_size": crop_size,
                    "transform": tname,
                    "n_pos": m_pce["n_pos"],
                    "n_neg": m_pce["n_neg"],
                    "pce_pos_mean": m_pce.get("pos_mean"),
                    "pce_pos_median": m_pce.get("pos_median"),
                    "ncc_pos_mean": m_ncc.get("pos_mean"),
                    "pce_auc": m_pce["auc"],
                    "pce_far_at_60": m_pce["far"],
                    "pce_frr_at_60": m_pce["frr"],
                    "ncc_far_at_075": m_ncc["far"],
                    "ncc_frr_at_075": m_ncc["frr"],
                }
            )

        # (d) Fingerprint-copy attack using disjoint victim attack_paths
        devices = sorted(splits.keys())
        min_attack_summary[str(crop_size)] = {
            "foreign_camera": None,
            "synthetic_noise_free": None,
        }
        rng_att = random.Random(seed + crop_size * 17)

        for n_att in attack_sizes:
            pces_foreign: list[float] = []
            pces_synth: list[float] = []
            for victim in devices:
                sp = splits[victim]
                if len(sp.attack_paths) < n_att:
                    continue
                k_victim_ref = default_refs[victim]
                k_attack = _compute_ref_k(sp.attack_paths[:n_att], cache)

                # Target (i): inject K_attack into foreign camera images
                foreign_pool = [
                    p for od in devices if od != victim for p in splits[od].test_paths
                ]
                rng_att.shuffle(foreign_pool)
                for f_path in foreign_pool[:10]:
                    f_entry = cache.get(f_path)
                    if f_entry is None:
                        continue
                    forged = inject_fingerprint(
                        f_entry[0], k_attack, strength=attack_strength
                    )
                    w_forged = extract_noise_residual(forged)
                    pces_foreign.append(pce_score(w_forged, k_victim_ref, forged))

                # Target (ii): inject K_attack into synthetic noise-free images
                for s_idx in range(10):
                    synth = _synthetic_noise_free_image(crop_size, s_idx)
                    forged_s = inject_fingerprint(
                        synth, k_attack, strength=attack_strength
                    )
                    w_synth = extract_noise_residual(forged_s)
                    pces_synth.append(pce_score(w_synth, k_victim_ref, forged_s))

            for target_kind, vals in (
                ("foreign_camera", pces_foreign),
                ("synthetic_noise_free", pces_synth),
            ):
                if not vals:
                    continue
                arr = np.asarray(vals, dtype=np.float64)
                pass_rate = float(np.mean(arr >= pce_threshold))
                attack_rows.append(
                    {
                        "crop_size": crop_size,
                        "n_attack": n_att,
                        "target_type": target_kind,
                        "n_trials": len(vals),
                        "pce_mean": float(np.mean(arr)),
                        "pce_median": float(np.median(arr)),
                        "pass_rate_ge_60": pass_rate,
                    }
                )
                if (
                    pass_rate >= 0.95
                    and min_attack_summary[str(crop_size)][target_kind] is None
                ):
                    min_attack_summary[str(crop_size)][target_kind] = n_att

    _write_csv(
        os.path.join(out_dir, "same_vs_diff_summary.csv"),
        [
            "crop_size",
            "n_devices",
            "n_pos",
            "n_neg",
            "pce_auc",
            "pce_far_at_60",
            "pce_frr_at_60",
            "pce_pos_median",
            "pce_neg_median",
            "ncc_auc",
            "ncc_far_at_075",
            "ncc_frr_at_075",
            "ncc_pos_median",
            "ncc_neg_median",
        ],
        same_vs_diff_summary,
    )
    _write_csv(
        os.path.join(out_dir, "roc_points.csv"),
        ["crop_size", "metric", "fpr", "tpr", "threshold"],
        roc_rows,
    )
    _write_csv(
        os.path.join(out_dir, "ref_size_sweep.csv"),
        [
            "crop_size",
            "n_ref",
            "n_devices",
            "n_pos",
            "n_neg",
            "pce_pos_mean",
            "pce_pos_median",
            "ncc_pos_mean",
            "pce_auc",
            "pce_far",
            "pce_frr",
            "ncc_far",
            "ncc_frr",
        ],
        ref_sweep_rows,
    )
    _write_csv(
        os.path.join(out_dir, "robustness.csv"),
        [
            "crop_size",
            "transform",
            "n_pos",
            "n_neg",
            "pce_pos_mean",
            "pce_pos_median",
            "ncc_pos_mean",
            "pce_auc",
            "pce_far_at_60",
            "pce_frr_at_60",
            "ncc_far_at_075",
            "ncc_frr_at_075",
        ],
        robustness_rows,
    )
    _write_csv(
        os.path.join(out_dir, "fingerprint_copy_attack.csv"),
        [
            "crop_size",
            "n_attack",
            "target_type",
            "n_trials",
            "pce_mean",
            "pce_median",
            "pass_rate_ge_60",
        ],
        attack_rows,
    )

    summary = {
        "dataset_path": str(dataset_path),
        "dataset_kind": dataset_kind,
        "dataset_license": DATASET_LICENSES.get(dataset_kind, ""),
        "n_devices_discovered": len(grouped),
        "total_images_loaded": sum(len(v) for v in grouped.values()),
        "seed": seed,
        "max_images": max_images,
        "crops": list(crops),
        "pipeline_params": {
            "wavelet": WAVELET_NAME,
            "levels": WAVELET_LEVELS,
            "noise_var_sigma_sq": WAVELET_NOISE_VAR,
            "pce_exclude_radius": PCE_EXCLUDE_RADIUS,
            "pce_threshold": pce_threshold,
            "ncc_threshold": ncc_threshold,
            "attack_strength": attack_strength,
        },
        "same_vs_diff_summary": same_vs_diff_summary,
        "ref_size_sweep": ref_sweep_rows,
        "robustness": robustness_rows,
        "fingerprint_copy_attack": attack_rows,
        "min_n_attack_for_95pct": min_attack_summary,
        "roc_curves": roc_curves,
    }
    # Write JSON summary without huge roc arrays duplicated separately? Keep clean summary.json!
    json_summary = {k: v for k, v in summary.items() if k != "roc_curves"}
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(json_summary, fh, indent=2)
    return summary
