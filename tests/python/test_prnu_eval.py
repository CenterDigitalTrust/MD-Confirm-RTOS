"""Unit and synthetic code-path tests for host/prnu-eval.

NOTE: These tests exercise software code paths on small synthetic images only.
They do NOT constitute empirical PRNU claims (see docs/PRNU_RESULTS.md).
"""

from __future__ import annotations

import csv
import json
import os
import pathlib
import subprocess
import sys
import tempfile

import numpy as np
from PIL import Image

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
PRNU_PKG_DIR = REPO_ROOT / "host" / "prnu-eval"
if str(PRNU_PKG_DIR) not in sys.path:
    sys.path.insert(0, str(PRNU_PKG_DIR))

from prnu_eval.cli import main as prnu_main  # noqa: E402
from prnu_eval.dataset import load_dataset  # noqa: E402
from prnu_eval.experiments import _CropCache, build_disjoint_splits  # noqa: E402
from prnu_eval.prnu import (  # noqa: E402
    apply_transform,
    estimate_reference_k,
    extract_noise_residual,
    inject_fingerprint,
    ncc_score,
    pce_score,
    zero_mean_rows_cols,
)


def _save_gray_png(path: pathlib.Path, arr: np.ndarray) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    img_u8 = np.clip(np.rint(arr), 0, 255).astype(np.uint8)
    Image.fromarray(img_u8, mode="L").save(path, format="PNG")


def _synth_camera_image(
    size: int,
    k_pattern: np.ndarray,
    rng: np.random.Generator,
    *,
    prnu_amp: float = 4.0,
) -> np.ndarray:
    yy, xx = np.meshgrid(
        np.linspace(0.0, 1.0, size, dtype=np.float64),
        np.linspace(0.0, 1.0, size, dtype=np.float64),
        indexing="ij",
    )
    scene = 110.0 + 35.0 * np.sin(2.0 * np.pi * yy * 1.5) * np.cos(2.0 * np.pi * xx * 1.2)
    shot = rng.normal(0.0, 1.2, size=(size, size))
    return np.clip(np.rint(scene * (1.0 + prnu_amp * k_pattern / 128.0) + shot), 0, 255)


def test_dresden_and_vision_grouping_filters_and_max_images() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        arr = np.full((32, 32), 120, dtype=np.uint8)

        dresden_root = root / "dresden"
        for fname in ("Nikon_D70_0_001.jpg", "Nikon_D70_0_002.jpg", "Nikon_D70_1_001.jpg"):
            dresden_root.mkdir(parents=True, exist_ok=True)
            Image.fromarray(arr, mode="L").save(dresden_root / fname, format="JPEG")

        grouped_d, kind_d = load_dataset(dresden_root, seed=42)
        assert kind_d == "Dresden"
        assert sorted(grouped_d.keys()) == ["Nikon_D70_0", "Nikon_D70_1"]
        assert len(grouped_d["Nikon_D70_0"]) == 2
        assert len(grouped_d["Nikon_D70_1"]) == 1

        vision_root = root / "vision"
        paths = [
            vision_root / "D01_Samsung_S3" / "images" / "flat" / "D01_I_flat_0001.jpg",
            vision_root / "D01_Samsung_S3" / "images" / "nat" / "D01_I_nat_0001.jpg",
            vision_root / "D02_Apple_iP5" / "images" / "nat" / "D02_I_nat_0001.jpg",
            vision_root / "D02_Apple_iP5" / "images" / "natWA" / "D02_I_nat_0002.jpg",
            vision_root / "D02_Apple_iP5" / "videos" / "D02_V_indoor_0001.jpg",
        ]
        for p in paths:
            p.parent.mkdir(parents=True, exist_ok=True)
            Image.fromarray(arr, mode="L").save(p, format="JPEG")

        grouped_v, kind_v = load_dataset(vision_root, seed=42)
        assert kind_v == "VISION"
        assert sorted(grouped_v.keys()) == ["D01_Samsung_S3", "D02_Apple_iP5"]
        assert {r.subset_kind for r in grouped_v["D01_Samsung_S3"]} == {"flat", "nat"}
        # Social natWA and videos must be excluded by default.
        assert len(grouped_v["D02_Apple_iP5"]) == 1

        # Balanced cap keeps both cameras represented when max_images=2.
        capped, _ = load_dataset(vision_root, max_images=2, seed=42)
        assert len(capped["D01_Samsung_S3"]) == 1
        assert len(capped["D02_Apple_iP5"]) == 1


def test_disjoint_splits_have_zero_overlap() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        rng = np.random.default_rng(7)
        for cam_idx in range(2):
            cam_dir = root / f"D0{cam_idx + 1}_TestCam" / "images"
            for i in range(4):
                p = cam_dir / "flat" / f"D0{cam_idx + 1}_I_flat_{i:04d}.png"
                p.parent.mkdir(parents=True, exist_ok=True)
                img = rng.integers(80, 180, size=(128, 128), dtype=np.uint8)
                Image.fromarray(img, mode="L").save(p)
            for i in range(6):
                p = cam_dir / "nat" / f"D0{cam_idx + 1}_I_nat_{i:04d}.png"
                p.parent.mkdir(parents=True, exist_ok=True)
                img = rng.integers(80, 180, size=(128, 128), dtype=np.uint8)
                Image.fromarray(img, mode="L").save(p)

        grouped, _ = load_dataset(root, seed=42)
        cache = _CropCache(crop_size=64)
        splits = build_disjoint_splits(grouped, cache, seed=42)
        assert len(splits) == 2
        for sp in splits.values():
            r_set = set(sp.ref_paths)
            t_set = set(sp.test_paths)
            a_set = set(sp.attack_paths)
            assert r_set and t_set and a_set
            assert r_set.isdisjoint(t_set)
            assert r_set.isdisjoint(a_set)
            assert t_set.isdisjoint(a_set)


def test_residual_zero_mean_ncc_and_11x11_pce_exclusion() -> None:
    rng = np.random.default_rng(123)
    size = 128
    k_a = zero_mean_rows_cols(rng.normal(0.0, 1.0, size=(size, size)))
    k_b = zero_mean_rows_cols(rng.normal(0.0, 1.0, size=(size, size)))

    refs_w: list[np.ndarray] = []
    refs_i: list[np.ndarray] = []
    for _ in range(5):
        img = _synth_camera_image(size, k_a, rng)
        w = extract_noise_residual(img)
        assert np.max(np.abs(np.mean(w, axis=0))) < 1e-10
        assert np.max(np.abs(np.mean(w, axis=1))) < 1e-10
        refs_w.append(w)
        refs_i.append(img)

    est_ka = estimate_reference_k(refs_w, refs_i)
    assert np.max(np.abs(np.mean(est_ka, axis=0))) < 1e-10
    assert np.max(np.abs(np.mean(est_ka, axis=1))) < 1e-10

    q_same = _synth_camera_image(size, k_a, rng)
    q_diff = _synth_camera_image(size, k_b, rng)
    w_same = extract_noise_residual(q_same)
    w_diff = extract_noise_residual(q_diff)

    ncc_same = ncc_score(w_same, est_ka, q_same)
    ncc_diff = ncc_score(w_diff, est_ka, q_diff)
    pce_same = pce_score(w_same, est_ka, q_same, exclude_radius=5)
    pce_diff = pce_score(w_diff, est_ka, q_diff, exclude_radius=5)

    assert ncc_same > ncc_diff + 0.1
    assert pce_same > 60.0
    assert abs(pce_diff) < pce_same * 0.25

    # Exact verification of 11x11 peak-neighborhood exclusion in pce_score:
    w0 = w_same - np.mean(w_same)
    x0 = zero_mean_rows_cols(q_same * est_ka)
    cc = np.fft.ifft2(np.fft.fft2(w0) * np.conj(np.fft.fft2(x0))).real
    cc_shift = np.fft.fftshift(cc)
    cy, cx = size // 2, size // 2
    mask = np.ones((size, size), dtype=bool)
    mask[cy - 5 : cy + 6, cx - 5 : cx + 6] = False
    expected = (cc[0, 0] ** 2) / float(np.mean(cc_shift[mask] ** 2))
    assert np.isclose(pce_same, expected, rtol=1e-9)


def test_robustness_transforms_and_attack_injection() -> None:
    rng = np.random.default_rng(99)
    size = 128
    k_victim = zero_mean_rows_cols(rng.normal(0.0, 1.0, size=(size, size)))
    k_other = zero_mean_rows_cols(rng.normal(0.0, 1.0, size=(size, size)))

    other_img = _synth_camera_image(size, k_other, rng)
    baseline = apply_transform(other_img, "baseline")
    j95 = apply_transform(other_img, "jpeg_95")
    j90 = apply_transform(other_img, "jpeg_90")
    j75 = apply_transform(other_img, "jpeg_75")
    down = apply_transform(other_img, "downscale_0.75")
    bright = apply_transform(other_img, "brightness_shift")

    for t in (baseline, j95, j90, j75, down, bright):
        assert t.shape == (size, size)
        assert t.dtype == np.float64
    assert np.mean(np.abs(j75 - baseline)) >= np.mean(np.abs(j95 - baseline))
    assert np.mean(bright) > np.mean(baseline)

    # Inject k_victim into foreign and synthetic noise-free images
    synth_clean = np.full((size, size), 128.0, dtype=np.float64)
    before_pce = pce_score(extract_noise_residual(other_img), k_victim, other_img)
    forged_foreign = inject_fingerprint(other_img, k_victim, strength=2.0)
    forged_synth = inject_fingerprint(synth_clean, k_victim, strength=2.0)
    after_foreign = pce_score(extract_noise_residual(forged_foreign), k_victim, forged_foreign)
    after_synth = pce_score(extract_noise_residual(forged_synth), k_victim, forged_synth)

    assert after_foreign > before_pce + 30.0
    assert after_synth > 30.0


def test_cli_end_to_end_outputs_and_seed_determinism() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = pathlib.Path(tmp)
        ds_dir = tmp_root / "dresden_synth"
        rng = np.random.default_rng(2025)
        crop = 128

        # Create 2 Dresden camera units with 8 images each (16 total) at 128x128 (small synthetic code-path test).
        for unit in (0, 1):
            k_pat = zero_mean_rows_cols(rng.normal(0.0, 1.0, size=(crop, crop)))
            for seq in range(1, 9):
                img = _synth_camera_image(crop, k_pat, rng, prnu_amp=3.5)
                _save_gray_png(ds_dir / f"Nikon_D70_{unit}_{seq:03d}.png", img)

        out1 = tmp_root / "out1"
        out2 = tmp_root / "out2"

        # Run once via real `python -m prnu_eval` CLI subprocess
        env = dict(os.environ)
        env["PYTHONPATH"] = str(PRNU_PKG_DIR)
        cmd = [
            sys.executable,
            "-m",
            "prnu_eval",
            "--dataset",
            str(ds_dir),
            "--out",
            str(out1),
            "--crops",
            "128",
            "--ref-sizes",
            "2,4",
            "--attack-sizes",
            "1,2",
            "--max-images",
            "16",
            "--seed",
            "42",
            "--report",
            str(out1 / "PRNU_RESULTS.md"),
        ]
        res = subprocess.run(cmd, env=env, capture_output=True, text=True, check=False)
        assert res.returncode == 0, f"stderr={res.stderr}"

        # Second run via Python entrypoint with identical seed for determinism check
        rc = prnu_main(
            [
                "--dataset",
                str(ds_dir),
                "--out",
                str(out2),
                "--crops",
                "128",
                "--ref-sizes",
                "2,4",
                "--attack-sizes",
                "1,2",
                "--max-images",
                "16",
                "--seed",
                "42",
            ]
        )
        assert rc == 0

        expected_files = [
            "same_vs_diff_pairs_128.csv",
            "same_vs_diff_summary.csv",
            "roc_points.csv",
            "ref_size_sweep.csv",
            "robustness.csv",
            "fingerprint_copy_attack.csv",
            "summary.json",
            "roc_prnu.png",
            "pce_vs_n.png",
            "PRNU_RESULTS.md",
        ]
        for fname in expected_files:
            fpath = out1 / fname
            assert fpath.is_file() and fpath.stat().st_size > 0, f"Missing/empty: {fname}"

        assert (out1 / "roc_prnu.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
        assert (out1 / "pce_vs_n.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"

        with open(out1 / "robustness.csv", newline="", encoding="utf-8") as fh:
            transforms = {row["transform"] for row in csv.DictReader(fh)}
        assert transforms == {
            "baseline",
            "jpeg_95",
            "jpeg_90",
            "jpeg_75",
            "downscale_0.75",
            "brightness_shift",
        }

        with open(out1 / "fingerprint_copy_attack.csv", newline="", encoding="utf-8") as fh:
            targets = {row["target_type"] for row in csv.DictReader(fh)}
        assert targets == {"foreign_camera", "synthetic_noise_free"}

        s1 = json.loads((out1 / "summary.json").read_text(encoding="utf-8"))
        s2 = json.loads((out2 / "summary.json").read_text(encoding="utf-8"))
        assert s1["same_vs_diff_summary"] == s2["same_vs_diff_summary"]
        assert s1["fingerprint_copy_attack"] == s2["fingerprint_copy_attack"]
