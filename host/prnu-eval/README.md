# `host/prnu-eval` — PRNU Evaluation Harness

Offline host evaluation suite for Photo-Response Non-Uniformity (PRNU) camera
sensor identification, transform robustness, and fingerprint-copy attacks.

## Installation

```bash
pip install -e host/prnu-eval
```

Or run directly from the repository root without installing into site-packages:

```bash
PYTHONPATH=host/prnu-eval python -m prnu_eval --dataset /path/to/dataset --out docs/evidence/prnu/
```

## Supported Datasets & License Notice

Dataset images must be downloaded separately by the user and **must never be
committed** to this repository:

- **Dresden Image Database** (TU Dresden, Gloe & Böhme): academic/non-commercial
  research license; check terms at the Dresden Forensics portal before use.
  Files matching `<Brand>_<Model>_<Unit>_<Seq>.<ext>` are grouped by camera
  unit (`<Brand>_<Model>_<Unit>`) so distinct physical devices of the same model
  are kept separate.
- **VISION Dataset** (LESC, University of Florence, Shullani et al.): Creative
  Commons Attribution 4.0 (CC BY 4.0) for research; device directories/prefixes
  matching `D<id>` (e.g. `D01_Samsung_GalaxyS3Mini`) are grouped per device.

Generic directory layouts (`<dataset>/<camera_id>/*.jpg`) are also supported.

## Documented Pipeline Parameters

- **Color conversion:** Decoded RGB (without EXIF orientation transpose, so
  arrays remain in sensor readout coordinates) converted to Rec.601 luminance
  `Y = 0.299*R + 0.587*G + 0.114*B` in `float64`.
- **Wavelet denoiser:** 2D DWT (`pywt.wavedec2`, wavelet `db4`, `mode="symmetric"`,
  `level=4`) with spatially adaptive Wiener shrinkage using minimum local
  variance over `[3, 5, 7, 9]` box windows and noise variance `sigma_sq = 5.0`
  (`sigma ~= 2.236` on `[0, 255]` intensity). Residual `W = I - F(I)`.
- **Reference estimator:** Luminance-weighted MLE `K = sum(W_i * I_i) / (sum(I_i^2) + eps)`.
- **Zero-mean normalization:** Column-mean subtraction followed by row-mean subtraction.
- **Detection statistics:** Normalized Cross-Correlation (`NCC`) and signed 2D FFT
  Peak-to-Correlation Energy (`PCE`) excluding an `11x11` neighborhood centered
  on the zero-shift peak `(0, 0)`.
- **Center crops:** `512x512` and `1024x1024`.

## Usage

```bash
# Quick smoke check with image cap and fixed seed:
python -m prnu_eval --dataset /path/to/Dresden --out docs/evidence/prnu/ --max-images 20 --seed 42

# Full evaluation run (updates docs/PRNU_RESULTS.md when --report is supplied):
python -m prnu_eval --dataset /path/to/Dresden --out docs/evidence/prnu/ --seed 42 --report docs/PRNU_RESULTS.md
```
