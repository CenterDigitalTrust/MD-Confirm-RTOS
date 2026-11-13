# PRNU Evaluation Results on Real Camera Images

**Status:** **`NOT YET MEASURED`** — Offline evaluation harness is implemented in [`host/prnu-eval/`](../host/prnu-eval/), tested on small synthetic data for code paths only ([`tests/python/test_prnu_eval.py`](../tests/python/test_prnu_eval.py)). No real Dresden Image Database or VISION dataset run has been executed in this repository yet (`MEASURED` tables will replace `NOT YET MEASURED` only after running on real camera images and committing outputs under `docs/evidence/prnu/`).

---

## 1. Datasets, Versions & License Boundaries

Dataset images are downloaded independently by the user and **must never be committed** to this repository (see [`.gitignore`](../.gitignore)).

| Dataset | Reference / Version Scope | Grouping Rule | License Terms |
|---------|---------------------------|---------------|---------------|
| **Dresden Image Database** | TU Dresden (Gloe & Böhme, *ACM SAC 2010*, consumer camera corpus) | `<Brand>_<Model>_<Unit>_<Seq>.<ext>` grouped per physical camera unit `<Brand>_<Model>_<Unit>` | Academic / non-commercial research license (obtain directly from TU Dresden Forensics portal). |
| **VISION Dataset** | LESC, University of Florence (Shullani et al., *EURASIP J. Inf. Secur. 2017*, v1.0) | `D<id>_...` directories / prefixes grouped per physical device; `videos/` and social-recompressed `natWA`/`natFB` excluded by default | Creative Commons Attribution 4.0 (CC BY 4.0) for research; must be fetched separately by the user. |

---

## 2. Documented Pipeline Parameters & Reproducibility

All pipeline parameters are fixed in [`host/prnu-eval/prnu_eval/prnu.py`](../host/prnu-eval/prnu_eval/prnu.py) and [`host/prnu-eval/prnu_eval/experiments.py`](../host/prnu-eval/prnu_eval/experiments.py):

- **Seed:** `seed = 42` (default) controls balanced `--max-images` sampling and strictly disjoint `ref` / `test` / `attack` splits per device.
- **Luminance Input:** Raw pixel decode (no EXIF orientation transpose) converted to Rec.601 float64 luminance $Y = 0.299 R + 0.587 G + 0.114 B$.
- **Wavelet Noise Residual ($W = I - F(I)$):** 2D DWT via `pywt.wavedec2` (`wavelet="db4"`, `level=4`, `mode="symmetric"`) + Mihcak local Wiener shrinkage across box windows `[3, 5, 7, 9]` with nominal noise variance $\sigma_0^2 = 5.0$ (`WAVELET_NOISE_VAR = 5.0`).
- **Normalization:** Column-mean subtraction followed by row-mean subtraction (`zero_mean_rows_cols`) on both residuals and estimated fingerprints.
- **Reference Estimation ($K$):** Luminance-weighted MLE averaging $K = \frac{\sum W_i I_i}{\sum I_i^2 + \epsilon}$ over $N_{\text{ref}}$ images (preferring flat-field frames when present).
- **Detection Statistics:**
  - **NCC:** Normalized Cross-Correlation between $W$ and zero-meaned $I \cdot K$; operating threshold **`0.75`**.
  - **PCE:** Signed 2D FFT cross-correlation Peak-to-Correlation Energy excluding an **`11x11`** neighborhood (`exclude_radius = 5`) centered on shift `(0, 0)`; operating threshold **`60.0`** linear ($\approx 17.78\text{ dB}$).
- **Center Crops:** `512x512` and `1024x1024`.

### Exact Commands

```bash
pip install --no-deps -e host/prnu-eval

# Full evaluation run (writes CSVs + PNGs under docs/evidence/prnu/ and updates this report):
python -m prnu_eval \
  --dataset /path/to/Dresden_or_VISION \
  --out docs/evidence/prnu/ \
  --report docs/PRNU_RESULTS.md \
  --seed 42

# Quick bounded smoke run using --max-images:
python -m prnu_eval \
  --dataset /path/to/Dresden_or_VISION \
  --out docs/evidence/prnu/ \
  --max-images 200 \
  --seed 42 \
  --report docs/PRNU_RESULTS.md
```

**Artifacts Produced by `--out docs/evidence/prnu/`:**
- CSV tables: `same_vs_diff_pairs_<crop>.csv`, `same_vs_diff_summary.csv`, `roc_points.csv`, `ref_size_sweep.csv`, `robustness.csv`, `fingerprint_copy_attack.csv`
- Summary JSON: `summary.json`
- Figures: `roc_prnu.png` (ROC curves), `pce_vs_n.png` (PCE vs `N_ref` and fingerprint-copy attack `N_attack`)
- Measured Markdown report: `docs/evidence/prnu/PRNU_RESULTS.md` (and `docs/PRNU_RESULTS.md` via `--report`)

---

## 3. Experiment (a): Same-Camera vs Different-Camera ROC / FAR / FRR (`NOT YET MEASURED`)

| Crop | Dataset | Devices | PCE AUC | FAR @ PCE=60 | FRR @ PCE=60 | FAR @ NCC=0.75 | FRR @ NCC=0.75 |
|------|---------|---------|---------|--------------|--------------|----------------|----------------|
| `512x512` | Dresden / VISION | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` |
| `1024x1024` | Dresden / VISION | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` |

---

## 4. Experiment (b): Reference Size Sweep $N_{\text{ref}} \in \{5, 10, 20, 50, 100\}$ (`NOT YET MEASURED`)

| Crop | $N_{\text{ref}}$ | Same-Camera PCE Median | PCE AUC | FAR @ PCE=60 | FRR @ PCE=60 |
|------|------------------|------------------------|---------|--------------|--------------|
| `512x512` / `1024x1024` | `5, 10, 20, 50, 100` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` |

---

## 5. Experiment (c): Degradation Robustness (`NOT YET MEASURED`)

| Crop | Transform | Same-Camera PCE Median | PCE AUC | FAR @ PCE=60 | FRR @ PCE=60 | FRR @ NCC=0.75 |
|------|-----------|------------------------|---------|--------------|--------------|----------------|
| `512x512` / `1024x1024` | `baseline` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` |
| `512x512` / `1024x1024` | `jpeg_95` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` |
| `512x512` / `1024x1024` | `jpeg_90` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` |
| `512x512` / `1024x1024` | `jpeg_75` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` |
| `512x512` / `1024x1024` | `downscale_0.75` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` |
| `512x512` / `1024x1024` | `brightness_shift` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` | `NOT YET MEASURED` |

---

## 6. Experiment (d): Fingerprint-Copy Attack ($N_{\text{attack}} \in \{1, 2, 5, 10, 20, 50\}$) (`NOT YET MEASURED`)

$K_{\text{attack}}$ is estimated from strictly disjoint victim-camera images (disjoint from both reference $K_{\text{ref}}$ images and positive/negative test images) and injected into (i) another camera's image (`foreign_camera`) and (ii) a synthetic noise-free image (`synthetic_noise_free`).

| Crop | Target Type | PCE vs $N_{\text{attack}}$ | Minimum $N_{\text{attack}}$ Passing `PCE >= 60` in $\ge 95\%$ Trials |
|------|-------------|----------------------------|--------------------------------------------------------------------|
| `512x512` | `foreign_camera` | `NOT YET MEASURED` | `NOT YET MEASURED` |
| `512x512` | `synthetic_noise_free` | `NOT YET MEASURED` | `NOT YET MEASURED` |
| `1024x1024` | `foreign_camera` | `NOT YET MEASURED` | `NOT YET MEASURED` |
| `1024x1024` | `synthetic_noise_free` | `NOT YET MEASURED` | `NOT YET MEASURED` |

---

## 7. Methodological & Deployment Limitations

1. **JPEG vs RAW Sensor Input:** Dresden Image Database and VISION primarily distribute in-camera processed JPEG images rather than uncompressed 12/16-bit linear Bayer RAW frames (`md-capture` target domain). JPEG quantization suppresses high-frequency sensor PRNU energy and alters ROC operating points relative to raw ADAS feeds.
2. **No Temperature Variation:** Public DSLR/smartphone corpora were acquired under mild ambient conditions without controlled automotive thermal chamber sweeps (`-40°C` to `+85°C`), so thermal dark-current and gain-drift impacts on PRNU SNR remain unmeasured.
3. **No Automotive CMOS Sensors:** Consumer camera modules do not reproduce automotive HDR/RCCB split-pixel/LED-flicker-mitigation (LFM) sensor architectures (e.g., Sony IMX390, ON Semi AR0820).
4. **Host Evaluation vs On-Target Runtime (`SIMULATED`):** [`host/prnu-eval/`](../host/prnu-eval/) implements the 2D `db4` wavelet + 2D FFT PCE pipeline offline in Python, whereas [`qnx/verify/md-verify.cpp`](../qnx/verify/md-verify.cpp) still runs a simplified 1D 3-sample residual dot-product estimator on `64x64` synthetic frames.
