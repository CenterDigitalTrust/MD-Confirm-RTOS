"""PRNU wavelet residual extraction, reference estimation, NCC/PCE, and attacks.

Pipeline parameters (fixed and reported in docs/PRNU_RESULTS.md):
  - Grayscale luminance: Rec.601 Y = 0.299*R + 0.587*G + 0.114*B (float64)
  - Wavelet denoising: 2D DWT `db4`, level=4, mode="symmetric", Mihcak spatial
    Wiener shrinkage with windows [3, 5, 7, 9] and sigma_0^2 = 5.0
  - Normalization: column zero-mean followed by row zero-mean
  - Detection: NCC and signed 2D FFT PCE with 11x11 peak exclusion (radius=5)
"""

from __future__ import annotations

import io
import math

import numpy as np
from PIL import Image
import pywt
from scipy.ndimage import uniform_filter

WAVELET_NAME = "db4"
WAVELET_LEVELS = 4
WAVELET_MODE = "symmetric"
WAVELET_NOISE_VAR = 5.0
PCE_EXCLUDE_RADIUS = 5  # (2*5 + 1) x (2*5 + 1) = 11x11 neighborhood
DEFAULT_PCE_THRESHOLD = 60.0
DEFAULT_NCC_THRESHOLD = 0.75


def pil_to_grayscale_f64(img: Image.Image) -> np.ndarray:
    """Convert PIL Image (raw pixel coordinates, no EXIF rotation) to float64 Y."""
    rgb = img.convert("RGB")
    arr = np.asarray(rgb, dtype=np.float64)
    return 0.299 * arr[:, :, 0] + 0.587 * arr[:, :, 1] + 0.114 * arr[:, :, 2]


def load_grayscale(path: str) -> np.ndarray:
    """Load an image file directly into Rec.601 float64 luminance [0, 255]."""
    with Image.open(path) as img:
        return pil_to_grayscale_f64(img)


def center_crop(arr: np.ndarray, crop_size: int) -> np.ndarray | None:
    """Return center (crop_size x crop_size) crop or None if image is smaller."""
    h, w = arr.shape[:2]
    if h < crop_size or w < crop_size:
        return None
    y0 = (h - crop_size) // 2
    x0 = (w - crop_size) // 2
    return arr[y0 : y0 + crop_size, x0 : x0 + crop_size]


def zero_mean_rows_cols(arr: np.ndarray) -> np.ndarray:
    """Subtract column means followed by row means to suppress linear pattern artifacts."""
    out = arr - np.mean(arr, axis=0, keepdims=True)
    out = out - np.mean(out, axis=1, keepdims=True)
    out = out - np.mean(out)
    return out


def _mihcak_wiener(subband: np.ndarray, noise_var: float) -> np.ndarray:
    sq = subband * subband
    local_var = np.full_like(sq, np.inf)
    for win in (3, 5, 7, 9):
        mean_sq = uniform_filter(sq, size=win, mode="reflect")
        est = np.maximum(0.0, mean_sq - noise_var)
        local_var = np.minimum(local_var, est)
    return subband * (local_var / (local_var + noise_var))


def extract_noise_residual(
    img_gray: np.ndarray,
    *,
    wavelet: str = WAVELET_NAME,
    levels: int = WAVELET_LEVELS,
    noise_var: float = WAVELET_NOISE_VAR,
) -> np.ndarray:
    """Extract normalized PRNU noise residual W = zm(I - F_wavelet(I))."""
    h, w = img_gray.shape
    max_lvl = pywt.dwt_max_level(min(h, w), pywt.Wavelet(wavelet).dec_len)
    use_levels = max(1, min(levels, max_lvl))

    coeffs = pywt.wavedec2(img_gray, wavelet, mode=WAVELET_MODE, level=use_levels)
    shrunk_coeffs: list = [coeffs[0]]
    for detail_tuple in coeffs[1:]:
        shrunk_coeffs.append(
            tuple(_mihcak_wiener(band, noise_var) for band in detail_tuple)
        )

    denoised = pywt.waverec2(shrunk_coeffs, wavelet, mode=WAVELET_MODE)[:h, :w]
    residual = img_gray - denoised
    return zero_mean_rows_cols(residual)


def estimate_reference_k(
    residuals: list[np.ndarray],
    intensities: list[np.ndarray],
) -> np.ndarray:
    """Estimate PRNU fingerprint K via luminance-weighted MLE averaging."""
    if not residuals or len(residuals) != len(intensities):
        raise ValueError("residuals and intensities must be non-empty lists of equal length")
    num = np.zeros_like(residuals[0], dtype=np.float64)
    den = np.zeros_like(residuals[0], dtype=np.float64)
    for w_i, img_i in zip(residuals, intensities):
        num += w_i * img_i
        den += img_i * img_i
    k_raw = num / (den + 1e-12)
    return zero_mean_rows_cols(k_raw)


def ncc_score(
    residual: np.ndarray,
    ref_k: np.ndarray,
    query_img: np.ndarray,
) -> float:
    """Compute Normalized Cross-Correlation (NCC) between W and I * K."""
    w0 = residual - np.mean(residual)
    template = zero_mean_rows_cols(query_img * ref_k)
    norm_w = math.sqrt(float(np.sum(w0 * w0)))
    norm_x = math.sqrt(float(np.sum(template * template)))
    if norm_w < 1e-12 or norm_x < 1e-12:
        return 0.0
    return float(np.sum(w0 * template) / (norm_w * norm_x))


def pce_score(
    residual: np.ndarray,
    ref_k: np.ndarray,
    query_img: np.ndarray,
    *,
    exclude_radius: int = PCE_EXCLUDE_RADIUS,
) -> float:
    """Compute signed 2D FFT Peak-to-Correlation Energy excluding (2r+1)^2 peak box."""
    w0 = residual - np.mean(residual)
    x0 = zero_mean_rows_cols(query_img * ref_k)
    if float(np.sum(w0 * w0)) < 1e-12 or float(np.sum(x0 * x0)) < 1e-12:
        return 0.0

    # Zero-shift cross-correlation: Re(ifft2(fft2(w0) * conj(fft2(x0)))) at [0, 0]
    cc = np.fft.ifft2(np.fft.fft2(w0) * np.conj(np.fft.fft2(x0))).real
    peak = float(cc[0, 0])

    cc_shifted = np.fft.fftshift(cc)
    h, w = cc_shifted.shape
    cy, cx = h // 2, w // 2
    y0 = max(0, cy - exclude_radius)
    y1 = min(h, cy + exclude_radius + 1)
    x_left = max(0, cx - exclude_radius)
    x_right = min(w, cx + exclude_radius + 1)

    mask = np.ones((h, w), dtype=bool)
    mask[y0:y1, x_left:x_right] = False
    sidelobes = cc_shifted[mask]
    sidelobe_energy = float(np.mean(sidelobes * sidelobes))
    if sidelobe_energy <= 1e-30:
        return 0.0
    sign = 1.0 if peak >= 0.0 else -1.0
    return float(sign * (peak * peak) / sidelobe_energy)


def apply_transform(crop_gray: np.ndarray, transform_name: str) -> np.ndarray:
    """Apply robustness degradation to a float64 grayscale crop (returns float64)."""
    clipped = np.clip(np.rint(crop_gray), 0, 255).astype(np.uint8)
    pil_img = Image.fromarray(clipped, mode="L")

    if transform_name == "baseline":
        return crop_gray.copy()
    if transform_name.startswith("jpeg_"):
        quality = int(transform_name.split("_", 1)[1])
        buf = io.BytesIO()
        pil_img.save(buf, format="JPEG", quality=quality)
        buf.seek(0)
        with Image.open(buf) as decoded:
            return np.asarray(decoded, dtype=np.float64)
    if transform_name == "downscale_0.75":
        h, w = crop_gray.shape
        small_w = max(8, int(round(w * 0.75)))
        small_h = max(8, int(round(h * 0.75)))
        down = pil_img.resize((small_w, small_h), resample=Image.Resampling.BICUBIC)
        restored = down.resize((w, h), resample=Image.Resampling.BICUBIC)
        return np.asarray(restored, dtype=np.float64)
    if transform_name == "brightness_shift":
        shifted = np.clip(crop_gray * 1.15 + 20.0, 0.0, 255.0)
        return np.rint(shifted).astype(np.float64)

    raise ValueError(f"Unknown transform: {transform_name}")


def inject_fingerprint(
    base_gray: np.ndarray,
    k_attack: np.ndarray,
    *,
    strength: float = 1.0,
) -> np.ndarray:
    """Simulate fingerprint-copy attack I_forged = clip_u8(I_base * (1 + alpha * K_norm))."""
    k_std = float(np.std(k_attack))
    k_unit = k_attack / k_std if k_std > 1e-12 else k_attack
    # Inject calibrated multiplicative fingerprint ~1.5 gray-level RMS at intensity 128
    delta = (np.maximum(base_gray, 1.0) / 128.0) * strength * 1.5 * k_unit
    forged = np.clip(np.rint(base_gray + delta), 0, 255)
    return forged.astype(np.float64)
