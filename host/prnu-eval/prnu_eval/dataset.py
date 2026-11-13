"""Dataset discovery and camera-device grouping for Dresden Image Database and VISION.

Never downloads or commits images. Discovers user-supplied local dataset trees,
groups images by physical camera device ID, and constructs strictly disjoint
reference / test / attack image splits with fixed RNG seeds.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import pathlib
import random
import re

IMAGE_EXTENSIONS = frozenset({".jpg", ".jpeg", ".png", ".tif", ".tiff", ".bmp"})

# Dresden Image Database filename convention: <Make>_<Model>_<Unit>_<Seq>.<ext>
_DRESDEN_RE = re.compile(
    r"^([A-Za-z0-9-]+_[A-Za-z0-9.+-]+_\d+)_\d+",
    re.IGNORECASE,
)

# VISION dataset convention: D01_Samsung_GalaxyS3Mini / D01_I_flat_0001.jpg
_VISION_DIR_RE = re.compile(r"^(D\d+)(?:_|$)", re.IGNORECASE)
_VISION_FILE_RE = re.compile(r"^(D\d+)_[IV]_", re.IGNORECASE)

DATASET_LICENSES: dict[str, str] = {
    "Dresden": (
        "Dresden Image Database (TU Dresden): academic/non-commercial research "
        "license; images must be downloaded by the user and never redistributed."
    ),
    "VISION": (
        "VISION Dataset (LESC, Univ. of Florence): CC BY 4.0 for research "
        "evaluation; images must be downloaded separately by the user."
    ),
    "Generic": "User-supplied local camera dataset grouped by parent directory.",
}


@dataclass(frozen=True)
class ImageRecord:
    path: str
    device_id: str
    dataset_kind: str
    subset_kind: str  # "flat" | "nat" | "unknown"


def _infer_subset_kind(rel_parts: tuple[str, ...], filename: str) -> str:
    lower_parts = [p.lower() for p in rel_parts]
    lower_name = filename.lower()
    if any(p == "flat" or p.startswith("flat") for p in lower_parts) or "_flat_" in lower_name:
        return "flat"
    if any(p == "nat" or p.startswith("nat_") for p in lower_parts) or "_nat_" in lower_name:
        return "nat"
    return "unknown"


def _is_social_recompressed(rel_parts: tuple[str, ...]) -> bool:
    for part in rel_parts:
        low = part.lower()
        if low in {"natfb", "natwa", "natfbh", "natfbl"} or "whatsapp" in low or "facebook" in low:
            return True
    return False


def detect_device_and_dataset(
    root: pathlib.Path,
    img_path: pathlib.Path,
) -> tuple[str, str, str]:
    """Infer (device_id, dataset_kind, subset_kind) from path and filename."""
    rel = img_path.relative_to(root)
    rel_parts = rel.parts[:-1]
    name = img_path.name

    m_dresden = _DRESDEN_RE.match(img_path.stem)
    if m_dresden:
        return m_dresden.group(1), "Dresden", _infer_subset_kind(rel_parts, name)

    m_vfile = _VISION_FILE_RE.match(name)
    if m_vfile:
        dev = next(
            (p for p in rel_parts if _VISION_DIR_RE.match(p)),
            m_vfile.group(1),
        )
        return dev, "VISION", _infer_subset_kind(rel_parts, name)

    for part in rel_parts:
        if _VISION_DIR_RE.match(part):
            return part, "VISION", _infer_subset_kind(rel_parts, name)

    parent_id = rel_parts[-1] if rel_parts else "unknown_device"
    return parent_id, "Generic", _infer_subset_kind(rel_parts, name)


def load_dataset(
    dataset_path: str | os.PathLike[str],
    *,
    max_images: int | None = None,
    seed: int = 42,
    include_social: bool = False,
) -> tuple[dict[str, list[ImageRecord]], str]:
    """Scan dataset_path recursively and return ({device_id: [ImageRecord, ...]}, dataset_kind).

    When ``max_images`` is set, performs balanced seeded sampling across devices
    so multi-camera comparisons remain possible during quick smoke runs.
    """
    root = pathlib.Path(dataset_path).resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Dataset directory not found: {root}")

    grouped: dict[str, list[ImageRecord]] = {}
    kind_counts: dict[str, int] = {}

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.name.startswith(".") or path.name.startswith("._"):
            continue
        if path.suffix.lower() not in IMAGE_EXTENSIONS:
            continue

        rel = path.relative_to(root)
        lower_dirs = [p.lower() for p in rel.parts[:-1]]
        if any(d in {"videos", "video", "thumbs", "thumbnails", ".git"} for d in lower_dirs):
            continue
        if not include_social and _is_social_recompressed(rel.parts[:-1]):
            continue

        device_id, dkind, skind = detect_device_and_dataset(root, path)
        rec = ImageRecord(
            path=str(path),
            device_id=device_id,
            dataset_kind=dkind,
            subset_kind=skind,
        )
        grouped.setdefault(device_id, []).append(rec)
        kind_counts[dkind] = kind_counts.get(dkind, 0) + 1

    if not grouped:
        raise ValueError(f"No supported image files found under {root}")

    rng = random.Random(seed)
    for dev in sorted(grouped.keys()):
        rng.shuffle(grouped[dev])

    if max_images is not None and max_images > 0:
        # Round-robin cap across devices so we keep multiple cameras whenever possible
        devices = sorted(grouped.keys())
        capped: dict[str, list[ImageRecord]] = {d: [] for d in devices}
        total = 0
        idx = 0
        while total < max_images:
            progressed = False
            for d in devices:
                if total >= max_images:
                    break
                if idx < len(grouped[d]):
                    capped[d].append(grouped[d][idx])
                    total += 1
                    progressed = True
            if not progressed:
                break
            idx += 1
        grouped = {d: recs for d, recs in capped.items() if recs}

    dominant_kind = max(kind_counts.items(), key=lambda kv: kv[1])[0]
    return grouped, dominant_kind
