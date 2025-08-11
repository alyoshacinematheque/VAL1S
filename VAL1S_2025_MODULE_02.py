# VAL1S Module 02: Conformance Check
# Extracts technical metadata (MediaInfo), evaluates against a policy, and writes a CSV report.

from pathlib import Path
import os, sys, csv, json, logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional
from pymediainfo import MediaInfo

# --- Runtime config ---
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
FOLLOW_SYMLINKS = False

# --- Skip rules (similar spirit to Module 01) ---
SKIP_ABS = {"/proc", "/sys", "/dev", "/run", "/tmp", "/var/lib", "/var/run", "/var/cache",
            "/System", "/Library"}
SKIP_NAMES = {".git", ".svn", ".DS_Store", "node_modules", "__pycache__"}
SKIP_EXTS  = {".tmp", ".swp"}

# --- Logging ---
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

# --- CSV schema (order matters) ---
CSV_COLUMNS = [
    "path",
    "media_class",
    "container",
    "video_codec",
    "audio_codec",
    "duration_ms",
    "width",
    "height",
    "frame_rate",
    "scan_type",            # Progressive/Interlaced/Unknown
    "pixel_format",         # e.g., YUV 4:2:2 10-bit if derivable (best-effort)
    "chroma_subsampling",
    "bit_depth",
    "audio_sample_rate",
    "audio_channels",
    "size_bytes",
    "policy_name",
    "conformance_ok",
    "failed_rules"          # semicolon-joined
]

# --- Default policy (override with --policy JSON if desired) ---
DEFAULT_POLICY: Dict[str, Any] = {
    "name": "VAL1S_Default_v1",
    "rules": {
        "video": {
            "containers": ["mov", "mp4", "mkv", "avi"],
            "video_codecs": ["prores", "h264", "mpeg-4 visual", "ffv1", "dv", "h265", "hevc", "jpeg2000"],
            "audio_codecs": ["pcm", "aac", "ac-3", "mp2", "mp3", "alac"],
            "width_min": 100, "height_min": 100,
            "width_max": 16384, "height_max": 16384,
            "fps_min": 1.0, "fps_max": 120.0,
            "bit_depth_min": 8, "bit_depth_max": 16
        },
        "audio": {
            "containers": ["wav", "aiff", "flac", "mp3", "m4a"],
            "audio_codecs": ["pcm", "flac", "mp3", "aac", "alac"],
            "sample_rate_min": 8000, "sample_rate_max": 384000,
            "channels_min": 1, "channels_max": 8,
            "bit_depth_min": 8, "bit_depth_max": 32
        },
        "image": {
            "containers": ["tiff", "tif", "png", "jpg", "jpeg", "bmp"],
            "bit_depth_min": 1, "bit_depth_max": 32,
            "width_min": 16, "height_min": 16,
            "width_max": 65535, "height_max": 65535
        }
    }
}


# ---------- Helpers ----------

def is_skippable(p: Path) -> bool:
    """Return True if this path should be skipped."""
    try:
        if not FOLLOW_SYMLINKS and p.is_symlink():
            return True
        if p.name in SKIP_NAMES or p.suffix.lower() in SKIP_EXTS:
            return True
        rp = p.resolve(strict=False)
        # Python 3.9 has no Path.is_relative_to; add fallback
        for root in SKIP_ABS:
            root_p = Path(root)
            try:
                if rp.is_relative_to(root_p):
                    return True
            except AttributeError:
                if str(rp).startswith(str(root_p)):
                    return True
        return False
    except Exception as e:
        logging.debug(f"is_skippable error for {p}: {e}")
        return True  # fail-safe


def _norm(s: Optional[str]) -> Optional[str]:
    return s.lower() if isinstance(s, str) else None


def classify_media(mi: MediaInfo) -> str:
    """Return 'video' | 'audio' | 'image' | 'other' based on track presence."""
    has_video = any(t.track_type == "Video" for t in mi.tracks)
    has_audio = any(t.track_type == "Audio" for t in mi.tracks)
    has_image = any(t.track_type == "Image" for t in mi.tracks)  # still image
    if has_video:
        return "video"
    if has_image and not has_video:
        return "image"
    if has_audio and not has_video:
        return "audio"
    return "other"


def extract_metadata(path: Path) -> Dict[str, Any]:
    """
    Best-effort extraction via pymediainfo. Returns a dict aligned (loosely) to CSV_COLUMNS.
    """
    meta: Dict[str, Any] = {
        "path": str(path),
        "media_class": "other",
        "container": None,
        "video_codec": None,
        "audio_codec": None,
        "duration_ms": None,
        "width": None,
        "height": None,
        "frame_rate": None,
        "scan_type": None,
        "pixel_format": None,
        "chroma_subsampling": None,
        "bit_depth": None,
        "audio_sample_rate": None,
        "audio_channels": None,
        "size_bytes": None
    }

    try:
        st = os.stat(path, follow_symlinks=FOLLOW_SYMLINKS)
        meta["size_bytes"] = st.st_size
    except Exception as e:
        logging.warning(f"stat failed for {path}: {e}")

    try:
        mi = MediaInfo.parse(str(path))
    except Exception as e:
        logging.warning(f"MediaInfo parse failed for {path}: {e}")
        return meta

    # Class
    media_class = classify_media(mi)
    meta["media_class"] = media_class

    # General/container info
    gen = next((t for t in mi.tracks if t.track_type == "General"), None)
    if gen:
        # e.g., 'MPEG-4', 'Matroska'
        container = _norm(getattr(gen, "format", None)) or _norm(getattr(gen, "internet_media_type", None))
        if container:
            # Normalize common container names
            container = container.replace("matroska", "mkv").replace("mpeg-4", "mp4")
            container = container.replace("quicktime", "mov")
        # Fall back to extension when MediaInfo is vague
        if not container:
            container = path.suffix.lower().lstrip(".") or None
        meta["container"] = container

        # Duration (ms)
        dur = getattr(gen, "duration", None)
        try:
            meta["duration_ms"] = int(float(dur)) if dur is not None else None
        except Exception:
            meta["duration_ms"] = None

    # Video
    v = next((t for t in mi.tracks if t.track_type == "Video"), None)
    if v:
        vc = _norm(getattr(v, "format", None)) or _norm(getattr(v, "codec_id", None))
        if vc:
            vc = vc.replace("mpeg-4 visual", "mpeg-4 visual").replace("h.264", "h264").replace("h.265", "h265")
        meta["video_codec"] = vc

        try:
            meta["width"]  = int(getattr(v, "width", None)) if getattr(v, "width", None) else None
            meta["height"] = int(getattr(v, "height", None)) if getattr(v, "height", None) else None
        except Exception:
            pass

        # Frame rate may be "23.976 (24000/1001)"
        fr = getattr(v, "frame_rate", None)
        if isinstance(fr, str):
            parts = fr.split()
            try:
                meta["frame_rate"] = float(parts[0])
            except Exception:
                meta["frame_rate"] = None
        elif isinstance(fr, (int, float)):
            meta["frame_rate"] = float(fr)

        scan = getattr(v, "scan_type", None) or getattr(v, "scan_type_store_method", None)
        meta["scan_type"] = scan if scan else None

        meta["chroma_subsampling"] = getattr(v, "chroma_subsampling", None) or None
        bd = getattr(v, "bit_depth", None)
        try:
            meta["bit_depth"] = int(bd) if bd is not None else None
        except Exception:
            meta["bit_depth"] = None

        # Pixel format (best-effort from chroma + bit depth)
        if meta["chroma_subsampling"] and meta["bit_depth"]:
            meta["pixel_format"] = f"{meta['chroma_subsampling']} {meta['bit_depth']}-bit"

    # Audio (first track)
    a = next((t for t in mi.tracks if t.track_type == "Audio"), None)
    if a:
        ac = _norm(getattr(a, "format", None)) or _norm(getattr(a, "codec_id", None))
        if ac:
            ac = ac.replace("pcm", "pcm")
        meta["audio_codec"] = ac
        sr = getattr(a, "sampling_rate", None)
        try:
            meta["audio_sample_rate"] = int(sr) if sr is not None else None
        except Exception:
            meta["audio_sample_rate"] = None
        ch = getattr(a, "channel_s", None) or getattr(a, "channel_s_original", None) or getattr(a, "channels", None)
        try:
            meta["audio_channels"] = int(ch) if ch is not None else None
        except Exception:
            meta["audio_channels"] = None

    # Image specifics (if still image)
    if media_class == "image":
        img = next((t for t in mi.tracks if t.track_type == "Image"), None)
        if img:
            try:
                meta["width"]  = meta["width"] or (int(getattr(img, "width", None)) if getattr(img, "width", None) else None)
                meta["height"] = meta["height"] or (int(getattr(img, "height", None)) if getattr(img, "height", None) else None)
            except Exception:
                pass
            bd = getattr(img, "bit_depth", None)
            try:
                meta["bit_depth"] = int(bd) if bd is not None else meta["bit_depth"]
            except Exception:
                pass

    # Final fallbacks
    if not meta["container"]:
        meta["container"] = path.suffix.lower().lstrip(".") or None

    return meta


def check_policy(meta: Dict[str, Any], policy: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Compare extracted metadata to policy rules for its media_class. Return (ok, failed_rules)."""
    cls = meta.get("media_class", "other")
    rules = policy.get("rules", {}).get(cls)
    failures: List[str] = []
    if not rules:
        # No rules for this class; treat as pass but note absence
        return True, failures

    def maybe_fail(cond: bool, label: str):
        if not cond:
            failures.append(label)

    # Container/codec checks
    container = (meta.get("container") or "").lower()
    if "containers" in rules:
        maybe_fail(container in [c.lower() for c in rules["containers"]], f"container:{container}")

    if cls in ("video", "audio"):
        vcodec = (meta.get("video_codec") or "").lower()
        acodec = (meta.get("audio_codec") or "").lower()
        if cls == "video":
            if "video_codecs" in rules:
                maybe_fail(bool(vcodec) and vcodec in [v.lower() for v in rules["video_codecs"]],
                           f"video_codec:{vcodec or 'none'}")
            if "audio_codecs" in rules:
                # Some silent video may have no audio track
                if acodec:
                    maybe_fail(acodec in [a.lower() for a in rules["audio_codecs"]], f"audio_codec:{acodec}")
        if cls == "audio":
            if "audio_codecs" in rules:
                maybe_fail(bool(acodec) and acodec in [a.lower() for a in rules["audio_codecs"]],
                           f"audio_codec:{acodec or 'none'}")

    # Ranges
    def in_range(v: Optional[float], lo: Optional[float], hi: Optional[float]) -> bool:
        if v is None:
            return True  # missing data doesn't fail by default
        if lo is not None and v < lo:
            return False
        if hi is not None and v > hi:
            return False
        return True

    if cls == "video":
        maybe_fail(in_range(meta.get("width"),  rules.get("width_min"),  rules.get("width_max")),  "width_range")
        maybe_fail(in_range(meta.get("height"), rules.get("height_min"), rules.get("height_max")), "height_range")
        maybe_fail(in_range(meta.get("frame_rate"), rules.get("fps_min"), rules.get("fps_max")),   "fps_range")
        maybe_fail(in_range(meta.get("bit_depth"), rules.get("bit_depth_min"), rules.get("bit_depth_max")), "bit_depth_range")

    if cls == "audio":
        maybe_fail(in_range(meta.get("audio_sample_rate"), rules.get("sample_rate_min"), rules.get("sample_rate_max")), "sr_range")
        maybe_fail(in_range(meta.get("audio_channels"),    rules.get("channels_min"),    rules.get("channels_max")),    "ch_range")
        maybe_fail(in_range(meta.get("bit_depth"),         rules.get("bit_depth_min"),   rules.get("bit_depth_max")),   "bit_depth_range")

    if cls == "image":
        maybe_fail(in_range(meta.get("width"),  rules.get("width_min"),  rules.get("width_max")),  "width_range")
        maybe_fail(in_range(meta.get("height"), rules.get("height_min"), rules.get("height_max")), "height_range")
        maybe_fail(in_range(meta.get("bit_depth"), rules.get("bit_depth_min"), rules.get("bit_depth_max")), "bit_depth_range")

    return (len(failures) == 0), failures


def load_policy(policy_path: Optional[Path]) -> Dict[str, Any]:
    if not policy_path:
        return DEFAULT_POLICY
    try:
        with open(policy_path, "r", encoding="utf-8") as f:
            pol = json.load(f)
            # minimal sanity
            if "name" not in pol:
                pol["name"] = policy_path.stem
            return pol
    except Exception as e:
        logging.error(f"Failed to load policy {policy_path}: {e}. Falling back to default.")
        return DEFAULT_POLICY


def write_header(writer: csv.writer):
    writer.writerow(CSV_COLUMNS)


def row_from_meta(meta: Dict[str, Any], policy_name: str, ok: bool, failures: List[str]) -> List[Any]:
    pf = ";".join(failures) if failures else ""
    return [
        meta.get("path"),
        meta.get("media_class"),
        meta.get("container"),
        meta.get("video_codec"),
        meta.get("audio_codec"),
        meta.get("duration_ms"),
        meta.get("width"),
        meta.get("height"),
        meta.get("frame_rate"),
        meta.get("scan_type"),
        meta.get("pixel_format"),
        meta.get("chroma_subsampling"),
        meta.get("bit_depth"),
        meta.get("audio_sample_rate"),
        meta.get("audio_channels"),
        meta.get("size_bytes"),
        policy_name,
        bool(ok),
        pf,
    ]


def walk_and_report(root: Path, out_csv: Path, policy: Dict[str, Any]):
    """Stream results to CSV while walking the tree."""
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        write_header(writer)

        for dirpath, dirnames, filenames in os.walk(root, followlinks=FOLLOW_SYMLINKS):
            dpath = Path(dirpath)

            # Prune subdirs
            kept = []
            for d in dirnames:
                sub = dpath / d
                if not is_skippable(sub):
                    kept.append(d)
            dirnames[:] = kept

            for name in filenames:
                p = dpath / name
                if is_skippable(p):
                    continue
                try:
                    meta = extract_metadata(p)
                    ok, failures = check_policy(meta, policy)
                    writer.writerow(row_from_meta(meta, policy.get("name", "policy"), ok, failures))
                except Exception as e:
                    logging.warning(f"error processing {p}: {e}")
                    # Write a minimal row indicating error
                    writer.writerow([str(p), "other", None, None, None, None, None, None, None,
                                     None, None, None, None, None, None,
                                     meta.get("size_bytes") if 'meta' in locals() else None,
                                     policy.get("name", "policy"), False, "exception"])


# ---------- CLI ----------

if __name__ == "__main__":
    import argparse
    import time

    parser = argparse.ArgumentParser(description="VAL1S Module 02: Conformance Check (MediaInfo-based)")
    parser.add_argument("target", type=Path, help="Directory to scan")
    parser.add_argument("--output", type=Path, default=Path.cwd(),
                        help="Directory to save report (default: current dir)")
    parser.add_argument("--policy", type=Path, default=None,
                        help="Path to JSON policy (overrides defaults)")
    parser.add_argument("--follow-symlinks", action="store_true",
                        help="Follow symlinks during walk")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase verbosity (-v, -vv)")
    parser.add_argument("--skip-name", action="append", default=[],
                        help="Add a basename to skip (can be used multiple times)")
    parser.add_argument("--skip-ext", action="append", default=[],
                        help="Add a file extension to skip (e.g. .tmp) (can be used multiple times)")
    parser.add_argument("--skip-abs", action="append", default=[],
                        help="Add an absolute path prefix to skip (can be used multiple times)")

    args = parser.parse_args()

    # Logging level
    if args.verbose >= 2:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbose == 1:
        logging.getLogger().setLevel(logging.INFO)

    # Validate target
    target = args.target.resolve()
    if not target.exists() or not target.is_dir():
        logging.error(f"Target is not a directory: {target}")
        sys.exit(2)

    # Apply CLI toggles/globals
    FOLLOW_SYMLINKS = args.follow_symlinks
    SKIP_NAMES |= set(args.skip_name or [])
    SKIP_EXTS  |= set(s.lower() for s in (args.skip_ext or []))
    SKIP_ABS   |= set(args.skip_abs or [])

    policy = load_policy(args.policy)

    # Output file
    out_csv = args.output / f"VAL1S_02_conformance_{RUN_TS}.csv"

    t0 = time.perf_counter()
    print("[VAL1S] Starting conformance scan…")
    walk_and_report(target, out_csv, policy)
    elapsed = time.perf_counter() - t0
    print(f"[VAL1S] Conformance report written to: {out_csv}")
    print(f"[VAL1S] Module 02 complete in {elapsed:.2f}s.")
