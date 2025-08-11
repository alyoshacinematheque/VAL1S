# VAL1S Module 03: Normalization Executor
# Fixed normalization:
#   - Video  -> FFV1 v3 in MKV (yuv422p10le, slicecrc=1)
#   - Audio  -> PCM s24le 96 kHz in WAV
#   - Images -> TIFF (rgb48le when possible)
#
# Inputs:
#   (A) --from-csv VAL1S_02_conformance_*.csv   # preferred, deterministic
#   (B) a directory to scan (best-effort classification via MediaInfo)
#
# Outputs:
#   - Actions CSV (plan) with per-file commands and statuses
#   - Optional execution to --out-root with logs and parallel jobs

from pathlib import Path
import os, sys, csv, logging, shlex, subprocess
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from pymediainfo import MediaInfo
except Exception:
    MediaInfo = None  # only needed when walking without CSV

def target_path(out_root: Path, src: Path, root_in: Path, media_class: str) -> Path:
    """Output path under out_root, preserving relative structure and using the right extension."""
    try:
        rel = src.relative_to(root_in)
    except ValueError:
        rel = src.name  # fall back to just the filename
    if media_class == "video":
        return out_root / Path(rel).with_suffix(".mkv")
    if media_class == "audio":
        return out_root / Path(rel).with_suffix(".wav")
    if media_class == "image":
        return out_root / Path(rel).with_suffix(".tiff")
    return out_root / Path(rel)

RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

# Skip rules similar to Module 01/02
SKIP_ABS = {"/proc", "/sys", "/dev", "/run", "/tmp", "/var/lib", "/var/run", "/var/cache",
            "/System", "/Library"}
SKIP_NAMES = {".git", ".svn", ".DS_Store", "node_modules", "__pycache__"}
SKIP_EXTS  = {".tmp", ".swp"}

FOLLOW_SYMLINKS = False

ACTIONS_COLUMNS = [
    "path_in",
    "media_class",
    "planned_action",
    "ffmpeg_cmd",
    "path_out",
    "status",       # planned|skipped|ok|error
    "message"
]

def is_skippable(p: Path) -> bool:
    try:
        if not FOLLOW_SYMLINKS and p.is_symlink():
            return True
        if p.name in SKIP_NAMES or p.suffix.lower() in SKIP_EXTS:
            return True
        rp = p.resolve(strict=False)
        for root in SKIP_ABS:
            root_p = Path(root)
            try:
                if rp.is_relative_to(root_p):
                    return True
            except AttributeError:
                if str(rp).startswith(str(root_p)):
                    return True
        return False
    except Exception:
        return True

# --- Classification ---

def classify_from_csv_row(row: Dict[str, str]) -> str:
    mc = (row.get("media_class") or "").lower()
    if mc in {"video", "audio", "image"}:
        return mc
    # Heuristic fallback if Module 02 columns aren't present
    path = row.get("path") or row.get("File Path") or ""
    ext = Path(path).suffix.lower()
    if ext in {".mov",".mp4",".mkv",".avi",".mxf",".mts",".m2ts",".mpg",".mpeg"}:
        return "video"
    if ext in {".wav",".aif",".aiff",".flac",".mp3",".m4a"}:
        return "audio"
    if ext in {".tif",".tiff",".png",".jpg",".jpeg",".bmp",".jp2"}:
        return "image"
    return "other"

def classify_with_mediainfo(p: Path) -> str:
    if MediaInfo is None:
        # naive extension-based fallback
        return classify_from_csv_row({"path": str(p)})
    try:
        mi = MediaInfo.parse(str(p))
        has_v = any(t.track_type == "Video" for t in mi.tracks)
        has_a = any(t.track_type == "Audio" for t in mi.tracks)
        has_i = any(t.track_type == "Image" for t in mi.tracks)
        if has_v: return "video"
        if has_i and not has_v: return "image"
        if has_a and not has_v: return "audio"
        return "other"
    except Exception:
        return classify_from_csv_row({"path": str(p)})

# --- Command builders ---

def build_video_cmd(src: Path, dst: Path, interlaced_hint: Optional[str] = None) -> List[str]:
    # Deinterlace only if hinted (you can wire in Module 02's scan_type later)
    vf_chain = []
    if interlaced_hint and interlaced_hint.lower().startswith("interl"):
        vf_chain.append("bwdif=mode=1:parity=auto:deint=all")
    vf = ",".join(vf_chain) if vf_chain else None

    cmd = [
        "ffmpeg", "-y", "-hide_banner", "-nostdin",
        "-i", str(src),
        "-map", "0",
        "-c:v", "ffv1", "-level", "3", "-g", "1",
        "-slices", "16", "-slicecrc", "1",
        "-pix_fmt", "yuv422p10le",
        "-c:a", "pcm_s24le",
        "-dn", "-sn",
        "-f", "matroska", str(dst)
    ]
    if vf:
        # Insert filter after input
        idx = cmd.index("-c:v")
        cmd[idx:idx] = ["-vf", vf]
    return cmd

def build_audio_cmd(src: Path, dst: Path) -> List[str]:
    return [
        "ffmpeg", "-y", "-hide_banner", "-nostdin",
        "-i", str(src),
        "-map", "0:a:0?",         # first audio or none
        "-c:a", "pcm_s24le",
        "-ar", "96000",
        "-vn", "-dn", "-sn",
        str(dst)
    ]

def build_image_cmd(src: Path, dst: Path) -> List[str]:
    # Use rgb48le when possible, fall back if conversion unsupported
    return [
        "ffmpeg", "-y", "-hide_banner", "-nostdin",
        "-i", str(src),
        "-pix_fmt", "rgb48le",
        str(dst)
    ]

# --- Planning ---

def row_is_interlaced(row: dict) -> bool:
    """Detect interlace from Module 02 CSV fields."""
    val = " ".join([
        (row.get("scan_type") or ""),
        (row.get("scan_order") or ""),
    ]).lower()
    return any(tok in val for tok in ("interl", "tff", "bff", "mbaff", "paff", "mixed"))

def plan_for_row(row: Dict[str, str], out_root: Path, root_in: Optional[Path]) -> Tuple[List[str], Dict[str, Any]]:
    src_str = row.get("path") or row.get("File Path") or ""
    if not src_str:
        return [], {"status": "skipped", "message": "no path in row"}
    src = Path(src_str)
    media_class = classify_from_csv_row(row)
    if media_class not in {"video","audio","image"}:
        return [], {"status": "skipped", "message": f"unsupported class {media_class}"}

    # Skip DPX images entirely
    if media_class == "image" and src.suffix.lower() == ".dpx":
        return [], {"status": "skipped", "message": "skipping DPX"}

    out_path = target_path(out_root, src, root_in or src.parent, media_class)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if media_class == "video":
        interlace_hint = "interlaced" if row_is_interlaced(row) else ""
        cmd = build_video_cmd(src, out_path, interlaced_hint=interlace_hint)
        action = "transcode_video_ffv1_mkv"
    elif media_class == "audio":
        cmd = build_audio_cmd(src, out_path)
        action = "normalize_audio_pcm96k24_wav"
    else:
        cmd = build_image_cmd(src, out_path)
        action = "normalize_image_tiff"

    return cmd, {
        "path_in": str(src),
        "media_class": media_class,
        "planned_action": action,
        "ffmpeg_cmd": " ".join(shlex.quote(c) for c in cmd),
        "path_out": str(out_path),
        "status": "planned",
        "message": ""
    }

def plan_from_csv(csv_path: Path, out_root: Path, root_in: Optional[Path]) -> List[Dict[str, Any]]:
    plans: List[Dict[str, Any]] = []
    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cmd, rec = plan_for_row(row, out_root, root_in)
            if rec:
                plans.append(rec | {"_cmd_list": cmd})
    return plans

def plan_from_walk(input_root: Path, out_root: Path) -> List[Dict[str, Any]]:
    plans: List[Dict[str, Any]] = []
    for dirpath, dirnames, filenames in os.walk(input_root, followlinks=FOLLOW_SYMLINKS):
        dpath = Path(dirpath)
        kept = []
        for d in dirnames:
            sub = dpath / d
            if not is_skippable(sub):
                kept.append(d)
        dirnames[:] = kept
        for name in filenames:
            p = dpath / name
            if is_skippable(p) or not p.is_file():
                continue
            mc = classify_with_mediainfo(p)
            row = {"path": str(p), "media_class": mc}
            cmd, rec = plan_for_row(row, out_root, input_root)
            if rec:
                plans.append(rec | {"_cmd_list": cmd})
    return plans

# --- Execution ---

def run_ffmpeg(rec: Dict[str, Any], log_dir: Path, force: bool=False) -> Dict[str, Any]:
    outp = Path(rec["path_out"])
    inp = Path(rec["path_in"])
    cmd = rec["_cmd_list"]
    if not inp.exists():
        rec["status"] = "error"
        rec["message"] = "input missing"
        return rec
    if outp.exists() and outp.stat().st_size > 0 and not force:
        rec["status"] = "skipped"
        rec["message"] = "output exists"
        return rec

    log_dir.mkdir(parents=True, exist_ok=True)
    base = outp.with_suffix("").name
    log_out = log_dir / f"{base}.out.log"
    log_err = log_dir / f"{base}.err.log"

    try:
        with open(log_out, "w", encoding="utf-8") as fo, open(log_err, "w", encoding="utf-8") as fe:
            proc = subprocess.run(cmd, stdout=fo, stderr=fe)
        if proc.returncode == 0 and outp.exists() and outp.stat().st_size > 0:
            rec["status"] = "ok"
            rec["message"] = ""
        else:
            rec["status"] = "error"
            rec["message"] = f"ffmpeg exit {proc.returncode}"
    except Exception as e:
        rec["status"] = "error"
        rec["message"] = f"exception: {e}"
    return rec

def write_actions_csv(path: Path, rows: List[Dict[str, Any]]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(ACTIONS_COLUMNS)
        for r in rows:
            w.writerow([r.get(k, "") for k in ACTIONS_COLUMNS])

# --- CLI ---

if __name__ == "__main__":
    import argparse
    import time

    parser = argparse.ArgumentParser(description="VAL1S Module 03: Normalize to FFV1/MKV (video), PCM 96k/24 WAV (audio), TIFF (images)")
    parser.add_argument("--from-csv", type=Path, help="Read inputs from Module 02 CSV (preferred)")
    parser.add_argument("--input-root", type=Path, help="Directory to scan if --from-csv not provided")
    parser.add_argument("--out-root", type=Path, default=Path.cwd() / f"VAL1S_03_output_{RUN_TS}",
                        help="Root directory for normalized outputs")
    parser.add_argument("--execute", action="store_true", help="Run ffmpeg; otherwise write a plan only")
    parser.add_argument("--jobs", type=int, default=2, help="Parallel jobs for execution (default: 2)")
    parser.add_argument("--force", action="store_true", help="Overwrite existing outputs")
    parser.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks during walk")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv)")
    args = parser.parse_args()

    # Logging level
    if args.verbose >= 2:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbose == 1:
        logging.getLogger().setLevel(logging.INFO)

    FOLLOW_SYMLINKS = args.follow_symlinks

    if not args.from_csv and not args.input_root:
        logging.error("Provide --from-csv or --input-root")
        sys.exit(2)

    t0 = time.perf_counter()

    # Plan
    if args.from_csv:
        src_csv = args.from_csv.resolve()
        if not src_csv.exists():
            logging.error(f"CSV not found: {src_csv}")
            sys.exit(2)
        # Try to infer a common root for relative pathing
        inferred_root = args.input_root.resolve() if args.input_root else None
        plans = plan_from_csv(src_csv, args.out_root.resolve(), inferred_root)
    else:
        root = args.input_root.resolve()
        if not root.exists() or not root.is_dir():
            logging.error(f"Input root invalid: {root}")
            sys.exit(2)
        plans = plan_from_walk(root, args.out_root.resolve())

    # Prepare actions CSV path
    actions_csv = Path.cwd() / f"VAL1S_03_actions_{RUN_TS}.csv"

    if not args.execute:
        write_actions_csv(actions_csv, plans)
        elapsed = time.perf_counter() - t0
        print(f"[VAL1S] Plan written: {actions_csv}")
        print(f"[VAL1S] Planned {len(plans)} actions in {elapsed:.2f}s.")
        sys.exit(0)

    # Execute
    log_dir = Path.cwd() / f"VAL1S_03_logs_{RUN_TS}"
    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as ex:
        futs = [ex.submit(run_ffmpeg, dict(p), log_dir, args.force) for p in plans]
        for fut in as_completed(futs):
            results.append(fut.result())

    write_actions_csv(actions_csv, results)

    ok = sum(1 for r in results if r["status"] == "ok")
    err = sum(1 for r in results if r["status"] == "error")
    skp = sum(1 for r in results if r["status"] == "skipped")
    elapsed = time.perf_counter() - t0

    print(f"[VAL1S] Executed {len(results)} actions: {ok} ok, {err} errors, {skp} skipped.")
    print(f"[VAL1S] Logs: {log_dir}")
    print(f"[VAL1S] Actions CSV: {actions_csv}")
    print(f"[VAL1S] Output root: {args.out_root}")
    print(f"[VAL1S] Module 03 complete in {elapsed:.2f}s.")
