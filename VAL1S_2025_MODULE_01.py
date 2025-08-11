# VAL1S Module 01: Inventory + Dupe Detection
# Recursively inventories files, computes hashes to detect duplicates,
# and writes CSV reports (inventory and duplicates).

from pathlib import Path
import os, csv, hashlib, logging
from datetime import datetime, timezone
import stat

# Paths/basenames to skip during scanning
SKIP_ABS = {"/proc", "/sys", "/dev", "/run", "/tmp", "/var/lib", "/var/run", "/var/cache",
            "/System", "/Library"}  # macOS-friendly additions
SKIP_NAMES = {".git", ".svn", ".DS_Store", "node_modules", "__pycache__"}
SKIP_EXTS = {".tmp", ".swp"}  # optional

# Behavior toggles
FOLLOW_SYMLINKS = False
HASH_ALGO = "sha256"
READ_CHUNK = 1024 * 1024  # 1 MiB

# Logging (quiet by default; raise level to INFO for progress)
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

# Time stamp (UTC, ISO 8601)
RUN_TS = datetime.now(timezone.utc).isoformat()

# In-memory indices
# size -> [paths] to minimize hashing
size_index = {}
# hash -> [paths] final duplicate groups
hash_index = {}
# inode set to avoid re-hashing hardlinks: (st_dev, st_ino) -> hash
inode_hash = {}

from pathlib import Path

def is_skippable(p) -> bool:
    """Return True if this path should be skipped."""
    try:
        p = Path(p)
        if not FOLLOW_SYMLINKS and p.is_symlink():
            return True

        # Skip by basename and extension
        if p.name in SKIP_NAMES or p.suffix.lower() in SKIP_EXTS:
            return True

        # Skip by absolute root prefixes (works cross-platform)
        rp = p.resolve(strict=False)
        for root in SKIP_ABS:
            root_p = Path(root)
            try:
                # Python 3.9+: cleaner containment check
                if rp.is_relative_to(root_p):
                    return True
            except AttributeError:
                # Fallback for older Pythons
                if str(rp).startswith(str(root_p)):
                    return True
        return False
    except Exception as e:
        logging.debug(f"is_skippable error for {p}: {e}")
        return True  # fail-safe: skip on error


def hash_file(path, chunk_size=READ_CHUNK):
    """SHA-256 (or HASH_ALGO) of a file. Returns hex digest or None on error."""
    try:
        h = hashlib.new(HASH_ALGO)
        with open(path, "rb") as f:
            while True:
                block = f.read(chunk_size)
                if not block:
                    break
                h.update(block)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError) as e:
        logging.warning(f"Hash skipped for {path}: {e}")
        return None

def walk_and_inventory(root_path):
    """Populate inventory_data and size_index by walking root_path."""
    root = Path(root_path)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=FOLLOW_SYMLINKS):
        dpath = Path(dirpath)

        # Prune subdirs in-place to avoid descending into skippable dirs
        pruned = []
        for d in dirnames:
            subdir = dpath / d
            if is_skippable(subdir):
                continue
            pruned.append(d)
        dirnames[:] = pruned

        for name in filenames:
            p = dpath / name
            if is_skippable(p):
                continue

            try:
                st = os.stat(p, follow_symlinks=FOLLOW_SYMLINKS)
                if not stat.S_ISREG(st.st_mode):
                    continue  # skip non-regular files

                size = st.st_size
                mtime_iso = datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat()

                # Record minimal row; keep schema simple
                inventory_data.append([str(p), size, mtime_iso])

                # Index by size for later hash prefilter
                size_index.setdefault(size, []).append(str(p))

                # Optionally cache inode identity now (used later for hardlink handling)
                inode_hash[(st.st_dev, st.st_ino)] = None

            except (PermissionError, FileNotFoundError, OSError) as e:
                logging.warning(f"Skipped {p}: {e}")
                continue

def detect_duplicates():
    """Populate hash_index with potential duplicate groups using size prefilter + hashing."""
    for size, paths in size_index.items():
        if len(paths) < 2:
            continue  # unique size, can't be a dupe

        for p in paths:
            try:
                st = os.stat(p, follow_symlinks=FOLLOW_SYMLINKS)
                inode_key = (st.st_dev, st.st_ino)

                # If we've already hashed this inode (hardlink), reuse digest
                digest = inode_hash.get(inode_key)
                if digest is None:
                    digest = hash_file(p)
                    inode_hash[inode_key] = digest

                if not digest:
                    continue  # couldn't hash (permissions, vanished, etc.)

                hash_index.setdefault(digest, []).append(p)

            except (PermissionError, FileNotFoundError, OSError) as e:
                logging.warning(f"Duplicate check skipped for {p}: {e}")
                continue

    # Optional: keep only actual duplicate groups (len > 1)
    for h in list(hash_index.keys()):
        if len(hash_index[h]) < 2:
            del hash_index[h]

def write_inventory_csv(out_path):
    """Write the inventory_data list to a CSV file in out_path."""
    Path(out_path).mkdir(parents=True, exist_ok=True)
    filename = Path(out_path) / f"VAL1S_01_inventory_{RUN_TS.replace(':', '')}.csv"
    try:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["File Path", "Size (bytes)", "Modified Time (UTC)"])
            writer.writerows(inventory_data)
        print(f"Inventory report written to: {filename}")
    except OSError as e:
        logging.error(f"Failed to write inventory CSV: {e}")

def write_dupes_csv(out_path):
    """Write duplicate groups (hash_index) to a CSV file in out_path."""
    Path(out_path).mkdir(parents=True, exist_ok=True)
    filename = Path(out_path) / f"VAL1S_01_dupes_{RUN_TS.replace(':', '')}.csv"
    try:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["SHA256 Hash", "Duplicate File Path"])
            for digest, paths in hash_index.items():
                if len(paths) < 2:
                    continue
                for p in paths:
                    writer.writerow([digest, p])
        print(f"Duplicate report written to: {filename}")
    except OSError as e:
        logging.error(f"Failed to write duplicate CSV: {e}")

if __name__ == "__main__":
    import argparse
    import sys
    import time

    parser = argparse.ArgumentParser(
        description="VAL1S Module 01: Inventory + Dupe Detection"
    )
    parser.add_argument("target", type=Path, help="Directory to scan")
    parser.add_argument("--output", type=Path, default=Path.cwd(),
                        help="Directory to save reports (default: current dir)")
    parser.add_argument("--follow-symlinks", action="store_true",
                        help="Follow symlinks during walk")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase verbosity (-v, -vv)")
    parser.add_argument("--algo", default=HASH_ALGO, choices=hashlib.algorithms_available,
                        help=f"Hash algorithm (default: {HASH_ALGO})")
    parser.add_argument("--chunk", type=int, default=READ_CHUNK,
                        help=f"Read chunk size in bytes (default: {READ_CHUNK})")
    parser.add_argument("--skip-name", action="append", default=[],
                        help="Add a basename to skip (can be used multiple times)")
    parser.add_argument("--skip-ext", action="append", default=[],
                        help="Add a file extension to skip (e.g. .tmp) (can be used multiple times)")
    parser.add_argument("--skip-abs", action="append", default=[],
                        help="Add an absolute path prefix to skip (can be used multiple times)")
    parser.add_argument("--inventory-only", action="store_true",
                        help="Only write inventory CSV (skip duplicate detection)")
    parser.add_argument("--dupes-only", action="store_true",
                        help="Only run duplicate detection (assumes inventory already built)")

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

    # Apply CLI options to globals
    FOLLOW_SYMLINKS = args.follow_symlinks
    HASH_ALGO = args.algo
    READ_CHUNK = args.chunk
    SKIP_NAMES |= set(args.skip_name or [])
    SKIP_EXTS  |= set(s.lower() for s in (args.skip_ext or []))
    SKIP_ABS   |= set(args.skip_abs or [])

    t0 = time.perf_counter()
    print("[VAL1S] Starting inventory scan…")
    walk_and_inventory(target)
    write_inventory_csv(args.output)

    if not args.inventory_only:
        print("[VAL1S] Running duplicate detection…")
        detect_duplicates()
        write_dupes_csv(args.output)

    # Summary
    files_scanned = len(inventory_data)
    bytes_total = sum(row[1] for row in inventory_data) if inventory_data else 0
    dupe_groups = len(hash_index)
    dupe_files = sum(len(v) for v in hash_index.values()) if hash_index else 0
    elapsed = time.perf_counter() - t0

    print(f"[VAL1S] Scanned {files_scanned} files "
          f"({bytes_total} bytes) in {elapsed:.2f}s.")
    if not args.inventory_only:
        print(f"[VAL1S] Duplicate groups: {dupe_groups} "
              f"({dupe_files} file paths).")
    print("[VAL1S] Module 01 complete.")
