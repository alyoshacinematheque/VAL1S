# VAL1S Module 01: Inventory + Dupe Detection
# Description: Recursively inventories all files in a target directory,
#              then computes SHA256 hashes to detect duplicates.
#              Outputs two CSV reports: inventory and duplicates.

from pathlib import Path
import os, hashlib, csv, logging
from datetime import datetime, timezone
import stat

# --- Runtime config ---
RUN_TS = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
FOLLOW_SYMLINKS = False

# Directories to skip during scanning
SKIP_ABS = {"/proc", "/sys", "/dev", "/run", "/tmp", "/var/lib", "/var/run", "/var/cache",
            "/System", "/Library"}
SKIP_NAMES = {".git", ".svn", ".DS_Store", "node_modules", "__pycache__"}
SKIP_EXTS = {".tmp", ".swp"}

# Storage for file metadata and hashes
inventory_data = []
size_index = {}
hash_index = {}
inode_hash = {}

# --- Logging ---
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

def is_skippable(p) -> bool:
    """Return True if this path should be skipped."""
    try:
        p = Path(p)
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
    except Exception as e:
        logging.debug(f"is_skippable error for {p}: {e}")
        return True

def hash_file(path, chunk_size=1024*1024):
    """SHA-256 of a file. Returns hex digest or None on error."""
    try:
        h = hashlib.sha256()
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
        dirnames[:] = [d for d in dirnames if not is_skippable(dpath / d)]
        for name in filenames:
            p = dpath / name
            if is_skippable(p):
                continue
            try:
                st = os.stat(p, follow_symlinks=FOLLOW_SYMLINKS)
                if not stat.S_ISREG(st.st_mode):
                    continue
                size = st.st_size
                mtime_iso = datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat()
                inventory_data.append([str(p), size, mtime_iso])
                size_index.setdefault(size, []).append(str(p))
                inode_hash[(st.st_dev, st.st_ino)] = None
            except (PermissionError, FileNotFoundError, OSError) as e:
                logging.warning(f"Skipped {p}: {e}")
                continue

def detect_duplicates():
    """Populate hash_index with potential duplicate groups."""
    for size, paths in size_index.items():
        if len(paths) < 2:
            continue
        for p in paths:
            try:
                st = os.stat(p, follow_symlinks=FOLLOW_SYMLINKS)
                inode_key = (st.st_dev, st.st_ino)
                digest = inode_hash.get(inode_key)
                if digest is None:
                    digest = hash_file(p)
                    inode_hash[inode_key] = digest
                if not digest:
                    continue
                hash_index.setdefault(digest, []).append(p)
            except (PermissionError, FileNotFoundError, OSError) as e:
                logging.warning(f"Duplicate check skipped for {p}: {e}")
                continue
    for h in list(hash_index.keys()):
        if len(hash_index[h]) < 2:
            del hash_index[h]

def write_inventory_csv(out_path):
    Path(out_path).mkdir(parents=True, exist_ok=True)
    filename = Path(out_path) / f"VAL1S_01_inventory_{RUN_TS}.csv"
    try:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["File Path", "Size (bytes)", "Modified Time (UTC)"])
            writer.writerows(inventory_data)
        print(f"Inventory report written to: {filename}")
    except OSError as e:
        logging.error(f"Failed to write inventory CSV: {e}")

def write_dupes_csv(out_path):
    Path(out_path).mkdir(parents=True, exist_ok=True)
    filename = Path(out_path) / f"VAL1S_01_dupes_{RUN_TS}.csv"
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
    parser = argparse.ArgumentParser(description="VAL1S Module 01: Inventory + Dupe Detection")
    parser.add_argument("target", help="Directory to scan")
    parser.add_argument("--output", default=".", help="Directory to save reports")
    parser.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks during walk")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv)")
    args = parser.parse_args()

    if args.verbose >= 2:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbose == 1:
        logging.getLogger().setLevel(logging.INFO)

    FOLLOW_SYMLINKS = args.follow_symlinks

    target = Path(args.target).resolve()
    if not target.exists() or not target.is_dir():
        logging.error(f"Target is not a directory: {target}")
        sys.exit(2)

    print("[VAL1S] Starting inventory scan...")
    walk_and_inventory(target)
    write_inventory_csv(args.output)

    print("[VAL1S] Running duplicate detection...")
    detect_duplicates()
    write_dupes_csv(args.output)

    print("[VAL1S] Module 01 complete.")
