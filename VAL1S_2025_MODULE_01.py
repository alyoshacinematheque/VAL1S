# VAL1S Module 01: Inventory + Dupe Detection
# Description: Recursively inventories all files in a target directory,
#              then computes SHA256 hashes to detect duplicates.
#              Outputs two CSV reports: inventory and duplicates.

import os
import hashlib
import csv
from datetime import datetime

# Directories to skip during scanning
SKIP_DIRS = ['/proc', '/sys', '/dev', '/run', '/tmp', '/var/lib', '/var/run', '/var/cache']

# Storage for file metadata and hashes
inventory_data = []
hash_dict = {}
dupes = {}

def is_skippable(path):
    return any(path.startswith(skip) for skip in SKIP_DIRS)

def hash_file(path, block_size=65536):
    try:
        hasher = hashlib.sha256()
        with open(path, 'rb') as f:
            for block in iter(lambda: f.read(block_size), b''):
                hasher.update(block)
        return hasher.hexdigest()
    except Exception:
        return None

def walk_and_inventory(root_path):
    for dirpath, dirnames, filenames in os.walk(root_path):
        if is_skippable(dirpath):
            dirnames[:] = []  # Don't descend into this directory
            continue
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            if not os.path.isfile(full_path):
                continue
            try:
                size = os.path.getsize(full_path)
                mtime = os.path.getmtime(full_path)
                inventory_data.append([full_path, size, mtime])
            except Exception:
                continue

def detect_duplicates():
    for path, size, mtime in inventory_data:
        file_hash = hash_file(path)
        if file_hash:
            if file_hash in hash_dict:
                dupes.setdefault(file_hash, [hash_dict[file_hash]]).append(path)
            else:
                hash_dict[file_hash] = path

def write_inventory_csv(out_path):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = os.path.join(out_path, f"VAL1S_01_inventory_{timestamp}.csv")
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['File Path', 'Size (bytes)', 'Modified Time'])
        writer.writerows(inventory_data)
    print(f"Inventory report written to: {filename}")

def write_dupes_csv(out_path):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = os.path.join(out_path, f"VAL1S_01_dupes_{timestamp}.csv")
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['SHA256 Hash', 'Duplicate File Path'])
        for h, paths in dupes.items():
            for path in paths:
                writer.writerow([h, path])
    print(f"Duplicate report written to: {filename}")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='VAL1S Module 01: Inventory + Dupe Detection')
    parser.add_argument('target', help='Directory to scan')
    parser.add_argument('--output', default='.', help='Directory to save reports')
    args = parser.parse_args()

    print("[VAL1S] Starting inventory scan...")
    walk_and_inventory(args.target)
    write_inventory_csv(args.output)

    print("[VAL1S] Running duplicate detection...")
    detect_duplicates()
    write_dupes_csv(args.output)

    print("[VAL1S] Module 01 complete.")
