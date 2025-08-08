# VAL1S Module 02: Format Profiler
# Description: Uses MediaInfo to profile the format of media files.
#              Reports actual format info regardless of file extension.

import os
import csv
import subprocess
from datetime import datetime

SKIP_DIRS = ['/proc', '/sys', '/dev', '/run', '/tmp', '/var/lib', '/var/run', '/var/cache']

format_report = []

def is_skippable(path):
    return any(path.startswith(skip) for skip in SKIP_DIRS)

def profile_format(path):
    try:
        result = subprocess.run(['mediainfo', '--Output=JSON', path], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            return None
    except Exception:
        return None

def walk_and_profile(root_path):
    for dirpath, dirnames, filenames in os.walk(root_path):
        if is_skippable(dirpath):
            dirnames[:] = []
            continue
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            if not os.path.isfile(full_path):
                continue
            format_data = profile_format(full_path)
            if format_data:
                format_report.append([full_path, format_data])

def write_format_csv(out_path):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = os.path.join(out_path, f"VAL1S_02_format_profile_{timestamp}.csv")
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['File Path', 'MediaInfo JSON'])
        writer.writerows(format_report)
    print(f"Format profile report written to: {filename}")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='VAL1S Module 02: Format Profiler')
    parser.add_argument('target', help='Directory to scan')
    parser.add_argument('--output', default='.', help='Directory to save report')
    args = parser.parse_args()

    print("[VAL1S] Starting format profiling scan...")
    walk_and_profile(args.target)
    write_format_csv(args.output)

    print("[VAL1S] Module 02 complete.")
