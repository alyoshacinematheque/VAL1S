# VAL1S Module 03: Conformance Checker
# Description: Compares media file metadata against defined format policies (JSON).

import os
import json
import csv
import subprocess
from datetime import datetime

SKIP_DIRS = ['/proc', '/sys', '/dev', '/run', '/tmp', '/var/lib', '/var/run', '/var/cache']

conformance_results = []

# Load policy JSON file
def load_policy(policy_path):
    with open(policy_path, 'r') as f:
        return json.load(f)

# Use mediainfo to extract attributes

def get_mediainfo(path):
    try:
        result = subprocess.run(['mediainfo', '--Output=JSON', path], capture_output=True, text=True)
        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            return None
    except Exception:
        return None

# Check if the file conforms to the policy
def check_conformance(info, policy):
    results = []
    for stream_type, conditions in policy.items():
        for file_stream in info.get('media', {}).get('track', []):
            if file_stream.get('@type') == stream_type:
                for key, expected in conditions.items():
                    actual = file_stream.get(key)
                    if actual != expected:
                        results.append((stream_type, key, actual, expected))
    return results

# Walk target and evaluate each file
def walk_and_check(root_path, policy):
    for dirpath, dirnames, filenames in os.walk(root_path):
        if any(dirpath.startswith(skip) for skip in SKIP_DIRS):
            dirnames[:] = []
            continue
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            if not os.path.isfile(full_path):
                continue
            info = get_mediainfo(full_path)
            if info:
                mismatches = check_conformance(info, policy)
                for stream_type, key, actual, expected in mismatches:
                    conformance_results.append([full_path, stream_type, key, actual, expected])

# Output CSV
def write_conformance_csv(out_path):
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = os.path.join(out_path, f"VAL1S_03_conformance_{timestamp}.csv")
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['File Path', 'Stream Type', 'Key', 'Actual', 'Expected'])
        writer.writerows(conformance_results)
    print(f"Conformance report written to: {filename}")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='VAL1S Module 03: Conformance Checker')
    parser.add_argument('target', help='Directory to scan')
    parser.add_argument('--policy', required=True, help='Path to JSON format policy')
    parser.add_argument('--output', default='.', help='Directory to save report')
    args = parser.parse_args()

    policy = load_policy(args.policy)

    print("[VAL1S] Starting conformance check...")
    walk_and_check(args.target, policy)
    write_conformance_csv(args.output)

    print("[VAL1S] Module 03 complete.")
