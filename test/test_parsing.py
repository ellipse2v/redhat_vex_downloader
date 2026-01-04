#!/usr/bin/env python3
# Copyright 2025 ellipse2v
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test script to verify CSV parsing works correctly."""

import csv
from datetime import datetime, timedelta
from pathlib import Path

def parse_changes_csv(csv_path: Path, start_date: datetime, end_date: datetime):
    """Parse changes.csv and return set of VEX filenames in date range."""
    vex_files = set()
    
    with open(csv_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                try:
                    # row[0] is the path, row[1] is the updated timestamp
                    file_date = datetime.strptime(row[1].strip('"'), "%Y-%m-%dT%H:%M:%S%z").replace(tzinfo=None)
                    if start_date <= file_date <= end_date:
                        # Extract just the filename from the path
                        vex_filename = row[0].strip('"').split('/')[-1]
                        vex_files.add(vex_filename)
                except (ValueError, IndexError) as e:
                    print(f"Error parsing row {row}: {e}")
                    continue
    
    return vex_files

# Test with last 5 days
end_date = datetime.now()
start_date = end_date - timedelta(days=5)

print(f"Testing date range: {start_date.date()} to {end_date.date()}")

# Use test file from test directory
csv_path = Path(__file__).parent / "test_changes.csv"
if csv_path.exists():
    vex_files = parse_changes_csv(csv_path, start_date, end_date)
    print(f"Found {len(vex_files)} VEX files:")
    for f in sorted(vex_files)[:10]:  # Show first 10
        print(f"  - {f}")
    if len(vex_files) > 10:
        print(f"  ... and {len(vex_files) - 10} more")
else:
    print("changes.csv not found!")