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

"""Test version of downloader with optimizations and debugging."""

import argparse
import csv
import json
import os
import re
import tarfile
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Set, Tuple

BASE_URL = "https://security.access.redhat.com/data/csaf/v2/vex/"
CHANGES_CSV = "changes.csv"
ARCHIVE_LATEST = "archive_latest.txt"
DATA_DIR = "data"
OUT_DIR = "out"
MAX_WORKERS = 5  # Reduced for testing

def download_file(url: str, dest: Path) -> bool:
    """Download a file from URL to destination."""
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(url, dest)
        return True
    except urllib.error.URLError as e:
        print(f"Error downloading {url}: {e}")
        return False

def get_archive_date(archive_path: Path) -> datetime:
    """Extract date from archive filename."""
    name = archive_path.stem.replace(".tar", "")
    date_str = name.split("_")[-1]
    return datetime.strptime(date_str, "%Y-%m-%d")

def parse_changes_csv(csv_path: Path, start_date: datetime, end_date: datetime) -> Set[str]:
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
                except (ValueError, IndexError):
                    continue
    
    return vex_files

def extract_archive(archive_path: Path, extract_dir: Path) -> None:
    """Extract tar.zst archive using Python."""
    import zstandard as zstd
    
    print(f"Extracting {archive_path}...")
    
    # Decompress zstd and extract tar
    dctx = zstd.ZstdDecompressor()
    
    with open(archive_path, 'rb') as compressed:
        with dctx.stream_reader(compressed) as reader:
            with tarfile.open(fileobj=reader, mode='r|') as tar:
                tar.extractall(path=extract_dir)

def find_vex_in_archive(extract_dir: Path, vex_filename: str) -> Path:
    """Find VEX file in extracted archive."""
    # VEX files are organized by year
    for year_dir in extract_dir.iterdir():
        if year_dir.is_dir():
            vex_path = year_dir / vex_filename
            if vex_path.exists():
                return vex_path
    return None

def download_vex_file(vex_filename: str, out_dir: Path, data_dir: Path) -> Tuple[str, bool]:
    """Download a single VEX file and save to both out and data directories."""
    url = BASE_URL + vex_filename
    
    # Determine year from filename (format: rhsa-YYYY-NNNN.json)
    try:
        year = vex_filename.split("-")[1].split("_")[0][:4]
    except IndexError:
        year = datetime.now().year
    
    # Save to output directory
    out_path = out_dir / vex_filename
    
    # Save to data directory with year structure
    data_year_dir = data_dir / str(year)
    data_path = data_year_dir / vex_filename
    
    success = download_file(url, out_path)
    
    if success:
        # Copy to data directory structure
        data_year_dir.mkdir(parents=True, exist_ok=True)
        if not data_path.exists():
            import shutil
            shutil.copy2(out_path, data_path)
    
    return vex_filename, success

def process_vex_files(vex_files: Set[str], data_dir: Path, out_dir: Path, limit: int = None) -> None:
    """Process VEX files with multi-threading."""
    out_dir.mkdir(parents=True, exist_ok=True)
    
    files_to_download = []
    
    # Limit number of files for testing
    if limit:
        vex_files = list(vex_files)[:limit]
        print(f"Limiting to {limit} files for testing")
    
    # Check which files exist in archive
    for i, vex_file in enumerate(vex_files):
        if i % 100 == 0:
            print(f"Processing file {i+1}/{len(vex_files)}: {vex_file}")
            
        vex_path = find_vex_in_archive(data_dir, vex_file)
        if vex_path and vex_path.exists():
            # Copy from archive to output
            import shutil
            shutil.copy2(vex_path, out_dir / vex_file)
            print(f"Copied from archive: {vex_file}")
        else:
            files_to_download.append(vex_file)
    
    if not files_to_download:
        print("All files found in archive!")
        return
    
    print(f"Downloading {len(files_to_download)} missing files...")
    
    # Download missing files with thread pool
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(download_vex_file, vex_file, out_dir, data_dir): vex_file
            for vex_file in files_to_download
        }
        
        for future in as_completed(futures):
            vex_file, success = future.result()
            if success:
                print(f"Downloaded: {vex_file}")
            else:
                print(f"Failed: {vex_file}")

def main():
    parser = argparse.ArgumentParser(
        description="Download Red Hat VEX files for specified date range"
    )
    parser.add_argument(
        "--start-date",
        type=str,
        help="Start date (YYYY-MM-DD)"
    )
    parser.add_argument(
        "--end-date",
        type=str,
        help="End date (YYYY-MM-DD), defaults to today if not specified"
    )
    parser.add_argument(
        "--days",
        type=int,
        help="Number of last N days to download (alternative to date range)"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of files to process (for testing)"
    )
    
    args = parser.parse_args()
    
    # Determine date range
    if args.days:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=args.days)
        print(f"Using last {args.days} days")
    elif args.start_date:
        start_date = datetime.strptime(args.start_date, "%Y-%m-%d")
        end_date = datetime.strptime(args.end_date, "%Y-%m-%d") if args.end_date else datetime.now()
    else:
        parser.error("Must specify either --days or --start-date")
    
    print(f"Date range: {start_date.date()} to {end_date.date()}")
    
    # Setup directories
    data_dir = Path(DATA_DIR)
    out_dir = Path(OUT_DIR)
    
    # Parse changes.csv for date range
    print("Parsing changes.csv...")
    changes_path = Path(CHANGES_CSV)
    vex_files = parse_changes_csv(changes_path, start_date, end_date)
    
    print(f"Found {len(vex_files)} VEX files in date range")
    
    # Process VEX files
    process_vex_files(vex_files, data_dir, out_dir, args.limit)
    
    print(f"\nComplete! VEX files saved to {out_dir}/")

if __name__ == "__main__":
    main()