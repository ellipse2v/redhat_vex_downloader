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

#!/usr/bin/env python3
"""
Red Hat VEX file downloader with archive management and multi-threading.
Downloads VEX files for specified date ranges from Red Hat security data.
"""

import argparse
import configparser
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

# Default configuration
DEFAULT_CONFIG = {
    'base_url': 'https://security.access.redhat.com/data/csaf/v2/vex/',
    'changes_csv': 'changes.csv',
    'archive_latest': 'archive_latest.txt',
    'data_dir': 'data',
    'out_dir': 'out',
    'max_workers': 20,
    'regex_pattern': '',
    'http_proxy': '',
    'https_proxy': ''
}

def load_config(config_file: str = 'config.ini') -> dict:
    """Load configuration from file, falling back to defaults."""
    config = DEFAULT_CONFIG.copy()
    
    if not os.path.exists(config_file):
        print(f"Config file {config_file} not found, using defaults")
        return config
    
    try:
        parser = configparser.ConfigParser()
        parser.read(config_file)
        
        # Network section
        if parser.has_section('Network'):
            if parser.has_option('Network', 'http_proxy'):
                config['http_proxy'] = parser.get('Network', 'http_proxy')
            if parser.has_option('Network', 'https_proxy'):
                config['https_proxy'] = parser.get('Network', 'https_proxy')
        
        # Filter section
        if parser.has_section('Filter'):
            if parser.has_option('Filter', 'regex_pattern'):
                config['regex_pattern'] = parser.get('Filter', 'regex_pattern')
        
        # Performance section
        if parser.has_section('Performance'):
            if parser.has_option('Performance', 'max_workers'):
                config['max_workers'] = parser.getint('Performance', 'max_workers')
        
        # Directories section
        if parser.has_section('Directories'):
            if parser.has_option('Directories', 'data_dir'):
                config['data_dir'] = parser.get('Directories', 'data_dir')
            if parser.has_option('Directories', 'out_dir'):
                config['out_dir'] = parser.get('Directories', 'out_dir')
        
        # Files section
        if parser.has_section('Files'):
            if parser.has_option('Files', 'base_url'):
                config['base_url'] = parser.get('Files', 'base_url')
            if parser.has_option('Files', 'changes_csv'):
                config['changes_csv'] = parser.get('Files', 'changes_csv')
            if parser.has_option('Files', 'archive_latest'):
                config['archive_latest'] = parser.get('Files', 'archive_latest')
                
    except Exception as e:
        print(f"Error reading config file: {e}")
        print("Using default configuration")
    
    return config


def setup_proxy(http_proxy: str = '', https_proxy: str = '') -> None:
    """Configure proxy settings for urllib."""
    proxy_config = {}
    
    if http_proxy:
        proxy_config['http'] = http_proxy
    if https_proxy:
        proxy_config['https'] = https_proxy
    
    if proxy_config:
        proxy_handler = urllib.request.ProxyHandler(proxy_config)
        opener = urllib.request.build_opener(proxy_handler)
        urllib.request.install_opener(opener)
        print(f"Configured proxy: {proxy_config}")

def download_file(url: str, dest: Path, timeout: int = 30) -> bool:
    """Download a file from URL to destination with timeout."""
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        
        # Use urlopen with timeout instead of urlretrieve for better control
        with urllib.request.urlopen(url, timeout=timeout) as response:
            with open(dest, 'wb') as f:
                f.write(response.read())
        
        return True
    except urllib.error.URLError as e:
        print(f"Error downloading {url}: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error downloading {url}: {e}")
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


def download_vex_file(vex_filename: str, out_dir: Path, data_dir: Path, base_url: str = None) -> Tuple[str, bool]:
    """Download a single VEX file and save to both out and data directories."""
    if base_url is None:
        base_url = DEFAULT_CONFIG['base_url']
    
    # Determine year from filename (format: cve-YYYY-NNNN.json or rhsa-YYYY-NNNN.json)
    try:
        # Extract year from filename - handles both cve-YYYY-NNNN and rhsa-YYYY-NNNN formats
        if vex_filename.startswith('cve-'):
            year = vex_filename.split('-')[1][:4]
        elif vex_filename.startswith('rhsa-'):
            year = vex_filename.split('-')[1].split('_')[0][:4]
        else:
            year = datetime.now().year
    except IndexError:
        year = datetime.now().year
    
    # Construct URL with year path
    url = f"{base_url.rstrip('/')}/{year}/{vex_filename}"
    
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


def check_vex_matches_regex(vex_path: Path, regex_pattern: str) -> bool:
    """Check if VEX file contains products matching regex in known_affected or fixed."""
    try:
        with open(vex_path, 'r') as f:
            data = json.load(f)
        
        pattern = re.compile(regex_pattern, re.IGNORECASE)
        
        # Check vulnerabilities
        vulnerabilities = data.get('vulnerabilities', [])
        
        for vuln in vulnerabilities:
            # Check known_affected
            known_affected = vuln.get('product_status', {}).get('known_affected', [])
            for product in known_affected:
                if pattern.search(product):
                    return True
            
            # Check fixed
            fixed = vuln.get('product_status', {}).get('fixed', [])
            for product in fixed:
                if pattern.search(product):
                    return True
        
        return False
        
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error reading {vex_path}: {e}")
        return False


def check_and_filter_vex(vex_file: Path, regex_pattern: str) -> Tuple[str, bool]:
    """Check if VEX file matches regex and return result."""
    matches = check_vex_matches_regex(vex_file, regex_pattern)
    return vex_file.name, matches


def filter_vex_files_by_regex(out_dir: Path, regex_pattern: str, max_workers: int = 20) -> None:
    """Filter VEX files by regex with multi-threading, removing non-matching files and logging."""
    print(f"\nFiltering files with regex: {regex_pattern}")
    
    vex_files = list(out_dir.glob("*.json"))
    
    if not vex_files:
        print("No VEX files to filter")
        return
    
    kept_files = []
    removed_files = []
    
    # Process files with thread pool
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(check_and_filter_vex, vex_file, regex_pattern): vex_file
            for vex_file in vex_files
        }
        
        for future in as_completed(futures):
            vex_file = futures[future]
            filename, matches = future.result()
            
            if matches:
                kept_files.append(filename)
                print(f"KEEP: {filename} - matches regex")
            else:
                removed_files.append(filename)
                print(f"REMOVE: {filename} - no match")
                vex_file.unlink()
    
    print(f"\nFiltering complete:")
    print(f"  Kept: {len(kept_files)} files")
    print(f"  Removed: {len(removed_files)} files")


def process_vex_files(vex_files: Set[str], data_dir: Path, out_dir: Path, limit: int = None, max_workers: int = 20, base_url: str = None) -> None:
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
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(download_vex_file, vex_file, out_dir, data_dir, base_url): vex_file
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
        "--regex",
        type=str,
        default="",
        help="Regex pattern to filter VEX files by product names in known_affected or fixed"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of files to process (for testing)"
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config.ini",
        help="Configuration file to use (default: config.ini)"
    )
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    
    # Setup proxy if configured
    setup_proxy(config['http_proxy'], config['https_proxy'])
    
    # Use regex from config if not provided in arguments
    if not args.regex and config['regex_pattern']:
        args.regex = config['regex_pattern']
        print(f"Using regex pattern from config: {args.regex}")
    
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
    data_dir = Path(config['data_dir'])
    out_dir = Path(config['out_dir'])
    
    # Download changes.csv
    changes_path = Path(config['changes_csv'])
    print("Downloading changes.csv...")
    download_file(config['base_url'] + config['changes_csv'], changes_path)
    
    # Download archive_latest.txt
    archive_latest_path = Path(config['archive_latest'])
    print("Downloading archive_latest.txt...")
    download_file(config['base_url'] + config['archive_latest'], archive_latest_path)
    
    # Read latest archive name
    with open(archive_latest_path, 'r') as f:
        latest_archive_name = f.read().strip()
    
    archive_path = Path(latest_archive_name)
    
    # Check if we need to download archive
    need_download = True
    
    if data_dir.exists():
        existing_archives = list(data_dir.glob("csaf_vex_*.tar.zst"))
        if existing_archives:
            existing_archive = existing_archives[0]
            existing_date = get_archive_date(existing_archive)
            latest_date = get_archive_date(archive_path)
            
            if existing_date >= latest_date:
                need_download = False
                archive_path = existing_archive
    else:
        data_dir.mkdir(parents=True, exist_ok=True)
    
    # Download and extract archive if needed
    if need_download:
        print(f"Downloading archive: {latest_archive_name}...")
        download_file(BASE_URL + latest_archive_name, data_dir / latest_archive_name)
        archive_path = data_dir / latest_archive_name
        extract_archive(archive_path, data_dir)
    else:
        print("Using existing archive")
        # Make sure it's extracted
        if not any(data_dir.iterdir()):
            extract_archive(archive_path, data_dir)
    
    # Parse changes.csv for date range
    print("Parsing changes.csv...")
    vex_files = parse_changes_csv(changes_path, start_date, end_date)
    
    print(f"Found {len(vex_files)} VEX files in date range")
    
    # Process VEX files
    process_vex_files(vex_files, data_dir, out_dir, args.limit, config['max_workers'], config['base_url'])
    
    # Apply regex filter if specified
    if args.regex:
        filter_vex_files_by_regex(out_dir, args.regex, config['max_workers'])
    
    print(f"\nComplete! VEX files saved to {out_dir}/")


if __name__ == "__main__":
    main()
