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

"""
Red Hat VEX Statistics Analyzer

Analyzes VEX files to generate statistics by RHEL version and severity.
Tracks progress with date-based indexing to allow incremental analysis.
"""

import argparse
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Set
import pickle
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import openpyxl
from openpyxl.styles import Font, PatternFill, Border, Side, Alignment
from openpyxl.worksheet.table import Table, TableStyleInfo

# Configuration
STATS_DIR = "stats"
INDEX_FILE = "stats_index.pkl"
OUTPUT_EXCEL = "vex_statistics_{date}.xlsx"
OUTPUT_SUMMARY = "vex_summary_{date}.txt"
MAX_WORKERS = 10  # Number of concurrent workers for file analysis

# RHEL version patterns
RHEL_PATTERNS = {
    'EL6': r'el6|rhel6|redhat.*6|rhel.*6',
    'EL7': r'el7|rhel7|redhat.*7|rhel.*7', 
    'EL8': r'el8|rhel8|redhat.*8|rhel.*8|rhel8\.\d+',
    'EL9': r'el9|rhel9|redhat.*9|rhel.*9|rhel9\.\d+',
    'EL10': r'el10|rhel10|redhat.*10|rhel.*10',
}

# Severity levels
SEVERITY_LEVELS = ['Critical', 'Important', 'Moderate', 'Low', 'Unknown']

# Status types
STATUS_TYPES = ['fixed', 'known_affected', 'known_not_affected', 'under_investigation']

def load_index(data_dir: Path = None) -> dict:
    """Load statistics index from file in data directory."""
    if data_dir is None:
        data_dir = Path("data")
    
    index_file = data_dir / INDEX_FILE
    if index_file.exists():
        try:
            with open(index_file, 'rb') as f:
                return pickle.load(f)
        except (EOFError, pickle.PickleError):
            return {}
    return {}

def save_index(index: dict, data_dir: Path = None) -> None:
    """Save statistics index to file in data directory."""
    if data_dir is None:
        data_dir = Path("data")
    
    index_file = data_dir / INDEX_FILE
    index_file.parent.mkdir(parents=True, exist_ok=True)
    with open(index_file, 'wb') as f:
        pickle.dump(index, f)

def get_vex_files(data_dir: Path, start_date: datetime = None) -> List[Path]:
    """Get list of VEX files to process, optionally filtered by date."""
    vex_files = []
    
    # Get all JSON files in data directory
    for year_dir in data_dir.iterdir():
        if year_dir.is_dir():
            for file_path in year_dir.glob("*.json"):
                if file_path.name.endswith('.json'):
                    vex_files.append(file_path)
    
    # Filter by date if specified
    if start_date:
        filtered_files = []
        for file_path in vex_files:
            # Extract date from filename (cve-YYYY-NNNN.json)
            try:
                if file_path.name.startswith('cve-'):
                    year = int(file_path.name.split('-')[1][:4])
                    file_date = datetime(year, 1, 1)
                    if file_date >= start_date:
                        filtered_files.append(file_path)
            except (IndexError, ValueError):
                filtered_files.append(file_path)
        return filtered_files
    
    return vex_files

def extract_rhel_versions(product_name: str) -> Set[str]:
    """Extract RHEL versions from product name."""
    versions = set()
    for version, pattern in RHEL_PATTERNS.items():
        if re.search(pattern, product_name, re.IGNORECASE):
            versions.add(version)
    return versions

def get_severity(vuln_data: dict) -> str:
    """Extract severity from vulnerability data with enhanced detection."""
    # Try different possible locations for severity
    severity = 'Unknown'
    
    # First check: baseSeverity field (most reliable)
    if 'baseSeverity' in vuln_data:
        base_severity = vuln_data['baseSeverity']
        if base_severity:
            return base_severity.capitalize()
    
    # Second check: baseSeverity in CVSS metrics (very common location)
    if 'metrics' in vuln_data:
        for metric in vuln_data['metrics']:
            # Check CVSS v3
            if 'cvss_v3' in metric:
                cvss_data = metric['cvss_v3']
                # Check baseSeverity in CVSS structure first
                if 'baseSeverity' in cvss_data:
                    cvss_severity = cvss_data['baseSeverity']
                    if cvss_severity:
                        return cvss_severity.capitalize()
                # Fallback to baseScore calculation for v3
                elif 'baseScore' in cvss_data:
                    score = cvss_data['baseScore']
                    if score >= 9.0:
                        return 'Critical'
                    elif score >= 7.0:
                        return 'Important'
                    elif score >= 4.0:
                        return 'Moderate'
                    elif score > 0:
                        return 'Low'
            
            # Check CVSS v2
            elif 'cvss_v2' in metric:
                cvss_data = metric['cvss_v2']
                # Check baseSeverity in CVSS v2 structure
                if 'baseSeverity' in cvss_data:
                    cvss_severity = cvss_data['baseSeverity']
                    if cvss_severity:
                        return cvss_severity.capitalize()
                # Fallback to baseScore calculation for v2 (different scale!)
                elif 'baseScore' in cvss_data:
                    score = cvss_data['baseScore']
                    if score >= 7.0:  # CVSS v2: 7.0-10.0 = High
                        return 'Important'  # Map High to Important
                    elif score >= 4.0:  # CVSS v2: 4.0-6.9 = Medium
                        return 'Moderate'   # Map Medium to Moderate
                    elif score > 0:     # CVSS v2: 0.1-3.9 = Low
                        return 'Low'
    
    # Third check: severity in product_status
    if 'product_status' in vuln_data:
        for status in vuln_data['product_status'].values():
            if isinstance(status, list):
                for item in status:
                    if isinstance(item, dict) and 'severity' in item:
                        return item['severity'].capitalize() if item['severity'] else 'Unknown'
    
    return severity

def analyze_vex_file(file_path: str, stats: dict) -> None:
    """Analyze a single VEX file and update statistics."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Get vulnerabilities
        vulnerabilities = data.get('vulnerabilities', [])
        
        for vuln in vulnerabilities:
            # Get severity
            severity = get_severity(vuln)
            if severity not in SEVERITY_LEVELS:
                severity = 'Unknown'
            
            # Get product status
            product_status = vuln.get('product_status', {})
            
            # Analyze each status type
            for status_type in STATUS_TYPES:
                products = product_status.get(status_type, [])
                
                for product in products:
                    # Extract RHEL versions
                    rhel_versions = extract_rhel_versions(product)
                    
                    # Update statistics
                    for version in rhel_versions:
                        if version not in stats:
                            stats[version] = {}
                        if severity not in stats[version]:
                            stats[version][severity] = {}
                        if status_type not in stats[version][severity]:
                            stats[version][severity][status_type] = 0
                        stats[version][severity][status_type] += 1
                        
                        # Also track total count
                        if 'total' not in stats[version][severity]:
                            stats[version][severity]['total'] = 0
                        stats[version][severity]['total'] += 1
                        
                        # Track overall totals
                        if 'overall' not in stats[version]:
                            stats[version]['overall'] = {}
                        if status_type not in stats[version]['overall']:
                            stats[version]['overall'][status_type] = 0
                        stats[version]['overall'][status_type] += 1
                        
                        if 'total' not in stats[version]['overall']:
                            stats[version]['overall']['total'] = 0
                        stats[version]['overall']['total'] += 1
    
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error processing {file_path}: {e}")

def create_excel_report(stats: dict, start_date: datetime = None) -> None:
    """Create Excel report with separate sheets for each RHEL version."""
    # Create stats directory
    Path(STATS_DIR).mkdir(parents=True, exist_ok=True)
    
    # Generate date string
    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    if start_date:
        date_str = f"{start_date.strftime('%Y%m%d')}_{datetime.now().strftime('%H%M%S')}"
    
    # Create Excel file path
    excel_file = Path(STATS_DIR) / OUTPUT_EXCEL.format(date=date_str)
    
    # Create Excel workbook and worksheet
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "VEX Statistics"
    
    # Write header
    header = ['RHEL Version', 'Severity', 'Status Type', 'Count']
    ws.append(header)
    
    # Write data
    for version in sorted(stats.keys()):
        for severity in sorted(stats[version].keys()):
            if severity == 'overall':
                continue
            for status_type in sorted(stats[version][severity].keys()):
                if status_type == 'total':
                    continue
                count = stats[version][severity][status_type]
                ws.append([version, severity, status_type, count])
    
    # Save Excel file
    wb.save(excel_file)
    
    # Save summary
    summary_file = Path(STATS_DIR) / OUTPUT_SUMMARY.format(date=date_str)
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write("Red Hat VEX Statistics Summary\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Data Range: {start_date.strftime('%Y-%m-%d') if start_date else 'All available'}\n\n")
        
        for version in sorted(stats.keys()):
            f.write(f"\n=== {version} Statistics ===\n")
            f.write(f"Total CVEs: {stats[version]['overall']['total']}\n\n")
            
            # Overall status distribution
            f.write("Status Distribution:\n")
            for status_type in STATUS_TYPES:
                count = stats[version]['overall'].get(status_type, 0)
                percentage = (count / stats[version]['overall']['total'] * 100) if stats[version]['overall']['total'] > 0 else 0
                f.write(f"  {status_type}: {count} ({percentage:.1f}%)\n")
            
            f.write("\nBy Severity:\n")
            
            # Show all severity levels, including those with 0 count
            for severity in SEVERITY_LEVELS:
                count = stats[version][severity]['total'] if (severity in stats[version] and 'total' in stats[version][severity]) else 0
                percentage = (count / stats[version]['overall']['total'] * 100) if stats[version]['overall']['total'] > 0 else 0
                f.write(f"  {severity}: {count} ({percentage:.1f}%)\n")
                
                # Detailed status for this severity
                for status_type in STATUS_TYPES:
                    status_count = stats[version][severity][status_type] if (severity in stats[version] and status_type in stats[version][severity]) else 0
                    status_percentage = (status_count / count * 100) if count > 0 else 0
                    f.write(f"    - {status_type}: {status_count} ({status_percentage:.1f}%)\n")
            
            # Add under_investigation if present in overall stats
            if 'under_investigation' in stats[version]['overall']:
                ui_count = stats[version]['overall']['under_investigation']
                ui_percentage = (ui_count / stats[version]['overall']['total'] * 100) if stats[version]['overall']['total'] > 0 else 0
                f.write(f"  Under_Investigation: {ui_count} ({ui_percentage:.1f}%)\n")
    
    print(f"Excel report generated: {excel_file}")

def main():
    parser = argparse.ArgumentParser(
        description="Red Hat VEX Statistics Analyzer - Generate statistics by RHEL version and severity"
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default="data",
        help="Directory containing VEX files (default: data)"
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from last run using saved index"
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset index and start fresh"
    )
    parser.add_argument(
        "--start-date",
        type=str,
        help="Start date for analysis (YYYY-MM-DD)"
    )
    
    args = parser.parse_args()
    
    # Load or reset index
    if args.reset:
        index = {}
        print("⚠️  Index reset - starting fresh analysis")
    else:
        index = load_index()
        if index and args.resume:
            print(f"📖 Resuming from previous run (last processed: {index.get('last_run', 'unknown')})")
        else:
            print("🆕 Starting new analysis")
    
    # Convert start date
    start_date = None
    if args.start_date:
        try:
            start_date = datetime.strptime(args.start_date, "%Y-%m-%d")
            print(f"📅 Analyzing files from {start_date.date()} onwards")
        except ValueError:
            print("❌ Invalid date format. Use YYYY-MM-DD")
            return
    
    # Get VEX files
    data_dir = Path(args.data_dir)
    if not data_dir.exists():
        print(f"❌ Data directory not found: {data_dir}")
        return
    
    vex_files = get_vex_files(data_dir, start_date)
    print(f"📊 Found {len(vex_files)} VEX files to analyze")
    
    if not vex_files:
        print("⚠️  No VEX files found to analyze")
        return
    
    # Initialize statistics
    stats = {}
    
    # Analyze files with multithreading
    print("🔍 Analyzing VEX files with multithreading...")
    
    # Use thread pool for parallel analysis
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(analyze_vex_file, str(file_path), stats): file_path
            for file_path in vex_files
        }
        
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % 100 == 0:
                print(f"  Processed {completed}/{len(vex_files)} files...")
    
    # Update index
    index['last_run'] = datetime.now().isoformat()
    index['file_count'] = len(vex_files)
    index['analysis_date'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Save index to data directory
    save_index(index, data_dir)
    
    # Save statistics as Excel
    create_excel_report(stats, start_date)
    
    # Print summary
    print("\n📈 Analysis Complete!")
    print(f"  Files analyzed: {len(vex_files)}")
    print(f"  RHEL versions found: {len(stats)}")
    
    for version in sorted(stats.keys()):
        total = stats[version]['overall']['total']
        print(f"  {version}: {total} CVEs")
    
    print(f"\n💾 Results saved in {STATS_DIR}/ directory")
    print("  Use --resume to continue from this point in future runs")

if __name__ == "__main__":
    main()