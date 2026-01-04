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
Unit tests for vex_statistics.py
Verifies that main functions work correctly
"""

import unittest
import json
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
import sys
import os

# Add current path to import module
sys.path.insert(0, '/mnt/d/dev/github/redhat_vex_downloader')

from vex_statistics import (
    extract_rhel_versions,
    get_severity,
    analyze_vex_file,
    create_excel_report,
    load_index,
    save_index
)

class TestVexStatistics(unittest.TestCase):
    """Test suite for vex_statistics functions"""
    
    def setUp(self):
        """Setup test environment"""
        self.test_dir = Path(tempfile.mkdtemp())
        self.test_data_dir = self.test_dir / "test_data"
        self.test_data_dir.mkdir()
        
        # Create a sample VEX file for testing
        self.sample_vex = {
            "cve": "CVE-2024-TEST",
            "vulnerabilities": [
                {
                    "baseSeverity": "Critical",
                    "product_status": {
                        "fixed": ["rhel8", "rhel9"],
                        "known_not_affected": ["rhel6", "rhel7"],
                        "under_investigation": ["rhel10"]
                    }
                },
                {
                    "baseSeverity": "Important", 
                    "product_status": {
                        "known_affected": ["rhel8-server", "rhel9-workstation"]
                    }
                }
            ]
        }
        
        self.vex_file = self.test_data_dir / "cve-2024-test.json"
        with open(self.vex_file, 'w') as f:
            json.dump(self.sample_vex, f)
    
    def tearDown(self):
        """Cleanup test environment"""
        shutil.rmtree(self.test_dir)
    
    def test_extract_rhel_versions(self):
        """Test RHEL version extraction"""
        # Test various product names
        test_cases = [
            ("rhel8", {"EL8"}),
            ("rhel9-server", {"EL9"}),
            ("redhat-enterprise-linux-7", {"EL7"}),
            ("rhel6-workstation", {"EL6"}),
            ("rhel10-beta", {"EL10"}),
            ("fedora-38", set()),  # Not a RHEL product
            ("unknown-product", set()),
        ]
        
        for product_name, expected_versions in test_cases:
            result = extract_rhel_versions(product_name)
            self.assertEqual(result, expected_versions, 
                           f"Failed for {product_name}: expected {expected_versions}, got {result}")
    
    def test_get_severity(self):
        """Test severity extraction"""
        # Test with baseSeverity
        vuln_with_severity = {"baseSeverity": "critical"}
        self.assertEqual(get_severity(vuln_with_severity), "Critical")
        
        # Test with product_status severity
        vuln_with_product_severity = {
            "product_status": {
                "fixed": [{"severity": "important"}]
            }
        }
        self.assertEqual(get_severity(vuln_with_product_severity), "Important")
        
        # Test with CVSS metrics
        vuln_with_cvss = {
            "metrics": [
                {
                    "cvss_v3": {
                        "baseScore": 8.5
                    }
                }
            ]
        }
        self.assertEqual(get_severity(vuln_with_cvss), "Important")  # 8.5 -> Important
        
        # Test unknown severity
        empty_vuln = {}
        self.assertEqual(get_severity(empty_vuln), "Unknown")
    
    def test_analyze_vex_file(self):
        """Test VEX file analysis"""
        stats = {}
        analyze_vex_file(str(self.vex_file), stats)
        
        # Verify statistics were collected
        self.assertIn("EL8", stats)
        self.assertIn("EL9", stats)
        self.assertIn("EL6", stats)
        self.assertIn("EL7", stats)
        self.assertIn("EL10", stats)
        
        # Check EL8 statistics
        el8_stats = stats["EL8"]
        self.assertIn("Critical", el8_stats)
        self.assertIn("Important", el8_stats)
        
        # Check Critical severity for EL8
        critical_stats = el8_stats["Critical"]
        self.assertIn("fixed", critical_stats)
        self.assertEqual(critical_stats["fixed"], 1)
        
        # Check Important severity for EL8
        important_stats = el8_stats["Important"]
        self.assertIn("known_affected", important_stats)
        self.assertEqual(important_stats["known_affected"], 1)
    
    def test_create_excel_report(self):
        """Test Excel report creation"""
        # Create test statistics
        test_stats = {
            "EL8": {
                "Critical": {
                    "fixed": 2,
                    "known_affected": 1,
                    "total": 3
                },
                "Important": {
                    "known_not_affected": 1,
                    "total": 1
                },
                "overall": {
                    "fixed": 2,
                    "known_affected": 1,
                    "known_not_affected": 1,
                    "total": 4
                }
            }
        }
        
        # Create Excel report
        create_excel_report(test_stats, datetime(2024, 1, 1))
        
        # Check that files were created
        stats_dir = Path("stats")
        excel_files = list(stats_dir.glob("vex_statistics_*.xlsx"))
        summary_files = list(stats_dir.glob("vex_summary_*.txt"))
        
        self.assertGreater(len(excel_files), 0, "Excel file should be created")
        self.assertGreater(len(summary_files), 0, "Summary file should be created")
        
        # Clean up created files (with error handling for permission issues)
        for file in excel_files + summary_files:
            try:
                file.unlink()
            except (PermissionError, FileNotFoundError):
                # Skip files that can't be deleted or don't exist
                pass
    
    def test_index_functions(self):
        """Test index load/save functions"""
        test_index = {
            "last_run": "2024-01-01T12:00:00",
            "file_count": 100,
            "analysis_date": "2024-01-01 12:00:00"
        }
        
        # Save index
        save_index(test_index, self.test_data_dir)
        index_file = self.test_data_dir / "stats_index.pkl"
        self.assertTrue(index_file.exists())
        
        # Load index
        loaded_index = load_index(self.test_data_dir)
        self.assertEqual(loaded_index, test_index)

if __name__ == "__main__":
    unittest.main(verbosity=2)