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

from vex_statistics import VEXAnalyzer, StatsIndex, ReportGenerator, VulnerabilityStats

class TestVexStatistics(unittest.TestCase):
    """Test suite for vex_statistics functions"""
    
    def setUp(self):
        """Setup test environment"""
        self.test_dir = Path(tempfile.mkdtemp())
        self.test_data_dir = self.test_dir / "test_data"
        self.test_data_dir.mkdir()
        self.analyzer = VEXAnalyzer(self.test_data_dir)
        
        # Create a sample VEX file for testing
        self.sample_vex = {
            "cve": "CVE-2024-TEST",
            "document": {
                "aggregate_severity": {
                    "text": "critical"
                }
            },
            "vulnerabilities": [
                {
                    "product_status": {
                        "fixed": ["rhel8", "rhel9"],
                        "known_not_affected": ["rhel6", "rhel7"],
                        "under_investigation": ["rhel10"]
                    }
                },
                {
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
            result = self.analyzer.extract_rhel_versions(product_name)
            self.assertEqual(result, expected_versions, 
                           f"Failed for {product_name}: expected {expected_versions}, got {result}")
    
    def test_get_severity(self):
        """Test severity extraction"""
        # Test with baseSeverity (legacy format)
        vuln_with_severity = {"baseSeverity": "critical"}
        self.assertEqual(self.analyzer.get_severity(vuln_with_severity), "Critical")
        
        # Test with document aggregate_severity (current Red Hat format)
        vuln_with_aggregate_severity = {
            "document": {
                "aggregate_severity": {
                    "text": "important"
                }
            }
        }
        self.assertEqual(self.analyzer.get_severity(vuln_with_aggregate_severity), "Important")
        
        # Test with CVSS v3 scores
        vuln_with_cvss_v3 = {
            "scores": [
                {
                    "cvss_v3": {
                        "baseScore": 8.5
                    }
                }
            ]
        }
        self.assertEqual(self.analyzer.get_severity(vuln_with_cvss_v3), "Important")  # 8.5 -> Important
        
        # Test with CVSS v3 baseSeverity
        vuln_with_cvss_severity = {
            "scores": [
                {
                    "cvss_v3": {
                        "baseSeverity": "critical"
                    }
                }
            ]
        }
        self.assertEqual(self.analyzer.get_severity(vuln_with_cvss_severity), "Critical")
        
        # Test unknown severity
        empty_vuln = {}
        self.assertEqual(self.analyzer.get_severity(empty_vuln), "Unknown")
    
    def test_analyze_vex_file(self):
        """Test VEX file analysis"""
        self.analyzer.analyze_file(self.vex_file)
        
        # Verify statistics were collected
        self.assertIn("EL8", self.analyzer.stats_by_version)
        self.assertIn("EL9", self.analyzer.stats_by_version)
        self.assertIn("EL6", self.analyzer.stats_by_version)
        self.assertIn("EL7", self.analyzer.stats_by_version)
        self.assertIn("EL10", self.analyzer.stats_by_version)
        
        # Check EL8 statistics - all vulnerabilities use the document-level severity
        el8_stats = self.analyzer.stats_by_version["EL8"]
        self.assertIn("Critical", el8_stats.by_severity)
        
        # Check Critical severity for EL8 (combines both vulnerabilities)
        critical_stats = el8_stats.by_severity["Critical"]
        self.assertIn("fixed", critical_stats)
        self.assertIn("known_affected", critical_stats)
        self.assertEqual(critical_stats["fixed"], 1)
        self.assertEqual(critical_stats["known_affected"], 1)
    
    def test_create_excel_report(self):
        """Test Excel report creation"""
        # Create test statistics using the current format
        
        test_stats = {
            "EL8": VulnerabilityStats()
        }
        
        # Add some test data
        test_stats["EL8"].add_entry("Critical", "fixed")
        test_stats["EL8"].add_entry("Critical", "fixed")
        test_stats["EL8"].add_entry("Critical", "known_affected")
        test_stats["EL8"].add_entry("Important", "known_not_affected")
        
        # Create report generator and generate reports
        report_gen = ReportGenerator(test_stats, datetime(2024, 1, 1))
        reports = report_gen.generate_all()
        
        # Check that files were created
        stats_dir = Path("stats")
        excel_files = list(stats_dir.glob("vex_statistics_*.xlsx"))
        summary_files = list(stats_dir.glob("vex_summary_*.txt"))
        csv_files = list(stats_dir.glob("vex_statistics_*.csv"))
        
        self.assertGreater(len(excel_files), 0, "Excel file should be created")
        self.assertGreater(len(summary_files), 0, "Summary file should be created")
        self.assertGreater(len(csv_files), 0, "CSV file should be created")
        
        # Clean up created files (with error handling for permission issues)
        for file in excel_files + summary_files + csv_files:
            try:
                file.unlink()
            except (PermissionError, FileNotFoundError):
                # Skip files that can't be deleted or don't exist
                pass
    
    def test_index_functions(self):
        """Test index load/save functions"""
        # Create stats index
        stats_index = StatsIndex(self.test_data_dir)
        
        # Update with test data
        test_data = {
            "last_run": "2024-01-01T12:00:00",
            "file_count": 100,
            "analysis_date": "2024-01-01 12:00:00"
        }
        stats_index.update(**test_data)
        
        # Save index
        stats_index.save()
        index_file = self.test_data_dir / "stats_index.pkl"
        self.assertTrue(index_file.exists())
        
        # Load index (create new instance to test loading)
        loaded_index = StatsIndex(self.test_data_dir)
        self.assertEqual(loaded_index.data, test_data)

if __name__ == "__main__":
    unittest.main(verbosity=2)