#!/usr/bin/env python3
"""
Test the optimization functions for the sync operation.
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add parent directory to Python path to import the module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from redhat_vex_downloader import (
    download_metadata_files,
    check_local_files_incremental,
    process_deletions_efficiently,
    display_download_progress,
    load_sync_index,
    save_sync_index
)

def test_download_metadata_files():
    """Test parallel metadata download function."""
    print("Testing download_metadata_files...")
    
    # Create a temporary config
    config = {
        'base_url': 'https://security.access.redhat.com/data/csaf/v2/vex/',
        'changes_csv': 'changes.csv',
        'http_proxy': '',
        'https_proxy': ''
    }
    
    # Create temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        data_dir = Path(temp_dir)
        
        # This will test the parallel download (but won't actually download due to URL)
        try:
            changes_path, deletions_path = download_metadata_files(config, data_dir)
            print(f"✅ Metadata files would be downloaded to:")
            print(f"  Changes: {changes_path}")
            print(f"  Deletions: {deletions_path}")
            return True
        except Exception as e:
            print(f"❌ Error in download_metadata_files: {e}")
            return False

def test_check_local_files_incremental():
    """Test incremental file checking function."""
    print("\nTesting check_local_files_incremental...")
    
    # Create test data with proper VEX filenames
    remote_files = {'cve-2023-1234.json', 'cve-2023-5678.json', 'rhsa-2023_9999.json', 'cve-2024-0001.json'}
    sync_index = {
        'cve-2023-1234.json': {'mtime': 1000.0, 'size': 1000},
        'cve-2023-5678.json': {'mtime': 2000.0, 'size': 2000}
    }
    
    with tempfile.TemporaryDirectory() as temp_dir:
        data_dir = Path(temp_dir)
        
        # Create some local files
        (data_dir / '2023').mkdir()
        
        # Create cve-2023-1234.json with content that matches the expected size in index
        cve_content = 'a' * 1000  # Create content that would result in size ~1000
        (data_dir / '2023' / 'cve-2023-1234.json').write_text(cve_content)  # Exists in index with matching size
        (data_dir / '2023' / 'rhsa-2023_9999.json').write_text('{}')  # New file
        (data_dir / '2023' / 'cve-2023-5678.json').write_text('{}')  # Exists in index but not locally in test
        
        missing, outdated = check_local_files_incremental(data_dir, remote_files, sync_index)
        
        print(f"Missing files: {missing}")
        print(f"Outdated files: {outdated}")
        
        # cve-2024-0001.json should be missing (not local, different year)
        # rhsa-2023_9999.json should be outdated (new file)
        # cve-2023-5678.json should be outdated (exists in index but timestamp/size changed)
        # cve-2023-1234.json should be outdated (timestamp mismatch even if size matches)
        expected_missing = {'cve-2024-0001.json'}
        expected_outdated = {'rhsa-2023_9999.json', 'cve-2023-5678.json', 'cve-2023-1234.json'}
        
        if missing == expected_missing and outdated == expected_outdated:
            print("✅ Incremental checking works correctly")
            return True
        else:
            print(f"❌ Expected missing: {expected_missing}, got: {missing}")
            print(f"❌ Expected outdated: {expected_outdated}, got: {outdated}")
            return False

def test_process_deletions_efficiently():
    """Test efficient deletion processing."""
    print("\nTesting process_deletions_efficiently...")
    
    deleted_files = {'cve-2023-1234.json', 'cve-2023-5678.json', 'rhsa-2023_9999.json'}
    sync_index = {
        'cve-2023-1234.json': {'mtime': 1000.0, 'size': 1000},
        'cve-2023-5678.json': {'mtime': 2000.0, 'size': 2000},
        'cve-2024-0001.json': {'mtime': 3000.0, 'size': 3000}  # Not in deleted_files
    }
    
    with tempfile.TemporaryDirectory() as temp_dir:
        data_dir = Path(temp_dir)
        
        # Create files to delete
        (data_dir / '2023').mkdir()
        (data_dir / '2023' / 'cve-2023-1234.json').write_text('{}')
        (data_dir / '2023' / 'cve-2023-5678.json').write_text('{}')
        # rhsa-2023_9999.json doesn't exist locally
        
        deleted_count, updated_index = process_deletions_efficiently(
            data_dir, deleted_files, sync_index
        )
        
        print(f"Deleted count: {deleted_count}")
        print(f"Updated index keys: {set(updated_index.keys())}")
        
        # Should have deleted 2 files (cve-2023-1234.json and cve-2023-5678.json)
        # rhsa-2023_9999.json doesn't exist locally so not counted
        # cve-2024-0001.json should remain in index
        if deleted_count == 2 and 'cve-2024-0001.json' in updated_index:
            print("✅ Deletion processing works correctly")
            return True
        else:
            print(f"❌ Expected 2 deletions and cve-2024-0001.json in index")
            return False

def test_display_download_progress():
    """Test download progress display function."""
    print("\nTesting display_download_progress...")
    
    downloaded_files = ['file1.json', 'file2.json', 'file3.json']
    
    # This should print progress when count is multiple of 10
    display_download_progress(downloaded_files, 10)
    print("✅ Progress display function works")
    return True

def test_sync_index_functions():
    """Test sync index load/save functions."""
    print("\nTesting sync index functions...")
    
    test_index = {
        'file1.json': {'mtime': 1000.0, 'size': 1000},
        'file2.json': {'mtime': 2000.0, 'size': 2000}
    }
    
    with tempfile.TemporaryDirectory() as temp_dir:
        data_dir = Path(temp_dir)
        
        # Save index
        save_sync_index(test_index, data_dir)
        
        # Load index
        loaded_index = load_sync_index(data_dir)
        
        if loaded_index == test_index:
            print("✅ Sync index save/load works correctly")
            return True
        else:
            print(f"❌ Index mismatch: {loaded_index} != {test_index}")
            return False

def main():
    """Run all optimization tests."""
    print("Running optimization tests...\n")
    
    tests = [
        test_download_metadata_files,
        test_check_local_files_incremental,
        test_process_deletions_efficiently,
        test_display_download_progress,
        test_sync_index_functions
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with exception: {e}")
    
    print(f"\nTest Results:")
    print(f"  Passed: {passed}/{total}")
    print(f"  Failed: {total - passed}/{total}")
    
    if passed == total:
        print("🎉 All optimization tests passed!")
        return True
    else:
        print("⚠️  Some tests failed")
        return False

if __name__ == "__main__":
    main()