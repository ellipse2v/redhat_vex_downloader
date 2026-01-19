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
Red Hat VEX file downloader with archive management and async operations.
Downloads VEX files for specified date ranges from Red Hat security data.

"""

import argparse
import configparser
import csv
import json
import logging
import os
import re
import tarfile
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Set, Tuple, Dict, Optional
from enum import Enum
import time

try:
    import aiohttp
    import asyncio
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False
    import urllib.request
    import urllib.error

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class DownloadStatus(Enum):
    """Status of download operations."""
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    CACHED = "cached"


@dataclass
class FileMetadata:
    """Metadata for a VEX file."""
    filename: str
    mtime: float
    size: int
    checksum: Optional[str] = None
    downloaded: Optional[str] = None
    
    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DownloadResult:
    """Result of a download operation."""
    filename: str
    status: DownloadStatus
    error: Optional[str] = None
    size: int = 0


@dataclass
class SyncStats:
    """Statistics for synchronization operations."""
    remote_files: int = 0
    missing_files: int = 0
    outdated_files: int = 0
    deleted_files: int = 0
    downloaded: int = 0
    failed: int = 0
    cached: int = 0
    start_time: float = 0
    end_time: float = 0
    last_sync_time: float = 0
    files_processed: int = 0
    
    @property
    def duration(self) -> float:
        return self.end_time - self.start_time if self.end_time > 0 else 0
    
    def print_summary(self):
        """Print formatted statistics."""
        logger.info("=" * 60)
        logger.info("Synchronization Summary")
        logger.info("=" * 60)
        logger.info(f"Remote files: {self.remote_files}")
        logger.info(f"Missing files: {self.missing_files}")
        logger.info(f"Outdated files: {self.outdated_files}")
        logger.info(f"Files to delete: {self.deleted_files}")
        logger.info(f"Successfully downloaded: {self.downloaded}")
        logger.info(f"Failed downloads: {self.failed}")
        logger.info(f"Cached/skipped: {self.cached}")
        logger.info(f"Duration: {self.duration:.2f} seconds")
        if self.downloaded > 0:
            logger.info(f"Average speed: {self.downloaded/self.duration:.2f} files/sec")
        
        # Show optimization statistics
        if self.files_processed > 0 and self.remote_files > 0:
            optimization_ratio = (1 - self.files_processed / self.remote_files) * 100
            logger.info(f"Files processed: {self.files_processed}/{self.remote_files}")
            if optimization_ratio > 10:
                logger.info(f"Optimization: {optimization_ratio:.1f}% fewer files checked")
        
        # Show last sync time if available
        if self.last_sync_time > 0:
            last_sync_date = datetime.fromtimestamp(self.last_sync_time).strftime('%Y-%m-%d %H:%M:%S')
            logger.info(f"Last synchronization: {last_sync_date}")
            
            # Calculate time since last sync
            if self.end_time > self.last_sync_time:
                days_since_sync = (self.end_time - self.last_sync_time) / 86400
                logger.info(f"Time since last sync: {days_since_sync:.1f} days")
        
        logger.info("=" * 60)


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
    'https_proxy': '',
    'max_retries': 3,
    'timeout': 30,
    'use_async': 'auto',
    'verify_checksums': 'true',
    'batch_size': 50,
    'discrepancy_threshold': 50000
}


class ConfigManager:
    """Manages configuration loading and validation."""
    
    def __init__(self, config_file: str = 'config.ini'):
        self.config = DEFAULT_CONFIG.copy()
        self._load_config(config_file)
        self._validate_config()
    
    def _load_config(self, config_file: str):
        """Load configuration from file."""
        if not os.path.exists(config_file):
            logger.warning(f"Config file {config_file} not found, using defaults")
            return
        
        try:
            parser = configparser.ConfigParser()
            parser.read(config_file)
            
            sections = {
                'Network': ['http_proxy', 'https_proxy', 'timeout', 'max_retries'],
                'Filter': ['regex_pattern'],
                'Performance': ['max_workers', 'use_async', 'batch_size'],
                'Directories': ['data_dir', 'out_dir'],
                'Files': ['base_url', 'changes_csv', 'archive_latest'],
                'Options': ['verify_checksums', 'discrepancy_threshold']
            }
            
            for section, options in sections.items():
                if parser.has_section(section):
                    for option in options:
                        if parser.has_option(section, option):
                            value = parser.get(section, option)
                            # Convert numeric values
                            if option in ['max_workers', 'timeout', 'max_retries', 'batch_size']:
                                self.config[option] = int(value)
                            else:
                                self.config[option] = value
        
        except Exception as e:
            logger.error(f"Error reading config file: {e}")
            logger.info("Using default configuration")
    
    def _validate_config(self):
        """Validate configuration values."""
        if self.config['max_workers'] < 1:
            self.config['max_workers'] = 1
        if self.config['max_workers'] > 100:
            logger.warning("max_workers > 100 may cause issues, limiting to 100")
            self.config['max_workers'] = 100
        
        if self.config['timeout'] < 5:
            self.config['timeout'] = 5
        
        if self.config['use_async'] == 'auto':
            self.config['use_async'] = ASYNC_AVAILABLE
        else:
            self.config['use_async'] = self.config['use_async'].lower() == 'true'
    
    def get(self, key: str, default=None):
        """Get configuration value."""
        return self.config.get(key, default)
    
    def __getitem__(self, key: str):
        return self.config[key]


class FileUtils:
    """Utility functions for file operations."""
    
    @staticmethod
    def extract_year_from_filename(filename: str) -> str:
        """Extract year from VEX filename."""
        try:
            if filename.startswith('cve-'):
                return filename.split('-')[1][:4]
            elif filename.startswith('rhsa-'):
                return filename.split('-')[1].split('_')[0][:4]
        except IndexError:
            pass
        return str(datetime.now().year)
    
    @staticmethod
    def calculate_checksum(file_path: Path) -> str:
        """Calculate SHA256 checksum of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating checksum for {file_path}: {e}")
            return ""
    
    @staticmethod
    def get_file_metadata(file_path: Path, calculate_checksum: bool = False) -> Optional[FileMetadata]:
        """Get file metadata including mtime, size, and optionally checksum."""
        try:
            stat = file_path.stat()
            checksum = FileUtils.calculate_checksum(file_path) if calculate_checksum else None
            return FileMetadata(
                filename=file_path.name,
                mtime=stat.st_mtime,
                size=stat.st_size,
                checksum=checksum
            )
        except (OSError, FileNotFoundError) as e:
            logger.debug(f"Could not get metadata for {file_path}: {e}")
            return None


class SyncIndexManager:
    """Manages synchronization index for tracking file states."""
    
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.index_file = data_dir / "sync_index.json"
        self.index: Dict[str, dict] = {}
        self.last_sync_time: float = 0
        self.load()
    
    def load(self) -> Dict[str, dict]:
        """Load synchronization index from file."""
        if self.index_file.exists():
            try:
                with open(self.index_file, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        if 'files' in data:
                            # New format with metadata
                            self.index = data['files']
                            self.last_sync_time = data.get('last_sync_time', 0)
                        else:
                            # Old format - just file entries
                            self.index = data
                        logger.info(f"Loaded sync index with {len(self.index)} entries")
                        if self.last_sync_time > 0:
                            last_sync_date = datetime.fromtimestamp(self.last_sync_time).strftime('%Y-%m-%d %H:%M:%S')
                            logger.info(f"Last synchronization: {last_sync_date}")
                    else:
                        logger.warning("Invalid sync index format")
                        self.index = {}
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Could not load sync index: {e}")
                self.index = {}
        return self.index
    
    def save(self):
        """Save synchronization index to file."""
        try:
            self.index_file.parent.mkdir(parents=True, exist_ok=True)
            # Save with metadata including last sync time
            data = {
                'files': self.index,
                'last_sync_time': self.last_sync_time,
                'format_version': 2
            }
            with open(self.index_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Saved sync index with {len(self.index)} entries")
            if self.last_sync_time > 0:
                last_sync_date = datetime.fromtimestamp(self.last_sync_time).strftime('%Y-%m-%d %H:%M:%S')
                logger.debug(f"Last synchronization recorded: {last_sync_date}")
        except Exception as e:
            logger.error(f"Error saving sync index: {e}")
    
    def update(self, filename: str, metadata: FileMetadata):
        """Update index entry for a file."""
        self.index[filename] = metadata.to_dict()
    
    def update_last_sync_time(self):
        """Update the last synchronization time to now."""
        self.last_sync_time = time.time()
    
    def remove(self, filename: str):
        """Remove entry from index."""
        if filename in self.index:
            del self.index[filename]
    
    def get(self, filename: str) -> Optional[dict]:
        """Get index entry for a file."""
        return self.index.get(filename)
    
    def has(self, filename: str) -> bool:
        """Check if file is in index."""
        return filename in self.index


class Downloader:
    """Handles file downloads with retry logic and progress tracking."""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.setup_proxy()
        self.session = None
    
    def setup_proxy(self):
        """Configure proxy settings."""
        http_proxy = self.config.get('http_proxy', '')
        https_proxy = self.config.get('https_proxy', '')
        
        if not ASYNC_AVAILABLE:
            proxy_config = {}
            if http_proxy:
                proxy_config['http'] = http_proxy
            if https_proxy:
                proxy_config['https'] = https_proxy
            
            if proxy_config:
                proxy_handler = urllib.request.ProxyHandler(proxy_config)
                opener = urllib.request.build_opener(proxy_handler)
                urllib.request.install_opener(opener)
                logger.info(f"Configured proxy: {proxy_config}")
    
    async def download_file_async(self, url: str, dest: Path) -> bool:
        """Download file asynchronously with retry logic."""
        if not ASYNC_AVAILABLE:
            return self.download_file_sync(url, dest)
        
        max_retries = self.config.get('max_retries', 3)
        timeout = self.config.get('timeout', 30)
        
        for attempt in range(max_retries):
            try:
                if self.session is None:
                    timeout_obj = aiohttp.ClientTimeout(total=timeout)
                    self.session = aiohttp.ClientSession(timeout=timeout_obj)
                
                async with self.session.get(url) as response:
                    if response.status == 200:
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        content = await response.read()
                        with open(dest, 'wb') as f:
                            f.write(content)
                        return True
                    else:
                        logger.warning(f"HTTP {response.status} for {url}")
                        
            except asyncio.TimeoutError:
                logger.warning(f"Timeout downloading {url} (attempt {attempt + 1}/{max_retries})")
            except Exception as e:
                logger.warning(f"Error downloading {url} (attempt {attempt + 1}/{max_retries}): {e}")
            
            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        return False
    
    def download_file_sync(self, url: str, dest: Path) -> bool:
        """Download file synchronously with retry logic."""
        max_retries = self.config.get('max_retries', 3)
        timeout = self.config.get('timeout', 30)
        
        for attempt in range(max_retries):
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                
                if ASYNC_AVAILABLE:
                    return False  # Should not reach here
                
                with urllib.request.urlopen(url, timeout=timeout) as response:
                    with open(dest, 'wb') as f:
                        f.write(response.read())
                return True
                
            except urllib.error.URLError as e:
                logger.warning(f"Error downloading {url} (attempt {attempt + 1}/{max_retries}): {e}")
            except Exception as e:
                logger.warning(f"Unexpected error downloading {url} (attempt {attempt + 1}/{max_retries}): {e}")
            
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
        
        return False
    
    async def close(self):
        """Close async session if open."""
        if self.session:
            await self.session.close()
            self.session = None


class VEXDownloader:
    """Main class for downloading and managing VEX files."""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.data_dir = Path(config['data_dir'])
        self.out_dir = Path(config['out_dir'])
        self.sync_index = SyncIndexManager(self.data_dir)
        self.downloader = Downloader(config)
        self.stats = SyncStats()
    
    def download_vex_file(self, vex_filename: str) -> DownloadResult:
        """Download a single VEX file."""
        year = FileUtils.extract_year_from_filename(vex_filename)
        url = f"{self.config['base_url'].rstrip('/')}/{year}/{vex_filename}"
        
        out_path = self.out_dir / vex_filename
        data_year_dir = self.data_dir / year
        data_path = data_year_dir / vex_filename
        
        # Check if file exists and is valid
        if data_path.exists():
            existing_metadata = FileUtils.get_file_metadata(data_path, 
                calculate_checksum=self.config.get('verify_checksums', 'true') == 'true')
            if existing_metadata:
                index_entry = self.sync_index.get(vex_filename)
                if index_entry:
                    # File exists and matches index - skip download
                    if out_path.parent != data_path.parent:
                        import shutil
                        out_path.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(data_path, out_path)
                    return DownloadResult(vex_filename, DownloadStatus.CACHED, size=existing_metadata.size)
        
        success = self.downloader.download_file_sync(url, out_path)
        
        if success:
            data_year_dir.mkdir(parents=True, exist_ok=True)
            if not data_path.exists() or data_path != out_path:
                import shutil
                shutil.copy2(out_path, data_path)
            
            metadata = FileUtils.get_file_metadata(data_path,
                calculate_checksum=self.config.get('verify_checksums', 'true') == 'true')
            if metadata:
                metadata.downloaded = datetime.now().isoformat()
                self.sync_index.update(vex_filename, metadata)
                return DownloadResult(vex_filename, DownloadStatus.SUCCESS, size=metadata.size)
        
        return DownloadResult(vex_filename, DownloadStatus.FAILED, error="Download failed")
    
    def parse_changes_csv(self, csv_path: Path, start_date: datetime, end_date: datetime) -> Set[str]:
        """Parse changes.csv and return set of VEX filenames in date range."""
        vex_files = set()
        
        try:
            with open(csv_path, 'r') as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 2:
                        try:
                            file_date = datetime.strptime(row[1].strip('"'), "%Y-%m-%dT%H:%M:%S%z").replace(tzinfo=None)
                            if start_date <= file_date <= end_date:
                                vex_filename = row[0].strip('"').split('/')[-1]
                                vex_files.add(vex_filename)
                        except (ValueError, IndexError):
                            continue
        except FileNotFoundError:
            logger.error(f"Changes CSV not found: {csv_path}")
        
        return vex_files
    
    def get_remote_file_list(self, changes_csv_path: Path) -> Set[str]:
        """Get complete list of VEX files from remote repository."""
        all_files = set()
        
        try:
            with open(changes_csv_path, 'r') as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 2:
                        try:
                            vex_filename = row[0].strip('"').split('/')[-1]
                            all_files.add(vex_filename)
                        except (ValueError, IndexError):
                            continue
        except FileNotFoundError:
            logger.error(f"Changes CSV not found: {changes_csv_path}")
        
        return all_files
    
    def get_recently_modified_files(self, changes_csv_path: Path, since_timestamp: float) -> Set[str]:
        """Get list of VEX files modified since a specific timestamp.
        
        Args:
            changes_csv_path: Path to changes.csv file
            since_timestamp: Only include files modified after this timestamp
            
        Returns:
            Set of filenames modified since the timestamp
        """
        recent_files = set()
        since_date = datetime.fromtimestamp(since_timestamp)
        
        try:
            with open(changes_csv_path, 'r') as f:
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= 2:
                        try:
                            # Parse the modification date from changes.csv
                            file_date_str = row[1].strip('"')
                            file_date = datetime.strptime(file_date_str, "%Y-%m-%dT%H:%M:%S%z").replace(tzinfo=None)
                            
                            # Only include files modified after our last sync
                            if file_date > since_date:
                                vex_filename = row[0].strip('"').split('/')[-1]
                                recent_files.add(vex_filename)
                        except (ValueError, IndexError):
                            continue
        except FileNotFoundError:
            logger.error(f"Changes CSV not found: {changes_csv_path}")
        
        logger.info(f"Found {len(recent_files)} files modified since {since_date.strftime('%Y-%m-%d %H:%M:%S')}")
        return recent_files
    
    def get_deleted_files(self, deletions_csv_path: Path) -> Set[str]:
        """Get list of deleted files from deletions.csv"""
        deleted_files = set()
        
        try:
            if deletions_csv_path.exists():
                with open(deletions_csv_path, 'r') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) >= 2:
                            try:
                                vex_filename = row[0].strip('"').split('/')[-1]
                                deleted_files.add(vex_filename)
                            except (ValueError, IndexError):
                                continue
        except Exception as e:
            logger.warning(f"Error reading deletions.csv: {e}")
        
        return deleted_files
    
    def check_local_files(self, remote_files: Set[str]) -> Tuple[Set[str], Set[str]]:
        """Check which files are missing or outdated."""
        missing_files = set()
        outdated_files = set()
        
        for remote_file in remote_files:
            year = FileUtils.extract_year_from_filename(remote_file)
            file_path = self.data_dir / year / remote_file
            
            if not file_path.exists():
                missing_files.add(remote_file)
            elif not self.sync_index.has(remote_file):
                outdated_files.add(remote_file)
            else:
                current_metadata = FileUtils.get_file_metadata(file_path)
                if current_metadata:
                    index_entry = self.sync_index.get(remote_file)
                    
                    # Check for significant changes
                    size_diff = abs(current_metadata.size - index_entry.get('size', 0))
                    time_diff = abs(current_metadata.mtime - index_entry.get('mtime', 0))
                    
                    size_threshold = max(100, index_entry.get('size', 0) * 0.05)
                    time_threshold = 3600
                    
                    if (size_diff > size_threshold) or (time_diff > time_threshold and size_diff > 0):
                        outdated_files.add(remote_file)
        
        return missing_files, outdated_files
    
    def process_deletions(self, deleted_files: Set[str]) -> int:
        """Process file deletions."""
        if not deleted_files:
            return 0
        
        deleted_count = 0
        files_to_delete = deleted_files & set(self.sync_index.index.keys())
        
        logger.info(f"Processing {len(files_to_delete)} deletions...")
        
        batch_size = self.config.get('batch_size', 50)
        
        for i in range(0, len(files_to_delete), batch_size):
            batch = list(files_to_delete)[i:i + batch_size]
            
            for deleted_file in batch:
                year = FileUtils.extract_year_from_filename(deleted_file)
                file_path = self.data_dir / year / deleted_file
                
                if file_path.exists():
                    try:
                        file_path.unlink()
                        deleted_count += 1
                        self.sync_index.remove(deleted_file)
                    except Exception as e:
                        logger.error(f"Error deleting {deleted_file}: {e}")
        
        return deleted_count
    
    def download_metadata_files(self) -> Tuple[Path, Path]:
        """Download changes.csv and deletions.csv"""
        changes_csv_path = self.data_dir / self.config['changes_csv']
        deletions_csv_path = self.data_dir / 'deletions.csv'
        
        logger.info("Downloading metadata files...")
        
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(self.downloader.download_file_sync, 
                              self.config['base_url'] + self.config['changes_csv'], 
                              changes_csv_path): 'changes',
                executor.submit(self.downloader.download_file_sync,
                              self.config['base_url'] + 'deletions.csv',
                              deletions_csv_path): 'deletions'
            }
            
            for future in as_completed(futures):
                name = futures[future]
                success = future.result()
                if success:
                    logger.info(f"Downloaded {name}.csv")
                else:
                    logger.warning(f"Failed to download {name}.csv")
        
        return changes_csv_path, deletions_csv_path
    
    def synchronize_archive(self):
        """Synchronize local archive with remote repository."""
        logger.info("Starting synchronization with remote repository...")
        self.stats.start_time = time.time()
        
        # Record last sync time from index
        self.stats.last_sync_time = self.sync_index.last_sync_time
        if self.stats.last_sync_time > 0:
            last_sync_date = datetime.fromtimestamp(self.stats.last_sync_time).strftime('%Y-%m-%d %H:%M:%S')
            logger.info(f"Last synchronization was on: {last_sync_date}")
        
        # Check for existing archive
        archive_exists = any(
            (self.data_dir / str(year)).exists() and 
            any((self.data_dir / str(year)).glob("*.json"))
            for year in range(2020, datetime.now().year + 1)
        )
        
        if not archive_exists:
            logger.info("No existing archive found - attempting complete archive download...")
            self._try_download_complete_archive(force=False)
        else:
            logger.info("Performing incremental synchronization...")
        
        # Download metadata
        changes_csv_path, deletions_csv_path = self.download_metadata_files()
        
        # Get file lists
        remote_files = self.get_remote_file_list(changes_csv_path)
        deleted_files = self.get_deleted_files(deletions_csv_path)
        
        self.stats.remote_files = len(remote_files)
        self.stats.deleted_files = len(deleted_files)
        
        logger.info(f"Found {len(remote_files)} files in remote repository")
        logger.info(f"Found {len(deleted_files)} deleted files")
        
        # Optimize by only checking recently modified files if we have a last sync time
        files_to_check = remote_files
        use_optimization = False
        
        if self.stats.last_sync_time > 0:
            # Use date-based optimization to only check files modified since last sync
            recent_files = self.get_recently_modified_files(changes_csv_path, self.stats.last_sync_time)
            if recent_files:
                logger.info(f"Using date-based optimization: checking {len(recent_files)} recently modified files instead of all {len(remote_files)} files")
                files_to_check = recent_files
                use_optimization = True
            else:
                logger.info("No files modified since last synchronization - checking all files to be safe")
        else:
            # No last sync time, try to use the latest archive date instead
            archive_latest_path = self.data_dir / self.config['archive_latest']
            if archive_latest_path.exists():
                try:
                    with open(archive_latest_path, 'r') as f:
                        latest_archive_name = f.read().strip()
                    
                    # Extract date from archive name (format: csaf_vex_YYYY-MM-DD.tar.zst)
                    if '_' in latest_archive_name and '.' in latest_archive_name:
                        date_part = latest_archive_name.split('_')[-1].split('.')[0]
                        try:
                            archive_date = datetime.strptime(date_part, "%Y-%m-%d")
                            archive_timestamp = archive_date.timestamp()
                            
                            # Use the archive date as reference for optimization
                            recent_files = self.get_recently_modified_files(changes_csv_path, archive_timestamp)
                            if recent_files:
                                logger.info(f"Using archive date optimization ({archive_date.strftime('%Y-%m-%d')}): checking {len(recent_files)} recently modified files instead of all {len(remote_files)} files")
                                files_to_check = recent_files
                                use_optimization = True
                            else:
                                logger.info(f"No files modified since archive date ({archive_date.strftime('%Y-%m-%d')}) - checking all files to be safe")
                        except ValueError:
                            logger.info("Could not parse date from archive name - checking all files")
                except (IOError, json.JSONDecodeError) as e:
                    logger.info(f"Could not read archive_latest.txt: {e} - checking all files")
            
            if not use_optimization:
                logger.info("No last sync time or archive date available - checking all files")
        
        if not remote_files:
            logger.warning("No files found in remote repository")
            return
        
        # Check local files (using optimized list if available)
        missing_files, outdated_files = self.check_local_files(files_to_check)
        
        self.stats.missing_files = len(missing_files)
        self.stats.outdated_files = len(outdated_files)
        self.stats.files_processed = len(files_to_check)
        
        logger.info(f"Checked {len(files_to_check)} files for discrepancies")
        logger.info(f"Missing files: {len(missing_files)}")
        logger.info(f"Outdated files: {len(outdated_files)}")
        
        # Check if we should force full archive download due to too many discrepancies
        files_to_download = missing_files | outdated_files
        discrepancy_threshold = self.config.get('discrepancy_threshold', 50000)
        
        if len(files_to_download) > discrepancy_threshold:
            logger.warning(f"Too many files to download ({len(files_to_download)} > {discrepancy_threshold}) - forcing full archive download")
            archive_success = self._try_download_complete_archive(force=True)
            
            if archive_success:
                # After successful archive download, rebuild the sync index from the extracted files
                logger.info("Rebuilding sync index from extracted archive files...")
                self._rebuild_sync_index_from_archive(remote_files)
                
                # Re-check what files are missing/outdated with the updated index
                missing_files, outdated_files = self.check_local_files(remote_files)
                self.stats.missing_files = len(missing_files)
                self.stats.outdated_files = len(outdated_files)
                files_to_download = missing_files | outdated_files
                
                logger.info(f"After archive download - Missing files: {len(missing_files)}")
                logger.info(f"After archive download - Outdated files: {len(outdated_files)}")
            else:
                # If archive download failed when it was required, we should not proceed with individual downloads
                logger.error(f"❌ Archive download failed but is required for {len(files_to_download)} files. Aborting synchronization.")
                logger.error(f"Please install required dependencies (zstandard) and ensure network connectivity, then retry.")
                self.stats.end_time = time.time()
                self.stats.print_summary()
                return
        
        # Process deletions
        deleted_count = self.process_deletions(deleted_files)
        logger.info(f"Deleted {deleted_count} files")
        
        # Download missing and outdated files
        if files_to_download:
            self._download_files_batch(files_to_download)
        
        # Update last sync time and save sync index
        self.sync_index.update_last_sync_time()
        self.sync_index.save()
        
        self.stats.end_time = time.time()
        self.stats.print_summary()
        
        if self.stats.failed > 0:
            logger.warning("Some operations failed. You may want to retry.")
        else:
            logger.info("✅ Local archive is fully synchronized!")
    
    def _try_download_complete_archive(self, force: bool = False):
        """Try to download and extract complete archive.
        
        Args:
            force: If True, this archive download is required and failures should be treated as critical
        
        Returns:
            bool: True if archive was successfully downloaded and extracted, False otherwise
        """
        # Download archive_latest.txt from the server to get the most recent archive name
        # We use a temporary file to avoid overwriting our local archive_latest.txt
        # which is only for information about what we have locally
        logger.info("Downloading archive_latest.txt from server to get the latest archive name...")
        
        # Create a temporary file for the server's archive_latest.txt
        temp_archive_latest_path = self.data_dir / "archive_latest_server.txt"
        
        if not self.downloader.download_file_sync(
            self.config['base_url'] + self.config['archive_latest'],
            temp_archive_latest_path
        ):
            if force:
                logger.error("❌ Failed to download archive_latest.txt from server - this is required for forced archive download")
                return False
            logger.warning("Failed to download archive_latest.txt from server, falling back to individual downloads")
            return False
        
        try:
            # Read the latest archive name from the server's archive_latest.txt
            with open(temp_archive_latest_path, 'r') as f:
                latest_archive_name = f.read().strip()
            
            logger.info(f"Latest archive from server: {latest_archive_name}")
            
            archive_path = self.data_dir / latest_archive_name
            archive_latest_path = self.data_dir / self.config['archive_latest']
            
            # For forced downloads, always download the latest archive
            if force:
                logger.info(f"Forced archive download requested - downloading latest archive: {latest_archive_name}")
                if self.downloader.download_file_sync(
                    self.config['base_url'] + latest_archive_name,
                    archive_path
                ):
                    logger.info("Extracting archive...")
                    if self._extract_archive(archive_path):
                        # Update our local archive_latest.txt to reflect what we now have
                        with open(archive_latest_path, 'w') as f:
                            f.write(latest_archive_name)
                        logger.info("✅ Archive extracted successfully!")
                        logger.info(f"Updated local archive_latest.txt to: {latest_archive_name}")
                        return True
                    else:
                        logger.error("❌ Archive extraction failed - this is required for forced archive download")
                        return False
                else:
                    logger.error("❌ Archive download failed - this is required for forced archive download")
                    return False
            
            # For non-forced downloads, only download if archive doesn't exist
            if not archive_path.exists():
                logger.info(f"Downloading complete archive: {latest_archive_name}")
                if self.downloader.download_file_sync(
                    self.config['base_url'] + latest_archive_name,
                    archive_path
                ):
                    logger.info("Extracting archive...")
                    if self._extract_archive(archive_path):
                        # Update our local archive_latest.txt to reflect what we now have
                        with open(archive_latest_path, 'w') as f:
                            f.write(latest_archive_name)
                        logger.info("✅ Archive extracted successfully!")
                        logger.info(f"Updated local archive_latest.txt to: {latest_archive_name}")
                        return True
                    else:
                        logger.warning("Archive extraction failed, falling back to individual downloads")
                        return False
                else:
                    logger.warning("Archive download failed, falling back to individual downloads")
                    return False
            else:
                logger.info(f"Latest archive {latest_archive_name} already exists locally, extracting...")
                if self._extract_archive(archive_path):
                    logger.info("✅ Archive extracted successfully!")
                    return True
                else:
                    logger.warning("Archive extraction failed, falling back to individual downloads")
                    return False
                    
        except Exception as e:
            if force:
                logger.error(f"❌ Error with archive approach: {e} - this is required for forced archive download")
            else:
                logger.error(f"Error with archive approach: {e}")
                logger.info("Falling back to individual file downloads...")
            return False
        finally:
            # Clean up the temporary archive_latest file from server
            if temp_archive_latest_path.exists():
                temp_archive_latest_path.unlink()
    
    def _extract_archive(self, archive_path: Path) -> bool:
        """Extract tar.zst archive.
        
        Returns:
            bool: True if extraction was successful, False otherwise
        """
        try:
            import zstandard as zstd
            
            logger.info(f"Extracting {archive_path}...")
            dctx = zstd.ZstdDecompressor()
            
            with open(archive_path, 'rb') as compressed:
                with dctx.stream_reader(compressed) as reader:
                    with tarfile.open(fileobj=reader, mode='r|') as tar:
                        tar.extractall(path=self.data_dir)
            return True
        except ImportError:
            logger.error("zstandard library not installed. Cannot extract archive.")
            logger.info("Install with: pip install zstandard")
            return False
        except Exception as e:
            logger.error(f"Error extracting archive: {e}")
            return False
    
    def _rebuild_sync_index_from_archive(self, remote_files: Set[str]):
        """Rebuild sync index from files extracted from archive.
        
        After extracting an archive, we need to update the sync index to reflect
        the new files and their metadata to avoid false "outdated" detections.
        
        Args:
            remote_files: Set of remote file names for reference
        """
        logger.info("Scanning extracted archive files and updating sync index...")
        
        # Clear the current sync index
        self.sync_index.index.clear()
        
        # Scan all years in data directory to find extracted files
        extracted_files_count = 0
        for year in range(2020, datetime.now().year + 1):
            year_dir = self.data_dir / str(year)
            if year_dir.exists():
                for file_path in year_dir.glob("*.json"):
                    if file_path.is_file():
                        # Get metadata for the extracted file
                        metadata = FileUtils.get_file_metadata(file_path, calculate_checksum=False)
                        if metadata:
                            # Update sync index with the extracted file
                            self.sync_index.update(file_path.name, metadata)
                            extracted_files_count += 1
        
        logger.info(f"Updated sync index with {extracted_files_count} files from extracted archive")
        
        # Save the updated sync index
        self.sync_index.save()
    
    def _download_files_batch(self, files: Set[str]):
        """Download files in batches with progress tracking."""
        logger.info(f"Downloading {len(files)} files...")
        
        self.out_dir.mkdir(parents=True, exist_ok=True)
        
        if TQDM_AVAILABLE:
            pbar = tqdm(total=len(files), desc="Downloading", unit="file")
        
        with ThreadPoolExecutor(max_workers=self.config['max_workers']) as executor:
            futures = {
                executor.submit(self.download_vex_file, vex_file): vex_file
                for vex_file in files
            }
            
            for future in as_completed(futures):
                result = future.result()
                
                if result.status == DownloadStatus.SUCCESS:
                    self.stats.downloaded += 1
                elif result.status == DownloadStatus.CACHED:
                    self.stats.cached += 1
                else:
                    self.stats.failed += 1
                    logger.error(f"Failed: {result.filename}")
                
                if TQDM_AVAILABLE:
                    pbar.update(1)
                elif (self.stats.downloaded + self.stats.cached) % 50 == 0:
                    logger.info(f"Progress: {self.stats.downloaded + self.stats.cached}/{len(files)} files")
        
        if TQDM_AVAILABLE:
            pbar.close()
    
    def filter_by_regex(self, regex_pattern: str):
        """Filter VEX files by regex pattern."""
        logger.info(f"Filtering files with regex: {regex_pattern}")
        
        vex_files = list(self.out_dir.glob("*.json"))
        
        if not vex_files:
            logger.warning("No VEX files to filter")
            return
        
        pattern = re.compile(regex_pattern, re.IGNORECASE)
        kept_files = []
        removed_files = []
        error_files = []
        
        with ThreadPoolExecutor(max_workers=self.config['max_workers']) as executor:
            futures = {
                executor.submit(self._check_vex_matches, vex_file, pattern): vex_file
                for vex_file in vex_files
            }
            
            for future in as_completed(futures):
                vex_file = futures[future]
                try:
                    matches = future.result()
                    
                    if matches:
                        kept_files.append(vex_file.name)
                    else:
                        removed_files.append(vex_file.name)
                        vex_file.unlink()
                except Exception as e:
                    error_files.append(vex_file.name)
                    logger.error(f"Error processing {vex_file.name}: {e}")
        
        logger.info(f"Filtering complete: Kept {len(kept_files)}, Removed {len(removed_files)}")
        if error_files:
            logger.warning(f"Encountered errors with {len(error_files)} files: {', '.join(error_files[:5])}{'...' if len(error_files) > 5 else ''}")
    
    def _check_vex_matches(self, vex_path: Path, pattern: re.Pattern) -> bool:
        """Check if VEX file matches regex pattern."""
        try:
            # First check if file is empty
            if vex_path.stat().st_size == 0:
                logger.warning(f"Skipping empty file: {vex_path}")
                return False
            
            with open(vex_path, 'r') as f:
                data = json.load(f)
            
            # Check if data is valid
            if not data or not isinstance(data, dict):
                logger.warning(f"Invalid JSON structure in {vex_path}")
                return False
            
            vulnerabilities = data.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                    
                product_status = vuln.get('product_status', {})
                if not isinstance(product_status, dict):
                    continue
                
                known_affected = product_status.get('known_affected', [])
                fixed = product_status.get('fixed', [])
                
                # Ensure we have lists
                if not isinstance(known_affected, list):
                    known_affected = []
                if not isinstance(fixed, list):
                    fixed = []
                
                for product in known_affected + fixed:
                    if isinstance(product, str) and pattern.search(product):
                        return True
            
            return False
            
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error reading {vex_path}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error processing {vex_path}: {e}")
            return False
    
    def update_sync_index_from_local_files(self):
        """Update sync index by scanning all local VEX files.
        
        This is useful when files have been manually extracted or updated
        and the sync index needs to be rebuilt to reflect the current state.
        """
        logger.info("Updating sync index from all local VEX files...")
        
        # Clear the current sync index
        self.sync_index.index.clear()
        
        # Scan all years in data directory to find VEX files
        local_files_count = 0
        for year in range(2020, datetime.now().year + 1):
            year_dir = self.data_dir / str(year)
            if year_dir.exists():
                for file_path in year_dir.glob("*.json"):
                    if file_path.is_file():
                        # Get metadata for the local file
                        metadata = FileUtils.get_file_metadata(file_path, calculate_checksum=False)
                        if metadata:
                            # Update sync index with the local file
                            self.sync_index.update(file_path.name, metadata)
                            local_files_count += 1
        
        logger.info(f"Updated sync index with {local_files_count} local files")
        
        # Save the updated sync index
        self.sync_index.save()
        # Update last sync time to reflect the manual update
        self.sync_index.update_last_sync_time()
        logger.info("✅ Sync index has been successfully updated from local files")
        return local_files_count
    
    def download_date_range(self, start_date: datetime, end_date: datetime, limit: Optional[int] = None):
        """Download VEX files for a specific date range."""
        logger.info(f"Downloading files from {start_date.date()} to {end_date.date()}")
        
        # Download metadata
        changes_csv_path, _ = self.download_metadata_files()
        
        # Parse date range
        vex_files = self.parse_changes_csv(changes_csv_path, start_date, end_date)
        logger.info(f"Found {len(vex_files)} files in date range")
        
        if limit:
            vex_files = set(list(vex_files)[:limit])
            logger.info(f"Limited to {limit} files")
        
        if vex_files:
            self._download_files_batch(vex_files)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Download Red Hat VEX files with advanced features",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Synchronize complete archive
  %(prog)s --sync
  
  # Download last 7 days
  %(prog)s --days 7
  
  # Download date range with filter
  %(prog)s --start-date 2024-01-01 --end-date 2024-01-31 --regex "rhel-9"
  
  # Download with custom config
  %(prog)s --config my_config.ini --sync
        """
    )
    
    parser.add_argument(
        "--start-date",
        type=str,
        help="Start date (YYYY-MM-DD)"
    )
    parser.add_argument(
        "--end-date",
        type=str,
        help="End date (YYYY-MM-DD), defaults to today"
    )
    parser.add_argument(
        "--days",
        type=int,
        help="Download last N days (alternative to date range)"
    )
    parser.add_argument(
        "--regex",
        type=str,
        default="",
        help="Regex pattern to filter VEX files"
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Limit number of files (for testing)"
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config.ini",
        help="Configuration file (default: config.ini)"
    )
    parser.add_argument(
        "--sync",
        action="store_true",
        help="Synchronize local archive with remote"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without doing it"
    )
    parser.add_argument(
        "--update-index",
        action="store_true",
        help="Update sync index from local files (useful after manual archive extraction)"
    )
    
    args = parser.parse_args()
    
    # Setup logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load configuration
    config = ConfigManager(args.config)
    
    # Override regex from args
    if args.regex:
        config.config['regex_pattern'] = args.regex
    
    # Initialize downloader
    downloader = VEXDownloader(config)
    
    try:
        if args.update_index:
            # Update index mode - useful after manual archive extraction
            if args.dry_run:
                logger.info("DRY RUN: Would update sync index from local files")
                return
            files_updated = downloader.update_sync_index_from_local_files()
            logger.info(f"✅ Sync index updated with {files_updated} local files")
            logger.info("You can now run synchronization to check for missing/outdated files")
            return
        
        if args.sync:
            # Synchronization mode
            if args.dry_run:
                logger.info("DRY RUN: Would synchronize archive")
                return
            downloader.synchronize_archive()
        else:
            # Date range mode
            if args.days:
                end_date = datetime.now()
                start_date = end_date - timedelta(days=args.days)
            elif args.start_date:
                start_date = datetime.strptime(args.start_date, "%Y-%m-%d")
                end_date = datetime.strptime(args.end_date, "%Y-%m-%d") if args.end_date else datetime.now()
            else:
                parser.error("Must specify either --days, --start-date, --sync, or --update-index")
            
            if args.dry_run:
                logger.info(f"DRY RUN: Would download files from {start_date.date()} to {end_date.date()}")
                return
            
            downloader.download_date_range(start_date, end_date, args.limit)
        
        # Apply regex filter if specified
        if config.get('regex_pattern'):
            if args.dry_run:
                logger.info(f"DRY RUN: Would filter with regex: {config.get('regex_pattern')}")
            else:
                downloader.filter_by_regex(config.get('regex_pattern'))
        
        logger.info(f"Complete! Files saved to {downloader.out_dir}/")
        
    except KeyboardInterrupt:
        logger.info("\nOperation cancelled by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=args.verbose)
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())