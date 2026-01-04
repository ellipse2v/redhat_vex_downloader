# Configuration Guide for Red Hat VEX Downloader

## Configuration File

The downloader uses a configuration file (`config.ini`) to manage settings like proxy configuration, regex patterns, and performance options.

### Basic Configuration

The default configuration file includes these sections:

```ini
[DEFAULT]
# Configuration for Red Hat VEX Downloader

[Network]
# Proxy configuration (leave empty if no proxy needed)
http_proxy = 
https_proxy = 

[Filter]
# Regex pattern to filter VEX files by product names
# Example: openshift|rhel|jboss
regex_pattern = 

[Performance]
# Maximum number of concurrent downloads
max_workers = 20

[Directories]
# Base directories
data_dir = data
out_dir = out

[Files]
# Remote files
base_url = https://security.access.redhat.com/data/csaf/v2/vex/
changes_csv = changes.csv
archive_latest = archive_latest.txt
```

## Archive Synchronization

The `--sync` option allows you to maintain a complete local mirror of Red Hat's VEX repository.

```bash
# Synchronize local archive with remote repository
python3 redhat_vex_downloader.py --sync
```

**How it works**:

### First Run (No Archive)
1. **Detects no existing archive**
2. **Attempts to download complete archive** (most efficient)
3. **If archive download fails**, falls back to individual file download
4. **Extracts archive** to build complete local mirror
5. **Sets sync index** based on archive date

### Incremental Run (Archive Exists)
1. **Loads sync index** (tracks file modification times and sizes)
2. **Downloads fresh metadata** (`changes.csv` and `deletions.csv`)
3. Parses `changes.csv` to get the complete file list
4. Parses `deletions.csv` to identify obsolete files
5. Compares your local archive with the remote repository
6. Identifies missing files, outdated files, AND files that should be deleted
7. Downloads missing/outdated files and removes obsolete files
8. **Updates sync index** with current file information
9. Provides detailed synchronization statistics

**Key Benefits**:
- **First run**: Uses complete archive for fastest initial setup
- **Incremental**: Only downloads changes after initial setup
- **Fallback**: Gracefully handles archive download failures
- **Efficiency**: Minimizes bandwidth and time

**Benefits**:
- Ensures your local archive is identical to Red Hat's repository
- Efficient updates (only downloads missing files)
- Proper cleanup (removes deleted files)
- Perfect for compliance and offline access
- Progress tracking with detailed reporting

**Example output**:
```
Starting synchronization with remote repository...
Found 308097 files in remote repository
Found 123 deleted files in deletions.csv
Local archive status:
  - Local files: 308100
  - Remote files: 308097
  - Missing files: 59
  - Files to delete: 3
Deleting 3 obsolete files...
✅ Deleted 3 obsolete files
Downloading 59 missing files to complete synchronization...
✅ Downloaded 10 files...
✅ Downloaded 20 files...
...
🎉 Local archive is now fully synchronized with remote repository!
```

**First Run vs Incremental Run**:

The synchronization automatically detects whether this is a first run or an incremental update:

- **First Run**: No existing sync index or very small index → Full synchronization
- **Incremental Run**: Existing sync index with many files → Only sync changes

**Example output (First Run)**:
```
Starting synchronization with remote repository...
🆕 First run detected - this may take longer as we build the initial index
   Tip: Subsequent runs will be much faster!
Found 308144 files in remote repository
Found 117 deleted files in deletions.csv
Local archive status:
  - Local files: 0
  - Remote files: 308144
  - Missing files: 308144
  - Outdated files: 0
  - Files to delete: 0
Downloading 308144 files to complete synchronization...
✅ Downloaded 100 files...
✅ Downloaded 200 files...
...
🎉 Local archive is now fully synchronized with remote repository!
```

**Example output (Incremental Run)**:
```
Starting synchronization with remote repository...
🔄 Performing incremental synchronization...
Found 308144 files in remote repository
Found 117 deleted files in deletions.csv
Local archive status:
  - Local files: 308144
  - Remote files: 308144
  - Missing files: 0
  - Outdated files: 47
  - Files to delete: 3
Deleting 3 obsolete files...
✅ Deleted 3 obsolete files
Downloading 47 updated files...
✅ Downloaded 10 files...
...
🎉 Local archive is now fully synchronized with remote repository!
```

**Advanced synchronization**:
```bash
# Regular synchronization (cron job)
0 3 * * 1 /usr/bin/python3 redhat_vex_downloader.py --sync

# Force re-download of deletions.csv
rm -f deletions.csv
python3 redhat_vex_downloader.py --sync
```

## Proxy Configuration

To configure a proxy, edit the `[Network]` section:

```ini
[Network]
# Proxy configuration for corporate networks
http_proxy = http://proxy.example.com:8080
https_proxy = http://proxy.example.com:8080
```

### Proxy Authentication

If your proxy requires authentication, use the format:

```ini
[Network]
http_proxy = http://username:password@proxy.example.com:8080
https_proxy = http://username:password@proxy.example.com:8080
```

## Regex Filtering

Configure automatic filtering by setting a regex pattern in the `[Filter]` section:

```ini
[Filter]
# Filter for OpenShift-related vulnerabilities
regex_pattern = openshift|ocp|kubernetes

# Filter for RHEL-specific vulnerabilities
regex_pattern = rhel|redhat

# Filter for multiple products
regex_pattern = openshift|rhel|jboss|ansible
```

## Performance Tuning

Adjust the number of concurrent downloads in the `[Performance]` section:

```ini
[Performance]
# For slower networks
max_workers = 5

# For faster networks
max_workers = 30
```

## Directory Configuration

Change the default directories if needed:

```ini
[Directories]
# Store data in a different location
data_dir = /path/to/vex_data
out_dir = /path/to/vex_output
```

## Usage Examples

### Using configuration file

```bash
# Use default config.ini
python3 redhat_vex_downloader.py --days 5

# Use custom config file
python3 redhat_vex_downloader.py --days 5 --config myconfig.ini

# Override regex from config file
python3 redhat_vex_downloader.py --days 5 --regex "openshift"
```

### Command line options

```bash
# Basic usage with days
python3 redhat_vex_downloader.py --days 7

# Specific date range
python3 redhat_vex_downloader.py --start-date 2025-12-01 --end-date 2025-12-31

# With regex filtering
python3 redhat_vex_downloader.py --days 5 --regex "openshift|kubernetes"

# Limited test run
python3 redhat_vex_downloader.py --days 1 --limit 10
```

## Troubleshooting

### Proxy Issues

If you have proxy issues:
1. Verify the proxy URL and port are correct
2. Check if authentication is required
3. Test proxy connectivity with `curl` or `wget`

### Configuration Errors

If the configuration file has errors:
1. Check for proper INI file syntax
2. Verify section names are correct
3. Ensure no duplicate keys exist

### Performance Issues

If downloads are slow:
1. Reduce `max_workers` for slower networks
2. Check network connectivity
3. Verify proxy settings if applicable