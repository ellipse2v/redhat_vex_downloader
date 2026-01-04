# Red Hat VEX Downloader

**Automate Red Hat Vulnerability Data Collection and Analysis**

The Red Hat VEX Downloader is a powerful Python tool designed to help security professionals, DevOps teams, and system administrators efficiently download, manage, and analyze Red Hat's Vulnerability Exploitability eXchange (VEX) files. This tool addresses the critical need for automated vulnerability data collection in enterprise environments where manual processes are time-consuming and error-prone.

## Why Use This Tool?

In today's fast-paced security landscape, staying updated with the latest vulnerability information is crucial. Red Hat provides VEX files that contain essential information about vulnerability status, exploitability, and remediation guidance. However, manually downloading and processing these files can be challenging, especially when:

- You need to track vulnerabilities across hundreds of products
- You want to focus on specific products (OpenShift, RHEL, JBoss, etc.)
- You're working in corporate environments with proxy restrictions
- You need historical data for compliance and auditing
- You want to integrate vulnerability data into your SIEM or security tools

The Red Hat VEX Downloader automates this entire process, saving you hours of manual work and ensuring you always have the most current vulnerability information at your fingertips.

## Features

### Core Features (Production Ready)

- **Download VEX files** from Red Hat security data repository
- **Multi-threading support** for faster downloads
- **Proxy configuration** for corporate environments
- **Regex filtering** to find specific product vulnerabilities
- **Archive management** to avoid re-downloading existing files
- **Configurable settings** via configuration file
- **Date range filtering** to get only recent updates

### Additional Tools (Under Construction)

🚧 **rpm_to_cve.py** - RPM to CVE mapping tool (Work in Progress)
- Maps RPM packages (NEVRA format) to CVEs with detailed vulnerability information
- Generates Excel reports with separate sheets for fixed, not fixed, and affected packages
- *Note: This tool is currently under active development and may have limited functionality*

🚧 **vex_statistics.py** - VEX statistics analyzer (Work in Progress)
- Analyzes VEX files to generate statistics by RHEL version and severity
- Tracks progress with date-based indexing for incremental analysis
- Creates Excel reports with visualizations
- *Note: This tool is currently under active development and may have limited functionality*

> ⚠️ **Important**: The additional tools are provided as preview features and may not have complete functionality. They are included to demonstrate potential future capabilities and for early testing purposes.

## Installation

### Requirements

- Python 3.7+
- Required packages: `zstandard` (for archive extraction)

```bash
pip install zstandard
```

### Optional Dependencies

For proxy authentication and advanced features:

```bash
pip install urllib3 requests
```

## Usage

### Basic Usage

```bash
# Download VEX files for the last 5 days
python3 redhat_vex_downloader.py --days 5

# Download for a specific date range
python3 redhat_vex_downloader.py --start-date 2025-12-01 --end-date 2025-12-31

# With regex filtering (e.g., OpenShift vulnerabilities)
python3 redhat_vex_downloader.py --days 7 --regex "openshift|ocp"
```

### Advanced Usage

```bash
# Limited test run (for debugging)
python3 redhat_vex_downloader.py --days 1 --limit 10

# Use custom configuration file
python3 redhat_vex_downloader.py --days 5 --config myconfig.ini

# Override regex from config file
python3 redhat_vex_downloader.py --days 5 --regex "rhel|redhat"
```

## Configuration

The tool uses a configuration file (`config.ini`) for persistent settings. 

### Proxy Configuration

Edit the `[Network]` section in `config.ini`:

```ini
[Network]
# Corporate proxy configuration
http_proxy = http://proxy.example.com:8080
https_proxy = http://proxy.example.com:8080

# With authentication
http_proxy = http://username:password@proxy.example.com:8080
https_proxy = http://username:password@proxy.example.com:8080
```

### Regex Filtering

Configure automatic filtering in the `[Filter]` section:

```ini
[Filter]
# Filter for specific products
regex_pattern = openshift|ocp|kubernetes

# Filter for RHEL vulnerabilities
regex_pattern = rhel|redhat
```

### Performance Tuning

Adjust concurrent downloads in the `[Performance]` section:

```ini
[Performance]
# For slower networks
max_workers = 5

# For faster networks
max_workers = 30
```

## Output Structure

```
data/
├── 2024/
│   ├── cve-2024-XXXX.json
│   └── rhsa-2024_XXXX.json
├── 2025/
│   ├── cve-2025-XXXX.json
│   └── rhsa-2025_XXXX.json
└── csaf_vex_2025-12-26.tar.zst

out/
├── cve-2024-XXXX.json
├── cve-2025-XXXX.json
└── rhsa-2025_XXXX.json

changes.csv
archive_latest.txt
config.ini
```

## File Formats

### VEX Files

The tool downloads two types of VEX files:

1. **CVE files**: `cve-YYYY-NNNN.json` (e.g., `cve-2025-12980.json`)
2. **RHSA files**: `rhsa-YYYY_NNNN.json` (e.g., `rhsa-2025_1234.json`)

### URL Structure

Files are downloaded from:
```
https://security.access.redhat.com/data/csaf/v2/vex/{year}/{filename}
```

Example:
```
https://security.access.redhat.com/data/csaf/v2/vex/2025/cve-2025-12980.json
```

## Command Line Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `--days N` | Download files from last N days | `--days 7` |
| `--start-date YYYY-MM-DD` | Start date for range | `--start-date 2025-12-01` |
| `--end-date YYYY-MM-DD` | End date for range | `--end-date 2025-12-31` |
| `--regex PATTERN` | Regex pattern for filtering | `--regex "openshift|rhel"` |
| `--limit N` | Limit files for testing | `--limit 10` |
| `--config FILE` | Custom config file | `--config myconfig.ini` |

## Practical Use Cases and Examples

### 🔍 Security Monitoring: Daily Vulnerability Updates

**Scenario**: You're a security analyst who needs to monitor daily vulnerability updates for your Red Hat infrastructure.

**Solution**:
```bash
# Create a daily cron job to download and analyze new vulnerabilities
python3 redhat_vex_downloader.py --days 1 --regex "rhel|openshift"

# Then process the results with your analysis tools
./analyze_vex.py --input out/ --output reports/daily_report_$(date +%Y%m%d).json
```

**Benefits**: Automatically get only the vulnerabilities relevant to your RHEL and OpenShift environments, ready for your daily security briefing.

### 🎯 Targeted Analysis: Focus on Specific Products

**Scenario**: Your team is responsible for OpenShift security and only cares about OpenShift-related vulnerabilities.

**Solution**:
```bash
# Configure OpenShift filtering in config.ini
[Filter]
regex_pattern = openshift|ocp|kubernetes|cri-o

# Then run with your configuration
python3 redhat_vex_downloader.py --days 30 --config openshift_config.ini
```

**Benefits**: Get a focused dataset of only OpenShift-related vulnerabilities, reducing noise and improving efficiency.

### 🏢 Corporate Environment: Working Behind Proxy

**Scenario**: You're in a corporate environment with strict proxy requirements and need to download vulnerability data regularly.

**Solution**:
```bash
# Configure your corporate proxy in config.ini
[Network]
http_proxy = http://username:password@corporate-proxy.example.com:8080
https_proxy = http://username:password@corporate-proxy.example.com:8080

[Performance]
max_workers = 5  # Reduce workers for corporate network policies

# Run the downloader
python3 redhat_vex_downloader.py --days 7
```

**Benefits**: Seamless integration with your corporate network while respecting IT policies.

### 📊 Compliance Reporting: Monthly Vulnerability Reports

**Scenario**: You need to generate monthly vulnerability reports for compliance purposes.

**Solution**:
```bash
# Download all vulnerabilities for the month
python3 redhat_vex_downloader.py --start-date 2025-12-01 --end-date 2025-12-31

# Generate compliance report
python3 generate_compliance_report.py --input out/ --output compliance_report_december.json

# Archive the data for audit purposes
zip -r vex_archive_december_2025.zip out/ data/
```

**Benefits**: Complete vulnerability dataset for compliance reporting and auditing.

### 🔬 Security Research: Historical Vulnerability Analysis

**Scenario**: You're researching vulnerability trends over time and need historical data.

**Solution**:
```bash
# Download vulnerabilities for the entire year
python3 redhat_vex_downloader.py --start-date 2025-01-01 --end-date 2025-12-31

# Analyze trends
python3 analyze_trends.py --input out/ --output vulnerability_trends_2025.json

# Visualize the data
python3 visualize_trends.py --input vulnerability_trends_2025.json --output trends_chart.png
```

**Benefits**: Comprehensive historical data for trend analysis and research.

### 🚀 DevOps Integration: Automated Vulnerability Scanning

**Scenario**: You want to integrate vulnerability data into your CI/CD pipeline.

**Solution**:
```bash
# Add to your CI/CD pipeline (e.g., GitHub Actions, GitLab CI)
- name: Download latest vulnerabilities
  run: |
    python3 redhat_vex_downloader.py --days 1 --limit 50
    ./scan_environment.py --vex-data out/ --output scan_results.json

- name: Fail build on critical vulnerabilities
  run: |
    ./check_critical.py --input scan_results.json
    # Exit with error if critical vulnerabilities found
```

**Benefits**: Automated vulnerability checking in your deployment pipeline.

### 🔄 Data Integration: Feed Your SIEM System

**Scenario**: You want to feed vulnerability data into your SIEM (Splunk, ELK, etc.).

**Solution**:
```bash
# Download and transform data for SIEM ingestion
python3 redhat_vex_downloader.py --days 1

# Convert to SIEM-friendly format
python3 vex_to_siem.py --input out/ --format splunk --output siem_feed.json

# Send to your SIEM
curl -X POST -H "Authorization: Bearer $SIEM_TOKEN" \
     -H "Content-Type: application/json" \
     -d @siem_feed.json \
     https://your-siem.example.com/api/v1/events
```

**Benefits**: Real-time vulnerability data in your security monitoring system.

### 🎓 Learning and Training: Educational Use

**Scenario**: You're learning about vulnerability management and want to explore real-world data.

**Solution**:
```bash
# Download a small dataset for learning
python3 redhat_vex_downloader.py --days 1 --limit 20

# Explore the data structure
python3 explore_vex.py --input out/

# Learn about specific vulnerabilities
python3 analyze_vulnerability.py --input out/cve-2025-XXXX.json --detailed
```

**Benefits**: Hands-on learning with real vulnerability data.

## Quick Start Examples

### Basic Commands

```bash
# Download vulnerabilities from the last 7 days
python3 redhat_vex_downloader.py --days 7

# Download with specific date range
python3 redhat_vex_downloader.py --start-date 2025-12-01 --end-date 2025-12-07

# Download and filter for specific products
python3 redhat_vex_downloader.py --days 3 --regex "openshift|rhel"
```

### Advanced Commands

```bash
# Limited download for testing
python3 redhat_vex_downloader.py --days 1 --limit 10

# Use custom configuration
python3 redhat_vex_downloader.py --days 5 --config my_config.ini

# Override regex from command line
python3 redhat_vex_downloader.py --days 3 --regex "jboss|wildfly"
```

### Configuration Examples

**Proxy Configuration** (`config.ini`):
```ini
[Network]
http_proxy = http://proxy.example.com:8080
https_proxy = http://proxy.example.com:8080

[Performance]
max_workers = 10
```

**Filter Configuration** (`config.ini`):
```ini
[Filter]
# For OpenShift team
regex_pattern = openshift|ocp|kubernetes|cri-o|podman

[Directories]
data_dir = /shared/vex_data
data_dir = /shared/vex_output
```

## Troubleshooting

### Proxy Issues

- Verify proxy URL and port are correct
- Check if authentication is required
- Test connectivity with `curl` or `wget`

### Configuration Errors

- Ensure proper INI file syntax
- Verify section names are correct
- Check for duplicate keys

### Download Failures

- Check network connectivity
- Verify Red Hat security data repository is accessible
- Review error messages for specific issues

### Performance Issues

- Reduce `max_workers` for slower networks
- Check disk space for large downloads
- Monitor memory usage during processing

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

### Contributing to Under Construction Tools

If you're interested in helping with the development of `rpm_to_cve.py` or `vex_statistics.py`, here are some ways to contribute:

**For rpm_to_cve.py:**
- Help improve RPM package parsing and NEVRA format handling
- Enhance CVE mapping algorithms
- Add support for more package formats
- Improve Excel report generation and formatting

**For vex_statistics.py:**
- Expand statistical analysis capabilities
- Add more visualization options
- Improve date-based indexing performance
- Enhance RHEL version detection

**How to contribute:**
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes and add tests
4. Update documentation if needed
5. Submit a pull request with a clear description

## Development Status

### rpm_to_cve.py
- ✅ Basic RPM parsing implemented
- ✅ CVE mapping framework in place
- 🚧 Excel report generation needs enhancement
- 🚧 Additional package format support needed
- 🚧 Performance optimization required

### vex_statistics.py
- ✅ Basic VEX file analysis working
- ✅ RHEL version extraction implemented
- ✅ Excel report generation functional
- 🚧 Advanced statistical analysis needed
- 🚧 More visualization options to add
- 🚧 Performance improvements for large datasets

## Testing Under Construction Tools

Both `rpm_to_cve.py` and `vex_statistics.py` include test suites that you can run to verify functionality:

### Running Tests for rpm_to_cve.py

```bash
# Basic functionality test
python3 rpm_to_cve.py --help

# Test with sample data (create a test RPM list first)
echo "package-1.0-1.el8.x86_64" > test_rpms.txt
python3 rpm_to_cve.py --input test_rpms.txt --output test_results.xlsx
```

### Running Tests for vex_statistics.py

```bash
# Run unit tests
python3 -m pytest test/test_vex_statistics_unit.py -v

# Test with sample VEX data
python3 test/test_stats.py

# Generate statistics report
python3 vex_statistics.py --input data/ --output stats_report.xlsx
```

### Test Data

The project includes test data files in the `test/` directory:
- `test/test_vex.json` - Sample VEX file for testing
- `test/test_changes.csv` - Sample CSV data for parsing tests

You can use these files to test the tools without downloading real data.

## Support

For issues or questions, please open a GitHub issue or contact the maintainers.

## Acknowledgements

- Red Hat for providing the VEX data
- Python community for excellent libraries
- All contributors who help improve this tool
