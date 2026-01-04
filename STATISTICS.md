# Red Hat VEX Statistics Analyzer

## Overview

The VEX Statistics Analyzer is a powerful tool that analyzes Red Hat VEX (Vulnerability Exploitability eXchange) files to generate comprehensive statistics by RHEL version and severity. It's designed to help security teams understand vulnerability trends, track remediation progress, and generate reports for compliance.

## Features

### 📊 Comprehensive Statistics
- **By RHEL Version**: EL6, EL7, EL8, EL9, EL10
- **By Severity**: Critical, Important, Moderate, Low, Unknown
- **By Status**: fixed, known_affected, known_not_affected, under_investigation

### 🔄 Incremental Analysis
- **Resume capability**: Continue from where you left off
- **Date-based filtering**: Analyze only new or updated files
- **Progress tracking**: Save and restore analysis state

### 📈 Multiple Output Formats
- **CSV**: Detailed data for spreadsheet analysis
- **Text Summary**: Human-readable reports
- **Index File**: Track analysis progress

### 🎯 Flexible Usage
- **Full analysis**: Process all available data
- **Incremental updates**: Analyze only new files
- **Date range filtering**: Focus on specific time periods

## Installation

No additional dependencies required beyond the main VEX downloader:

```bash
# The statistics script uses the same dependencies as the main downloader
pip install zstandard  # Only needed if you're also using the downloader
```

## Usage

### Basic Analysis

```bash
# Analyze all VEX files
python3 vex_statistics.py --data-dir data

# Analyze files from a specific date onwards
python3 vex_statistics.py --data-dir data --start-date 2025-01-01
```

### Incremental Analysis

```bash
# First run - full analysis
python3 vex_statistics.py --data-dir data

# Subsequent runs - only analyze new files
python3 vex_statistics.py --data-dir data --resume

# Reset and start fresh
python3 vex_statistics.py --data-dir data --reset
```

### Date Range Analysis

```bash
# Analyze only recent files
python3 vex_statistics.py --data-dir data --start-date 2025-12-01

# Regular updates (cron job example)
0 2 * * * /usr/bin/python3 /path/to/vex_statistics.py --data-dir data --resume
```

## Output Files

The script generates several output files in the `stats/` directory:

### 1. CSV File (`vex_statistics_{date}.csv`)

Detailed statistical data in CSV format for spreadsheet analysis:

```csv
RHEL Version,Severity,Status Type,Count
EL7,Critical,fixed,42
EL7,Critical,known_affected,18
EL7,Critical,known_not_affected,112
EL7,Critical,under_investigation,3
EL7,Important,fixed,245
EL7,Important,known_affected,89
...
```

### 2. Summary File (`vex_summary_{date}.txt`)

Human-readable summary with key metrics and percentages:

```
Red Hat VEX Statistics Summary
Generated: 2025-12-28 14:30:45
Data Range: 2025-01-01 onwards

=== EL7 Statistics ===
Total CVEs: 1248

Status Distribution:
  fixed: 425 (34.1%)
  known_affected: 187 (15.0%)
  known_not_affected: 562 (45.0%)
  under_investigation: 74 (5.9%)

By Severity:
  Critical: 175 (14.0%)
    - fixed: 42 (24.0%)
    - known_affected: 18 (10.3%)
    - known_not_affected: 112 (64.0%)
    - under_investigation: 3 (1.7%)
  Important: 542 (43.4%)
    - fixed: 245 (45.2%)
    - known_affected: 89 (16.4%)
    - known_not_affected: 187 (34.5%)
    - under_investigation: 21 (3.9%)
  Moderate: 389 (31.2%)
  Low: 112 (9.0%)
  Unknown: 30 (2.4%)
```

### 3. Index File (`stats_index.pkl`)

Binary file tracking analysis progress:
- Last run timestamp
- File count processed
- Analysis date

## Statistics Breakdown

### By RHEL Version

The tool categorizes vulnerabilities by major RHEL versions:
- **EL6**: Red Hat Enterprise Linux 6
- **EL7**: Red Hat Enterprise Linux 7
- **EL8**: Red Hat Enterprise Linux 8
- **EL9**: Red Hat Enterprise Linux 9
- **EL10**: Red Hat Enterprise Linux 10

### By Severity

Vulnerabilities are classified by severity using CVSS v3 scores:
- **Critical**: CVSS ≥ 9.0
- **Important**: CVSS ≥ 7.0
- **Moderate**: CVSS ≥ 4.0
- **Low**: CVSS > 0
- **Unknown**: No CVSS score available

### By Status

Each vulnerability is tracked by its current status:
- **fixed**: Vulnerability has been fixed
- **known_affected**: Product is known to be affected
- **known_not_affected**: Product is confirmed not affected
- **under_investigation**: Status is being investigated

## Practical Use Cases

### 📊 Security Reporting

Generate monthly vulnerability reports for management:

```bash
# Monthly report generation
python3 vex_statistics.py --data-dir data --start-date $(date -d "-1 month" +%Y-%m-01)

# Email the results
echo "Monthly VEX Report" | mail -s "VEX Statistics Report" security-team@example.com -A stats/vex_summary_*.txt
```

### 🎯 Product-Specific Analysis

Focus on specific RHEL versions for targeted remediation:

```bash
# Analyze EL8 vulnerabilities
python3 vex_statistics.py --data-dir data

# Extract EL8 data from CSV
grep "^EL8," stats/vex_statistics_*.csv > el8_vulnerabilities.csv
```

### 🔬 Trend Analysis

Track vulnerability trends over time:

```bash
# Monthly analysis script
for month in {01..12}; do
    python3 vex_statistics.py --data-dir data --start-date "2025-${month}-01" --reset
    mv stats/vex_summary_*.txt "stats/monthly_2025${month}.txt"
done

# Generate trend report
python3 generate_trends.py --input stats/monthly_*.txt --output vulnerability_trends_2025.pdf
```

### 🛡️ Compliance Reporting

Generate reports for compliance audits:

```bash
# Quarterly compliance report
python3 vex_statistics.py --data-dir data --start-date $(date -d "-3 months" +%Y-%m-%d)

# Generate compliance report
python3 generate_compliance_report.py --input stats/vex_summary_*.txt --output compliance_report_q1_2025.pdf
```

### 🚀 DevOps Integration

Integrate with CI/CD pipelines:

```yaml
# GitHub Actions example
- name: Generate VEX Statistics
  run: |
    python3 vex_statistics.py --data-dir data --resume
    # Upload results as artifacts
    echo "VEX_STATS_FILE=stats/vex_summary_*.txt" >> $GITHUB_ENV

- name: Upload Statistics
  uses: actions/upload-artifact@v3
  with:
    name: vex-statistics
    path: ${{ env.VEX_STATS_FILE }}
```

## Understanding the Data

### Key Metrics

1. **Total CVEs**: Total number of vulnerabilities for each RHEL version
2. **Status Distribution**: Percentage of vulnerabilities in each status
3. **Severity Breakdown**: Distribution across severity levels
4. **Status by Severity**: Detailed breakdown of status within each severity level

### Example Interpretation

```
EL8 Statistics:
- Total CVEs: 852
- Critical: 124 (14.6%) - High priority for immediate patching
- Important: 342 (40.1%) - Should be patched soon
- Moderate: 287 (33.7%) - Schedule for regular patching
- Fixed: 412 (48.4%) - Already remediated
- Known Affected: 198 (23.2%) - Requires attention
```

### Actionable Insights

1. **Prioritization**: Focus on Critical/Important vulnerabilities
2. **Remediation Tracking**: Monitor increase in "fixed" status
3. **Risk Assessment**: Identify versions with high "known_affected" counts
4. **Trend Analysis**: Track changes in vulnerability counts over time

## Advanced Usage

### Custom Date Ranges

```bash
# Last 7 days
python3 vex_statistics.py --data-dir data --start-date $(date -d "-7 days" +%Y-%m-%d)

# Specific quarter
python3 vex_statistics.py --data-dir data --start-date "2025-01-01" --reset
python3 vex_statistics.py --data-dir data --start-date "2025-04-01" --resume
```

### Automated Reporting

```bash
#!/bin/bash
# Weekly vulnerability report
REPORT_DATE=$(date +%Y%m%d)
OUTPUT_DIR="reports/weekly_${REPORT_DATE}"

# Generate statistics
python3 vex_statistics.py --data-dir data --start-date $(date -d "-7 days" +%Y-%m-%d) --reset

# Create report directory
mkdir -p "$OUTPUT_DIR"

# Move results
mv stats/vex_statistics_*.csv "$OUTPUT_DIR/"
mv stats/vex_summary_*.txt "$OUTPUT_DIR/"

# Generate HTML report
python3 generate_html_report.py --input "$OUTPUT_DIR/vex_summary_*.txt" --output "$OUTPUT_DIR/report.html"

# Email report
echo "Weekly VEX Report - ${REPORT_DATE}" | mail -s "VEX Weekly Report" security-team@example.com -A "$OUTPUT_DIR/report.html"
```

### Data Integration

```python
# Example: Load statistics into pandas for advanced analysis
import pandas as pd
import glob

# Load all CSV files
df_list = []
for csv_file in glob.glob('stats/vex_statistics_*.csv'):
    df = pd.read_csv(csv_file)
    df['report_date'] = pd.to_datetime(csv_file.split('_')[-1].split('.')[0], format='%Y%m%d_%H%M%S')
    df_list.append(df)

# Combine all data
all_stats = pd.concat(df_list)

# Generate pivot tables
pivot_by_version = all_stats.pivot_table(
    index=['RHEL Version', 'Severity'],
    columns='Status Type',
    values='Count',
    aggfunc='sum'
)

# Save to Excel
pivot_by_version.to_excel('vex_analysis_pivot.xlsx')
```

## Troubleshooting

### No Files Found

**Issue**: "No VEX files found to analyze"

**Solutions**:
- Verify `--data-dir` points to correct directory
- Check that directory contains JSON files
- Ensure files have `.json` extension

### Slow Performance

**Issue**: Analysis takes too long

**Solutions**:
- Use `--start-date` to limit date range
- Reduce number of files with date filtering
- Run during off-peak hours
- Consider using `--resume` for incremental analysis

### Missing Data

**Issue**: Some RHEL versions show no data

**Solutions**:
- Check if you have data for those versions
- Verify file naming conventions
- Review RHEL pattern matching in script

### Index Corruption

**Issue**: Problems with resume functionality

**Solutions**:
- Use `--reset` to start fresh
- Delete `stats/stats_index.pkl` manually
- Check file permissions

## Best Practices

### Regular Updates

```bash
# Weekly synchronization and analysis
0 1 * * 1 /usr/bin/python3 redhat_vex_downloader.py --sync
0 2 * * 1 /usr/bin/python3 vex_statistics.py --data-dir data --resume
```

### Data Retention

```bash
# Keep statistics for 1 year
find stats/ -name "vex_*" -type f -mtime +365 -delete
```

### Version Control

```bash
# Track statistics changes in git
.gitignore:
stats/vex_statistics_*.csv
stats/vex_summary_*.txt

# But track index for resume capability
# stats/stats_index.pkl
```

### Backup

```bash
# Regular backup of statistics
tar -czvf vex_stats_backup_$(date +%Y%m%d).tar.gz stats/
```

## Integration with Other Tools

### SIEM Integration

```python
# Convert statistics to SIEM-friendly format
import json
import csv

def csv_to_siem(csv_file):
    siem_events = []
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            event = {
                'event_type': 'vex_statistics',
                'rhel_version': row['RHEL Version'],
                'severity': row['Severity'],
                'status': row['Status Type'],
                'count': int(row['Count']),
                'timestamp': datetime.now().isoformat()
            }
            siem_events.append(event)
    return siem_events
```

### Dashboard Integration

```python
# Generate data for dashboards
import pandas as pd

def generate_dashboard_data(csv_file):
    df = pd.read_csv(csv_file)
    
    # By RHEL version
    by_version = df.groupby('RHEL Version')['Count'].sum().reset_index()
    
    # By severity
    by_severity = df.groupby('Severity')['Count'].sum().reset_index()
    
    # By status
    by_status = df.groupby('Status Type')['Count'].sum().reset_index()
    
    return {
        'by_version': by_version.to_dict('records'),
        'by_severity': by_severity.to_dict('records'),
        'by_status': by_status.to_dict('records')
    }
```

## Future Enhancements

### Planned Features

- **Time-series analysis**: Track changes over time
- **Comparison reports**: Compare between date ranges
- **Visualization**: Built-in chart generation
- **Export formats**: JSON, Excel, HTML
- **Email notifications**: Automatic report delivery
- **API integration**: REST API for statistics access

### Contribution Ideas

- Add support for other Linux distributions
- Enhance RHEL version detection
- Improve severity classification
- Add more status types
- Implement caching for faster analysis

## Support

For issues or questions:
- Check the main README for contact information
- Open a GitHub issue with detailed description
- Include sample data if possible

## License

This tool is licensed under the MIT License. See the main LICENSE file for details.