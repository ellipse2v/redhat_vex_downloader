# RPM to CVE Mapping Tool

## Overview

The RPM to CVE Mapping Tool is a powerful utility that maps RPM packages to their associated CVEs (Common Vulnerabilities and Exposures) with detailed vulnerability information. It generates comprehensive Excel reports that help security teams understand which packages are affected by known vulnerabilities and what remediation options are available.

## Features

### 🔍 Comprehensive RPM Analysis
- **NEVRA Format Support**: Parses RPM names in Name-Epoch:Version-Release.Architecture format
- **Multi-RPM Processing**: Analyzes lists of RPMs from CSV files
- **Detailed CVE Information**: Extracts CVSS scores, vectors, and severity levels

### 📊 Excel Reporting
- **Multiple Sheets**: Separate sheets for Fixed, Not Fixed, and Affected packages
- **Conditional Formatting**: Color-coded CVSS scores by severity
- **Summary Statistics**: Overview of findings with percentages
- **Professional Layout**: Tables with proper formatting and styles

### 🎯 Categorization
- **Fixed Packages**: RPMs with available fixes
- **Not Fixed Packages**: RPMs confirmed not affected
- **Affected Packages**: RPMs known to be vulnerable
- **Severity Classification**: Critical, Important, Moderate, Low, Unknown

### 📈 Detailed Information
- **CVSS Scores**: Numerical vulnerability scores
- **CVSS Vectors**: Complete vulnerability vectors
- **Severity Levels**: Human-readable risk assessment
- **Remediation Info**: Fix information for vulnerable packages

## Installation

### Requirements

```bash
pip install openpyxl
```

The tool requires the `openpyxl` library for Excel report generation.

## Usage

### Basic Usage

```bash
# Map RPMs to CVEs
python3 rpm_to_cve.py --rpm-list rpm_list.csv --data-dir data

# Specify output file name
python3 rpm_to_cve.py --rpm-list rpm_list.csv --output my_report.xlsx
```

### Input File Format

The RPM list should be a CSV file with one RPM per line in NEVRA format:

```csv
rpm
kernel-3:3.10.0-1160.el7.x86_64
openssl-1:1.0.2k-21.el7_9.x86_64
httpd-2:2.4.6-97.el7_9.x86_64
```

Or with header:

```csv
package
kernel-3:3.10.0-1160.el7.x86_64
openssl-1:1.0.2k-21.el7_9.x86_64
httpd-2:2.4.6-97.el7_9.x86_64
```

### NEVRA/NEVR Format

The tool supports both NEVRA and NEVR formats:

**NEVRA (with Architecture)**:
```
Name-Epoch:Version-Release.Architecture
```

**NEVR (without Architecture)**:
```
Name-Epoch:Version-Release
```

Examples:
- `kernel-3:3.10.0-1160.el7.x86_64` (NEVRA)
- `openssl-1:1.0.2k-21.el7_9.x86_64` (NEVRA)
- `httpd-2:2.4.6-97.el7_9` (NEVR)
- `bash-4:4.2.46-35.el7_9` (NEVR)

The tool automatically detects and handles both formats.

## Output

The tool generates an Excel file with multiple sheets:

### 1. Summary Sheet

Overview statistics including:
- Total RPMs analyzed
- RPMs with/without CVEs
- CVE distribution by category
- Severity breakdown

### 2. Fixed Sheet

RPMs with available fixes:
- **RPM**: Package name
- **CVE**: Vulnerability ID
- **Severity**: Risk level
- **CVSS Score**: Numerical score (color-coded)
- **CVSS Vector**: Complete vector string
- **Fixed In**: Remediation information

### 3. Not Fixed Sheet

RPMs confirmed not affected:
- **RPM**: Package name
- **CVE**: Vulnerability ID
- **Severity**: Risk level
- **CVSS Score**: Numerical score
- **CVSS Vector**: Complete vector string
- **Additional Info**: Source file reference

### 4. Affected Sheet

RPMs known to be vulnerable:
- **RPM**: Package name
- **CVE**: Vulnerability ID
- **Severity**: Risk level
- **CVSS Score**: Numerical score (color-coded)
- **CVSS Vector**: Complete vector string
- **Additional Info**: Source file reference

## Practical Use Cases

### 🛡️ Security Patch Management

```bash
# Analyze current system RPMs
rpm -qa --qf "%{NAME}-%{EPOCH}:%{VERSION}-%{RELEASE}.%{ARCH}\n" > system_rpms.csv

# Generate CVE report
python3 rpm_to_cve.py --rpm-list system_rpms.csv --data-dir data

# Review critical vulnerabilities
# Open the Excel file and filter by "Critical" severity
```

### 📦 Package Update Planning

```bash
# Compare current vs proposed packages
echo "Current packages:" > comparison.csv
rpm -qa --qf "%{NAME}-%{EPOCH}:%{VERSION}-%{RELEASE}.%{ARCH}\n" >> comparison.csv
echo "" >> comparison.csv
echo "Proposed packages:" >> comparison.csv
yum list updates --qf "%{name}-%{epoch}:%{version}-%{release}.%{arch}\n" >> comparison.csv

# Analyze both sets
python3 rpm_to_cve.py --rpm-list comparison.csv --data-dir data
```

### 🔍 Vulnerability Assessment

```bash
# Assess specific packages
cat > critical_packages.csv << EOF
package
openssl-1:1.0.2k-21.el7_9.x86_64
kernel-3:3.10.0-1160.el7.x86_64
httpd-2:2.4.6-97.el7_9.x86_64
EOF

# Generate detailed report
python3 rpm_to_cve.py --rpm-list critical_packages.csv --data-dir data

# Focus on critical vulnerabilities only
# Use Excel filtering to show only "Critical" severity
```

### 📊 Compliance Reporting

```bash
# Monthly vulnerability report
python3 rpm_to_cve.py --rpm-list production_servers.csv --data-dir data --output monthly_report_$(date +%Y%m).xlsx

# Archive for compliance
cp reports/*.xlsx compliance_archive/
```

### 🚀 CI/CD Integration

```yaml
# GitHub Actions example
- name: Check for vulnerabilities
  run: |
    python3 rpm_to_cve.py --rpm-list package_list.csv --data-dir data --output vulnerabilities.xlsx
    
    # Fail if critical vulnerabilities found
    if grep -q "Critical" reports/vulnerabilities.xlsx; then
      echo "❌ Critical vulnerabilities found!"
      exit 1
    fi
```

## Understanding the Results

### CVSS Scores

The tool uses CVSS (Common Vulnerability Scoring System) to assess vulnerability severity:

- **Critical (9.0-10.0)**: 🔴 Highest risk, immediate action required
- **Important (7.0-8.9)**: 🟠 High risk, patch soon
- **Moderate (4.0-6.9)**: 🟡 Medium risk, schedule patching
- **Low (0.1-3.9)**: 🟢 Low risk, patch as resources allow
- **Unknown**: ⚪ No score available

### Status Categories

- **Fixed**: Package has an available fix or update
- **Not Fixed**: Package is confirmed not vulnerable
- **Affected**: Package is known to be vulnerable
- **Under Investigation**: Status is being determined

### Excel Features

- **Color Coding**: CVSS scores are color-coded by severity
- **Tables**: Properly formatted tables for easy analysis
- **Filtering**: Use Excel's filter capabilities to focus on specific issues
- **Sorting**: Sort by severity, RPM name, or CVE ID

## Advanced Usage

### Automated Reporting

```bash
#!/bin/bash
# Weekly vulnerability report
REPORT_DATE=$(date +%Y%m%d)
OUTPUT_FILE="rpm_vulnerabilities_${REPORT_DATE}.xlsx"

# Generate current RPM list
rpm -qa --qf "%{NAME}-%{EPOCH}:%{VERSION}-%{RELEASE}.%{ARCH}\n" > current_rpms.csv

# Generate report
python3 rpm_to_cve.py --rpm-list current_rpms.csv --data-dir data --output "$OUTPUT_FILE"

# Email report
echo "Weekly RPM Vulnerability Report" | mail -s "Vulnerability Report" security-team@example.com -A "reports/$OUTPUT_FILE"
```

### Multiple Server Analysis

```bash
# Analyze multiple servers
for server in server1 server2 server3; do
    echo "Analyzing $server..."
    ssh $server "rpm -qa --qf '%{NAME}-%{EPOCH}:%{VERSION}-%{RELEASE}.%{ARCH}\n'" > "${server}_rpms.csv"
    python3 rpm_to_cve.py --rpm-list "${server}_rpms.csv" --data-dir data --output "${server}_report.xlsx"
done

# Combine reports
python3 combine_reports.py --input reports/*_report.xlsx --output combined_vulnerabilities.xlsx
```

### Integration with Other Tools

```python
# Convert Excel to JSON for API consumption
import pandas as pd
import json

def excel_to_json(excel_file):
    # Read all sheets
    xls = pd.ExcelFile(excel_file)
    
    results = {}
    for sheet_name in xls.sheet_names:
        df = pd.read_excel(excel_file, sheet_name=sheet_name)
        results[sheet_name] = df.to_dict('records')
    
    return json.dumps(results, indent=2)

# Save as JSON
with open('vulnerabilities.json', 'w') as f:
    f.write(excel_to_json('reports/rpm_vulnerabilities.xlsx'))
```

## Troubleshooting

### No RPMs Found

**Issue**: "No RPMs found in the input file"

**Solutions**:
- Verify file path is correct
- Check file permissions
- Ensure file contains RPM data
- Confirm NEVRA format is correct

### No VEX Files Found

**Issue**: "No VEX files found to process"

**Solutions**:
- Run `redhat_vex_downloader.py --sync` first
- Verify data directory path
- Check that VEX files exist in data/year/ directories

### Slow Performance

**Issue**: Analysis takes too long

**Solutions**:
- Process smaller RPM lists
- Use incremental analysis
- Run during off-peak hours
- Consider using `--resume` for large datasets

### Excel File Issues

**Issue**: Problems opening Excel file

**Solutions**:
- Ensure openpyxl is installed
- Check file permissions
- Try opening with different spreadsheet software
- Verify disk space is available

## Best Practices

### Regular Scanning

```bash
# Weekly scan
0 2 * * 1 /usr/bin/python3 rpm_to_cve.py --rpm-list production_rpms.csv --data-dir data --output weekly_report.xlsx
```

### Version Control

```bash
# Track changes in reports
.gitignore:
reports/*.xlsx

# But track RPM lists
# rpm_lists/*.csv
```

### Data Retention

```bash
# Keep reports for 6 months
find reports/ -name "*.xlsx" -type f -mtime +180 -delete
```

### Backup

```bash
# Regular backup
tar -czvf rpm_cve_backup_$(date +%Y%m%d).tar.gz reports/
```

## Integration Examples

### SIEM Integration

```python
# Convert to SIEM events
import pandas as pd

def excel_to_siem(excel_file):
    xls = pd.ExcelFile(excel_file)
    
    for sheet_name in xls.sheet_names:
        df = pd.read_excel(excel_file, sheet_name=sheet_name)
        
        for _, row in df.iterrows():
            event = {
                'event_type': 'rpm_vulnerability',
                'rpm': row['RPM'],
                'cve': row['CVE'],
                'severity': row['Severity'],
                'cvss_score': row['CVSS Score'],
                'status': sheet_name,
                'timestamp': datetime.now().isoformat()
            }
            # Send to SIEM
            send_to_siem(event)
```

### Dashboard Integration

```python
# Generate dashboard data
import pandas as pd

def generate_dashboard_data(excel_file):
    xls = pd.ExcelFile(excel_file)
    
    # By severity
    severity_data = []
    for sheet_name in xls.sheet_names:
        df = pd.read_excel(excel_file, sheet_name=sheet_name)
        severity_counts = df['Severity'].value_counts()
        for severity, count in severity_counts.items():
            severity_data.append({
                'category': sheet_name,
                'severity': severity,
                'count': count
            })
    
    return severity_data
```

## Future Enhancements

### Planned Features

- **HTML Reports**: Web-based reporting
- **JSON API**: Programmatic access to results
- **Email Notifications**: Automatic alerts for critical vulnerabilities
- **Trend Analysis**: Historical comparison
- **Remediation Guidance**: Detailed fix instructions

### Contribution Ideas

- Add support for other package formats
- Enhance RPM matching algorithms
- Improve CVSS vector parsing
- Add more severity classification options
- Implement caching for faster analysis

## Support

For issues or questions:
- Check the main README for contact information
- Open a GitHub issue with detailed description
- Include sample RPM list and VEX files if possible

## License

This tool is licensed under the MIT License. See the main LICENSE file for details.