# Sysvex

Modular system security auditing toolkit.

## Platform Support

✅ **Linux** - Full support  
✅ **Windows** - Full support  
✅ **macOS** - Full support

The app automatically detects your platform and adjusts its security checks accordingly.

## Features

- **Cross-platform security auditing** for Windows, Linux, and macOS
- **Multiple output formats**: JSON, HTML, CSV, and console
- **Automated report organization** in Documents folder
- **Modular architecture** with extensible security modules
- **Professional reports** with severity classification and recommendations

## Installation

```bash
# Install from source
git clone <repository-url>
cd sysvex
pip install -e .

# Or install dependencies manually
pip install psutil
```

## Usage

### Basic Usage

```bash
# Run all default modules (filesystem, network, processes) - console output
sysvex

# Run specific modules
sysvex --modules filesystem,network

# Run single module
sysvex --modules processes
```

### Output Formats

```bash
# Save to JSON (auto-saved to Documents/Sysvex Auditing/)
sysvex --format json

# Save to HTML report with visual dashboard
sysvex --format html

# Save to CSV for spreadsheet analysis
sysvex --format csv

# Console output (default)
sysvex --format console
```

### Custom Output Paths

```bash
# Custom filename in default directory
sysvex --format json --output security_audit.json

# Full custom path
sysvex --format html --output /path/to/report.html

# Windows example
sysvex --format csv --output C:\Reports\security.csv

# Quiet mode (no console output)
sysvex --format json --quiet
```

## Module Options

### Filesystem Module
- **World-writable files**: Detects files writable by others
- **SUID/SGID executables**: Identifies files with elevated privileges (Unix only)
- **Sensitive file permissions**: Checks `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` (Unix) or SAM database (Windows)
- **Hidden files**: Flags hidden files and temporary files
- **Recently modified files**: Tracks changes within 7 days

### Network Module
- **Listening ports**: Detects services listening on all interfaces (0.0.0.0)
- **Public services**: Identifies known services (SSH, HTTP, FTP, etc.)
- **Suspicious connections**: Flags connections to known malicious ports
- **Outbound connections**: Monitors unusual outbound patterns
- **IP classification**: Distinguishes between private and public IP connections

### Process Module
- **Suspicious binaries**: Detects processes from unexpected locations
- **Command-line patterns**: Identifies reverse shells, download tools, persistence mechanisms
- **Privilege anomalies**: Monitors privilege escalation attempts
- **System processes**: Flags non-system processes running with elevated privileges
- **Memory-only processes**: Detects processes without executable paths

## Platform-Specific Features

### Windows
- **Sensitive files**: SAM database, hosts file, network configurations
- **Suspicious processes**: PowerShell encoded commands, rundll32, certutil
- **Temp directories**: `%TEMP%`, `%TMP%`, System32 temp
- **Legitimate paths**: Program Files, System32, ProgramData

### Linux/Unix
- **Sensitive files**: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`
- **SUID/SGID detection**: Unix permission escalation vectors
- **Unix permissions**: World-readable/writable file detection
- **Standard paths**: `/usr/bin`, `/bin`, `/sbin`

### macOS
- Inherits Unix/Linux functionality
- macOS-specific paths and processes

## Output Format Examples

### JSON Output
```json
{
  "scan_info": {
    "timestamp": "2024-01-15T10:30:00",
    "total_findings": 42,
    "severity_breakdown": {
      "CRITICAL": 2,
      "HIGH": 8,
      "MEDIUM": 15,
      "LOW": 17
    }
  },
  "findings": [
    {
      "id": "FS-001",
      "title": "World-writable file",
      "severity": "HIGH",
      "description": "File is writable by others",
      "evidence": "/tmp/suspicious_file",
      "recommendation": "Restrict permissions: chmod o-w /tmp/suspicious_file",
      "source_module": "filesystem"
    }
  ]
}
```

### HTML Report
- Visual dashboard with color-coded severity levels
- Summary statistics and charts
- Expandable finding details
- Professional appearance for sharing

### CSV Output
- Spreadsheet-compatible format
- All finding details in tabular format
- Easy for data analysis and filtering

## Report Organization

Reports are automatically saved to:
- **Linux/macOS**: `~/Documents/Sysvex Auditing/`
- **Windows**: `C:\Users\{Username}\Documents\Sysvex Auditing/`

Files are automatically timestamped: `sysvex_report_YYYYMMDD_HHMMSS.format`

## Severity Levels

- **CRITICAL**: Immediate security risk
- **HIGH**: Serious security concern
- **MEDIUM**: Potential security issue
- **LOW**: Informational/monitoring

## Examples

```bash
# Quick security scan with HTML report
sysvex --format html

# Detailed analysis with JSON for automation
sysvex --format json --modules all

# Silent background scan
sysvex --format csv --quiet --output security_scan.csv

# Custom filename
sysvex --format html --output "security_audit_$(date +%Y%m%d).html"

# Scan specific module with custom output
sysvex --modules filesystem --format json --output filesystem_audit.json
```

## Development

```bash
# Run with development setup
export PYTHONPATH=src
python -m sysvex.cli

# Test individual modules
python -c "
from sysvex.modules.filesystem import Module
module = Module()
findings = module.run({'scan_path': '/tmp'})
print(f'Found {len(findings)} issues')
"
```

## Publishing

See the [publishing guide](https://github.com/PuRiToX/sysvex#publishing) for detailed instructions on publishing to PyPI.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Support

- **Issues**: [GitHub Issues](https://github.com/PuRiToX/sysvex/issues)
- **Documentation**: [GitHub Wiki](https://github.com/PuRiToX/sysvex/wiki)