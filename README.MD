# Sysvex

Modular system security auditing toolkit.

## Platform Support

✅ **Linux** - Full support  
✅ **Windows** - Full support  
✅ **macOS** - Full support

The app automatically detects your platform and adjusts its security checks accordingly.

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
# Run all default modules (filesystem, network, processes)
PYTHONPATH=src python -m sysvex.cli

# Run specific modules
PYTHONPATH=src python -m sysvex.cli --modules filesystem,network

# Run single module
PYTHONPATH=src python -m sysvex.cli --modules processes
```

### Module Options

#### Filesystem Module
- Scans for world-writable files
- Detects SUID/SGID executables
- Checks sensitive file permissions (/etc/passwd, /etc/shadow, etc.)
- Identifies hidden and recently modified files
- Default scan path: `/tmp`

#### Network Module
- Detects services listening on all interfaces (0.0.0.0)
- Identifies known public services (SSH, HTTP, FTP, etc.)
- Flags connections to suspicious ports
- Monitors unusual outbound connections
- Distinguishes between private and public IP connections

#### Process Module
- Detects suspicious binaries (from /tmp, hidden directories)
- Identifies suspicious command-line patterns (reverse shells, etc.)
- Monitors privilege anomalies (SetUID/SetGID)
- Flags non-system processes running as root
- Detects memory-only processes

### Output Format

The tool outputs findings in the following format:
```
[HIGH] World-writable file
  -> File is writable by others
  Evidence: /tmp/suspicious_file

[MEDIUM] Hidden file
  -> Hidden file detected
  Evidence: /tmp/.hidden_script
```

### Severity Levels

- **CRITICAL**: Immediate security risk
- **HIGH**: Serious security concern
- **MEDIUM**: Potential security issue
- **LOW**: Informational/monitoring

## Examples

```bash
# Scan filesystem for security issues
PYTHONPATH=src python -m sysvex.cli --modules filesystem

# Check network connections and listening services
PYTHONPATH=src python -m sysvex.cli --modules network

# Analyze running processes for suspicious activity
PYTHONPATH=src python -m sysvex.cli --modules processes

# Full security audit
PYTHONPATH=src python -m sysvex.cli
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