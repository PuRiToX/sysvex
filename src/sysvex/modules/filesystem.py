import os
import time
import stat
from sysvex.engine.models import Finding
from .base import BaseModule
from sysvex.utils.platform import get_platform_config, get_default_scan_path, is_windows

HIDDEN_FILE_DAYS = 7

class Module(BaseModule):
    name = "filesystem"

    def run(self, context=None):
        config = get_platform_config()
        scan_path = context.get('scan_path', get_default_scan_path()) if context else get_default_scan_path()
        findings = []

        # Scan for sensitive file permissions
        for sensitive_path in config['sensitive_paths']:
            if os.path.exists(sensitive_path):
                try:
                    file_stat = os.stat(sensitive_path)
                    mode = file_stat.st_mode
                    
                    # Check for world-readable sensitive files (Unix only)
                    if not is_windows():
                        if mode & stat.S_IROTH:
                            findings.append(Finding(
                                finding_id="FS-004",
                                title="World-readable sensitive file",
                                severity="HIGH",
                                description=f"Sensitive file {sensitive_path} is readable by others",
                                evidence=sensitive_path,
                                recommendation="Restrict permissions: chmod o-r {sensitive_path}",
                                source_module=self.name
                            ))
                        
                        # Check for world-writable sensitive files (Unix only)
                        if mode & stat.S_IWOTH:
                            findings.append(Finding(
                                finding_id="FS-005",
                                title="World-writable sensitive file",
                                severity="CRITICAL",
                                description=f"Sensitive file {sensitive_path} is writable by others",
                                evidence=sensitive_path,
                                recommendation="Restrict permissions: chmod o-w {sensitive_path}",
                                source_module=self.name
                            ))
                    else:
                        # Windows: Check if sensitive file has weak permissions
                        # This is a simplified check - in reality, Windows ACLs are more complex
                        try:
                            # Try to read the file - if we can, it might be too permissive
                            with open(sensitive_path, 'r', encoding='utf-8') as f:
                                f.read(1)  # Try to read first byte
                            findings.append(Finding(
                                finding_id="FS-004",
                                title="Sensitive file with potentially weak permissions",
                                severity="MEDIUM",
                                description=f"Sensitive file {sensitive_path} may have overly permissive access",
                                evidence=sensitive_path,
                                recommendation="Review file permissions and ACLs",
                                source_module=self.name
                            ))
                        except (PermissionError, OSError):
                            # Good - file is properly protected
                            pass
                        
                except (OSError, PermissionError, FileNotFoundError):
                    continue

        for root, _, files in os.walk(scan_path):
            for f in files:
                path = os.path.join(root, f)
                try:
                    file_stat = os.stat(path)
                    mode = file_stat.st_mode
                    
                    # World-writable files (Unix only)
                    if not is_windows():
                        if mode & stat.S_IWOTH:
                            findings.append(Finding(
                                finding_id="FS-001",
                                title="World-writable file",
                                severity="HIGH",
                                description="File is writable by others",
                                evidence=path,
                                recommendation="Restrict permissions: chmod o-w {path}",
                                source_module=self.name
                            ))

                        # SUID/SGID files (Unix only)
                        if mode & stat.S_ISUID:
                            findings.append(Finding(
                                finding_id="FS-006",
                                title="SUID executable",
                                severity="HIGH",
                                description="File has SUID bit set - runs with owner privileges",
                                evidence=path,
                                recommendation="Verify SUID bit is necessary and file is secure",
                                source_module=self.name
                            ))
                        
                        if mode & stat.S_ISGID:
                            findings.append(Finding(
                                finding_id="FS-007",
                                title="SGID executable",
                                severity="MEDIUM",
                                description="File has SGID bit set - runs with group privileges",
                                evidence=path,
                                recommendation="Verify SGID bit is necessary and file is secure",
                                source_module=self.name
                            ))
                    else:
                        # Windows: Check for files in suspicious locations
                        if any(path.lower().startswith(temp_dir.lower()) for temp_dir in config['temp_dirs']):
                            findings.append(Finding(
                                finding_id="FS-001",
                                title="File in temporary directory",
                                severity="MEDIUM",
                                description="File located in temporary directory",
                                evidence=path,
                                recommendation="Review file - temporary directories are common attack vectors",
                                source_module=self.name
                            ))

                    # Hidden files (cross-platform)
                    if f.startswith(".") or (is_windows() and f.startswith("$")):
                        findings.append(Finding(
                            finding_id="FS-002",
                            title="Hidden file",
                            severity="MEDIUM",
                            description="Hidden file detected",
                            evidence=path,
                            recommendation="Review file contents",
                            source_module=self.name
                        ))

                    # Recently modified files (cross-platform)
                    mtime = os.path.getmtime(path)
                    if (time.time() - mtime) < (HIDDEN_FILE_DAYS * 86400):
                        findings.append(Finding(
                            finding_id="FS-003",
                            title="Recently modified file",
                            severity="LOW",
                            description=f"File modified in last {HIDDEN_FILE_DAYS} days",
                            evidence=path,
                            recommendation="Check if change is expected",
                            source_module=self.name
                        ))

                except (OSError, PermissionError, FileNotFoundError):
                    continue

        return findings
