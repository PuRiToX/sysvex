import os
import time
import stat
from sysvex.engine.models import Finding
from .base import BaseModule
from sysvex.utils.platform import get_default_scan_path, is_windows
from sysvex.utils.filters import (
    should_exclude_path, is_within_depth, should_skip_file_for_fp_reduction,
    is_likely_system_hidden_file, get_default_exclusions
)

# Changed from 7 to 30 days to reduce false positives
HIDDEN_FILE_DAYS = 30
# Maximum file size to analyze (100MB)
MAX_FILE_SIZE = 100 * 1024 * 1024

class Module(BaseModule):
    name = "filesystem"

    def run(self, context=None):
        # Get config from context if available, else load fresh
        if context and 'platform_config' in context:
            config = context['platform_config']
        else:
            from sysvex.utils.platform import get_platform_config
            config = get_platform_config()

        # Get filtering options from context
        user_exclusions = set(context.get('exclude_paths', [])) if context else set()
        max_depth = context.get('max_depth') if context else None

        # Merge default exclusions with user exclusions
        all_exclusions = get_default_exclusions() | set(config.get('default_exclusions', set()))
        if user_exclusions:
            all_exclusions = all_exclusions | set(user_exclusions)

        scan_path = context.get('scan_path', get_default_scan_path()) if context else get_default_scan_path()
        findings = []

        # Scan for sensitive file permissions
        for sensitive_path in config['sensitive_paths']:
            if not os.path.exists(sensitive_path):
                continue

            # Check exclusions
            if should_exclude_path(sensitive_path, all_exclusions):
                continue

            try:
                file_stat = os.stat(sensitive_path)
                mode = file_stat.st_mode

                # Skip if file is too large (not typical for sensitive files anyway)
                if file_stat.st_size > MAX_FILE_SIZE:
                    continue

                if not is_windows():
                    # Unix: Check for world-readable/writable sensitive files
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
                # Note: Removed Windows "try to open file" permission check - it was causing
                # errors and providing little value. Windows ACL checking requires pywin32.

            except (OSError, PermissionError, FileNotFoundError):
                continue

        # Walk directory tree with depth limiting
        for root, dirs, files in os.walk(scan_path):
            # Check depth limit
            if max_depth is not None:
                if not is_within_depth(scan_path, root, max_depth):
                    # Don't descend further
                    dirs[:] = []
                    continue

            # Filter directories to exclude
            dirs[:] = [
                d for d in dirs
                if not should_exclude_path(os.path.join(root, d), all_exclusions, scan_path)
            ]

            for filename in files:
                path = os.path.join(root, filename)

                # Check exclusions
                if should_exclude_path(path, all_exclusions, scan_path):
                    continue

                try:
                    file_stat = os.stat(path)

                    # Skip files that are too large or special files
                    if should_skip_file_for_fp_reduction(path, file_stat):
                        continue

                    mode = file_stat.st_mode

                    if not is_windows():
                        # Unix-specific checks
                        # World-writable files
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

                        # SUID/SGID files
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
                        # Windows: Only flag files in temp dirs as suspicious
                        temp_dirs = config.get('temp_dirs', [])
                        if any(path.lower().startswith(td.lower()) for td in temp_dirs):
                            # Only flag executable files in temp dirs
                            if filename.lower().endswith(('.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js')):
                                findings.append(Finding(
                                    finding_id="FS-001",
                                    title="Executable in temporary directory",
                                    severity="MEDIUM",
                                    description="Executable file located in temporary directory",
                                    evidence=path,
                                    recommendation="Review file - temporary directories are common attack vectors",
                                    source_module=self.name
                                ))

                    # Hidden files - with false positive reduction
                    if filename.startswith(".") or (is_windows() and filename.startswith("$")):
                        # Skip if likely a legitimate system/config file
                        if not is_likely_system_hidden_file(filename, path, is_windows()):
                            findings.append(Finding(
                                finding_id="FS-002",
                                title="Hidden file",
                                severity="MEDIUM",
                                description="Hidden file detected",
                                evidence=path,
                                recommendation="Review file contents",
                                source_module=self.name
                            ))

                    # Recently modified files - with increased threshold and exclusions
                    mtime = os.path.getmtime(path)
                    days_since_modified = (time.time() - mtime) / 86400

                    if days_since_modified < HIDDEN_FILE_DAYS:
                        # Skip system directories for recent file checks
                        system_dirs = ['/usr', '/bin', '/sbin', '/lib', '/lib64',
                                       'System32', 'SysWOW64', 'WinSxS', 'Program Files']
                        if not any(sd in path for sd in system_dirs):
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
