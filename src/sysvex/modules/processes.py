import psutil
from sysvex.engine.models import Finding
from .base import BaseModule
from sysvex.utils.platform import get_platform_config, is_windows

class Module(BaseModule):
    name = "processes"

    def run(self, context=None):
        config = get_platform_config()
        findings = []

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'uids', 'gids']):
            try:
                proc_info = proc.info
                
                # Skip if we can't get basic info
                if not proc_info['name'] or not proc_info['exe']:
                    continue

                # Check for unsigned/unexpected binaries
                if self._is_suspicious_binary(proc_info['exe'], config):
                    findings.append(Finding(
                        finding_id="PROC-001",
                        title="Suspicious or unsigned binary",
                        severity="HIGH",
                        description=f"Process running from suspicious location: {proc_info['exe']}",
                        evidence=f"PID: {proc_info['pid']}, Name: {proc_info['name']}, Path: {proc_info['exe']}",
                        recommendation="Investigate binary authenticity and origin",
                        source_module=self.name
                    ))

                # Check for suspicious command-line patterns
                if proc_info['cmdline']:
                    cmdline = ' '.join(proc_info['cmdline']).lower()
                    for pattern in config['suspicious_patterns']:
                        if pattern in cmdline:
                            findings.append(Finding(
                                finding_id="PROC-002",
                                title="Suspicious command-line pattern",
                                severity="HIGH",
                                description=f"Process with suspicious command line: {pattern}",
                                evidence=f"PID: {proc_info['pid']}, Command: {' '.join(proc_info['cmdline'])}",
                                recommendation="Investigate potential malicious activity",
                                source_module=self.name
                            ))
                            break  # Only report once per process

                # Check for privilege anomalies
                if proc_info['uids'] and proc_info['gids']:
                    real_uid, effective_uid, saved_uid = proc_info['uids']
                    real_gid, effective_gid, saved_gid = proc_info['gids']

                    # Process running with elevated privileges (Unix: root, Windows: admin)
                    if is_windows():
                        # Windows: Check for SYSTEM or Administrator privileges
                        if effective_uid == 0 and not self._is_system_process(proc_info['name'], config):
                            findings.append(Finding(
                                finding_id="PROC-003",
                                title="Non-system process with elevated privileges",
                                severity="MEDIUM",
                                description=f"Process {proc_info['name']} running with elevated privileges",
                                evidence=f"PID: {proc_info['pid']}, Name: {proc_info['name']}, User: {proc_info['username']}",
                                recommendation="Verify if elevated privileges are necessary",
                                source_module=self.name
                            ))
                    else:
                        # Unix: Check for root privileges
                        if effective_uid == 0 and not self._is_system_process(proc_info['name'], config):
                            findings.append(Finding(
                                finding_id="PROC-003",
                                title="Non-system process running as root",
                                severity="MEDIUM",
                                description=f"Process {proc_info['name']} running with root privileges",
                                evidence=f"PID: {proc_info['pid']}, Name: {proc_info['name']}, User: {proc_info['username']}",
                                recommendation="Verify if root privileges are necessary",
                                source_module=self.name
                            ))

                    # SetUID/SetGID anomalies
                    if real_uid != effective_uid:
                        findings.append(Finding(
                            finding_id="PROC-004",
                            title="Process with elevated user privileges",
                            severity="HIGH",
                            description=f"Process running with different effective UID than real UID",
                            evidence=f"PID: {proc_info['pid']}, Real UID: {real_uid}, Effective UID: {effective_uid}",
                            recommendation="Investigate privilege escalation",
                            source_module=self.name
                        ))

                    if real_gid != effective_gid:
                        findings.append(Finding(
                            finding_id="PROC-005",
                            title="Process with elevated group privileges",
                            severity="MEDIUM",
                            description=f"Process running with different effective GID than real GID",
                            evidence=f"PID: {proc_info['pid']}, Real GID: {real_gid}, Effective GID: {effective_gid}",
                            recommendation="Investigate group privilege escalation",
                            source_module=self.name
                        ))

                # Check for processes with no executable path (potential malware)
                if not proc_info['exe'] and proc_info['name']:
                    findings.append(Finding(
                        finding_id="PROC-006",
                        title="Process without executable path",
                        severity="HIGH",
                        description=f"Process {proc_info['name']} has no associated executable",
                        evidence=f"PID: {proc_info['pid']}, Name: {proc_info['name']}",
                        recommendation="Investigate potential memory-only malware",
                        source_module=self.name
                    ))

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return findings

    def _is_suspicious_binary(self, exe_path, config):
        """Check if binary is in suspicious location or has suspicious characteristics"""
        if not exe_path:
            return True

        # Common legitimate binary locations
        legitimate_paths = config['legitimate_paths']

        # Check if binary is in legitimate location
        is_legitimate = any(exe_path.lower().startswith(path.lower()) for path in legitimate_paths)
        
        # Check for temporary directories
        suspicious_paths = config['temp_dirs']
        is_suspicious = any(exe_path.lower().startswith(temp_dir.lower()) for temp_dir in suspicious_paths)

        # Check for hidden directories
        if "/." in exe_path and not is_legitimate:
            is_suspicious = True
        
        # Windows-specific hidden directory check
        if is_windows() and ("\\." in exe_path or exe_path.startswith("\\\\?\\")):
            is_suspicious = True

        return is_suspicious or not is_legitimate

    def _is_system_process(self, process_name, config):
        """Check if process is a known system process"""
        if not process_name:
            return False
        
        # Check against whitelist
        for legitimate in config['legitimate_processes']:
            if legitimate.lower() in process_name.lower():
                return True
        
        # Platform-specific checks
        if is_windows():
            # Windows system processes
            if process_name.lower().endswith('.exe') and any(sys_proc in process_name.lower() for sys_proc in ['system', 'smss', 'csrss', 'wininit', 'services']):
                return True
        else:
            # Unix kernel processes
            if process_name.startswith('[') and process_name.endswith(']'):
                return True
        
        return False