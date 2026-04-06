import os
import time
from .base import BaseModule
from sysvex.engine.models import Finding

HIDDEN_FILE_DAYS = 7

class Module(BaseModule):
    name = "filesystem"

    def run(self, scan_path="/tmp"):
        findings = []

        for root, _, files in os.walk(scan_path):
            for f in files:
                path = os.path.join(root, f)
                try:
                    # World-writable files
                    if os.stat(path).st_mode & 0o002:
                        findings.append(Finding(
                            id="FS-001",
                            title="World-writable file",
                            severity="HIGH",
                            description="File is writable by others",
                            evidence=path,
                            recommendation="Restrict permissions"
                        ))

                    # Hidden files
                    if f.startswith("."):
                        findings.append(Finding(
                            id="FS-002",
                            title="Hidden file",
                            severity="MEDIUM",
                            description="Hidden file detected",
                            evidence=path,
                            recommendation="Review file contents"
                        ))

                    # Recently modified files
                    mtime = os.path.getmtime(path)
                    if (time.time() - mtime) < (HIDDEN_FILE_DAYS * 86400):
                        findings.append(Finding(
                            id="FS-003",
                            title="Recently modified file",
                            severity="LOW",
                            description=f"File modified in last {HIDDEN_FILE_DAYS} days",
                            evidence=path,
                            recommendation="Check if change is expected"
                        ))

                except Exception:
                    continue

        return findings