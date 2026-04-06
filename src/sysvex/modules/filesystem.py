import os
from .base import BaseModule
from sysvex.engine.models import Finding

class Module(BaseModule):
    name = "filesystem"

    def run(self):
        findings = []

        for root, _, files in os.walk("/tmp"):
            for f in files:
                path = os.path.join(root, f)
                try:
                    if os.stat(path).st_mode & 0o002:
                        findings.append(
                            Finding(
                                id="FS-001",
                                title="World-writable file",
                                severity="HIGH",
                                description="File is writable by others",
                                evidence=path,
                                recommendation="Restrict permissions"
                            )
                        )
                except Exception:
                    continue

        return findings