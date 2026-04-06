import psutil
from .base import BaseModule
from sysvex.engine.models import Finding

class Module(BaseModule):
    name = "network"

    def run(self):
        findings = []

        # Get all current network connections
        for conn in psutil.net_connections(kind='inet'):
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            status = conn.status

            # High severity: listening on all interfaces
            if conn.status == "LISTEN" and conn.laddr.ip == "0.0.0.0":
                findings.append(Finding(
                    id="NET-001",
                    title="Service listening on all interfaces",
                    severity="HIGH",
                    description=f"Service listening on 0.0.0.0:{conn.laddr.port}",
                    evidence=f"Local: {laddr}, Remote: {raddr}, Status: {status}",
                    recommendation="Bind service to specific IP if not intended for public"
                ))

            # Medium severity: established connections to unknown remote addresses
            if conn.status == "ESTABLISHED" and conn.raddr:
                findings.append(Finding(
                    id="NET-002",
                    title="Established external connection",
                    severity="MEDIUM",
                    description="Connection established to remote host",
                    evidence=f"Local: {laddr}, Remote: {raddr}, Status: {status}",
                    recommendation="Verify connection is expected"
                ))

        return findings