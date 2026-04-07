import psutil
import ipaddress
from sysvex.engine.models import Finding
from .base import BaseModule

# Common public service ports
PUBLIC_SERVICES = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    993: "IMAPS", 995: "POP3S", 3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL"
}

# Suspicious remote ports (commonly used in attacks)
SUSPICIOUS_PORTS = {
    4444: "Metasploit", 5555: "Android Debug", 6667: "IRC", 8080: "Proxy",
    8443: "Alternative HTTPS", 9000: "Alternative HTTP", 12345: "NetBus",
    31337: "Back Orifice", 5900: "VNC"
}

class Module(BaseModule):
    name = "network"

    def run(self, context=None):
        findings = []

        # Get all network connections once (performance fix)
        try:
            all_connections = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, psutil.Error):
            # Can't access network connections on some systems
            return findings

        # Build listening ports set for efficient lookup
        listening_ports = {}
        for conn in all_connections:
            if conn.status == "LISTEN" and conn.laddr:
                listening_ports[conn.laddr.port] = conn
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            status = conn.status

            # High severity: listening on all interfaces for public services
            if conn.status == "LISTEN" and conn.laddr and conn.laddr.ip == "0.0.0.0":
                service_name = PUBLIC_SERVICES.get(conn.laddr.port, "Unknown service")
                findings.append(Finding(
                    finding_id="NET-001",
                    title="Public service listening on all interfaces",
                    severity="HIGH",
                    description=f"{service_name} listening on 0.0.0.0:{conn.laddr.port}",
                    evidence=f"Local: {laddr}, Service: {service_name}",
                    recommendation="Bind service to specific IP or firewall if not intended for public",
                    source_module=self.name
                ))

            # Medium severity: unknown public services
            if conn.status == "LISTEN" and conn.laddr and conn.laddr.port in PUBLIC_SERVICES:
                service_name = PUBLIC_SERVICES[conn.laddr.port]
                findings.append(Finding(
                    finding_id="NET-003",
                    title="Known public service detected",
                    severity="MEDIUM",
                    description=f"{service_name} service is running",
                    evidence=f"Local: {laddr}, Service: {service_name}",
                    recommendation="Ensure service is properly configured and secured",
                    source_module=self.name
                ))

            # High severity: connections to suspicious ports
            if conn.status == "ESTABLISHED" and conn.raddr and conn.raddr.port in SUSPICIOUS_PORTS:
                suspicious_service = SUSPICIOUS_PORTS[conn.raddr.port]
                findings.append(Finding(
                    finding_id="NET-004",
                    title="Connection to suspicious port",
                    severity="HIGH",
                    description=f"Connection to {suspicious_service} service on port {conn.raddr.port}",
                    evidence=f"Local: {laddr}, Remote: {raddr}, Service: {suspicious_service}",
                    recommendation="Investigate potential malicious activity",
                    source_module=self.name
                ))

            # Medium severity: established connections to unknown remote addresses
            if conn.status == "ESTABLISHED" and conn.raddr:
                # Check if remote IP is public (not private)
                if not self._is_private_ip(conn.raddr.ip):
                    findings.append(Finding(
                        finding_id="NET-002",
                        title="Established external connection",
                        severity="MEDIUM",
                        description="Connection established to remote host",
                        evidence=f"Local: {laddr}, Remote: {raddr}, Status: {status}",
                        recommendation="Verify connection is expected and authorized",
                        source_module=self.name
                    ))

            # Low severity: unusual outbound connection patterns
            if conn.status == "ESTABLISHED" and conn.raddr and conn.raddr.port > 1024:
                if conn.raddr.port not in PUBLIC_SERVICES and conn.raddr.port not in SUSPICIOUS_PORTS:
                    findings.append(Finding(
                        finding_id="NET-005",
                        title="Unusual outbound connection",
                        severity="LOW",
                        description=f"Connection to non-standard port {conn.raddr.port}",
                        evidence=f"Local: {laddr}, Remote: {raddr}",
                        recommendation="Monitor for potential data exfiltration",
                        source_module=self.name
                    ))

        return findings
    
    def _is_private_ip(self, ip):
        """Check if IP address is private"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            # Fallback to basic check for common private ranges
            return (ip.startswith('10.') or ip.startswith('192.168.') or 
                   ip.startswith('172.') or ip.startswith('127.') or
                   ip.startswith('169.254.'))
