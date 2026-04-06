import platform as _platform
import os

def get_platform():
    """Get the current platform name"""
    return _platform.system().lower()

def is_windows():
    """Check if running on Windows"""
    return get_platform() == 'windows'

def is_linux():
    """Check if running on Linux"""
    return get_platform() == 'linux'


def get_default_reports_dir():
    """Get default reports directory for the current platform"""
    if is_windows():
        # Windows: Documents\Sysvex Audits
        documents = os.path.expandvars(r'%USERPROFILE%\Documents')
        return os.path.join(documents, 'Sysvex Audits')
    else:
        # Linux: ~/Documents/Sysvex Audits
        home = os.path.expanduser('~')
        return os.path.join(home, 'Documents', 'Sysvex Audits')

def ensure_reports_dir():
    """Ensure reports directory exists and return path"""
    reports_dir = get_default_reports_dir()
    os.makedirs(reports_dir, exist_ok=True)
    return reports_dir

def get_platform_config():
    """Get platform-specific configuration"""
    if is_windows():
        return {
            'sensitive_paths': [
                os.path.expandvars(r'%SystemRoot%\System32\config\SAM'),
                os.path.expandvars(r'%SystemRoot%\System32\drivers\etc\hosts'),
                os.path.expandvars(r'%SystemRoot%\System32\drivers\etc\networks'),
                os.path.expandvars(r'%SystemRoot%\System32\config\SECURITY'),
                os.path.expandvars(r'%ProgramData%\Microsoft\Network\Connections\Pbk\rasphone.pbk'),
            ],
            'temp_dirs': [
                os.path.expandvars(r'%TEMP%'),
                os.path.expandvars(r'%TMP%'),
                os.path.expandvars(r'%SystemRoot%\Temp'),
            ],
            'legitimate_paths': [
                os.path.expandvars(r'%SystemRoot%\System32'),
                os.path.expandvars(r'%SystemRoot%\SysWOW64'),
                os.path.expandvars(r'%ProgramFiles%'),
                os.path.expandvars(r'%ProgramFiles(x86)%'),
                os.path.expandvars(r'%ProgramData%'),
            ],
            'suspicious_patterns': [
                'powershell -c', 'cmd /c', 'powershell.exe -enc',
                'rundll32.exe', 'regsvr32.exe', 'certutil.exe',
                'bitsadmin.exe', 'wmic.exe', 'netsh.exe',
                'schtasks.exe', 'sc.exe', 'wevtutil.exe'
            ],
            'legitimate_processes': {
                'svchost.exe', 'lsass.exe', 'winlogon.exe', 'explorer.exe',
                'chrome.exe', 'firefox.exe', 'code.exe', 'python.exe',
                'java.exe', 'node.exe', 'powershell.exe', 'cmd.exe',
                'system', 'smss.exe', 'csrss.exe', 'wininit.exe'
            }
        }
    else:  # Linux
        return {
            'sensitive_paths': [
                '/etc/passwd', '/etc/shadow', '/etc/sudoers',
                '/etc/ssh/sshd_config', '/etc/hosts', '/etc/crontab',
                '/etc/gshadow', '/etc/group', '/etc/protocols'
            ],
            'temp_dirs': [
                '/tmp', '/var/tmp', '/dev/shm', '/run/user'
            ],
            'legitimate_paths': [
                '/usr/bin', '/usr/sbin', '/bin', '/sbin',
                '/usr/local/bin', '/usr/local/sbin',
                '/opt', '/snap', '/flatpak',
                '/lib', '/lib64', '/usr/lib', '/usr/lib64'
            ],
            'suspicious_patterns': [
                'nc -l', 'netcat', 'ncat', 'socat',
                'bash -i', 'sh -i', '/bin/sh', '/bin/bash',
                'python -c', 'perl -e', 'ruby -e',
                'wget', 'curl', 'fetch',
                'chmod +x', 'chmod 777',
                'nohup', 'screen', 'tmux',
                'iptables', 'ufw', 'firewall',
                'crontab', 'at', 'batch',
                'ssh-keygen', 'authorized_keys',
                'passwd', 'shadow', '/etc/passwd'
            ],
            'legitimate_processes': {
                'init', 'kthreadd', 'ksoftirqd', 'migration', 'rcu_', 'watchdog',
                'systemd', 'kmod', 'udevd', 'NetworkManager', 'gdm', 'Xorg',
                'gnome-shell', 'firefox', 'chrome', 'chromium', 'code', 'vim',
                'bash', 'zsh', 'fish', 'python', 'python3', 'node', 'java'
            }
        }

def get_default_scan_path():
    """Get default scan path for the current platform"""
    if is_windows():
        return os.path.expandvars(r'%TEMP%')
    else:
        return '/tmp'

def normalize_path(path):
    """Normalize path for the current platform"""
    if is_windows():
        return os.path.normpath(path).replace('/', '\\')
    else:
        return os.path.normpath(path)
