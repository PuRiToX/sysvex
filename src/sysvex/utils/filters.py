import fnmatch
import os


def get_default_exclusions():
    """Get default directory/file patterns to exclude from scanning"""
    return {
        # Version control
        '.git', '.svn', '.hg', '.bzr',
        # Python
        '__pycache__', '*.pyc', '*.pyo', '*.egg-info', '.pytest_cache',
        '.venv', 'venv', 'env', '.env', '.tox',
        # Node.js
        'node_modules', 'bower_components',
        # IDEs and editors
        '.idea', '.vscode', '.vs', '*.swp', '*.swo', '*~',
        # Build artifacts
        'build', 'dist', 'target', '.gradle', '.cache',
        # Logs
        '*.log', 'logs',
        # Package managers
        'vendor', '.bundle',
        # System directories (Unix)
        '/proc', '/sys', '/dev', '/run', '/snap',
        # Windows system directories
        'System Volume Information', '$RECYCLE.BIN', 'Windows.old',
    }


def should_exclude_path(path, exclude_patterns, root_scan_path=None):
    """
    Check if a path should be excluded based on patterns.

    Args:
        path: The path to check
        exclude_patterns: Set or list of glob patterns to exclude
        root_scan_path: Optional root path for relative matching

    Returns:
        True if path should be excluded, False otherwise
    """
    if not exclude_patterns:
        return False

    # Normalize path for matching
    norm_path = os.path.normpath(path)
    path_parts = norm_path.split(os.sep)
    basename = os.path.basename(norm_path)

    for pattern in exclude_patterns:
        pattern = pattern.strip()
        if not pattern:
            continue

        # Direct match on basename
        if fnmatch.fnmatch(basename, pattern):
            return True

        # Match on full path
        if fnmatch.fnmatch(norm_path, pattern):
            return True

        # Match on any path component
        for part in path_parts:
            if fnmatch.fnmatch(part, pattern):
                return True

        # Relative pattern matching from root
        if root_scan_path and not pattern.startswith(('/', '\\', '*')):
            full_pattern = os.path.join(root_scan_path, pattern)
            if fnmatch.fnmatch(norm_path, full_pattern):
                return True

    return False


def is_within_depth(root_path, current_path, max_depth):
    """
    Check if current_path is within max_depth levels from root_path.

    Args:
        root_path: The root scan directory
        current_path: The current file/directory path
        max_depth: Maximum allowed depth (0 means only root level)

    Returns:
        True if within depth limit, False otherwise
    """
    if max_depth is None or max_depth < 0:
        return True

    # Calculate relative depth
    try:
        rel_path = os.path.relpath(current_path, root_path)
        depth = len(rel_path.split(os.sep)) - 1  # -1 because file counts as level
        return depth <= max_depth
    except ValueError:
        # On Windows, relpath can fail if paths are on different drives
        return True


def should_skip_file_for_fp_reduction(filepath, file_stat, _platform_config=None):
    """
    Determine if a file should be skipped to reduce false positives.

    Args:
        filepath: Full path to the file
        file_stat: os.stat result for the file
        platform_config: Optional platform configuration dict

    Returns:
        True if file should be skipped, False otherwise
    """
    # Skip extremely large files (>100MB) - likely not suspicious
    if file_stat and hasattr(file_stat, 'st_size'):
        if file_stat.st_size > 100 * 1024 * 1024:  # 100MB
            return True
    elif filepath:
        # Fallback to direct size check if stat not provided
        try:
            size = os.path.getsize(filepath)
            if size > 100 * 1024 * 1024:
                return True
        except (OSError, IOError):
            pass

    # Skip socket files, pipes, device files
    if file_stat:
        mode = file_stat.st_mode
        if (hasattr(os.stat, 'S_ISSOCK') and os.stat.S_ISSOCK(mode)) or \
           (hasattr(os.stat, 'S_ISFIFO') and os.stat.S_ISFIFO(mode)) or \
           (hasattr(os.stat, 'S_ISCHR') and os.stat.S_ISCHR(mode)) or \
           (hasattr(os.stat, 'S_ISBLK') and os.stat.S_ISBLK(mode)):
            return True

    return False


def is_likely_system_hidden_file(filename, filepath, is_windows=False):
    """
    Determine if a hidden file is likely a legitimate system file.

    Args:
        filename: The filename (not full path)
        filepath: Full path to the file
        is_windows: Whether we're on Windows

    Returns:
        True if likely a system file, False if potentially suspicious
    """
    if is_windows:
        # Windows system hidden files start with $ or are in system dirs
        system_indicators = [
            filename.startswith('$'),
            'System32' in filepath,
            'SysWOW64' in filepath,
            'WinSxS' in filepath,
            'Microsoft' in filepath and 'Windows' in filepath,
        ]

        # Dotfiles in user directories are usually config files
        user_dirs = ['AppData', 'Application Data', 'Documents']
        if any(ud in filepath for ud in user_dirs):
            if filename.startswith('.'):
                return True

        return any(system_indicators)
    else:
        # Unix: Dotfiles in home directory are usually config files
        home = os.path.expanduser('~')
        if filepath.startswith(home):
            common_configs = {
                '.bashrc', '.bash_profile', '.zshrc', '.profile',
                '.vimrc', '.gitconfig', '.ssh', '.gnupg',
                '.local', '.config', '.cache', '.pki',
                '.Xauthority', '.ICEauthority',
            }
            if filename in common_configs or filename.startswith('.'):
                # Only flag dotfiles in temp directories as suspicious
                temp_dirs = ['/tmp', '/var/tmp', '/dev/shm']
                if any(filepath.startswith(td) for td in temp_dirs):
                    return False
                return True

        return False


def filter_findings(findings, min_severity=None):
    """
    Filter findings by minimum severity level.

    Args:
        findings: List of Finding objects
        min_severity: Minimum severity to include ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')

    Returns:
        Filtered list of findings
    """
    if not min_severity:
        return findings

    severity_order = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
    min_level = severity_order.get(min_severity.upper(), 0)

    return [
        f for f in findings
        if severity_order.get(f.severity.upper(), 0) >= min_level
    ]
