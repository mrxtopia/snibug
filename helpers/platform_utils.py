"""Platform detection and compatibility utilities."""
import os
import sys
import platform
from pathlib import Path

def is_termux():
    """Detect if running in Termux environment."""
    return os.path.exists('/data/data/com.termux') or 'com.termux' in os.environ.get('PREFIX', '')


def default_scan_threads() -> int:
    """Concurrent probes for SNI / HTTP scans (tuned for Termux vs desktop)."""
    try:
        v = int(os.environ.get("SNIBUG_THREADS", "0"))
        if 0 < v <= 512:
            return v
    except ValueError:
        pass
    cpu = os.cpu_count() or 4
    if is_termux():
        return min(96, max(24, cpu * 8))
    return min(256, max(48, cpu * 24))


def default_scan_timeout() -> int:
    """Seconds per connection/read for mass scans."""
    try:
        t = int(os.environ.get("SNIBUG_TIMEOUT", "0"))
        if 0 < t <= 120:
            return t
    except ValueError:
        pass
    return 5


def is_windows():
    """Check if running on Windows."""
    return platform.system() == 'Windows'

def is_linux():
    """Check if running on Linux."""
    return platform.system() == 'Linux'

def is_macos():
    """Check if running on macOS."""
    return platform.system() == 'Darwin'

def get_platform_name():
    """Get human-readable platform name."""
    if is_termux():
        return "Termux (Android)"
    elif is_windows():
        return "Windows"
    elif is_linux():
        return "Linux"
    elif is_macos():
        return "macOS"
    else:
        return platform.system()

def get_home_dir():
    """Get platform-appropriate home directory."""
    if is_termux():
        return Path(os.environ.get('HOME', '/data/data/com.termux/files/home'))
    else:
        return Path.home()

def get_storage_dir():
    """Get platform-appropriate storage directory."""
    if is_termux():
        # Termux storage location
        storage = Path('/storage/emulated/0')
        if storage.exists():
            return storage
    return get_home_dir()

def supports_color():
    """Check if terminal supports color output."""
    if is_windows():
        # Windows 10+ supports ANSI colors
        return True
    
    # Check TERM environment variable
    term = os.environ.get('TERM', '')
    if 'color' in term or term in ['xterm', 'xterm-256color', 'screen', 'linux']:
        return True
    
    return sys.stdout.isatty()

def get_max_workers():
    """Get optimal number of worker threads for platform."""
    try:
        cpu_count = os.cpu_count() or 4
        
        if is_termux():
            # Limit workers on mobile devices
            return min(cpu_count, 8)
        else:
            return min(cpu_count * 2, 20)
    except:
        return 10

def ensure_directory(path):
    """Create directory if it doesn't exist, cross-platform."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path

class PlatformPaths:
    """Platform-specific path management."""
    
    def __init__(self):
        self.home = get_home_dir()
        self.storage = get_storage_dir()
        
    def get_results_dir(self):
        """Get results directory path."""
        if is_termux():
            # Use storage for easy access on Android
            return ensure_directory(self.storage / 'SNI_Scanner' / 'results')
        else:
            return ensure_directory(Path.cwd() / 'results')
    
    def get_export_dir(self):
        """Get export directory path."""
        if is_termux():
            return ensure_directory(self.storage / 'SNI_Scanner' / 'export')
        else:
            return ensure_directory(Path.cwd() / 'export')
    
    def get_config_dir(self):
        """Get configuration directory path."""
        if is_termux():
            return ensure_directory(self.home / '.sni_scanner')
        else:
            return ensure_directory(Path.cwd() / '.config')
