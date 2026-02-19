"""OpenSSH with session-bind@pl.loee agent extension."""

import os
import sys

__version__ = "0.1.0"


def _bin_dir():
    return os.path.join(os.path.dirname(__file__), "bin")


def ssh_path():
    """Return the absolute path to the patched ssh binary."""
    return os.path.join(_bin_dir(), "ssh")


def main():
    """Exec the patched ssh binary, replacing the current process."""
    binary = ssh_path()
    if not os.path.isfile(binary):
        print(f"Error: ssh binary not found at {binary}", file=sys.stderr)
        sys.exit(1)
    os.execvp(binary, [binary] + sys.argv[1:])
