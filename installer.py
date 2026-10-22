#!/usr/bin/env python3
"""Pinned release installer; does not read or overwrite certificate state."""

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

VERSION = "v0.1.8"
SCRIPT_SHA256 = "a8f560704e47e5090d7c2829a35f9829f2ba241e000ee420137dbbd97642ca72"
SOURCE_URL = f"https://raw.githubusercontent.com/yasinmalek82/simple-cert/{VERSION}/simple_cert.py"


class InstallError(Exception):
    pass


def supports_system(system_id, version_id):
    if system_id == "ubuntu":
        version = re.fullmatch(r"([0-9]{2})\.(04|10)", version_id)
        return bool(version and int(version[1]) >= 22)
    return system_id == "debian" and version_id in ("12", "13")


def verify_download(data):
    if hashlib.sha256(data).hexdigest() != SCRIPT_SHA256:
        raise InstallError("Release checksum verification failed. Existing installation retained.")


@contextlib.contextmanager
def install_lock(prefix):
    library = prefix / "lib"
    library.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(library / ".simple-cert.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise InstallError("Another installation or uninstall is running.") from None
        yield
    finally:
        os.close(descriptor)


def install_file(source, prefix):
    with install_lock(prefix):
        _install_file(source, prefix)


def _install_file(source, prefix):
    target = prefix / "lib/simple-cert"
    commands = prefix / "bin"
    if target.is_symlink():
        raise InstallError("The program directory must not be a symbolic link.")
    target.mkdir(parents=True, exist_ok=True)
    commands.mkdir(parents=True, exist_ok=True)
    command = commands / "simple-cert"
    installed = target / "simple_cert.py"
    if command.exists() or command.is_symlink():
        if not command.is_symlink() or command.resolve() != installed.resolve():
            raise InstallError("A different simple-cert command already exists. No replacement performed.")
    descriptor, name = tempfile.mkstemp(prefix=".install-", dir=target)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(source.read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o755)
        result = subprocess.run(
            [sys.executable, str(temporary), "--version"],
            capture_output=True,
            timeout=30,
            check=False,
        )
        if result.returncode or result.stdout.strip() != b"simple-cert 0.1.8":
            raise InstallError("Downloaded program failed its version check. Existing installation retained.")
        os.replace(temporary, installed)
    finally:
        temporary.unlink(missing_ok=True)
    temporary_link = commands / f".simple-cert-{os.getpid()}"
    try:
        temporary_link.symlink_to(installed.absolute())
        os.replace(temporary_link, command)
    finally:
        temporary_link.unlink(missing_ok=True)
    metadata = {
        "application": "simple-cert",
        "version": VERSION.removeprefix("v"),
        "sha256": hashlib.sha256(installed.read_bytes()).hexdigest(),
    }
    descriptor, name = tempfile.mkstemp(prefix=".manifest-", dir=target)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(metadata, stream)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o644)
        os.replace(temporary, target / "installation.json")
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description="Install a pinned simple-cert release.")
    parser.add_argument("--prefix", type=Path, default=Path("/usr/local"))
    args = parser.parse_args()
    try:
        if platform.system() != "Linux" or os.geteuid() != 0:
            raise InstallError("Run the installer as root on the Linux mother server.")
        if sys.version_info < (3, 10):
            raise InstallError("Python 3.10 or newer is required.")
        release = platform.freedesktop_os_release()
        if not supports_system(release.get("ID", ""), release.get("VERSION_ID", "")):
            raise InstallError("Supported systems: Ubuntu 22.04 or newer, and Debian 12/13.")
        for command in ("sh", "git", "openssl", "curl"):
            if not shutil.which(command):
                raise InstallError(f"Missing prerequisite: {command}. Use the bootstrap installer.")
        with urllib.request.urlopen(SOURCE_URL, timeout=60) as response:
            data = response.read(2 * 1024 * 1024)
        verify_download(data)
        with tempfile.TemporaryDirectory(prefix="simple-cert-install-") as directory:
            source = Path(directory) / "simple_cert.py"
            source.write_bytes(data)
            install_file(source, args.prefix.expanduser().absolute())
        print("Installed simple-cert 0.1.8. Existing settings and certificates have been preserved.")
        print("Open the menu: sudo simple-cert")
        print("Run it on the mother server. Certificates are delivered as local files only.")
        return 0
    except InstallError as error:
        print(f"Installation failed: {error}", file=sys.stderr)
        return 1
    except (OSError, urllib.error.URLError, subprocess.SubprocessError):
        # Network responses and downloaded content are never included in diagnostics.
        print(
            "Installation failed. Check OS support, root access, disk space and GitHub access.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
