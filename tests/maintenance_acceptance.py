"""Isolated program-only acceptance; --live-update downloads the public release, never CA data."""

import argparse
import hashlib
import importlib.util
import json
import os
import pty
import select
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def terminal_uninstall(script, other, state, remove_others):
    # Constrain discovery to these two disposable copies, even when running as root.
    harness = (
        "import importlib.util,sys; from pathlib import Path; "
        "s=importlib.util.spec_from_file_location('app',sys.argv[1]); "
        "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
        "m.candidate_scripts=lambda:[Path(sys.argv[1]),Path(sys.argv[2])]; "
        "m.menu(m.Manager(Path(sys.argv[3])))"
    )
    master, slave = pty.openpty()
    process = subprocess.Popen(
        [sys.executable, "-c", harness, str(script), str(other), str(state)],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env={**os.environ, "TERM": "xterm"},
    )
    os.close(slave)

    def until(marker):
        output = b""
        deadline = time.monotonic() + 20
        while marker not in output:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([master], [], [], remaining)[0]:
                raise RuntimeError("Uninstall terminal prompt timed out")
            output += os.read(master, 65536)

    try:
        until(b"Choose [0-4]:")
        os.write(master, b"4\n")
        until(b"Choose utility action:")
        os.write(master, b"2\n")
        until(b"Type uninstall:")
        os.write(master, b"uninstall\n")
        until(b"Remove these other installations too?")
        os.write(master, b"yes\n" if remove_others else b"\n")
        assert process.wait(timeout=20) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live-update", action="store_true")
    args = parser.parse_args()
    installer = load_module("installer", ROOT / "installer.py")
    with tempfile.TemporaryDirectory(prefix="simple-cert-maintenance-acceptance-") as directory:
        root = Path(directory)
        current, other = root / "current", root / "other"
        for prefix in (current, other):
            installer.install_file(ROOT / "simple_cert.py", prefix)
        script = current / "lib/simple-cert/simple_cert.py"
        other_script = other / "lib/simple-cert/simple_cert.py"
        state = root / "private-state"
        state.mkdir(mode=0o700)
        settings = state / "settings.json"
        settings.write_text('{"email":"test@example.com","token":"fixture-only"}')
        certificate = state / "certificate-preservation-marker.pem"
        certificate.write_text("Disposable preservation marker, not a real certificate or private key.")
        expected = {path: path.read_bytes() for path in (settings, certificate)}
        if args.live_update:
            # A deliberately older temporary build exercises the real updater and real public installer.
            source = script.read_text().replace(
                f'VERSION = "{installer.VERSION.removeprefix("v")}"', 'VERSION = "0.0.0"', 1
            )
            script.write_text(source)
            metadata = {
                "application": "simple-cert",
                "version": "0.0.0",
                "sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
            }
            (script.parent / "installation.json").write_text(json.dumps(metadata))
            result = subprocess.run(
                [sys.executable, str(script), "--state-dir", str(state)],
                input=b"4\n1\nyes\n",
                capture_output=True,
                timeout=180,
                check=True,
            )
            assert ("Updated to " + installer.VERSION).encode() in result.stdout, (
                "The public update did not complete"
            )
            assert script.read_bytes() == (ROOT / "simple_cert.py").read_bytes()
            assert len(list(script.parent.glob("simple_cert*.py"))) == 1
            print("Live public update replaced one program file in the original prefix.")
        terminal_uninstall(script, other_script, state, remove_others=False)
        assert not script.exists() and other_script.exists()
        installer.install_file(ROOT / "simple_cert.py", current)
        terminal_uninstall(script, other_script, state, remove_others=True)
        assert not script.exists() and not other_script.exists()
        for path, contents in expected.items():
            assert path.read_bytes() == contents
        print("Real terminal uninstall passed: keep/delete other copies, preserve private data.")


if __name__ == "__main__":
    main()
