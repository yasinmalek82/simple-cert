"""Real Docker mount/UID acceptance with generated PEMs; no panel, CA or Core changes."""

import importlib.util
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path


def command(*args):
    return subprocess.run(args, check=True, capture_output=True)


def main():
    if os.geteuid() != 0:
        raise RuntimeError("Run in a disposable rootful Docker CI runner as root")
    source = Path(__file__).resolve().parents[1] / "simple_cert.py"
    spec = importlib.util.spec_from_file_location("app", source)
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)
    name = "simple-cert-fixture-" + uuid.uuid4().hex
    image = "pasarguard/panel:simple-cert-fixture"
    command("docker", "pull", "python:3.13-slim")
    command("docker", "tag", "python:3.13-slim", image)
    with tempfile.TemporaryDirectory(prefix="simple-cert-panel-") as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        data = root / "data"
        data.mkdir(mode=0o755)
        pair = root / "pair"
        pair.mkdir()
        command(
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "30",
            "-subj",
            "/CN=example.com",
            "-addext",
            "subjectAltName=DNS:example.com",
            "-keyout",
            str(pair / "key.pem"),
            "-out",
            str(pair / "fullchain.pem"),
        )
        command(
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "--user",
            "1000:1000",
            "--volume",
            f"{data}:/var/lib/pasarguard",
            image,
            "python3",
            "-c",
            "import time; time.sleep(600)",
        )
        try:
            target = next(item for item in app.discover_panels() if item["name"] == name)
            manager = app.Manager(root / "state")
            manager.configure("fixture@example.com", "fixture-token")

            def obtain(record, destination, *, renew):
                for filename in ("fullchain.pem", "key.pem"):
                    shutil.copyfile(pair / filename, destination / filename)

            manager.obtain = obtain
            record = manager.issue(["example.com"])
            directory = "/var/lib/pasarguard/certs/simple-cert/" + record["id"]
            record = app.publish_delivery(manager, record, target, directory)
            current = data / "certs/simple-cert" / record["id"] / "current"
            previous = current.resolve()
            assert (current / "key.pem").stat().st_uid == 1000
            assert (current / "key.pem").stat().st_mode & 0o777 == 0o600
            record = manager.renew(record["id"])
            assert current.resolve() != previous and previous.exists()
            assert record["deliveries"][0]["status"] == "complete"
            record = app.publish_delivery(manager, record, target, directory + "-second")
            assert len(record["deliveries"]) == 2
            assert current.is_dir()
            assert (manager.root / "certificates" / record["id"] / "current/key.pem").is_file()
            print("PASS: actual Docker mount, non-root reader, private PEMs, renewal and second delivery")
        finally:
            command("docker", "rm", "-f", name)


if __name__ == "__main__":
    main()
