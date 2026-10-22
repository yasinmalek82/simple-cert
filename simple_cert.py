#!/usr/bin/env python3
"""Small Cloudflare DNS-01 certificate menu. Runtime: Python stdlib + OpenSSL."""

import argparse
import contextlib
import datetime as dt
import fcntl
import getpass
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import uuid
import warnings
from pathlib import Path

VERSION = "0.1.6"
REPOSITORY = "yasinmalek82/simple-cert"
LEGACY_RELEASES = {
    "57f5f5b583dd558ac4f52d23eba9d425b03229e34f07a2227a6590c88fe504a1": "0.1.0",
    "56fd53a80c838bf9837c67d7c39b62fda18ab775415781f59a433c1c6e49daf7": "0.1.1",
    "0c6951e490fbf7f198028864ffe54a8185ebe10f680bf4a3ac04ee55ea05896a": "0.1.2",
    "5831604e33d6b653ed7aa954b334ed09b6ae5a98e5f3ce9874630ff7bfc56557": "0.1.3",
}
ACME_COMMIT = "3688b094adffc1a52d3b994c586cd97caa2f0b85"
CA = "https://acme-v02.api.letsencrypt.org/directory"
MENU = f"""
  SIMPLE CERT v{VERSION}
  Cloudflare DNS verification | Let's Encrypt
  ------------------------------------------------
  1. Issue certificate
  2. List certificates and file paths
  3. Renew certificate
  4. Cloudflare settings
  5. Update simple-cert
  6. Uninstall simple-cert
  0. Exit
  ------------------------------------------------
"""


class Error(Exception):
    """A safe, operator-facing error without raw command output."""


def run(argv, *, env=None, cwd=None, allowed=(0,), timeout=1800, message=None):
    try:
        result = subprocess.run(
            argv,
            env=env,
            cwd=cwd,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Error(message or "Command unavailable or timed out; private output suppressed.") from None
    if result.returncode not in allowed:
        raise Error(message or "Operation failed; private command output suppressed.")
    return result


def private_dir(path):
    if path.is_symlink():
        raise Error("A private directory must not be a symbolic link.")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def save(path, value):
    """Replace JSON atomically, with private permissions and durable intent."""
    private_dir(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_dir(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def sync_dir(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def load(path):
    try:
        result = json.loads(path.read_text())
        if not isinstance(result, dict):
            raise ValueError
        return result
    except (ValueError, OSError):
        raise Error(
            "Cannot read saved settings or certificate state. Check the private state directory."
        ) from None


@contextlib.contextmanager
def locked(root):
    private_dir(root)
    descriptor = os.open(root / "operation.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Error("Another simple-cert operation is running. Try again when it finishes.") from None
        yield
    finally:
        os.close(descriptor)


def normalize_domains(values):
    domains = set()
    for value in values:
        raw = value.strip().lower().removesuffix(".")
        wildcard = raw.startswith("*.")
        raw = raw[2:] if wildcard else raw
        try:
            name = raw.encode("idna").decode("ascii")
        except UnicodeError:
            raise Error("Enter a DNS name, such as example.com or *.example.com.") from None
        labels = name.split(".")
        if (
            len(name) > 253
            or len(labels) < 2
            or all(part.isdigit() for part in labels)
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in labels)
        ):
            raise Error(
                "Enter a DNS name, such as example.com or *.example.com. URLs and IPs are not accepted."
            )
        domains.add(("*." if wildcard else "") + name)
    if not domains:
        raise Error("At least one domain is required.")
    return sorted(domains, key=lambda name: (name.startswith("*."), name))


def validate_pair(folder, domains, *, check_validity=True):
    cert, key = str(folder / "fullchain.pem"), str(folder / "key.pem")
    message = "Invalid or unreadable certificate/key files; old certificate retained."
    details = run(
        [
            "openssl",
            "x509",
            "-in",
            cert,
            "-noout",
            "-dates",
            "-ext",
            "subjectAltName",
        ],
        message=message,
    ).stdout.decode("ascii", errors="replace")
    public_cert = run(["openssl", "x509", "-in", cert, "-noout", "-pubkey"], message=message).stdout.strip()
    public_key = run(
        [
            "openssl",
            "pkey",
            "-in",
            key,
            "-pubout",
            "-passin",
            "pass:",
        ],
        message=message,
    ).stdout.strip()
    if public_cert != public_key:
        raise Error("Certificate and private key do not match; old certificate retained.")
    names = set(re.findall(r"DNS:([^,\s]+)", details))
    if not set(domains).issubset(names):
        raise Error("Certificate does not contain the requested DNS names; old certificate retained.")
    try:
        dates = dict(
            line.split("=", 1)
            for line in details.splitlines()
            if line.startswith(("notBefore=", "notAfter="))
        )
        start = dt.datetime.strptime(dates["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=dt.timezone.utc
        )
        end = dt.datetime.strptime(dates["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
    except (KeyError, ValueError):
        raise Error("Certificate validity dates could not be read.") from None
    if check_validity and not start <= dt.datetime.now(dt.timezone.utc) < end:
        raise Error("Certificate is expired or not yet valid; old certificate retained.")
    return {"expires_at": end.isoformat()}


class Manager:
    def __init__(self, root):
        self.root = Path(root).expanduser().absolute()
        private_dir(self.root)

    def config(self):
        path = self.root / "settings.json"
        if not path.exists():
            raise Error("Configure Cloudflare settings first (menu option 4).")
        result = load(path)
        if not result.get("email") or not result.get("token"):
            raise Error("Configure Cloudflare settings first (menu option 4).")
        return result

    def configure(self, email, token):
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254:
            raise Error("Enter a valid ACME account email address.")
        if not token or len(token) > 1024 or any(char.isspace() or ord(char) < 32 for char in token):
            raise Error("Enter a valid Cloudflare API token without spaces or newlines.")
        with locked(self.root):
            save(self.root / "settings.json", {"email": email, "token": token})

    def harden(self):
        # acme.sh also saves DNS tokens in its own configuration files.
        for directory, _, files in os.walk(self.root, followlinks=False):
            Path(directory).chmod(0o700)
            for name in files:
                path = Path(directory) / name
                if not path.is_symlink():
                    path.chmod(0o600)

    def install_engine(self):
        engine = self.root / "engine"
        if (engine / "acme.sh").is_file():
            if not (engine / "revision").is_file() or (engine / "revision").read_text() != ACME_COMMIT:
                raise Error("Unexpected ACME engine revision. Restore the dedicated engine before retrying.")
            return
        print("Preparing the dedicated ACME client (first use only)...", flush=True)
        with tempfile.TemporaryDirectory(prefix="engine-", dir=self.root) as temporary:
            source = Path(temporary)
            run(["git", "init", str(source)])
            run(
                [
                    "git",
                    "-C",
                    str(source),
                    "fetch",
                    "--depth",
                    "1",
                    "https://github.com/acmesh-official/acme.sh.git",
                    ACME_COMMIT,
                ],
                timeout=300,
                message="Cannot download the ACME client. Check access to github.com.",
            )
            run(["git", "-C", str(source), "checkout", "--detach", "FETCH_HEAD"])
            actual = run(["git", "-C", str(source), "rev-parse", "HEAD"]).stdout.decode().strip()
            if actual != ACME_COMMIT:
                raise Error("ACME client revision verification failed.")
            # The engine remains private; it is always invoked through sh, never executed directly.
            shutil.copytree(source, engine, ignore=shutil.ignore_patterns(".git"))
            (engine / "revision").write_text(ACME_COMMIT)
        self.harden()

    def obtain(self, record, destination, renew=False):
        config = self.config()
        self.install_engine()
        env = {key: value for key, value in os.environ.items() if not key.startswith("CF_")}
        env.update({"CF_Token": config["token"], "LC_ALL": "C", "AUTO_UPGRADE": "0"})
        account = private_dir(self.root / "account")
        cert_home = private_dir(self.root / "acme-certificates" / record["id"])
        export = private_dir(self.root / "acme-exports" / record["id"])
        base = [
            "sh",
            str(self.root / "engine" / "acme.sh"),
            "--home",
            str(self.root / "engine"),
            "--config-home",
            str(account),
            "--cert-home",
            str(cert_home),
            "--server",
            CA,
            "--no-color",
        ]
        failure = (
            "ACME/Cloudflare operation failed or timed out. Check the token's Zone DNS Edit + Zone Read "
            "permissions, zone access, DNS propagation, CAA records and CA rate limits. "
            "Private ACME output is suppressed; existing certificates are retained."
        )
        try:
            if renew:
                run(
                    [*base, "--renew", "-d", record["domains"][0], "--ecc"],
                    env=env,
                    allowed=(0, 2),
                    message=failure,
                )
            else:
                run(
                    [*base, "--register-account", "--accountemail", config["email"]], env=env, message=failure
                )
                domains = [item for domain in record["domains"] for item in ("-d", domain)]
                run(
                    [*base, "--issue", "--dns", "dns_cf", "--keylength", "ec-256", *domains],
                    env=env,
                    allowed=(0, 2),
                    message=failure,
                )
            run(
                [
                    *base,
                    "--install-cert",
                    "-d",
                    record["domains"][0],
                    "--ecc",
                    "--fullchain-file",
                    str(export / "fullchain.pem"),
                    "--key-file",
                    str(export / "key.pem"),
                ],
                env=env,
                message=failure,
            )
            # acme.sh remembers export paths and rewrites them during renewal.
            # Never register a published version as an ACME export destination.
            for name in ("fullchain.pem", "key.pem"):
                shutil.copyfile(export / name, destination / name)
        finally:
            self.harden()

    def records(self):
        result = []
        for path in sorted((self.root / "certificates").glob("*/record.json")):
            record = load(path)
            record["active"] = (path.parent / "current" / "fullchain.pem").is_file()
            # The pointer is authoritative if interruption happened after publication.
            if record["active"]:
                record.update(validate_pair(path.parent / "current", record["domains"], check_validity=False))
            result.append(record)
        return result

    def issue(self, domains):
        domains = normalize_domains(domains)
        identifier = hashlib.sha256("\n".join(domains).encode()).hexdigest()[:24]
        with locked(self.root):
            self.config()
            folder = private_dir(self.root / "certificates" / identifier)
            path = folder / "record.json"
            if path.exists():
                raise Error("This domain set is already saved. Use Renew certificate (menu option 3).")
            return self._obtain({"id": identifier, "domains": domains}, folder, renew=False)

    def renew(self, identifier):
        if not re.fullmatch(r"[a-f0-9]{24}", identifier):
            raise Error("Invalid certificate selection.")
        with locked(self.root):
            self.config()
            folder = self.root / "certificates" / identifier
            record = load(folder / "record.json")
            # A failed first issuance can be retried without pretending a certificate already exists.
            active = (folder / "current" / "fullchain.pem").is_file()
            record = self._obtain(record, folder, renew=record.get("issued", False) or active)
        return refresh_deliveries(self, record)

    def _obtain(self, record, folder, renew):
        record["operation"] = "renewing" if renew else "issuing"
        save(folder / "record.json", record)
        versions = private_dir(folder / "versions")
        version = private_dir(versions / uuid.uuid4().hex)
        link = folder / (".current-" + uuid.uuid4().hex)
        print("Validating DNS and requesting the certificate. This can take several minutes...", flush=True)
        try:
            self.obtain(record, version, renew=renew)
            metadata = validate_pair(version, record["domains"])
            for name in ("fullchain.pem", "key.pem"):
                path = version / name
                path.chmod(0o600)
                with path.open("rb") as stream:
                    os.fsync(stream.fileno())
            sync_dir(version)
            sync_dir(versions)
            record.update({"operation": "publishing", "candidate": version.name})
            save(folder / "record.json", record)
            link.symlink_to(Path("versions") / version.name)
            os.replace(link, folder / "current")
            sync_dir(folder)
            record.update(metadata)
            record.update({"operation": "complete", "issued": True})
            record.pop("candidate", None)
            save(folder / "record.json", record)
            return record
        except BaseException:
            # Preserve a published version even if the final state write was interrupted.
            if (folder / "current").resolve() != version:
                shutil.rmtree(version, ignore_errors=True)
            record["operation"] = "failed"
            save(folder / "record.json", record)
            raise
        finally:
            link.unlink(missing_ok=True)
            self.harden()


def docker_panels(containers):
    """Keep only the fields required to locate a running mother panel."""
    result = []
    for item in containers:
        config = item.get("Config", {})
        if not re.search(r"(?:^|/)pasarguard/panel(?:[:@]|$)", config.get("Image", "")):
            continue
        if not item.get("State", {}).get("Running"):
            continue
        data = next(
            (value[9:] for value in config.get("Env", []) if value.startswith("DATA_DIR=")),
            "/var/lib/pasarguard",
        )
        result.append(
            {
                "kind": "docker",
                "id": item["Id"],
                "name": item["Name"].lstrip("/"),
                "data": data,
                "userns": item.get("HostConfig", {}).get("UsernsMode", ""),
                "mounts": [
                    {key: mount.get(key) for key in ("Source", "Destination", "Type", "RW")}
                    for mount in item.get("Mounts", [])
                ],
            }
        )
    return result


def discover_panels():
    """Inspect local Docker only; never expose inspect/environment output."""
    try:
        endpoint = os.environ.get("DOCKER_HOST")
        if not endpoint:
            contexts = json.loads(run(["docker", "context", "inspect"], timeout=15).stdout)
            endpoint = contexts[0]["Endpoints"]["docker"]["Host"]
        if not endpoint.startswith("unix://"):
            return []
        ids = run(["docker", "ps", "-q"], timeout=15).stdout.decode().split()
        if not ids:
            return []
        return docker_panels(json.loads(run(["docker", "inspect", *ids], timeout=15).stdout))
    except (Error, ValueError, KeyError, IndexError, TypeError):
        return []


def checked_path(value):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or path == Path("/"):
        raise Error("Use an absolute directory inside the panel data directory, without '..'.")
    return path


def no_symlinks(path):
    for part in [*reversed(path.parents), path]:
        if part.is_symlink():
            raise Error("Certificate delivery paths must not contain symbolic links.")


def panel_location(target, directory):
    path = checked_path(directory)
    data = checked_path(target["data"])
    if not path.is_relative_to(data) or path == data:
        raise Error("Choose a subdirectory of the detected panel data directory.")
    mounts = [
        mount
        for mount in target["mounts"]
        if mount.get("Destination") and path.is_relative_to(Path(mount["Destination"]))
    ]
    if not mounts:
        raise Error("The panel directory has no shared Docker mount.")
    mount = max(mounts, key=lambda value: len(Path(value["Destination"]).parts))
    if not mount["RW"] or mount["Type"] not in ("bind", "volume") or mount["Destination"] == "/":
        raise Error("The panel needs a writable, dedicated data mount.")
    host = checked_path(mount["Source"]) / path.relative_to(mount["Destination"])
    no_symlinks(host)
    # A nested mount may hide files below the selected publication directory.
    if any(
        Path(value["Destination"]).is_relative_to(path)
        for value in target["mounts"]
        if value.get("Destination")
    ):
        raise Error("Choose a directory without nested mounts inside it.")
    return host


def panel_reader_identity(target):
    options = run(["docker", "info", "--format", "{{json .SecurityOptions}}"], timeout=15).stdout.decode()
    if target["userns"] not in ("", "host") or "rootless" in options or "userns" in options:
        raise Error("Automatic delivery requires local rootful Docker without user namespace remapping.")
    output = (
        run(
            [
                "docker",
                "exec",
                target["id"],
                "python3",
                "-c",
                "import os; print(str(os.geteuid())+':'+str(os.getegid()))",
            ],
            timeout=15,
        )
        .stdout.decode()
        .strip()
    )
    if not re.fullmatch(r"[0-9]+:[0-9]+", output):
        raise Error("Cannot identify the panel certificate reader.")
    identity = tuple(int(value) for value in output.split(":"))
    if any(value >= 2**32 - 1 for value in identity):
        raise Error("Unsupported panel reader identity.")
    return identity


def panel_reader_check(target, host, directory):
    names = ("fullchain.pem", "key.pem")
    expected = " ".join(hashlib.sha256((host / name).read_bytes()).hexdigest() for name in names)
    script = "import hashlib,sys; print(' '.join(hashlib.sha256(open(p,'rb').read()).hexdigest() for p in sys.argv[1:]))"
    actual = (
        run(
            [
                "docker",
                "exec",
                target["id"],
                "python3",
                "-c",
                script,
                *[str(Path(directory) / name) for name in names],
            ],
            timeout=15,
        )
        .stdout.decode()
        .strip()
    )
    if actual != expected:
        raise Error("The panel could not read the matching certificate and key.")


def delivery_parents(path):
    """Create traversable parents without changing existing panel directories."""
    missing = []
    parent = path
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o711)
        directory.chmod(0o711)


def publish_delivery(manager, record, target, directory):
    fresh = next(
        (
            item
            for item in discover_panels()
            if item["kind"] == target["kind"] and item["name"] == target["name"]
        ),
        None,
    )
    if fresh is None:
        raise Error("The selected local PasarGuard panel is no longer available.")
    host = panel_location(fresh, directory)
    if host.is_relative_to(manager.root.resolve()) or manager.root.resolve().is_relative_to(host):
        raise Error("Panel delivery must be separate from the private certificate state directory.")
    uid, gid = panel_reader_identity(fresh)
    with locked(manager.root):
        record_path = manager.root / "certificates" / record["id"] / "record.json"
        record = load(record_path)
        source = record_path.parent / "current"
        metadata = validate_pair(source, record["domains"])
        marker = host / ".simple-cert-delivery.json"
        if host.exists() and any(host.iterdir()):
            if not marker.is_file() or marker.is_symlink() or load(marker).get("id") != record["id"]:
                raise Error(
                    "Destination is not an owned simple-cert delivery directory; choose an empty directory."
                )
        for name in ("versions", "current"):
            path = host / name
            if name == "versions" and path.is_symlink():
                raise Error("Invalid delivery versions directory.")
            if name == "current" and (path.exists() or path.is_symlink()):
                if not path.is_symlink() or not re.fullmatch(r"versions/[a-f0-9]{32}", os.readlink(path)):
                    raise Error("Invalid delivery current pointer.")
        deliveries = record.setdefault("deliveries", [])
        delivery = next(
            (
                item
                for item in deliveries
                if item["directory"] == directory
                and item["name"] == fresh["name"]
                and item["kind"] == fresh["kind"]
            ),
            None,
        )
        if delivery is None:
            delivery = {
                "kind": fresh["kind"],
                "name": fresh["name"],
                "directory": directory,
                "host_directory": str(host),
            }
            deliveries.append(delivery)
        elif delivery["host_directory"] != str(host):
            raise Error("Panel mount changed. Select a new delivery directory explicitly.")
        delivery["status"] = "pending"
        save(record_path, record)
        version = uuid.uuid4().hex
        candidate = host / "versions" / version
        link = host / (".current-" + version)
        try:
            delivery_parents(host.parent)
            host.mkdir(mode=0o711, exist_ok=True)
            # Only owned directories are changed; private PEMs remain readable by the panel UID.
            host.chmod(0o711)
            descriptor, temporary = tempfile.mkstemp(prefix=".marker-", dir=host)
            try:
                with os.fdopen(descriptor, "w") as stream:
                    json.dump({"id": record["id"]}, stream)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, marker)
            finally:
                Path(temporary).unlink(missing_ok=True)
            (host / "versions").mkdir(mode=0o711, exist_ok=True)
            candidate.mkdir(mode=0o700)
            os.chown(candidate, uid, gid)
            for name in ("fullchain.pem", "key.pem"):
                destination = candidate / name
                descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write((source / name).read_bytes())
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chown(destination, uid, gid)
            validate_pair(candidate, record["domains"])
            panel_candidate = str(Path(directory) / "versions" / version)
            panel_reader_check(fresh, candidate, panel_candidate)
            sync_dir(candidate)
            link.symlink_to(Path("versions") / version)
            os.replace(link, host / "current")
            sync_dir(host)
            panel_reader_check(fresh, host / "current", str(Path(directory) / "current"))
            delivery.update(metadata)
            delivery["status"] = "complete"
            save(record_path, record)
            return record
        except (OSError, Error):
            raise Error(
                "Certificate remains saved locally. Panel delivery is pending; previous files are retained."
            ) from None
        finally:
            link.unlink(missing_ok=True)


def refresh_deliveries(manager, record):
    for delivery in list(record.get("deliveries", [])):
        try:
            record = publish_delivery(manager, record, delivery, delivery["directory"])
        except Error:
            with locked(manager.root):
                path = manager.root / "certificates" / record["id"] / "record.json"
                record = load(path)
                for saved in record.get("deliveries", []):
                    if saved["directory"] == delivery["directory"] and saved["name"] == delivery["name"]:
                        saved["status"] = "pending"
                save(path, record)
            print("Local renewal succeeded; a panel delivery is pending. Retry from certificate details.")
    return record


def delivery_menu(manager, record, targets=None):
    targets = discover_panels() if targets is None else targets
    if not targets:
        print("No supported local PasarGuard Docker panel found. Local certificate files are retained.")
        return record
    target = targets[0]
    if len(targets) > 1:
        for index, item in enumerate(targets, 1):
            print(f"{index}. {item['name']}")
        choice = input("Panel number (0 to cancel): ").strip()
        if choice == "0":
            return record
        if not choice.isdigit() or not 1 <= int(choice) <= len(targets):
            raise Error("Invalid panel selection.")
        target = targets[int(choice) - 1]
    default = str(Path(target["data"]) / "certs" / "simple-cert" / record["id"])
    print(f"Panel: {target['name']}")
    directory = input(f"Certificate directory inside the panel [{default}]: ").strip() or default
    host = panel_location(target, directory)
    print(f"Host directory: {host}\nPanel directory: {directory}")
    print("A managed copy is published. Local source and previous delivery paths are retained.")
    if input("Publish certificate and private key here? Type yes: ").strip().lower() != "yes":
        print("Panel delivery cancelled.")
        return record
    record = publish_delivery(manager, record, target, directory)
    print("Panel reader verified. Enter these paths in the selected Core:")
    print(f"Certificate file: {directory}/current/fullchain.pem\nKey file: {directory}/current/key.pem")
    print("Serve on node: disabled. Core configuration and services have not been changed.")
    return record


def offer_panel_delivery(manager, record):
    if not sys.stdin.isatty():
        return
    targets = discover_panels()
    if (
        targets
        and input("Local PasarGuard found. Publish a certificate copy for the panel? [y/N]: ").strip().lower()
        == "y"
    ):
        delivery_menu(manager, record, targets)


def settings_menu(manager):
    if not sys.stdin.isatty():
        raise Error("Settings must be entered in an interactive terminal; tokens use hidden input.")
    previous = manager.config() if (manager.root / "settings.json").exists() else {}
    print("\nCloudflare API token permissions: Zone > DNS > Edit and Zone > Zone > Read.")
    print("Limit the token to the DNS zone(s) you need. Never paste it into a shell command.")
    print("Your email is used for a Let's Encrypt account. Issuing accepts the CA's subscriber agreement.")
    print("Blank input keeps an existing setting.")
    email = input(f"Account email [{previous.get('email', 'not set')}]: ").strip() or previous.get(
        "email", ""
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            token = getpass.getpass("Cloudflare API token (hidden): ").strip() or previous.get("token", "")
        except getpass.GetPassWarning:
            raise Error("A hidden token prompt is unavailable. Reopen an interactive SSH terminal.") from None
    manager.configure(email, token)
    print("Settings saved privately.")


def show(manager, record):
    folder = manager.root / "certificates" / record["id"] / "current"
    print("\nDomains: " + ", ".join(record["domains"]))
    print("Expires (UTC): " + record.get("expires_at", "not issued"))
    print("Last operation: " + record["operation"])
    if (folder / "fullchain.pem").is_file():
        print(f"Full chain: {folder / 'fullchain.pem'}\nPrivate key: {folder / 'key.pem'}")
        print("Local files only. Copy them to the destination service when needed.")
    for delivery in record.get("deliveries", []):
        print(f"Panel {delivery['name']}: {delivery['status']}")
        print(f"Certificate file: {delivery['directory']}/current/fullchain.pem")
        print(f"Key file: {delivery['directory']}/current/key.pem")


def clear_screen():
    interactive = (
        sys.stdin.isatty() and sys.stdout.isatty() and os.environ.get("TERM", "") not in ("", "dumb")
    )
    if interactive:
        print("\033[2J\033[H", end="", flush=True)
    return interactive


def display_file(manager, record, filename):
    if filename not in ("fullchain.pem", "key.pem") or not re.fullmatch(r"[a-f0-9]{24}", record["id"]):
        raise Error("Invalid certificate file selection.")
    if filename == "key.pem":
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            raise Error("Private keys can only be displayed in an interactive terminal, without redirection.")
        print("This displays the private key on your terminal. Do not share it or record this session.")
        if input("Display private key? Type yes: ").strip().lower() != "yes":
            print("Private key display cancelled.")
            return
    with locked(manager.root):
        folder = manager.root / "certificates" / record["id"]
        try:
            path = (folder / "current" / filename).resolve(strict=True)
            path.relative_to((folder / "versions").resolve())
            if path.stat().st_size > 1024 * 1024:
                raise ValueError
            contents = path.read_text(encoding="ascii")
        except (OSError, ValueError):
            raise Error("No readable published certificate file is available for this selection.") from None
    print(f"\n--- {filename} ---")
    print(contents.rstrip())
    print(f"--- End of {filename} ---")


def certificate_menu(manager, record):
    while True:
        interactive = clear_screen()
        show(manager, record)
        print(
            "\n1. View fullchain.pem\n2. View key.pem (private)\n3. Publish/change PasarGuard certificate path\n0. Back to main menu"
        )
        choice = input("Choose action [0-3]: ").strip()
        if choice == "0":
            return
        try:
            if choice == "3":
                record = delivery_menu(manager, record)
            elif choice not in ("1", "2"):
                raise Error("Invalid file selection.")
            else:
                display_file(manager, record, "fullchain.pem" if choice == "1" else "key.pem")
        except Error as error:
            print(f"\nError: {error}")
        if interactive:
            input("Press Enter to return to certificate details...")


@contextlib.contextmanager
def application_lock(prefix):
    library = prefix / "lib"
    library.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(library / ".simple-cert.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Error("Another installation or uninstall is running. Try again later.") from None
        yield
    finally:
        os.close(descriptor)


def identify_installation(candidate):
    """Recognize our installed layout by manifest digest or exact historical release bytes."""
    try:
        script = Path(candidate).resolve(strict=True)
        if (
            script.name != "simple_cert.py"
            or script.parent.name != "simple-cert"
            or script.parent.parent.name != "lib"
            or script.stat().st_size > 2 * 1024 * 1024
        ):
            return None
        digest = hashlib.sha256(script.read_bytes()).hexdigest()
        marker = script.parent / "installation.json"
        if marker.exists():
            if marker.is_symlink():
                return None
            metadata = json.loads(marker.read_text())
            if (
                not isinstance(metadata, dict)
                or metadata.get("application") != "simple-cert"
                or metadata.get("sha256") != digest
            ):
                return None
            version = metadata.get("version", "")
        else:
            version = LEGACY_RELEASES.get(digest, "")
        if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
            return None
        prefix = script.parents[2]
        command = prefix / "bin/simple-cert"
        commands = [command] if command.is_symlink() and command.resolve() == script else []
        return {
            "script": script,
            "prefix": prefix,
            "version": version,
            "sha256": digest,
            "commands": commands,
        }
    except (OSError, ValueError, RuntimeError):
        return None


def candidate_scripts():
    candidates = [Path(__file__)]
    for prefix in (Path("/usr/local"), Path("/usr"), Path.home() / ".local"):
        candidates.append(prefix / "lib/simple-cert/simple_cert.py")
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if directory:
            candidates.append(Path(directory) / "simple-cert")
    return candidates


def discover_installations():
    copies = {}
    for candidate in candidate_scripts():
        identified = identify_installation(candidate)
        if identified is None:
            continue
        script = identified["script"]
        if script not in copies:
            copies[script] = identified
        candidate = Path(candidate).absolute()
        if candidate.name == "simple-cert" and candidate.is_symlink():
            if candidate not in copies[script]["commands"]:
                copies[script]["commands"].append(candidate)
    return list(copies.values())


def remove_installation(installation):
    with application_lock(installation["prefix"]):
        current = identify_installation(installation["script"])
        if current is None or current["sha256"] != installation["sha256"]:
            raise Error("The selected installation changed after discovery; it was not removed.")
        script = current["script"]
        for command in installation["commands"]:
            if command.is_symlink() and command.resolve() == script:
                command.unlink()
        script.unlink()
        (script.parent / "installation.json").unlink(missing_ok=True)
        # Preserve unknown files, private state and all certificate versions. Never recurse.
        with contextlib.suppress(OSError):
            script.parent.rmdir()
        print(f"Removed simple-cert {current['version']}: {script}")


def uninstall_menu(manager):
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise Error("Uninstall requires an interactive terminal.")
    current_script = Path(__file__).resolve()
    copies = discover_installations()
    current = next((item for item in copies if item["script"] == current_script), None)
    if current is None:
        raise Error("This is not a recognized installed copy. Run the installed simple-cert command.")
    others = [item for item in copies if item["script"] != current_script]
    print(f"\nCurrent installation: {current['version']} | {current_script}")
    print(f"Settings, ACME data and all certificates will be kept at: {manager.root}")
    if input("Remove this program? Type uninstall: ").strip().lower() != "uninstall":
        print("Uninstall cancelled.")
        return False
    selected = [current]
    if others:
        print("\nOther recognized simple-cert installations:")
        for item in others:
            print(f"  {item['version']} | {item['script']}")
        if input("Remove these other installations too? [y/N]: ").strip().lower() in ("y", "yes"):
            selected = [*others, current]
    with locked(manager.root):
        for item in selected:
            remove_installation(item)
    print("Uninstall complete. Settings and certificates were preserved.")
    return True


def download(url):
    request = urllib.request.Request(url, headers={"User-Agent": "simple-cert/" + VERSION})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read(2 * 1024 * 1024 + 1)
        if len(data) > 2 * 1024 * 1024:
            raise Error("Update response is too large. No installation changes made.")
        return data
    except (OSError, urllib.error.URLError):
        raise Error(
            "Cannot check GitHub for updates. Check connectivity and public API rate limits."
        ) from None


def update_menu(manager):
    installation = identify_installation(Path(__file__))
    if installation is None:
        raise Error("Update is available from an installed copy. Run the installed simple-cert command.")
    if os.geteuid() != 0:
        raise Error("Run sudo simple-cert to update the installed program.")
    print("Checking the latest stable GitHub release...")
    try:
        release = json.loads(download(f"https://api.github.com/repos/{REPOSITORY}/releases/latest"))
        tag = release["tag_name"]
        match = re.fullmatch(r"v([0-9]{1,6})\.([0-9]{1,6})\.([0-9]{1,6})", tag)
        if not match or release["draft"] is not False or release["prerelease"] is not False:
            raise ValueError
        newest = tuple(int(value) for value in match.groups())
        if newest <= tuple(int(value) for value in VERSION.split(".")):
            print(f"Already up to date: simple-cert {VERSION}.")
            return False
        assets = release["assets"]
        digest = next(item["digest"] for item in assets if item["name"] == "installer.py")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError
    except (ValueError, KeyError, TypeError, StopIteration):
        raise Error("GitHub returned unsupported release metadata. No installation changes made.") from None
    print(f"Current: {VERSION} -> Available: {tag}")
    print("The existing program will be replaced in place. Settings and all certificates are preserved.")
    if input("Install this update? Type yes: ").strip().lower() != "yes":
        print("Update cancelled.")
        return False
    data = download(f"https://raw.githubusercontent.com/{REPOSITORY}/{tag}/installer.py")
    if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
        raise Error("Installer checksum verification failed. Existing program retained.")
    with locked(manager.root), tempfile.TemporaryDirectory(prefix="simple-cert-update-") as directory:
        current = identify_installation(installation["script"])
        if current is None or current["sha256"] != installation["sha256"]:
            raise Error(
                "The installation changed while downloading. Update cancelled; inspect it before retrying."
            )
        installer = Path(directory) / "installer.py"
        installer.write_bytes(data)
        run(
            [sys.executable, str(installer), "--prefix", str(installation["prefix"])],
            message="Update did not complete. Inspect the installed version before retrying; private state is preserved.",
        )
        result = run([sys.executable, str(installation["script"]), "--version"])
        if result.stdout.strip() != ("simple-cert " + tag.removeprefix("v")).encode():
            raise Error("The installed version did not match the release. Inspect it before retrying.")
    print(f"Updated to {tag}. Run simple-cert again to load the new version.")
    return True


def menu(manager):
    while True:
        interactive = clear_screen()
        print(MENU)
        try:
            choice = input("Choose [0-6]: ").strip()
            if choice == "0":
                return
            if choice == "4":
                settings_menu(manager)
            elif choice == "5":
                if update_menu(manager):
                    return
            elif choice == "6":
                if uninstall_menu(manager):
                    return
            elif choice == "1":
                if not (manager.root / "settings.json").exists():
                    settings_menu(manager)
                domains = normalize_domains([input("Domain (example.com or *.example.com): ")])
                if (
                    not domains[0].startswith("*.")
                    and input("Include *." + domains[0] + " as well? [y/N]: ").strip().lower() == "y"
                ):
                    domains.append("*." + domains[0])
                print("DNS must be hosted on Cloudflare. No A/AAAA or proxy changes are required.")
                if (
                    input("Issue a public Let's Encrypt certificate for these names? [y/N]: ").strip().lower()
                    == "y"
                ):
                    issued = manager.issue(domains)
                    show(manager, issued)
                    offer_panel_delivery(manager, issued)
            elif choice in ("2", "3"):
                records = manager.records()
                if not records:
                    print("No certificates saved yet.")
                else:
                    for index, record in enumerate(records, 1):
                        print(
                            f"{index}. {', '.join(record['domains'])} | {record.get('expires_at', 'not issued')} | {record['operation']}"
                        )
                    selection = input("Certificate number (0 to cancel): ").strip()
                    if selection == "0":
                        continue
                    if not selection.isdigit() or not 1 <= int(selection) <= len(records):
                        raise Error("Invalid certificate number.")
                    selected = records[int(selection) - 1]
                    if choice == "2":
                        certificate_menu(manager, selected)
                        continue
                    else:
                        print("The ACME client renews only when due; no forced renewal is performed.")
                        show(manager, manager.renew(selected["id"]))
            else:
                print("Invalid choice. Choose a number from 0 to 6.")
        except Error as error:
            print(f"\nError: {error}")
        except KeyboardInterrupt:
            print("\nCancelled. Any existing certificate files are retained.")
        except EOFError:
            print("\nGoodbye.")
            return
        if interactive:
            try:
                input("Press Enter to return to the menu...")
            except EOFError:
                print("\nGoodbye.")
                return
            except KeyboardInterrupt:
                print()


def main():
    parser = argparse.ArgumentParser(
        prog="simple-cert", description="Interactive Cloudflare DNS-01 certificate tool."
    )
    parser.add_argument("--version", action="version", version=f"simple-cert {VERSION}")
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path.home() / ".local/share/simple-cert",
        help="Private state directory (default: ~/.local/share/simple-cert)",
    )
    args = parser.parse_args()
    os.umask(0o077)
    try:
        menu(Manager(args.state_dir))
    except Error as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except OSError:
        print(
            "Error: Cannot access private files or a required command. Check permissions and disk space.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
