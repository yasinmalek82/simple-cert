#!/usr/bin/env python3
"""Small Cloudflare DNS-01 certificate menu. Runtime: Python stdlib + OpenSSL."""

import argparse
import contextlib
import datetime as dt
import fcntl
import getpass
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import warnings
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

VERSION = "0.1.10"
REPOSITORY = "yasinmalek82/simple-cert"
LEGACY_RELEASES = {
    "57f5f5b583dd558ac4f52d23eba9d425b03229e34f07a2227a6590c88fe504a1": "0.1.0",
    "56fd53a80c838bf9837c67d7c39b62fda18ab775415781f59a433c1c6e49daf7": "0.1.1",
    "0c6951e490fbf7f198028864ffe54a8185ebe10f680bf4a3ac04ee55ea05896a": "0.1.2",
    "5831604e33d6b653ed7aa954b334ed09b6ae5a98e5f3ce9874630ff7bfc56557": "0.1.3",
}
ACME_COMMIT = "3688b094adffc1a52d3b994c586cd97caa2f0b85"
CA = "https://acme-v02.api.letsencrypt.org/directory"
AUTOMATION_DIR = Path("/etc/simple-cert")
SYSTEMD_DIR = Path("/etc/systemd/system")
MENU = f"""
  SIMPLE CERT v{VERSION}
  Cloudflare DNS verification | Let's Encrypt
  ------------------------------------------------
  1. Node/config certificates
  2. Panel HTTPS certificates
  3. Settings and automation
  4. Program maintenance
  0. Exit
  ------------------------------------------------
"""
CORE_MENU = """
  NODE/CONFIG CERTIFICATES
  1. Issue certificate
  2. List certificates and file paths
  3. Renew certificate manually
  0. Back to main menu
"""
PANEL_MENU = """
  PANEL HTTPS CERTIFICATES
  1. Issue certificate
  2. List certificates and file paths
  3. Renew certificate manually
  4. Detailed current HTTPS report
  5. Refresh current HTTPS status
  0. Back to main menu
  Separate files only; activation is manual.
"""


class Error(Exception):
    """A safe, operator-facing error without raw command output."""


class Busy(Error):
    """An operation lock is already held by another writer."""


class OutcomeUnknown(Error):
    """A side effect may have completed; inspect evidence before retrying."""


def run(argv, *, env=None, cwd=None, allowed=(0,), timeout=1800, message=None):
    try:
        with subprocess.Popen(
            argv,
            env=env,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        ) as process:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except BaseException:
                # Killing only the shell can leave ACME/curl descendants modifying
                # DNS or export files after the operation lock has been released.
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                raise
            result = subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
    except subprocess.TimeoutExpired:
        raise OutcomeUnknown(
            message or "Command timed out; outcome unknown; private output suppressed."
        ) from None
    except OSError:
        raise Error(message or "Command unavailable; private output suppressed.") from None
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
            raise Busy("Another simple-cert operation is running. Try again when it finishes.") from None
        yield
    finally:
        os.close(descriptor)


@contextlib.contextmanager
def certificate_lock(manager, identifier):
    if not isinstance(identifier, str) or not re.fullmatch(CERTIFICATE_ID, identifier):
        raise Error("Invalid certificate selection.")
    with locked(manager.root / "certificates" / identifier):
        yield


def pair_digest(folder):
    try:
        return hashlib.sha256(
            b"\0".join((folder / name).read_bytes() for name in ("fullchain.pem", "key.pem"))
        ).hexdigest()
    except OSError:
        return None


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


CERTIFICATE_ID = r"(?:[a-z0-9][a-z0-9.-]{0,199}--)?[a-f0-9]{24}"


def certificate_identifier(domains):
    domains = normalize_domains(domains)
    digest = hashlib.sha256("\n".join(domains).encode()).hexdigest()[:24]
    label = domains[0].replace("*.", "wildcard.")[:200]
    return f"{label}--{digest}"


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
    def __init__(self, root, *, purpose="core"):
        if purpose not in ("core", "panel"):
            raise Error("Invalid certificate section.")
        self.purpose = purpose
        self.settings_root = Path(root).expanduser().absolute()
        self.root = self.settings_root if purpose == "core" else self.settings_root / "panel-https"
        private_dir(self.root)

    def config(self):
        path = self.settings_root / "settings.json"
        if not path.exists():
            raise Error(
                "Configure Cloudflare settings first (Settings and automation > Cloudflare settings)."
            )
        result = load(path)
        if (
            not isinstance(result.get("email"), str)
            or not isinstance(result.get("token"), str)
            or not result.get("email")
            or not result.get("token")
        ):
            raise Error(
                "Configure Cloudflare settings first (Settings and automation > Cloudflare settings)."
            )
        return result

    def configure(self, email, token):
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254:
            raise Error("Enter a valid ACME account email address.")
        if not token or len(token) > 1024 or any(char.isspace() or ord(char) < 32 for char in token):
            raise Error("Enter a valid Cloudflare API token without spaces or newlines.")
        with locked(self.settings_root):
            save(self.settings_root / "settings.json", {"email": email, "token": token})

    def harden(self, homes=()):
        # Harden only ACME workspaces touched by this operation, never all retained versions.
        for home in homes:
            for directory, _, files in os.walk(home, followlinks=False):
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
            source = Path(temporary) / "source"
            candidate = Path(temporary) / "engine"
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
            shutil.copytree(source, candidate, ignore=shutil.ignore_patterns(".git"))
            (candidate / "revision").write_text(ACME_COMMIT)
            for directory, _, files in os.walk(candidate):
                Path(directory).chmod(0o700)
                for name in files:
                    (Path(directory) / name).chmod(0o600)
            os.replace(candidate, engine)
        self.harden((engine,))

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
        completed = False
        try:
            if renew:
                response = run(
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
                response = run(
                    [*base, "--issue", "--dns", "dns_cf", "--keylength", "ec-256", *domains],
                    env=env,
                    allowed=(0, 2),
                    message=failure,
                )
            completed = True
            record["acme_result"] = "not due" if response.returncode == 2 else "client completed"
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
        except (Error, OSError):
            if completed:
                raise OutcomeUnknown(
                    "ACME completed but export is uncertain; reconcile before retrying."
                ) from None
            raise
        finally:
            self.harden((account, cert_home, export))

    def read_record(self, identifier):
        if not isinstance(identifier, str) or not re.fullmatch(CERTIFICATE_ID, identifier):
            raise Error("Invalid certificate selection.")
        path = self.root / "certificates" / identifier / "record.json"
        if path.is_symlink() or path.parent.is_symlink():
            raise Error("Invalid certificate record path.")
        record = load(path)
        try:
            if record.get("id") != identifier or not isinstance(record.get("domains"), list):
                raise ValueError
            if normalize_domains(record["domains"]) != record["domains"]:
                raise ValueError
            if record.get("operation") not in (
                "complete",
                "failed",
                "unknown",
                "issuing",
                "renewing",
                "publishing",
            ):
                raise ValueError
            if record.get("purpose", self.purpose) != self.purpose:
                raise ValueError
            if "issued" in record and type(record["issued"]) is not bool:
                raise ValueError
            automation = record.get("automation", {})
            if not isinstance(automation, dict) or type(automation.get("enabled", False)) is not bool:
                raise ValueError
            if record.get("expires_at"):
                expiry = dt.datetime.fromisoformat(record["expires_at"])
                if expiry.tzinfo is None:
                    raise ValueError
            schedule = record.get("schedule", {})
            if not isinstance(schedule, dict):
                raise ValueError
            if schedule:
                if type(schedule.get("attempts")) is not int or not 0 <= schedule["attempts"] <= 3:
                    raise ValueError
                if not isinstance(schedule.get("attempt_id"), str) or not isinstance(
                    schedule.get("day"), str
                ):
                    raise ValueError
                if schedule.get("outcome") not in ("in progress", "done", "failed", "unknown"):
                    raise ValueError
                if type(schedule.get("slot", -1)) is not int:
                    raise ValueError
            deliveries = record.get("deliveries", [])
            if not isinstance(deliveries, list):
                raise ValueError
            for item in deliveries:
                if not isinstance(item, dict) or not all(
                    isinstance(item.get(k), str)
                    for k in ("kind", "name", "directory", "host_directory", "status")
                ):
                    raise ValueError
                checked_path(item["directory"])
                checked_path(item["host_directory"])
        except (ValueError, TypeError, AttributeError):
            raise Error("Invalid certificate state; restore its private record before writing.") from None
        return record

    def records(self):
        result = []
        for path in sorted((self.root / "certificates").glob("*/record.json")):
            try:
                record = self.read_record(path.parent.name)
            except (Error, OSError):
                print("Warning: unreadable certificate record: " + path.parent.name)
                continue
            current = path.parent / "current"
            record["active"] = (current / "fullchain.pem").is_file()
            record["file_status"] = "not issued"
            if record["active"]:
                try:
                    record.update(validate_pair(current, record["domains"], check_validity=False))
                    record["file_status"] = "available"
                except Error:
                    record["file_status"] = "invalid"
            result.append(record)
        return result

    def issue(self, domains):
        domains = normalize_domains(domains)
        identifier = certificate_identifier(domains)
        with certificate_lock(self, identifier), locked(self.root):
            self.config()
            legacy = identifier.rsplit("--", 1)[1]
            folder = self.root / "certificates" / identifier
            path = folder / "record.json"
            if path.exists() or (self.root / "certificates" / legacy / "record.json").exists():
                raise Error("This domain set is already saved. Use Renew certificate (menu option 3).")
            private_dir(folder)
            return self._obtain(
                {"id": identifier, "domains": domains, "purpose": self.purpose}, folder, renew=False
            )

    def renew(self, identifier):
        if not re.fullmatch(CERTIFICATE_ID, identifier):
            raise Error("Invalid certificate selection.")
        with certificate_lock(self, identifier), locked(self.root):
            self.config()
            record = self.read_record(identifier)
            record = self._renew_locked(record)
        return refresh_deliveries(self, record) if self.purpose == "core" else record

    def _renew_locked(self, record):
        if record["operation"] in ("unknown", "issuing", "renewing", "publishing"):
            raise OutcomeUnknown("An unfinished operation requires reconciliation before another CA request.")
        folder = self.root / "certificates" / record["id"]
        active = (folder / "current" / "fullchain.pem").is_file()
        return self._obtain(record, folder, renew=record.get("issued", False) or active)

    def _obtain(self, record, folder, renew, source=None):
        version_name = uuid.uuid4().hex
        record.pop("acme_result", None)
        record.update(
            {
                "operation": "renewing" if renew else "issuing",
                "candidate": version_name,
                "export_before": pair_digest(self.root / "acme-exports" / record["id"]),
            }
        )
        save(folder / "record.json", record)
        versions = private_dir(folder / "versions")
        version = private_dir(versions / version_name)
        link = folder / (".current-" + uuid.uuid4().hex)
        print("Checking certificate renewal and validating files...", flush=True)
        try:
            if source is None:
                self.obtain(record, version, renew=renew)
            else:
                for name in ("fullchain.pem", "key.pem"):
                    shutil.copyfile(source / name, version / name)
            metadata = validate_pair(version, record["domains"])
            if pair_digest(folder / "current") == pair_digest(version):
                shutil.rmtree(version)
                record.update(metadata)
                record.update({"operation": "complete", "issued": True, "result": "unchanged"})
            else:
                for name in ("fullchain.pem", "key.pem"):
                    path = version / name
                    path.chmod(0o600)
                    with path.open("rb") as stream:
                        os.fsync(stream.fileno())
                sync_dir(version)
                sync_dir(versions)
                record["operation"] = "publishing"
                save(folder / "record.json", record)
                link.symlink_to(Path("versions") / version.name)
                os.replace(link, folder / "current")
                sync_dir(folder)
                record.update(metadata)
                record.update({"operation": "complete", "issued": True, "result": "changed"})
            record.pop("candidate", None)
            record.pop("export_before", None)
            save(folder / "record.json", record)
            return record
        except BaseException as error:
            published = (folder / "current").resolve() == version
            uncertain = (
                published
                or record.get("acme_result") in ("not due", "client completed")
                or isinstance(error, (OutcomeUnknown, KeyboardInterrupt, SystemExit))
            )
            if not uncertain:
                shutil.rmtree(version, ignore_errors=True)
                record.pop("candidate", None)
            record["operation"] = "unknown" if uncertain else "failed"
            save(folder / "record.json", record)
            raise
        finally:
            link.unlink(missing_ok=True)

    def reconcile(self, identifier):
        """Recover validated output only. Never call the CA or replay a service action."""
        with certificate_lock(self, identifier), locked(self.root):
            record = self.read_record(identifier)
            folder = self.root / "certificates" / identifier
            if record["operation"] == "complete" and record.get("issued"):
                validate_pair(folder / "current", record["domains"])
                if record.get("schedule", {}).get("outcome") in ("unknown", "in progress"):
                    record["schedule"]["outcome"] = "done"
                    save(folder / "record.json", record)
                return record
            name = record.get("candidate", "")
            candidate = folder / "versions" / name
            if not re.fullmatch(r"[a-f0-9]{32}", name):
                raise OutcomeUnknown("No recoverable candidate; operator review required.")
            if candidate.is_symlink():
                raise Error("Invalid recovery candidate.")
            try:
                validate_pair(candidate, record["domains"])
            except Error:
                export = self.root / "acme-exports" / identifier
                if pair_digest(export) is None or pair_digest(export) == record.get("export_before"):
                    raise OutcomeUnknown("No new validated ACME export; outcome remains unknown.") from None
                validate_pair(export, record["domains"])
                candidate = export
            if candidate == (folder / "current").resolve():
                record.update(validate_pair(candidate, record["domains"]))
                record.update({"operation": "complete", "issued": True, "result": "changed"})
                record.pop("candidate", None)
                record.pop("export_before", None)
                save(folder / "record.json", record)
            else:
                old_candidate = folder / "versions" / name
                record = self._obtain(record, folder, renew=True, source=candidate)
                if old_candidate != (folder / "current").resolve():
                    shutil.rmtree(old_candidate, ignore_errors=True)
            if record.get("schedule", {}).get("outcome") in ("unknown", "in progress"):
                record["schedule"]["outcome"] = "done"
                save(folder / "record.json", record)
        return refresh_deliveries(self, record) if self.purpose == "core" else record


def require_systemd():
    if sys.platform != "linux" or os.geteuid() != 0 or not Path("/run/systemd/system").is_dir():
        raise Error("Automatic renewal requires root on the Linux mother with systemd.")
    try:
        ZoneInfo("Asia/Tehran")
    except ZoneInfoNotFoundError:
        raise Error("Install system timezone data before enabling automatic renewal.") from None


def unit_argument(value):
    value = str(value)
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise Error("Control characters are not allowed in timer paths.")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'


def automation_units(script, state):
    service = (
        "[Unit]\nDescription=Simple Cert file renewal (manual activation)\nWants=network-online.target\nAfter=network-online.target\n\n"
        "[Service]\nType=oneshot\nUser=root\nUMask=0077\nTimeoutStartSec=infinity\nKillMode=control-group\n"
        f"ExecStart=/usr/bin/python3 {unit_argument(script)} --state-dir {unit_argument(state)} --worker\n"
    )
    timer = (
        "[Unit]\nDescription=Simple Cert daily file renewal\n\n[Timer]\n"
        "OnCalendar=*-*-* 04:00,10,20:00 Asia/Tehran\nPersistent=false\nAccuracySec=1s\n"
        "Unit=simple-cert-renew.service\n\n[Install]\nWantedBy=timers.target\n"
    )
    return {"simple-cert-renew.service": service, "simple-cert-renew.timer": timer}


def write_unit(path, text):
    fd, temporary = tempfile.mkstemp(prefix=".simple-cert-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary).chmod(0o644)
        os.replace(temporary, path)
        sync_dir(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def automation_owner():
    path = AUTOMATION_DIR / "automation.json"
    return load(path) if path.exists() else None


def install_automation(manager):
    require_systemd()
    installation = identify_installation(Path(__file__))
    if installation is None:
        raise Error("Enable automation from a recognized installed copy.")
    script = str(installation["script"])
    state = str(manager.settings_root.resolve())
    units = automation_units(script, state)
    with locked(AUTOMATION_DIR), application_lock(installation["prefix"]):
        owner = automation_owner()
        if owner and (owner.get("script") != script or owner.get("state") != state):
            raise Error("Automatic renewal belongs to another installation or state directory.")
        for name, text in units.items():
            path = SYSTEMD_DIR / name
            if path.is_symlink() or (path.exists() and (not owner or path.read_text() != text)):
                raise Error("An unrecognized renewal unit exists; no replacement performed.")
        owner = {"script": script, "state": state, "status": "installing"}
        save(AUTOMATION_DIR / "automation.json", owner)
        for name, text in units.items():
            write_unit(SYSTEMD_DIR / name, text)
        run(["systemctl", "daemon-reload"], timeout=30)
        run(["systemctl", "enable", "--now", "simple-cert-renew.timer"], timeout=30)
        owner["status"] = "enabled"
        save(AUTOMATION_DIR / "automation.json", owner)


def remove_automation(installation):
    owner = automation_owner()
    if not owner or owner.get("script") != str(installation["script"]):
        return
    require_systemd()
    with locked(AUTOMATION_DIR):
        units = automation_units(owner["script"], owner["state"])
        for name, text in units.items():
            path = SYSTEMD_DIR / name
            if path.is_symlink() or (path.exists() and path.read_text() != text):
                raise Error("Renewal units changed; inspect before uninstalling.")
        owner["status"] = "removing"
        save(AUTOMATION_DIR / "automation.json", owner)
        run(["systemctl", "disable", "--now", "simple-cert-renew.timer"], timeout=30)
        run(["systemctl", "stop", "simple-cert-renew.service"], timeout=60)
        for name in units:
            (SYSTEMD_DIR / name).unlink(missing_ok=True)
        sync_dir(SYSTEMD_DIR)
        run(["systemctl", "daemon-reload"], timeout=30)
        (AUTOMATION_DIR / "automation.json").unlink()
        sync_dir(AUTOMATION_DIR)


def set_automation(manager, identifier, enabled):
    with certificate_lock(manager, identifier):
        record = manager.read_record(identifier)
        if enabled:
            if record["operation"] != "complete" or not record.get("issued"):
                raise Error("Complete or reconcile issuance before enabling automatic renewal.")
            validate_pair(manager.root / "certificates" / identifier / "current", record["domains"])
        record["automation"] = {"enabled": bool(enabled)}
        save(manager.root / "certificates" / identifier / "record.json", record)
    return record


def enqueue_notice(root, key, message):
    # Queue and acknowledgements are independent of certificate operation state.
    with locked(root / "notices"):
        path = root / "notifications.json"
        queue = load(path) if path.exists() else {}
        if key not in queue:
            queue[key] = {"message": message, "sent": False}
            save(path, queue)


def configure_telegram(root, token, chat_id):
    if not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]{8,200}", token) or not re.fullmatch(r"-?[0-9]{1,24}", chat_id):
        raise Error("Enter a valid bot token and numeric Telegram chat ID.")
    with locked(root / "notices"):
        save(root / "telegram.json", {"token": token, "chat_id": chat_id})


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Error("Redirect refused; private request suppressed.")


def send_telegram(config, message):
    if (
        not isinstance(config.get("token"), str)
        or not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]{8,200}", config["token"])
        or not isinstance(config.get("chat_id"), str)
        or not re.fullmatch(r"-?[0-9]{1,24}", config["chat_id"])
    ):
        raise Error("Invalid saved Telegram settings; reconfigure using the hidden prompt.")
    payload = json.dumps(
        {"chat_id": config["chat_id"], "text": message, "disable_web_page_preview": True}
    ).encode()
    request = urllib.request.Request(
        "https://api.telegram.org/bot" + config["token"] + "/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=15) as response:
            result = json.loads(response.read(65537))
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise ValueError
    except (OSError, ValueError, KeyError, urllib.error.URLError):
        raise Error("Telegram delivery failed; private response suppressed.") from None


def flush_notices(root):
    path = root / "telegram.json"
    if not path.exists():
        return
    with locked(root / "notices"):
        config = load(path)
        queue_path = root / "notifications.json"
        queue = load(queue_path) if queue_path.exists() else {}
        for event in queue.values():
            if not event.get("sent"):
                send_telegram(config, event["message"])
                event["sent"] = True
                save(queue_path, queue)


def expiry_notice(manager, record, now):
    if not record.get("expires_at"):
        return
    remaining = (dt.datetime.fromisoformat(record["expires_at"]) - now).total_seconds() / 86400
    thresholds = [value for value in (7, 3, 1) if remaining <= value]
    if thresholds:
        threshold = min(thresholds)
        key = f"expiry:{manager.purpose}:{record['id']}:{record['expires_at']}:{threshold}"
        enqueue_notice(
            manager.settings_root,
            key,
            f"{manager.purpose} certificate {', '.join(record['domains'])}: {max(0, int(remaining))} days remaining. Check renewal and manual activation.",
        )


def finish_schedule(manager, identifier, schedule, outcome):
    with certificate_lock(manager, identifier):
        record = manager.read_record(identifier)
        if record.get("schedule", {}).get("attempt_id") != schedule["attempt_id"]:
            raise Error("Scheduled operation identity changed; outcome not overwritten.")
        record["schedule"]["outcome"] = outcome
        save(manager.root / "certificates" / identifier / "record.json", record)
    return record


def worker_certificate(manager, identifier, local, now):
    folder = manager.root / "certificates" / identifier
    reconcile = False
    checked = False
    with certificate_lock(manager, identifier), locked(manager.root):
        record = manager.read_record(identifier)
        if record.get("automation", {}).get("enabled") is not True:
            return
        expiry_notice(manager, record, now)
        old = record.get("schedule", {})
        if not isinstance(old, dict):
            raise Error("Invalid schedule state; automatic renewal blocked.")
        if old.get("outcome") == "failed" and old.get("day") != local.date().isoformat():
            enqueue_notice(
                manager.settings_root,
                f"failed:{manager.purpose}:{identifier}:{record.get('incident', old['attempt_id'])}",
                f"{manager.purpose} certificate {identifier}: unresolved renewal failure from the previous window. Expires {record.get('expires_at', 'unknown')}; inspect local status.",
            )
        if old.get("outcome") in ("in progress", "unknown") or record["operation"] in (
            "issuing",
            "renewing",
            "publishing",
            "unknown",
        ):
            reconcile = True
            schedule = old or {"attempt_id": uuid.uuid4().hex, "day": local.date().isoformat(), "attempts": 0}
            record["schedule"] = {**schedule, "outcome": "unknown"}
            save(folder / "record.json", record)
        else:
            same_day = old.get("day") == local.date().isoformat()
            attempts = old.get("attempts", 0) if same_day else 0
            slot = local.minute // 10
            if type(attempts) is not int or not 0 <= attempts <= 3:
                raise Error("Invalid attempt budget; automatic renewal blocked.")
            if same_day and old.get("outcome") == "done":
                checked = True
                schedule = old
            elif same_day and old.get("slot", -1) >= slot:
                return
            if not checked and attempts >= 3:
                return
            if not checked:
                schedule = {
                    "attempt_id": uuid.uuid4().hex,
                    "day": local.date().isoformat(),
                    "attempts": attempts + 1,
                    "slot": slot,
                    "outcome": "in progress",
                }
                record["schedule"] = schedule
                save(folder / "record.json", record)
                try:
                    record = manager._renew_locked(record)
                except BaseException as error:
                    record = manager.read_record(identifier)
                    outcome = (
                        "unknown"
                        if record["operation"] == "unknown"
                        or isinstance(error, (OutcomeUnknown, KeyboardInterrupt, SystemExit))
                        else "failed"
                    )
                    record["schedule"]["outcome"] = outcome
                    record["incident"] = record.get("incident") or schedule["attempt_id"]
                    save(folder / "record.json", record)
                    if outcome == "unknown" or slot == 2 or attempts == 2:
                        enqueue_notice(
                            manager.settings_root,
                            f"{outcome}:{manager.purpose}:{identifier}:{record['incident']}",
                            f"{manager.purpose} certificate {', '.join(record['domains'])}: {outcome}; inspect local status. Existing files retained; manual activation required.",
                        )
                    raise
    try:
        if reconcile:
            record = manager.reconcile(identifier)
        if manager.purpose == "core":
            record = refresh_deliveries(manager, record)
    except BaseException:
        finish_schedule(manager, identifier, schedule, "unknown")
        enqueue_notice(
            manager.settings_root,
            f"unknown:{manager.purpose}:{identifier}:{schedule['attempt_id']}",
            f"{manager.purpose} certificate {identifier}: recovery requires operator review; no new CA request made.",
        )
        raise
    pending = any(item["status"] != "complete" for item in record.get("deliveries", []))
    record = finish_schedule(manager, identifier, schedule, "done")
    fingerprint = pair_digest(folder / "current")
    if record.get("result") == "changed":
        enqueue_notice(
            manager.settings_root,
            f"renewed:{manager.purpose}:{identifier}:{fingerprint}",
            f"{manager.purpose} certificate {', '.join(record['domains'])}: renewed files. Expires {record.get('expires_at', 'unknown')}. Manual activation required.",
        )
    if pending:
        enqueue_notice(
            manager.settings_root,
            f"delivery:{manager.purpose}:{identifier}:{fingerprint}",
            f"{manager.purpose} certificate {identifier}: local files available; Delivery pending. Retry delivery from certificate details.",
        )
    if record.get("incident") and not pending:
        enqueue_notice(
            manager.settings_root,
            f"recovered:{manager.purpose}:{identifier}:{record['incident']}",
            f"{manager.purpose} certificate {identifier}: renewal recovered; manual activation required.",
        )
        with certificate_lock(manager, identifier):
            record = manager.read_record(identifier)
            record.pop("incident", None)
            save(folder / "record.json", record)


def worker(root, now=None):
    root = Path(root).expanduser().absolute()
    fixed_clock = now is not None
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        raise Error("Worker requires a timezone-aware clock.")
    try:
        local = now.astimezone(ZoneInfo("Asia/Tehran"))
    except ZoneInfoNotFoundError:
        raise Error("Asia/Tehran timezone data unavailable; automatic renewal blocked.") from None
    try:
        lock = locked(root / "worker")
        lock.__enter__()
    except Busy:
        print("Worker already running; skipped.")
        return 0
    failed = False
    try:
        if local.hour == 4 and local.minute < 30:
            for purpose in ("core", "panel"):
                manager = Manager(root, purpose=purpose)
                for record in manager.records():
                    try:
                        instant = now if fixed_clock else dt.datetime.now(dt.timezone.utc)
                        current_local = instant.astimezone(ZoneInfo("Asia/Tehran"))
                        if current_local.hour != 4 or current_local.minute >= 30:
                            break
                        worker_certificate(manager, record["id"], current_local, instant)
                    except (Error, OSError):
                        failed = True
                        print(
                            f"{purpose} certificate {record['id']}: automatic operation needs review; private output suppressed."
                        )
        try:
            flush_notices(root)
        except (Error, OSError):
            failed = True
            print("Telegram unavailable; notices retained for retry.")
    finally:
        lock.__exit__(None, None, None)
    return int(failed)


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
        compose_dir = (config.get("Labels") or {}).get("com.docker.compose.project.working_dir")
        result.append(
            {
                "kind": "docker",
                "id": item["Id"],
                "name": item["Name"].lstrip("/"),
                "data": data,
                "userns": item.get("HostConfig", {}).get("UsernsMode", ""),
                "https": {
                    name: value
                    for entry in config.get("Env", [])
                    if "=" in entry
                    for name, value in [entry.split("=", 1)]
                    if name in HTTPS_KEYS
                },
                "env_file": str(Path(compose_dir) / ".env")
                if compose_dir and Path(compose_dir).is_absolute()
                else None,
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
        context = os.environ.get("DOCKER_CONTEXT")
        endpoint = None if context else os.environ.get("DOCKER_HOST")
        if not endpoint:
            argv = ["docker", "context", "inspect"] + ([context] if context else [])
            contexts = json.loads(run(argv, timeout=15).stdout)
            endpoint = contexts[0]["Endpoints"]["docker"]["Host"]
        if not endpoint.startswith("unix://"):
            return []
        docker = ["docker", "--host", endpoint]
        env = {k: v for k, v in os.environ.items() if k not in ("DOCKER_HOST", "DOCKER_CONTEXT")}
        ids = run([*docker, "ps", "-q"], env=env, timeout=15).stdout.decode().split()
        if not ids:
            return []
        targets = docker_panels(json.loads(run([*docker, "inspect", *ids], env=env, timeout=15).stdout))
        for target in targets:
            target["docker"] = docker
        return targets
    except (Error, ValueError, KeyError, IndexError, TypeError):
        return []


HTTPS_KEYS = {"UVICORN_SSL_CERTFILE", "UVICORN_SSL_KEYFILE", "UVICORN_HOST", "UVICORN_PORT"}


def read_settings_values(path, keys):
    """Read selected assignments without sourcing shell or dotenv code."""
    result = {}
    try:
        if not path.is_file() or path.stat().st_size > 1024 * 1024:
            return result
        for line in path.read_text(errors="replace").splitlines():
            name, separator, value = line.strip().removeprefix("export ").partition("=")
            if not separator or name.strip() not in keys:
                continue
            try:
                values = shlex.split(value, comments=True)
            except ValueError:
                continue
            if len(values) == 1:
                result[name.strip()] = values[0]
    except OSError:
        pass
    return result


def panel_certificate_host_path(target, path):
    """Read mapping permits read-only mounts and normal live/archive symlinks."""
    path = checked_path(path)
    if target["kind"] == "native":
        return path
    mounts = [
        item
        for item in target["mounts"]
        if item.get("Destination") and path.is_relative_to(Path(item["Destination"]))
    ]
    if not mounts:
        raise Error("Configured certificate has no local host mount mapping.")
    mount = max(mounts, key=lambda item: len(Path(item["Destination"]).parts))
    source = checked_path(mount["Source"])
    host = source / path.relative_to(mount["Destination"])
    if not host.resolve().is_relative_to(source.resolve()):
        raise Error("Certificate symlink leaves its mapped mount; runtime path is unverified.")
    return host


def inspect_panel_https(target):
    values = dict(target.get("https", {}))
    source = "running container environment"
    if "UVICORN_SSL_CERTFILE" not in values and target.get("env_file"):
        values = {**read_settings_values(Path(target["env_file"]), HTTPS_KEYS), **values}
        source = "env file (runtime configuration not verified)"
    status = {
        "name": target["name"],
        "source": source,
        "public_url": "not confirmed",
        "state": "certificate unavailable",
        "certfile": values.get("UVICORN_SSL_CERTFILE", "not configured"),
        "keyfile": values.get("UVICORN_SSL_KEYFILE", "not configured"),
        "listener": values.get("UVICORN_HOST", "0.0.0.0") + ":" + values.get("UVICORN_PORT", "8000"),
    }
    try:
        host = panel_certificate_host_path(target, status["certfile"])
        status["host_certfile"] = str(host)
        if values.get("UVICORN_SSL_KEYFILE"):
            try:
                status["host_keyfile"] = str(
                    panel_certificate_host_path(target, values["UVICORN_SSL_KEYFILE"])
                )
            except Error:
                pass
        if not host.is_file() or host.stat().st_size > 1024 * 1024:
            return status
        details = run(
            [
                "openssl",
                "x509",
                "-in",
                str(host),
                "-noout",
                "-dates",
                "-ext",
                "subjectAltName",
                "-subject",
                "-sha256",
                "-fingerprint",
            ],
            timeout=15,
            message="Configured panel certificate cannot be decoded; private output suppressed.",
        ).stdout.decode("ascii", errors="replace")
        dates = dict(
            line.split("=", 1)
            for line in details.splitlines()
            if line.startswith(("notBefore=", "notAfter="))
        )
        start = dt.datetime.strptime(dates["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=dt.timezone.utc
        )
        end = dt.datetime.strptime(dates["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
        domains = sorted(set(re.findall(r"DNS:([a-zA-Z0-9.*-]+)", details)))
        now = dt.datetime.now(dt.timezone.utc)
        status.update(
            {
                "domains": domains,
                "expires_at": end.isoformat(),
                "days_remaining": (end - now).days,
                "state": "expired"
                if end <= now
                else "not yet valid"
                if now < start
                else "valid configured PEM",
            }
        )
    except (Error, OSError, KeyError, ValueError):
        pass
    return status


def renewal_command(command):
    """Recognize direct clients and simple env/shell wrappers, without execution."""
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return None
    for index, token in enumerate(tokens):
        if token in (";", "&&", "||", "|", ">", ">>", "<", "&"):
            tokens = tokens[:index]
            break
    if tokens and Path(tokens[0]).name == "env":
        tokens.pop(0)
    while tokens and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[0]):
        tokens.pop(0)
    if (
        tokens
        and Path(tokens[0]).name in ("sh", "bash")
        and len(tokens) > 1
        and not tokens[1].startswith("-")
    ):
        tokens.pop(0)
    if not tokens:
        return None
    client, args = Path(tokens[0]).name, tokens[1:]

    def option(flag, default=None):
        for index, value in enumerate(args):
            if value.startswith(flag + "="):
                return value.split("=", 1)[1]
            if value == flag:
                return args[index + 1] if index + 1 < len(args) else ""
        return default

    if client == "acme.sh" and ("--cron" in args or "--renew" in args):
        domain = option("-d") or option("--domain")
        if "--cron" not in args and not domain:
            return None
        home = str(Path(tokens[0]).parent) if Path(tokens[0]).is_absolute() else "/root/.acme.sh"
        result = {"client": client, "home": option("--config-home", option("--home", home))}
        if domain:
            result["domain"] = domain
        return result
    if client == "certbot" and "renew" in args:
        result = {"client": client, "home": option("--config-dir", "/etc/letsencrypt")}
        name = option("--cert-name")
        if name:
            result["cert_name"] = name
        return result
    return None


def parse_renewal_cron(text, *, source, active, system=False):
    jobs = []
    for line in text.splitlines():
        parts = line.strip().split()
        if not parts or parts[0].startswith("#"):
            continue
        if parts[0].startswith("@"):
            if parts[0] not in (
                "@hourly",
                "@daily",
                "@midnight",
                "@weekly",
                "@monthly",
                "@yearly",
                "@annually",
            ):
                continue
            skip = 1
        else:
            if len(parts) < 6 or not all(re.fullmatch(r"[0-9*/,-]+", field) for field in parts[:5]):
                continue
            skip = 5
        command = " ".join(parts[skip + int(system) :])
        job = renewal_command(command)
        if job:
            jobs.append({**job, "source": source, "active": active})
    return jobs


def renewal_jobs(*, system_root=Path("/")):
    jobs = []
    deadline = time.monotonic() + 15
    cron_active = None
    for unit in ("cron.service", "crond.service"):
        try:
            result = run(["systemctl", "is-active", unit], allowed=(0, 3, 4), timeout=3)
            if result.stdout.strip() == b"active":
                cron_active = True
                break
            if result.stdout.strip() == b"inactive":
                cron_active = False
        except Error:
            pass
    candidates = [(system_root / "etc/crontab", True)]
    candidates += [(path, True) for path in (system_root / "etc/cron.d").glob("*")]
    candidates += [
        (path, False)
        for base in ("var/spool/cron/crontabs", "var/spool/cron")
        for path in (system_root / base).glob("*")
    ]
    for path, system in candidates:
        try:
            if path.is_file() and path.stat().st_size <= 1024 * 1024:
                jobs.extend(
                    parse_renewal_cron(
                        path.read_text(errors="replace"), source=str(path), active=cron_active, system=system
                    )
                )
        except OSError:
            pass
    try:
        jobs.extend(
            parse_renewal_cron(
                run(["crontab", "-l"], allowed=(0, 1), timeout=3).stdout.decode(errors="replace"),
                source="current-user crontab",
                active=cron_active,
            )
        )
    except Error:
        pass
    try:
        listed = run(
            ["systemctl", "list-timers", "--all", "--no-legend", "--no-pager"], timeout=3
        ).stdout.decode(errors="replace")
        timers = sorted(set(re.findall(r"[A-Za-z0-9_.@:-]+\.timer\b", listed)))
        if len(timers) > 128:
            jobs.append(
                {
                    "client": "unknown",
                    "source": "timer inventory limit reached; coverage is partial",
                    "active": None,
                }
            )
        for timer in timers[:128]:
            if time.monotonic() >= deadline:
                jobs.append(
                    {
                        "client": "unknown",
                        "source": "systemd scan budget reached; coverage is partial",
                        "active": None,
                    }
                )
                break
            props = run(
                [
                    "systemctl",
                    "show",
                    timer,
                    "--property=ActiveState,Unit,NextElapseUSecRealtime",
                    "--no-pager",
                ],
                timeout=3,
            ).stdout.decode(errors="replace")
            values = dict(line.split("=", 1) for line in props.splitlines() if "=" in line)
            service = values.get("Unit", timer.removesuffix(".timer") + ".service")
            if not re.fullmatch(r"[A-Za-z0-9_.@:-]+\.service", service):
                continue
            props = run(
                [
                    "systemctl",
                    "show",
                    service,
                    "--property=ExecStart,Result,ExecMainExitTimestamp",
                    "--no-pager",
                ],
                timeout=3,
            ).stdout.decode(errors="replace")
            command = re.search(r"argv\[\]=(.*?)\s+;", props)
            job = renewal_command(command.group(1)) if command else None
            if job:
                result = re.search(r"^Result=(.*)$", props, re.MULTILINE)
                finished = re.search(r"^ExecMainExitTimestamp=(.+)$", props, re.MULTILINE)
                jobs.append(
                    {
                        **job,
                        "source": timer,
                        "active": values.get("ActiveState") == "active",
                        "next_run": values.get("NextElapseUSecRealtime", "unknown"),
                        "last_result": result.group(1) if result and finished else "not recorded",
                        "last_run": finished.group(1) if finished else "not recorded",
                    }
                )
    except Error:
        jobs.append({"client": "unknown", "source": "systemd timer inspection unavailable", "active": None})
    return jobs


def inspect_renewal(status, jobs, *, system_root=Path("/")):
    host = status.get("host_certfile")
    if not host:
        return []
    expected = Path(host).resolve()
    matches = []
    homes = {"/root/.acme.sh", str(Path.home() / ".acme.sh")}
    homes.update(job["home"] for job in jobs if job.get("client") == "acme.sh")
    records = []
    for home in homes:
        if not Path(home).is_absolute() or ".." in Path(home).parts:
            continue
        directory = system_root / home.lstrip("/")
        for config in list(directory.glob("*/*.conf"))[:512]:
            values = read_settings_values(
                config, {"Le_RealFullChainPath", "Le_ReloadCmd", "Le_Domain", "Le_Alt"}
            )
            path = values.get("Le_RealFullChainPath")
            if path and Path(path).is_absolute() and Path(path).resolve() == expected:
                records.append(
                    {
                        "client": "acme.sh",
                        "home": home,
                        "record": str(config),
                        "domain": values.get("Le_Domain", config.stem),
                        "reload_hook": "configured (not executed)"
                        if values.get("Le_ReloadCmd")
                        else "not found",
                    }
                )
    certbot_homes = {"/etc/letsencrypt"}
    certbot_homes.update(job["home"] for job in jobs if job.get("client") == "certbot")
    for home in certbot_homes:
        if not Path(home).is_absolute() or ".." in Path(home).parts:
            continue
        for config in list((system_root / home.lstrip("/") / "renewal").glob("*.conf"))[:512]:
            values = read_settings_values(config, {"fullchain", "renew_hook", "deploy_hook"})
            path = values.get("fullchain")
            if path and Path(path).is_absolute() and Path(path).resolve() == expected:
                records.append(
                    {
                        "client": "certbot",
                        "home": home,
                        "record": str(config),
                        "cert_name": config.stem,
                        "reload_hook": "configured (not executed)"
                        if values.get("renew_hook") or values.get("deploy_hook")
                        else "not found",
                    }
                )
    for record in records:
        related = [
            job
            for job in jobs
            if job.get("client") == record["client"]
            and job.get("home") == record["home"]
            and (not job.get("domain") or job["domain"] == record.get("domain"))
            and (not job.get("cert_name") or job["cert_name"] == record.get("cert_name"))
        ]
        if not related:
            matches.append(
                {**record, "source": "no matching schedule found", "state": "tracking record only"}
            )
        for job in related:
            state = (
                "scheduled"
                if job["active"] is True
                else "scheduler inactive"
                if job["active"] is False
                else "scheduler state unknown"
            )
            matches.append({**record, **job, "state": state})
    return matches


def show_panel_https_status():
    """Only read config, certificate metadata and schedules. Do not invoke clients."""
    print("Inspecting panel certificate and renewal schedules (read-only)...", flush=True)
    lines = [
        "\nCURRENT PANEL HTTPS STATUS (read-only)",
        "Configured files only; public URL and live served TLS are not verified.",
    ]
    targets = discover_panels()
    if not targets:
        env_file = Path("/opt/pasarguard/.env")
        if env_file.is_file():
            targets = [
                {
                    "kind": "native",
                    "name": "standard .env configuration",
                    "https": {},
                    "env_file": str(env_file),
                }
            ]
    if not targets:
        lines.append("No supported current panel configuration found; HTTPS status is unknown.")
    try:
        jobs = renewal_jobs() if targets else []
    except (Error, OSError, ValueError):
        jobs = [{"client": "unknown", "source": "renewal schedule inspection unavailable", "active": None}]
    for target in targets:
        status = inspect_panel_https(target)
        lines += [
            f"Panel/container: {status['name']}",
            f"Configuration source: {status['source']}",
            f"Public panel URL: {status['public_url']} (certificate names are not a verified URL)",
            f"Configured listener: {status['listener']}",
            f"Configured certificate: {status['certfile']}",
            f"Configured private key path: {status['keyfile']}",
            f"Host certificate path: {status.get('host_certfile', 'unmapped')}",
            f"Host private key path: {status.get('host_keyfile', 'unmapped')}",
            f"Certificate state: {status['state']}",
        ]
        if status.get("expires_at"):
            lines += [
                "Certificate domain(s): " + ", ".join(status["domains"]),
                f"Expires (UTC): {status['expires_at']} | Days remaining: {status['days_remaining']}",
            ]
        try:
            matches = inspect_renewal(status, jobs)
        except (Error, OSError, ValueError):
            matches = []
            lines.append("Renewal tracking records could not be inspected completely.")
        for match in matches:
            lines += [
                f"Renewal evidence: {match['client']} via {match['source']} | {match['state']}",
                f"Associated export record: {match['record']} | Reload hook: {match['reload_hook']}",
            ]
            if match.get("next_run"):
                lines.append(
                    f"Next timer run: {match['next_run']} | Last service result: {match.get('last_result', 'unknown')} | Last exit: {match.get('last_run', 'not recorded')}"
                )
        if not matches:
            lines.append(
                "Renewal owner: unknown; no matching export record/schedule found in inspected locations."
            )
    for job in jobs:
        if job.get("client") == "unknown":
            lines.append("Scan coverage: " + job["source"])
    lines += [
        "A configured schedule is not proof of successful renewal or TLS reload.",
        "Custom jobs, reverse proxies, other containers and nonstandard env paths may require manual inspection.",
    ]
    report = "\n".join(lines)
    # Escape terminal control sequences from local paths/configuration metadata.
    report = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "?", report)
    print(report)
    return report


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


def panel_docker(target, args, **kwargs):
    env = {k: v for k, v in os.environ.items() if k not in ("DOCKER_HOST", "DOCKER_CONTEXT")}
    return run([*target.get("docker", ["docker"]), *args], env=env, **kwargs)


def panel_reader_identity(target):
    options = panel_docker(
        target, ["info", "--format", "{{json .SecurityOptions}}"], timeout=15
    ).stdout.decode()
    if target["userns"] not in ("", "host") or "rootless" in options or "userns" in options:
        raise Error("Automatic delivery requires local rootful Docker without user namespace remapping.")
    output = (
        panel_docker(
            target,
            [
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
        panel_docker(
            target,
            [
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
    require_core_section(manager)
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
    with certificate_lock(manager, record["id"]):
        record_path = manager.root / "certificates" / record["id"] / "record.json"
        record = manager.read_record(record["id"])
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
        if pair_digest(host / "current") == pair_digest(source):
            panel_reader_check(fresh, host / "current", str(Path(directory) / "current"))
            delivery.update(metadata)
            delivery["status"] = "complete"
            delivery.pop("candidate", None)
            save(record_path, record)
            return record
        version = uuid.uuid4().hex
        delivery["status"] = "pending"
        delivery["candidate"] = version
        save(record_path, record)
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
            (host / "versions").chmod(0o711)
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
            sync_dir(host / "versions")
            link.symlink_to(Path("versions") / version)
            os.replace(link, host / "current")
            sync_dir(host)
            delivery["status"] = "published-unverified"
            save(record_path, record)
            panel_reader_check(fresh, host / "current", str(Path(directory) / "current"))
            delivery.update(metadata)
            delivery["status"] = "complete"
            delivery.pop("candidate", None)
            save(record_path, record)
            return record
        except (OSError, Error):
            if (host / "current").is_symlink() and os.readlink(host / "current") == f"versions/{version}":
                raise Error(
                    "Panel files were published; reader verification is pending. "
                    "Previous versions remain available. Retry from certificate details."
                ) from None
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
            with certificate_lock(manager, record["id"]):
                path = manager.root / "certificates" / record["id"] / "record.json"
                record = manager.read_record(record["id"])
                for saved in record.get("deliveries", []):
                    if saved["directory"] == delivery["directory"] and saved["name"] == delivery["name"]:
                        if saved["status"] != "published-unverified":
                            saved["status"] = "pending"
                save(path, record)
            print("Local renewal succeeded; a panel delivery is pending. Retry from certificate details.")
    return record


def require_core_section(manager):
    if manager.purpose != "core":
        raise Error("Core path publication is available only for node/config certificates.")


def delivery_menu(manager, record, targets=None):
    require_core_section(manager)
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
    default = str(Path(target["data"]) / "certs" / "simple-cert" / certificate_identifier(record["domains"]))
    print(f"PasarGuard container: {target['name']}")
    print("Node/config Core TLS files. These are filesystem paths, not the panel URL.")
    print("Existing panel HTTPS certificates and .env are not changed.")
    directory = input(f"Certificate directory inside the container [{default}]: ").strip() or default
    host = panel_location(target, directory)
    print(
        f"Host filesystem directory (mother server): {host}\nContainer filesystem directory (for Core): {directory}"
    )
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
    if manager.purpose != "core" or not sys.stdin.isatty():
        return
    targets = discover_panels()
    if (
        targets
        and input("Local PasarGuard found. Publish node/config certificate files for Core? [y/N]: ")
        .strip()
        .lower()
        == "y"
    ):
        delivery_menu(manager, record, targets)


def settings_menu(manager):
    if not sys.stdin.isatty():
        raise Error("Settings must be entered in an interactive terminal; tokens use hidden input.")
    previous = manager.config() if (manager.settings_root / "settings.json").exists() else {}
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
    file_status = "not issued"
    if (folder / "fullchain.pem").is_file():
        try:
            record.update(validate_pair(folder, record["domains"], check_validity=False))
            file_status = "available"
        except Error:
            file_status = "invalid"
    purpose = "Panel HTTPS" if manager.purpose == "panel" else "Node/config Core TLS"
    print("\nCertificate section: " + purpose)
    print("Domains: " + ", ".join(record["domains"]))
    print("File status: " + file_status)
    print("Expires (UTC): " + record.get("expires_at", "not issued"))
    print("Last operation: " + record["operation"])
    print("ACME result: " + record.get("acme_result", "not recorded"))
    if (folder / "fullchain.pem").is_file():
        print(f"Full chain: {folder / 'fullchain.pem'}\nPrivate key: {folder / 'key.pem'}")
        print("Separate certificate files only. Existing panel HTTPS and .env are unchanged.")
    labels = {"unchanged": "Unchanged", "changed": "New files published; Manual activation required"}
    print("Result: " + labels.get(record.get("result"), record.get("operation", "unknown")))
    print("Automatic renewal: " + ("enabled" if record.get("automation", {}).get("enabled") else "disabled"))
    if record.get("expires_at"):
        remaining = (dt.datetime.fromisoformat(record["expires_at"]) - dt.datetime.now(dt.timezone.utc)).days
        print(f"Days remaining: {remaining}")
    versions = folder.parent / "versions"
    count = len(list(versions.iterdir())) if versions.is_dir() else 0
    size = sum(
        path.stat().st_size for path in versions.rglob("*") if path.is_file() and not path.is_symlink()
    )
    print(f"Versions: {count} | Retained bytes: {size}")
    if record.get("schedule"):
        schedule = record["schedule"]
        print(
            f"Last automatic check: {schedule.get('day', 'unknown')} | {schedule.get('outcome', 'unknown')} | Attempts: {schedule.get('attempts', 0)}"
        )
    for delivery in record.get("deliveries", []):
        print(f"Core file delivery via container {delivery['name']}: {delivery['status']}")
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
    if filename not in ("fullchain.pem", "key.pem") or not re.fullmatch(CERTIFICATE_ID, record["id"]):
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
        record = manager.read_record(record["id"])
        show(manager, record)
        print("\n1. View fullchain.pem\n2. View key.pem (private)")
        if manager.purpose == "core":
            print("3. Publish/change node/config Core paths")
        print("4. Renew manually\n5. Enable/disable automatic renewal\n6. Reconcile interrupted operation")
        if manager.purpose == "core":
            print("7. Retry registered deliveries (no CA request)")
        print("0. Back to certificate list/menu")
        choice = input("Choose certificate action: ").strip()
        if choice == "0":
            return
        try:
            if choice == "3" and manager.purpose == "core":
                record = delivery_menu(manager, record)
            elif choice == "4":
                record = manager.renew(record["id"])
                show(manager, record)
            elif choice == "5":
                enabled = not record.get("automation", {}).get("enabled", False)
                print("Daily file checks: 04:00 Tehran; retries at 04:10 and 04:20.")
                print("Services are activated manually. Some consumers may read changed files automatically.")
                if (
                    input(("Enable" if enabled else "Disable") + " automatic renewal? Type yes: ")
                    .strip()
                    .lower()
                    == "yes"
                ):
                    if enabled:
                        install_automation(manager)
                    record = set_automation(manager, record["id"], enabled)
            elif choice == "6":
                record = manager.reconcile(record["id"])
                show(manager, record)
            elif choice == "7" and manager.purpose == "core":
                record = refresh_deliveries(manager, record)
                show(manager, record)
            elif choice not in ("1", "2"):
                raise Error("Invalid certificate action.")
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
        remove_automation(current)
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


def section_menu(manager):
    status_report = None
    while True:
        interactive = clear_screen()
        panel_section = manager.purpose == "panel"
        if panel_section:
            if status_report is None:
                with contextlib.redirect_stdout(io.StringIO()):
                    status_report = show_panel_https_status()
            print("Current HTTPS configuration (read-only; live TLS unverified):")
            for line in (status_report or "").splitlines():
                if line.startswith(
                    (
                        "Panel/container:",
                        "Certificate state:",
                        "Expires (UTC):",
                        "Renewal evidence:",
                        "No supported",
                    )
                ):
                    print(line)
        print(PANEL_MENU if panel_section else CORE_MENU)
        try:
            choice = input("Choose [0-5]: " if panel_section else "Choose [0-3]: ").strip()
            if panel_section and choice == "5":
                status_report = None
                continue
            if panel_section and choice == "4":
                print(status_report or "No current HTTPS report available.")
            elif choice == "0":
                return
            elif choice == "1":
                if not (manager.settings_root / "settings.json").exists():
                    settings_menu(manager)
                domain_prompt = (
                    "Panel HTTPS domain (example.com or *.example.com): "
                    if panel_section
                    else "Node/config domain (example.com or *.example.com): "
                )
                domains = normalize_domains([input(domain_prompt)])
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
                            f"{index}. {', '.join(record['domains'])} | {record.get('expires_at', 'not issued')} | {record['operation']} | Files: {record.get('file_status', 'unknown')}"
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
                print("Invalid choice. Choose an action shown in this menu.")
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


def hidden_value(prompt):
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise Error("Secret entry requires an interactive terminal.")
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(prompt).strip()
        except getpass.GetPassWarning:
            raise Error("A hidden prompt is unavailable; reopen a private SSH terminal.") from None


def utility_menu(manager, maintenance=False):
    while True:
        interactive = clear_screen()
        if maintenance:
            print("\nPROGRAM MAINTENANCE\n1. Update simple-cert\n2. Uninstall simple-cert\n0. Back")
        else:
            print(
                "\nSETTINGS AND AUTOMATION\n1. Cloudflare settings\n2. Telegram settings\n3. Automation status\n4. Retry queued notices\n5. Send Telegram test notice\n0. Back"
            )
        choice = input("Choose utility action: ").strip()
        if choice == "0":
            return False
        try:
            if maintenance and choice in ("1", "2"):
                if update_menu(manager) if choice == "1" else uninstall_menu(manager):
                    return True
            elif not maintenance and choice == "1":
                settings_menu(manager)
            elif not maintenance and choice == "2":
                token = hidden_value("Dedicated Telegram bot token (hidden): ")
                chat = input("Telegram chat ID: ").strip()
                configure_telegram(manager.settings_root, token, chat)
                print("Telegram settings saved privately. No message sent.")
            elif not maintenance and choice == "3":
                owner = automation_owner()
                print("Schedule: 04:00, 04:10, 04:20 Asia/Tehran; no missed-run catch-up.")
                print("Timer registration: " + (owner.get("status", "unknown") if owner else "not installed"))
                if owner:
                    print("Registered state directory: " + owner["state"])
                    try:
                        enabled = run(
                            ["systemctl", "is-enabled", "simple-cert-renew.timer"],
                            allowed=(0, 1, 3, 4),
                            timeout=5,
                        )
                        active = run(
                            ["systemctl", "is-active", "simple-cert-renew.timer"],
                            allowed=(0, 3, 4),
                            timeout=5,
                        )
                        print("Timer enabled: " + ("yes" if enabled.returncode == 0 else "no"))
                        print("Timer active: " + ("yes" if active.returncode == 0 else "no"))
                    except Error:
                        print("Live timer state: unknown")
                for purpose in ("core", "panel"):
                    section = Manager(manager.settings_root, purpose=purpose)
                    for record in section.records():
                        print(
                            f"{purpose}: {record['id']} | automatic renewal: {record.get('automation', {}).get('enabled', False)} | {record.get('schedule', {}).get('outcome', 'not checked')}"
                        )
            elif not maintenance and choice == "4":
                flush_notices(manager.settings_root)
                print("Queued notice delivery attempted; missing Telegram settings leave notices queued.")
            elif not maintenance and choice == "5":
                if input("Send a test to the configured Telegram chat? Type yes: ").strip().lower() == "yes":
                    send_telegram(
                        load(manager.settings_root / "telegram.json"),
                        "Simple Cert test notice. No certificate or service changed.",
                    )
                    print("Telegram accepted the test notice.")
            else:
                print("Invalid choice.")
        except (Error, OSError):
            print(
                "Operation could not complete. Check configuration and permissions; private output suppressed."
            )
        if interactive:
            input("Press Enter to return to the menu...")


def menu(manager):
    while True:
        interactive = clear_screen()
        print(MENU)
        try:
            choice = input("Choose [0-4]: ").strip()
            if choice == "0":
                return
            if choice in ("1", "2"):
                section_menu(Manager(manager.settings_root, purpose="core" if choice == "1" else "panel"))
            elif choice in ("3", "4"):
                if utility_menu(manager, maintenance=choice == "4"):
                    return
            else:
                print("Invalid choice. Choose a number from 0 to 4.")
                if interactive:
                    input("Press Enter to return to the menu...")
        except KeyboardInterrupt:
            print("\nCancelled; inspect unfinished operations before retrying.")
        except EOFError:
            print("\nGoodbye.")
            return
        except Error as error:
            print(f"Error: {error}")
            if interactive:
                input("Press Enter to return to the menu...")


def terminate_operation(signum, frame):
    raise SystemExit(128 + signum)


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
    parser.add_argument(
        "--worker", action="store_true", help="Noninteractive scheduled file renewal; no activation"
    )
    parser.add_argument(
        "--reconcile", metavar="CERTIFICATE_ID", help="Recover saved output without contacting the CA"
    )
    parser.add_argument(
        "--section", choices=("core", "panel"), default="core", help="Section for --reconcile"
    )
    args = parser.parse_args()
    os.umask(0o077)
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, terminate_operation)
    try:
        if args.worker:
            owner = automation_owner()
            if (
                not owner
                or owner.get("script") != str(Path(__file__).resolve())
                or owner.get("state") != str(args.state_dir.expanduser().resolve())
            ):
                raise Error("Worker registration does not match this installation and state directory.")
            require_systemd()
            return worker(args.state_dir)
        manager = Manager(args.state_dir, purpose=args.section)
        if args.reconcile:
            show(manager, manager.reconcile(args.reconcile))
        else:
            menu(manager)
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
